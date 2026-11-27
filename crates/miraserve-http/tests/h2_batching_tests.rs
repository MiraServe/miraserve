//! End-to-end protocol, real-flush, header-growth, control-frame, observer, and parity tests
//! for MiraServe's vendored `h2` (`COPY_LIMIT = 4096`) change.
//!
//! Exercises the real `h2` server through `hyper` as MiraServe configures it, over a controlled
//! in-memory transport with independent write/flush/shutdown gates and real waker registration
//! (never manual repolling), plus full-stack `HttpEngine` access-log and HTTP/1.1 + upgrade
//! parity checks.

use std::collections::{BTreeMap, VecDeque};
use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body::{Body, Frame};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoConnBuilder;
use miraserve_config::parse_kdl;
use miraserve_http::{HttpEngine, WriteGuardedIo};
use miraserve_tls::AcmeChallengeStore;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore, watch};
use tracing::field::{Field, Visit};
use tracing::{Event, Metadata, Subscriber, span};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_RST_STREAM: u8 = 0x3;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_PING: u8 = 0x6;
const FRAME_GOAWAY: u8 = 0x7;
const FRAME_WINDOW_UPDATE: u8 = 0x8;
const FRAME_CONTINUATION: u8 = 0x9;

const FLAG_END_STREAM: u8 = 0x1;
const FLAG_ACK: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;

const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;
const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;

// ---------------------------------------------------------------------------
// Strict verified h2 source-mode reader (`vendor/h2-source.env`)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum H2SourceMode {
    Vendored,
    Registry,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedH2Source {
    mode: H2SourceMode,
    version: String,
    archive_sha256: String,
    vendored_version: String,
}

impl VerifiedH2Source {
    /// True when the checkout is in registry mode at the same upstream version that
    /// `vendor/h2/Cargo.toml` carries (so exact unpatched upstream framing assertions apply).
    fn is_vendored_upstream_registry(&self) -> bool {
        self.mode == H2SourceMode::Registry && self.version == self.vendored_version
    }
}

fn is_valid_semver_triple(s: &str) -> bool {
    let mut parts = s.split('.');
    let Some(a) = parts.next() else {
        return false;
    };
    let Some(b) = parts.next() else {
        return false;
    };
    let Some(c) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    [a, b, c]
        .iter()
        .all(|p| !p.is_empty() && p.bytes().all(|ch| ch.is_ascii_digit()))
}

fn is_valid_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn parse_h2_source_env(contents: &str) -> Result<VerifiedH2Source, String> {
    let mut mode: Option<H2SourceMode> = None;
    let mut version: Option<String> = None;
    let mut sha: Option<String> = None;

    for (idx, raw_line) in contents.split('\n').enumerate() {
        let lineno = idx + 1;
        // Tolerate CRLF line endings on Windows checkouts, but reject stray embedded CRs.
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.contains('\r') {
            return Err(format!(
                "invalid CR in vendor/h2-source.env at line {lineno}"
            ));
        }
        let trimmed = line.trim_matches(|c| c == ' ' || c == '\t');
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if line != trimmed {
            return Err(format!(
                "unexpected leading/trailing whitespace in vendor/h2-source.env at line {lineno}: {line:?}"
            ));
        }
        let Some((key, val)) = line.split_once('=') else {
            return Err(format!(
                "invalid line {lineno} in vendor/h2-source.env (missing '='): {line:?}"
            ));
        };
        match key {
            "H2_SOURCE_MODE" => {
                if mode.is_some() {
                    return Err(format!(
                        "duplicate H2_SOURCE_MODE in vendor/h2-source.env at line {lineno}"
                    ));
                }
                mode = Some(match val {
                    "vendored" => H2SourceMode::Vendored,
                    "registry" => H2SourceMode::Registry,
                    other => {
                        return Err(format!(
                            "invalid H2_SOURCE_MODE {other:?} in vendor/h2-source.env at line {lineno}"
                        ));
                    }
                });
            }
            "H2_VERSION" => {
                if version.is_some() {
                    return Err(format!(
                        "duplicate H2_VERSION in vendor/h2-source.env at line {lineno}"
                    ));
                }
                if !is_valid_semver_triple(val) {
                    return Err(format!(
                        "invalid H2_VERSION {val:?} in vendor/h2-source.env at line {lineno}"
                    ));
                }
                version = Some(val.to_owned());
            }
            "H2_ARCHIVE_SHA256" => {
                if sha.is_some() {
                    return Err(format!(
                        "duplicate H2_ARCHIVE_SHA256 in vendor/h2-source.env at line {lineno}"
                    ));
                }
                if !is_valid_sha256_hex(val) {
                    return Err(format!(
                        "invalid H2_ARCHIVE_SHA256 {val:?} in vendor/h2-source.env at line {lineno}"
                    ));
                }
                sha = Some(val.to_owned());
            }
            other => {
                return Err(format!(
                    "unexpected key {other:?} in vendor/h2-source.env at line {lineno}"
                ));
            }
        }
    }

    match (mode, version, sha) {
        (Some(mode), Some(version), Some(archive_sha256)) => Ok(VerifiedH2Source {
            mode,
            version,
            archive_sha256,
            vendored_version: String::new(),
        }),
        _ => Err(
            "vendor/h2-source.env must define H2_SOURCE_MODE, H2_VERSION, and H2_ARCHIVE_SHA256 exactly once"
                .to_owned(),
        ),
    }
}

fn parse_cargo_package_version(contents: &str) -> Result<String, String> {
    let mut in_package = false;
    for raw_line in contents.split('\n') {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line).trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if in_package
            && let Some(rest) = line.strip_prefix("version")
            && let Some(val_raw) = rest.trim_start().strip_prefix('=')
        {
            let val = val_raw.trim();
            if let Some(unquoted) = val.strip_prefix('"').and_then(|s| s.strip_suffix('"'))
                && is_valid_semver_triple(unquoted)
            {
                return Ok(unquoted.to_owned());
            }
            return Err(format!(
                "invalid [package].version in vendor/h2/Cargo.toml: {val:?}"
            ));
        }
    }
    Err("missing [package].version in vendor/h2/Cargo.toml".to_owned())
}

fn read_vendored_h2_version() -> Result<String, String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("vendor")
        .join("h2")
        .join("Cargo.toml");
    let meta = std::fs::symlink_metadata(&path)
        .map_err(|err| format!("failed to stat {}: {err}", path.display()))?;
    if !meta.file_type().is_file() {
        return Err(format!(
            "{} must be a regular file (not a symlink or directory)",
            path.display()
        ));
    }
    let contents = std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    parse_cargo_package_version(&contents)
}

fn read_h2_source_env() -> Result<VerifiedH2Source, String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("vendor")
        .join("h2-source.env");
    let meta = std::fs::symlink_metadata(&path)
        .map_err(|err| format!("failed to stat {}: {err}", path.display()))?;
    if !meta.file_type().is_file() {
        return Err(format!(
            "{} must be a regular file (not a symlink or directory)",
            path.display()
        ));
    }
    let contents = std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let mut parsed = parse_h2_source_env(&contents)?;
    parsed.vendored_version = read_vendored_h2_version()?;
    Ok(parsed)
}

#[test]
fn h2_source_env_parser_is_strict_and_validates_workspace_selector() -> TestResult {
    let current = read_h2_source_env()?;
    assert!(
        matches!(
            current.mode,
            H2SourceMode::Vendored | H2SourceMode::Registry
        ),
        "unexpected mode: {current:?}"
    );
    assert!(is_valid_semver_triple(&current.version));
    assert!(is_valid_sha256_hex(&current.archive_sha256));
    assert!(is_valid_semver_triple(&current.vendored_version));
    if current.mode == H2SourceMode::Vendored {
        assert_eq!(
            current.version, current.vendored_version,
            "vendored selector version must match vendor/h2/Cargo.toml"
        );
    }

    let ok_reg = parse_h2_source_env(
        "# comment\n\nH2_SOURCE_MODE=registry\nH2_VERSION=0.4.1\nH2_ARCHIVE_SHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
    )?;
    assert_eq!(ok_reg.mode, H2SourceMode::Registry);
    assert_eq!(ok_reg.version, "0.4.1");

    for bad in [
        "",
        "H2_SOURCE_MODE=vendored\nH2_VERSION=0.4.0\n",
        "H2_SOURCE_MODE=git\nH2_VERSION=0.4.0\nH2_ARCHIVE_SHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
        "H2_SOURCE_MODE=vendored\nH2_SOURCE_MODE=registry\nH2_VERSION=0.4.0\nH2_ARCHIVE_SHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
        "H2_SOURCE_MODE=vendored\nH2_VERSION=0.4\nH2_ARCHIVE_SHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
        "H2_SOURCE_MODE=vendored\nH2_VERSION=0.4.0\nH2_ARCHIVE_SHA256=ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n",
        "H2_SOURCE_MODE=vendored\nH2_VERSION=0.4.0\nH2_ARCHIVE_SHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\nEXTRA=1\n",
        " H2_SOURCE_MODE=vendored\nH2_VERSION=0.4.0\nH2_ARCHIVE_SHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
    ] {
        assert!(
            parse_h2_source_env(bad).is_err(),
            "malformed vendor/h2-source.env unexpectedly accepted: {bad:?}"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Controlled in-memory transport (scalar & vectored, real waker gates)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum WriteMode {
    Open { max_chunk: usize },
    Blocked,
    WriteZero,
    Error(io::ErrorKind),
}

#[derive(Clone, Copy, Debug)]
enum FlushMode {
    Open,
    Blocked,
    Error(io::ErrorKind),
}

#[derive(Clone, Copy, Debug)]
enum ShutdownMode {
    Open,
    Blocked,
    Error(io::ErrorKind),
}

#[derive(Clone, Copy, Debug)]
struct WriteRecord {
    start_offset: usize,
    bytes: usize,
    vectored_slices: usize,
}

struct IoShared {
    read_buf: VecDeque<u8>,
    read_eof: bool,
    read_waker: Option<Waker>,

    write_mode: WriteMode,
    write_waker: Option<Waker>,
    written_bytes: Vec<u8>,
    write_records: Vec<WriteRecord>,

    flush_mode: FlushMode,
    flush_waker: Option<Waker>,
    flush_blocked_polls: usize,
    flush_completed: usize,
    flush_errors: usize,

    shutdown_mode: ShutdownMode,
    shutdown_waker: Option<Waker>,
    shutdown_blocked_polls: usize,
    shutdown_completed: usize,
    polls_after_shutdown: usize,
}

struct ControlledState {
    inner: Mutex<IoShared>,
    written_notify: Notify,
    write_blocked_notify: Notify,
    flush_blocked_notify: Notify,
    flush_done_notify: Notify,
    shutdown_blocked_notify: Notify,
    shutdown_done_notify: Notify,
}

#[derive(Clone)]
struct TransportController {
    state: Arc<ControlledState>,
}

struct ControlledIo {
    state: Arc<ControlledState>,
    vectored: bool,
}

fn controlled_transport(vectored: bool) -> (ControlledIo, TransportController) {
    let state = Arc::new(ControlledState {
        inner: Mutex::new(IoShared {
            read_buf: VecDeque::new(),
            read_eof: false,
            read_waker: None,
            write_mode: WriteMode::Open {
                max_chunk: usize::MAX,
            },
            write_waker: None,
            written_bytes: Vec::new(),
            write_records: Vec::new(),
            flush_mode: FlushMode::Open,
            flush_waker: None,
            flush_blocked_polls: 0,
            flush_completed: 0,
            flush_errors: 0,
            shutdown_mode: ShutdownMode::Open,
            shutdown_waker: None,
            shutdown_blocked_polls: 0,
            shutdown_completed: 0,
            polls_after_shutdown: 0,
        }),
        written_notify: Notify::new(),
        write_blocked_notify: Notify::new(),
        flush_blocked_notify: Notify::new(),
        flush_done_notify: Notify::new(),
        shutdown_blocked_notify: Notify::new(),
        shutdown_done_notify: Notify::new(),
    });
    (
        ControlledIo {
            state: Arc::clone(&state),
            vectored,
        },
        TransportController { state },
    )
}

impl TransportController {
    fn push_client(&self, bytes: &[u8]) {
        let waker = {
            let Ok(mut g) = self.state.inner.lock() else {
                return;
            };
            g.read_buf.extend(bytes);
            g.read_waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }

    fn close_client_read(&self) {
        let waker = {
            let Ok(mut g) = self.state.inner.lock() else {
                return;
            };
            g.read_eof = true;
            g.read_waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }

    fn set_write_mode(&self, mode: WriteMode) {
        let waker = {
            let Ok(mut g) = self.state.inner.lock() else {
                return;
            };
            g.write_mode = mode;
            if matches!(mode, WriteMode::Blocked) {
                None
            } else {
                g.write_waker.take()
            }
        };
        if let Some(w) = waker {
            w.wake();
        }
    }

    fn set_flush_mode(&self, mode: FlushMode) {
        let waker = {
            let Ok(mut g) = self.state.inner.lock() else {
                return;
            };
            g.flush_mode = mode;
            if matches!(mode, FlushMode::Blocked) {
                None
            } else {
                g.flush_waker.take()
            }
        };
        if let Some(w) = waker {
            w.wake();
        }
    }

    fn set_shutdown_mode(&self, mode: ShutdownMode) {
        let waker = {
            let Ok(mut g) = self.state.inner.lock() else {
                return;
            };
            g.shutdown_mode = mode;
            if matches!(mode, ShutdownMode::Blocked) {
                None
            } else {
                g.shutdown_waker.take()
            }
        };
        if let Some(w) = waker {
            w.wake();
        }
    }

    fn written_snapshot(&self) -> Vec<u8> {
        self.state
            .inner
            .lock()
            .map_or_else(|_| Vec::new(), |g| g.written_bytes.clone())
    }

    fn write_records_snapshot(&self) -> Vec<WriteRecord> {
        self.state
            .inner
            .lock()
            .map_or_else(|_| Vec::new(), |g| g.write_records.clone())
    }

    fn stats(&self) -> (usize, usize, usize, usize, usize, usize) {
        self.state.inner.lock().map_or((0, 0, 0, 0, 0, 0), |g| {
            (
                g.flush_blocked_polls,
                g.flush_completed,
                g.flush_errors,
                g.shutdown_blocked_polls,
                g.shutdown_completed,
                g.polls_after_shutdown,
            )
        })
    }

    async fn wait_for_frames<F>(
        &self,
        timeout: Duration,
        mut pred: F,
    ) -> Result<Vec<RawFrame>, String>
    where
        F: FnMut(&[RawFrame]) -> bool,
    {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.state.written_notify.notified();
            let bytes = self.written_snapshot();
            let (frames, _) = parse_frames(&bytes);
            if pred(&frames) {
                return Ok(frames);
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(format!(
                    "timed out waiting for expected HTTP/2 frames (decoded {} frames, {} bytes)",
                    frames.len(),
                    bytes.len()
                ));
            }
            let _ = tokio::time::timeout(deadline - now, notified).await;
        }
    }

    async fn wait_for_flush_blocked(
        &self,
        min_polls: usize,
        timeout: Duration,
    ) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.state.flush_blocked_notify.notified();
            if self.stats().0 >= min_polls {
                return Ok(());
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err("timed out waiting for blocked poll_flush".to_owned());
            }
            let _ = tokio::time::timeout(deadline - now, notified).await;
        }
    }

    async fn wait_for_flush_completed(
        &self,
        min_completed: usize,
        timeout: Duration,
    ) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.state.flush_done_notify.notified();
            if self.stats().1 >= min_completed {
                return Ok(());
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err("timed out waiting for completed poll_flush".to_owned());
            }
            let _ = tokio::time::timeout(deadline - now, notified).await;
        }
    }

    async fn wait_for_shutdown_blocked(
        &self,
        min_polls: usize,
        timeout: Duration,
    ) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.state.shutdown_blocked_notify.notified();
            if self.stats().3 >= min_polls {
                return Ok(());
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err("timed out waiting for blocked poll_shutdown".to_owned());
            }
            let _ = tokio::time::timeout(deadline - now, notified).await;
        }
    }

    async fn wait_for_write_blocked(&self, timeout: Duration) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.state.write_blocked_notify.notified();
            let is_waiting = self
                .state
                .inner
                .lock()
                .is_ok_and(|g| g.write_waker.is_some());
            if is_waiting {
                return Ok(());
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err("timed out waiting for blocked poll_write".to_owned());
            }
            let _ = tokio::time::timeout(deadline - now, notified).await;
        }
    }
}

impl AsyncRead for ControlledIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let Ok(mut g) = self.state.inner.lock() else {
            return Poll::Ready(Err(io::Error::other("transport mutex poisoned")));
        };
        if !g.read_buf.is_empty() {
            let to_read = buf.remaining().min(g.read_buf.len());
            let mut tmp = vec![0_u8; to_read];
            for slot in &mut tmp {
                if let Some(b) = g.read_buf.pop_front() {
                    *slot = b;
                }
            }
            buf.put_slice(&tmp);
            return Poll::Ready(Ok(()));
        }
        if g.read_eof {
            return Poll::Ready(Ok(()));
        }
        g.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl ControlledIo {
    fn write_slices(
        &self,
        cx: &mut Context<'_>,
        slices: &[&[u8]],
        vectored_slices: usize,
    ) -> Poll<io::Result<usize>> {
        let total_avail: usize = slices.iter().map(|s| s.len()).sum();
        let (result, notify_written, notify_blocked) = {
            let Ok(mut g) = self.state.inner.lock() else {
                return Poll::Ready(Err(io::Error::other("transport mutex poisoned")));
            };
            if g.shutdown_completed > 0 {
                g.polls_after_shutdown = g.polls_after_shutdown.saturating_add(1);
            }
            match g.write_mode {
                WriteMode::Open { max_chunk } => {
                    if total_avail == 0 {
                        (Poll::Ready(Ok(0)), false, false)
                    } else {
                        let start_offset = g.written_bytes.len();
                        let mut left = total_avail.min(max_chunk.max(1));
                        let mut copied = 0_usize;
                        for slice in slices {
                            if left == 0 {
                                break;
                            }
                            let take = slice.len().min(left);
                            if let Some(part) = slice.get(..take) {
                                g.written_bytes.extend_from_slice(part);
                            }
                            copied += take;
                            left -= take;
                        }
                        g.write_records.push(WriteRecord {
                            start_offset,
                            bytes: copied,
                            vectored_slices,
                        });
                        (Poll::Ready(Ok(copied)), true, false)
                    }
                }
                WriteMode::Blocked => {
                    g.write_waker = Some(cx.waker().clone());
                    (Poll::Pending, false, true)
                }
                WriteMode::WriteZero => (Poll::Ready(Ok(0)), false, false),
                WriteMode::Error(kind) => (Poll::Ready(Err(io::Error::from(kind))), false, false),
            }
        };
        if notify_written {
            self.state.written_notify.notify_waiters();
        }
        if notify_blocked {
            self.state.write_blocked_notify.notify_waiters();
        }
        result
    }
}

impl AsyncWrite for ControlledIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.write_slices(cx, &[buf], 1)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if !self.vectored {
            let first = bufs
                .iter()
                .find(|s| !s.is_empty())
                .map_or(&[][..], |s| &**s);
            return self.write_slices(cx, &[first], 1);
        }
        let slices: Vec<&[u8]> = bufs.iter().map(|s| &**s).collect();
        self.write_slices(cx, &slices, slices.len())
    }

    fn is_write_vectored(&self) -> bool {
        self.vectored
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let (result, notify_blocked, notify_done) = {
            let Ok(mut g) = self.state.inner.lock() else {
                return Poll::Ready(Err(io::Error::other("transport mutex poisoned")));
            };
            if g.shutdown_completed > 0 {
                g.polls_after_shutdown = g.polls_after_shutdown.saturating_add(1);
            }
            match g.flush_mode {
                FlushMode::Open => {
                    g.flush_completed = g.flush_completed.saturating_add(1);
                    (Poll::Ready(Ok(())), false, true)
                }
                FlushMode::Blocked => {
                    g.flush_blocked_polls = g.flush_blocked_polls.saturating_add(1);
                    g.flush_waker = Some(cx.waker().clone());
                    (Poll::Pending, true, false)
                }
                FlushMode::Error(kind) => {
                    g.flush_errors = g.flush_errors.saturating_add(1);
                    (Poll::Ready(Err(io::Error::from(kind))), false, false)
                }
            }
        };
        if notify_blocked {
            self.state.flush_blocked_notify.notify_waiters();
        }
        if notify_done {
            self.state.flush_done_notify.notify_waiters();
        }
        result
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let (result, notify_blocked, notify_done) = {
            let Ok(mut g) = self.state.inner.lock() else {
                return Poll::Ready(Err(io::Error::other("transport mutex poisoned")));
            };
            if g.shutdown_completed > 0 {
                g.polls_after_shutdown = g.polls_after_shutdown.saturating_add(1);
            }
            match g.shutdown_mode {
                ShutdownMode::Open => {
                    g.shutdown_completed = g.shutdown_completed.saturating_add(1);
                    (Poll::Ready(Ok(())), false, true)
                }
                ShutdownMode::Blocked => {
                    g.shutdown_blocked_polls = g.shutdown_blocked_polls.saturating_add(1);
                    g.shutdown_waker = Some(cx.waker().clone());
                    (Poll::Pending, true, false)
                }
                ShutdownMode::Error(kind) => {
                    (Poll::Ready(Err(io::Error::from(kind))), false, false)
                }
            }
        };
        if notify_blocked {
            self.state.shutdown_blocked_notify.notify_waiters();
        }
        if notify_done {
            self.state.shutdown_done_notify.notify_waiters();
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Minimal RFC 9113 HTTP/2 frame encoder & decoder (no unsafe, no indexing)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct RawFrame {
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

fn encode_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + payload.len());
    let len_u32 = u32::try_from(payload.len()).unwrap_or(0);
    out.push(u8::try_from((len_u32 >> 16) & 0xff).unwrap_or(0));
    out.push(u8::try_from((len_u32 >> 8) & 0xff).unwrap_or(0));
    out.push(u8::try_from(len_u32 & 0xff).unwrap_or(0));
    out.push(frame_type);
    out.push(flags);
    out.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn encode_settings(params: &[(u16, u32)]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(params.len() * 6);
    for &(id, val) in params {
        payload.extend_from_slice(&id.to_be_bytes());
        payload.extend_from_slice(&val.to_be_bytes());
    }
    encode_frame(FRAME_SETTINGS, 0, 0, &payload)
}

fn encode_settings_ack() -> Vec<u8> {
    encode_frame(FRAME_SETTINGS, FLAG_ACK, 0, &[])
}

fn encode_ping(ack: bool, data: [u8; 8]) -> Vec<u8> {
    encode_frame(FRAME_PING, u8::from(ack) * FLAG_ACK, 0, &data)
}

fn encode_window_update(stream_id: u32, increment: u32) -> Vec<u8> {
    encode_frame(
        FRAME_WINDOW_UPDATE,
        0,
        stream_id,
        &(increment & 0x7fff_ffff).to_be_bytes(),
    )
}

fn encode_rst_stream(stream_id: u32, error_code: u32) -> Vec<u8> {
    encode_frame(FRAME_RST_STREAM, 0, stream_id, &error_code.to_be_bytes())
}

fn encode_data(stream_id: u32, end_stream: bool, payload: &[u8]) -> Vec<u8> {
    let flags = if end_stream { FLAG_END_STREAM } else { 0 };
    encode_frame(FRAME_DATA, flags, stream_id, payload)
}

fn push_hpack_str(out: &mut Vec<u8>, value: &[u8]) {
    let len = value.len();
    if len < 127 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        out.push(127);
        let mut rem = len - 127;
        while rem >= 128 {
            out.push(u8::try_from((rem & 0x7f) | 0x80).unwrap_or(0));
            rem >>= 7;
        }
        out.push(u8::try_from(rem).unwrap_or(0));
    }
    out.extend_from_slice(value);
}

fn encode_request_headers(
    stream_id: u32,
    method: &Method,
    path: &str,
    end_stream: bool,
) -> Vec<u8> {
    encode_request_headers_for_host(stream_id, method, "h2.example.test", path, end_stream)
}

fn encode_request_headers_for_host(
    stream_id: u32,
    method: &Method,
    authority: &str,
    path: &str,
    end_stream: bool,
) -> Vec<u8> {
    let mut block = Vec::new();
    if *method == Method::GET {
        block.push(0x82); // :method: GET
    } else if *method == Method::POST {
        block.push(0x83); // :method: POST
    } else {
        block.push(0x02);
        push_hpack_str(&mut block, method.as_str().as_bytes());
    }
    block.push(0x87); // :scheme: https
    block.push(0x01); // literal without indexing, name = :authority (static idx 1)
    push_hpack_str(&mut block, authority.as_bytes());
    block.push(0x04); // literal without indexing, name = :path (static idx 4)
    push_hpack_str(&mut block, path.as_bytes());
    let flags = FLAG_END_HEADERS | if end_stream { FLAG_END_STREAM } else { 0 };
    encode_frame(FRAME_HEADERS, flags, stream_id, &block)
}

fn parse_frames_with_spans(bytes: &[u8]) -> (Vec<(usize, usize, RawFrame)>, usize) {
    let mut frames = Vec::new();
    let mut pos = 0_usize;
    while let Some(hdr) = bytes.get(pos..pos + 9) {
        let Some(&[l0, l1, l2, frame_type, flags, s0, s1, s2, s3]) = hdr.get(..9) else {
            break;
        };
        let len = (usize::from(l0) << 16) | (usize::from(l1) << 8) | usize::from(l2);
        let end = pos + 9 + len;
        let Some(payload) = bytes.get(pos + 9..end) else {
            break;
        };
        let stream_id = u32::from_be_bytes([s0 & 0x7f, s1, s2, s3]);
        frames.push((
            pos,
            end,
            RawFrame {
                frame_type,
                flags,
                stream_id,
                payload: payload.to_vec(),
            },
        ));
        pos = end;
    }
    (frames, pos)
}

fn parse_frames(bytes: &[u8]) -> (Vec<RawFrame>, usize) {
    let (spanned, pos) = parse_frames_with_spans(bytes);
    (spanned.into_iter().map(|(_, _, f)| f).collect(), pos)
}

/// Counts how many recorded transport writes (starting at `from_write`) carry at least one byte
/// of any HTTP/2 `DATA` frame.
fn count_data_carrying_writes(bytes: &[u8], records: &[WriteRecord], from_write: usize) -> usize {
    let (spanned, _) = parse_frames_with_spans(bytes);
    let data_spans: Vec<(usize, usize)> = spanned
        .iter()
        .filter(|(_, _, f)| f.frame_type == FRAME_DATA)
        .map(|&(start, end, _)| (start, end))
        .collect();
    records
        .get(from_write..)
        .unwrap_or(&[])
        .iter()
        .filter(|w| {
            let w_start = w.start_offset;
            let w_end = w.start_offset.saturating_add(w.bytes);
            data_spans
                .iter()
                .any(|&(f_start, f_end)| f_start < w_end && f_end > w_start)
        })
        .count()
}

/// Runs an async test body under both Tokio runtime flavours (`current_thread` and
/// 2-worker `multi_thread`).
macro_rules! dual_runtime_test {
    ($name:ident, $mt_name:ident, $body:path) => {
        #[tokio::test(flavor = "current_thread")]
        async fn $name() -> TestResult {
            $body().await
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $mt_name() -> TestResult {
            $body().await
        }
    };
}

fn miraserve_h2_builder() -> AutoConnBuilder<TokioExecutor> {
    let mut builder = AutoConnBuilder::new(TokioExecutor::new());
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(100)
        .max_header_list_size(128 * 1024)
        .initial_stream_window_size(Some(256 * 1024))
        .initial_connection_window_size(Some(4 * 1024 * 1024))
        .max_pending_accept_reset_streams(Some(50));
    builder
}

/// Deterministic payload pattern unique to each stream ID and byte offset.
fn stream_pattern(stream_id: u32, len: usize) -> Vec<u8> {
    let seed = u8::try_from(stream_id % 251).unwrap_or(1);
    (0..len)
        .map(|i| seed.wrapping_add(u8::try_from(i % 251).unwrap_or(0)))
        .collect()
}

mod tokio_permit_box {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use tokio::sync::Semaphore;

    /// Awaits one retained permit from a `Semaphore`, eliminating the lost-wakeup race
    /// inherent in `Notify::notify_waiters()` when the releaser runs before `poll_frame`.
    pub(super) struct WaitPermit {
        fut: Pin<Box<dyn Future<Output = ()> + Send>>,
    }

    impl WaitPermit {
        pub(super) fn new(sem: Arc<Semaphore>) -> Self {
            Self {
                fut: Box::pin(async move {
                    let _ = sem.acquire_owned().await;
                }),
            }
        }

        pub(super) fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
            self.fut.as_mut().poll(cx)
        }
    }
}

/// Single-chunk response body matching `Full<Bytes>` on the wire (`is_end_stream()` turns true
/// immediately after yielding its single chunk so hyper sends `DATA(END_STREAM)` in one frame)
/// that grants a retained permit on `Drop`, which hyper's `PipeToSendStream` runs strictly after
/// `SendStream::send_data(chunk, true)` has handed the body into `h2`'s send queue.
struct AckBody {
    data: Option<Bytes>,
    handed_off: Arc<Semaphore>,
}

impl AckBody {
    fn new(bytes: Bytes, handed_off: Arc<Semaphore>) -> Self {
        Self {
            data: Some(bytes),
            handed_off,
        }
    }
}

impl Body for AckBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.data.take().map(|b| Ok(Frame::data(b))))
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_none()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        let len = u64::try_from(self.data.as_ref().map_or(0, Bytes::len)).unwrap_or(0);
        http_body::SizeHint::with_exact(len)
    }
}

impl Drop for AckBody {
    fn drop(&mut self) {
        self.handed_off.add_permits(1);
    }
}

enum BodyStep {
    Data(Bytes),
    Trailers(http::HeaderMap),
    Wait(Arc<Semaphore>),
}

struct FlexBody {
    steps: VecDeque<BodyStep>,
    waiting: Option<tokio_permit_box::WaitPermit>,
}

impl FlexBody {
    fn from_steps(steps: Vec<BodyStep>) -> Self {
        Self {
            steps: VecDeque::from(steps),
            waiting: None,
        }
    }
}

impl Body for FlexBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        loop {
            if let Some(wait) = self.waiting.as_mut() {
                match wait.poll_ready(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(()) => self.waiting = None,
                }
            }
            match self.steps.pop_front() {
                Some(BodyStep::Data(b)) => return Poll::Ready(Some(Ok(Frame::data(b)))),
                Some(BodyStep::Trailers(t)) => return Poll::Ready(Some(Ok(Frame::trailers(t)))),
                Some(BodyStep::Wait(sem)) => {
                    self.waiting = Some(tokio_permit_box::WaitPermit::new(sem));
                }
                None => return Poll::Ready(None),
            }
        }
    }
}

/// Complete client-side HTTP/2 preface + SETTINGS handshake with our server over `ControlledIo`.
async fn complete_h2_handshake(
    ctrl: &TransportController,
    client_settings: &[(u16, u32)],
) -> Result<(), String> {
    let mut init = Vec::new();
    init.extend_from_slice(CLIENT_PREFACE);
    init.extend_from_slice(&encode_settings(client_settings));
    ctrl.push_client(&init);

    // Wait for server SETTINGS and server's ACK of our SETTINGS.
    ctrl.wait_for_frames(Duration::from_secs(5), |frames| {
        let saw_srv_settings = frames
            .iter()
            .any(|f| f.frame_type == FRAME_SETTINGS && (f.flags & FLAG_ACK) == 0);
        let saw_settings_ack = frames
            .iter()
            .any(|f| f.frame_type == FRAME_SETTINGS && (f.flags & FLAG_ACK) != 0);
        saw_srv_settings && saw_settings_ack
    })
    .await?;

    // Acknowledge server's SETTINGS.
    ctrl.push_client(&encode_settings_ack());
    Ok(())
}

// ---------------------------------------------------------------------------
// 1. Burst: copied (1, 255, 256, 1024, 4095), chained (4096, 16384),
//    distinct zero-length terminal DATA, trailers, real batching write-count
//    bound, stream-window limit, connection-window exhaustion, split writes
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
async fn run_burst_scenario(vectored: bool, max_write_chunk: usize) -> TestResult {
    let (io, ctrl) = controlled_transport(vectored);
    ctrl.set_write_mode(WriteMode::Open {
        max_chunk: max_write_chunk,
    });

    let gate_empty_term = Arc::new(Semaphore::new(0));
    let gate_empty_term_svc = Arc::clone(&gate_empty_term);

    let svc = service_fn(move |req: Request<Incoming>| {
        let gate_empty = Arc::clone(&gate_empty_term_svc);
        async move {
            let path = req.uri().path().to_owned();
            let body = match path.as_str() {
                "/s1" => {
                    FlexBody::from_steps(vec![BodyStep::Data(Bytes::from(stream_pattern(1, 1)))])
                }
                "/s3" => {
                    FlexBody::from_steps(vec![BodyStep::Data(Bytes::from(stream_pattern(3, 255)))])
                }
                "/s5" => {
                    FlexBody::from_steps(vec![BodyStep::Data(Bytes::from(stream_pattern(5, 256)))])
                }
                "/s7" => FlexBody::from_steps(vec![BodyStep::Data(Bytes::from(stream_pattern(
                    7, 1_024,
                )))]),
                "/s9" => FlexBody::from_steps(vec![BodyStep::Data(Bytes::from(stream_pattern(
                    9, 4_095,
                )))]),
                "/s11" => FlexBody::from_steps(vec![BodyStep::Data(Bytes::from(stream_pattern(
                    11, 4_096,
                )))]),
                "/s13" => FlexBody::from_steps(vec![BodyStep::Data(Bytes::from(stream_pattern(
                    13, 16_384,
                )))]),
                // Emit 500 bytes, pause until those 500 bytes are sent without END_STREAM,
                // then finish with EOF so h2 MUST emit a distinct zero-length DATA(END_STREAM).
                "/s15-empty-term" => FlexBody::from_steps(vec![
                    BodyStep::Data(Bytes::from(stream_pattern(15, 500))),
                    BodyStep::Wait(gate_empty),
                ]),
                "/s17-trailers" => {
                    let mut trailers = http::HeaderMap::new();
                    trailers.insert(
                        HeaderName::from_static("x-checksum"),
                        HeaderValue::from_static("ok-batch"),
                    );
                    FlexBody::from_steps(vec![
                        BodyStep::Data(Bytes::from(stream_pattern(17, 300))),
                        BodyStep::Trailers(trailers),
                    ])
                }
                _ => FlexBody::from_steps(vec![]),
            };
            Ok::<_, std::convert::Infallible>(Response::new(body))
        }
    });

    let server_task = tokio::spawn(async move {
        let _ = miraserve_h2_builder()
            .serve_connection(TokioIo::new(io), svc)
            .await;
    });

    complete_h2_handshake(&ctrl, &[(SETTINGS_INITIAL_WINDOW_SIZE, 32_768)]).await?;

    // Send 9 concurrent requests in a single client read burst:
    // 1 B, 255 B, 256 B, 1024 B, 4095 B, 4096 B, 16384 B, distinct empty-terminal DATA, trailers.
    let mut burst = Vec::new();
    for (sid, path) in [
        (1_u32, "/s1"),
        (3, "/s3"),
        (5, "/s5"),
        (7, "/s7"),
        (9, "/s9"),
        (11, "/s11"),
        (13, "/s13"),
        (15, "/s15-empty-term"),
        (17, "/s17-trailers"),
    ] {
        burst.extend_from_slice(&encode_request_headers(sid, &Method::GET, path, true));
    }
    ctrl.push_client(&burst);

    // Wait for stream 15's 500-byte DATA frame (without END_STREAM), then release one retained
    // permit so h2 must transmit a separate zero-length DATA frame carrying END_STREAM (immune to
    // lost wakeups even if the permit is added before FlexBody polls BodyStep::Wait).
    ctrl.wait_for_frames(Duration::from_secs(10), |fs| {
        let s15_bytes: usize = fs
            .iter()
            .filter(|f| f.stream_id == 15 && f.frame_type == FRAME_DATA)
            .map(|f| f.payload.len())
            .sum();
        s15_bytes == 500
    })
    .await?;
    gate_empty_term.add_permits(1);

    let expected_streams: [(u32, usize, bool); 9] = [
        (1, 1, false),
        (3, 255, false),
        (5, 256, false),
        (7, 1_024, false),
        (9, 4_095, false),
        (11, 4_096, false),
        (13, 16_384, false),
        (15, 500, false),
        (17, 300, true),
    ];

    let frames = ctrl
        .wait_for_frames(Duration::from_secs(10), |fs| {
            expected_streams.iter().all(|&(sid, _, _)| {
                fs.iter()
                    .any(|f| f.stream_id == sid && (f.flags & FLAG_END_STREAM) != 0)
            })
        })
        .await?;

    // Verify exact decoded bytes, frame order, flags, END_STREAM, and window debits per stream.
    let mut conn_debit = 0_usize;
    for &(sid, expected_len, expect_trailers) in &expected_streams {
        let sframes: Vec<&RawFrame> = frames.iter().filter(|f| f.stream_id == sid).collect();
        let first = sframes
            .first()
            .ok_or_else(|| format!("missing frames for stream {sid}"))?;
        assert_eq!(
            first.frame_type, FRAME_HEADERS,
            "stream {sid} must start with HEADERS"
        );
        assert_ne!(
            first.flags & FLAG_END_HEADERS,
            0,
            "stream {sid} HEADERS must set END_HEADERS"
        );

        let mut payload_bytes = Vec::new();
        let mut saw_end_stream = false;
        let mut headers_count = 0_usize;
        let mut trailer_had_end_stream = false;
        let mut data_frames = Vec::new();

        for f in &sframes {
            assert!(
                !saw_end_stream,
                "stream {sid} received frame {:?} after END_STREAM",
                f.frame_type
            );
            assert_eq!(f.flags & FLAG_PADDED, 0, "unexpected PADDED flag");
            match f.frame_type {
                FRAME_HEADERS => {
                    headers_count += 1;
                    if (f.flags & FLAG_END_STREAM) != 0 {
                        saw_end_stream = true;
                        if headers_count == 2 {
                            trailer_had_end_stream = true;
                        }
                    }
                }
                FRAME_DATA => {
                    data_frames.push((f.payload.len(), (f.flags & FLAG_END_STREAM) != 0));
                    payload_bytes.extend_from_slice(&f.payload);
                    conn_debit += f.payload.len();
                    if (f.flags & FLAG_END_STREAM) != 0 {
                        saw_end_stream = true;
                    }
                }
                other => {
                    return Err(format!("unexpected frame type {other} on stream {sid}").into());
                }
            }
        }

        assert!(saw_end_stream, "stream {sid} never received END_STREAM");
        assert_eq!(
            payload_bytes,
            stream_pattern(sid, expected_len),
            "decoded payload mismatch on stream {sid} (vectored={vectored}, max_chunk={max_write_chunk})"
        );
        if sid == 15 {
            assert!(
                data_frames.len() >= 2,
                "stream 15 must send non-empty DATA followed by distinct zero-length DATA(END_STREAM), got {data_frames:?}"
            );
            assert_eq!(
                data_frames.last().copied(),
                Some((0, true)),
                "stream 15 terminal frame must be a distinct zero-length DATA with END_STREAM, got {data_frames:?}"
            );
            assert!(
                data_frames
                    .iter()
                    .take(data_frames.len() - 1)
                    .all(|&(len, es)| len > 0 && !es),
                "stream 15 preceding DATA frame(s) must be non-empty without END_STREAM: {data_frames:?}"
            );
        }
        if expect_trailers {
            assert_eq!(headers_count, 2, "stream {sid} must send trailing HEADERS");
            assert!(
                trailer_had_end_stream,
                "stream {sid} trailing HEADERS must carry END_STREAM"
            );
        } else {
            assert_eq!(headers_count, 1, "stream {sid} expected 1 HEADERS frame");
        }
    }
    assert_eq!(
        conn_debit,
        1 + 255 + 256 + 1_024 + 4_095 + 4_096 + 16_384 + 500 + 300
    );

    if max_write_chunk == usize::MAX && vectored {
        let writes = ctrl.write_records_snapshot();
        assert!(
            writes.iter().any(|w| w.vectored_slices >= 2),
            "expected chained >= 4096 DATA frame to invoke multi-slice vectored write: {writes:?}"
        );
    }

    ctrl.close_client_read();
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;

    // Phase B (unsplit transport, flush gate open): assert what the patch actually changes.
    // Queue N = 12 ready responses (1,024 B DATA payload each) behind WriteMode::Blocked while
    // FlushMode::Open stays open, then release the write gate once all 12 handlers have queued
    // their responses into h2.
    //
    // Bound rationale:
    // - Patched h2 (`COPY_LIMIT = 4096`, initial buffer `16,384 B`, `min_buffer_capacity = 4,105 B`)
    //   copies 1 KiB DATA frames into the shared write buffer before draining; this test asserts
    //   at most `MAX_PATCHED_DATA_WRITES` (4) DATA-carrying transport writes for N = 12 responses.
    // - Unpatched upstream h2 (CHAIN_THRESHOLD = 256 vectored, 1024 scalar) chains EVERY 1,024 B
    //   DATA frame into Next::Data, occupying `next` and forcing a transport write per stream:
    //   mathematically >= 12 DATA-carrying writes on both scalar and vectored transports.
    if max_write_chunk == usize::MAX {
        const N_BATCH: u32 = 12;
        const MAX_PATCHED_DATA_WRITES: usize = 4;

        let (io_b, ctrl_b) = controlled_transport(vectored);
        let handed_off = Arc::new(Semaphore::new(0));
        let handed_off_svc = Arc::clone(&handed_off);
        let svc_b = service_fn(move |req: Request<Incoming>| {
            let handed_off = Arc::clone(&handed_off_svc);
            async move {
                let sid: u32 = req
                    .uri()
                    .path()
                    .trim_start_matches("/b")
                    .parse()
                    .unwrap_or(1);
                Ok::<_, std::convert::Infallible>(Response::new(AckBody::new(
                    Bytes::from(stream_pattern(sid, 1_024)),
                    handed_off,
                )))
            }
        });
        let server_task_b = tokio::spawn(async move {
            let _ = miraserve_h2_builder()
                .serve_connection(TokioIo::new(io_b), svc_b)
                .await;
        });

        complete_h2_handshake(&ctrl_b, &[(SETTINGS_INITIAL_WINDOW_SIZE, 65_535)]).await?;
        ctrl_b.set_flush_mode(FlushMode::Open);
        ctrl_b.set_write_mode(WriteMode::Blocked);

        let mut reqs = Vec::new();
        for i in 0_u32..N_BATCH {
            let sid = 1 + i * 2;
            reqs.extend_from_slice(&encode_request_headers(
                sid,
                &Method::GET,
                &format!("/b{sid}"),
                true,
            ));
        }
        ctrl_b.push_client(&reqs);

        // Wait for explicit body hand-off acknowledgements (all 12 bodies dropped by
        // PipeToSendStream strictly after send_data(chunk, true) queued them in h2).
        tokio::time::timeout(Duration::from_secs(5), handed_off.acquire_many(N_BATCH))
            .await
            .map_err(|_| format!("timed out waiting for all {N_BATCH} bodies to hand off to h2"))??
            .forget();
        ctrl_b
            .wait_for_write_blocked(Duration::from_secs(5))
            .await?;

        let writes_before = ctrl_b.write_records_snapshot().len();
        ctrl_b.set_write_mode(WriteMode::Open {
            max_chunk: usize::MAX,
        });

        let batch_frames = ctrl_b
            .wait_for_frames(Duration::from_secs(5), |fs| {
                (0_u32..N_BATCH).all(|i| {
                    let sid = 1 + i * 2;
                    fs.iter()
                        .any(|f| f.stream_id == sid && (f.flags & FLAG_END_STREAM) != 0)
                })
            })
            .await?;

        for i in 0_u32..N_BATCH {
            let sid = 1 + i * 2;
            let got: Vec<u8> = batch_frames
                .iter()
                .filter(|f| f.stream_id == sid && f.frame_type == FRAME_DATA)
                .flat_map(|f| f.payload.iter().copied())
                .collect();
            assert_eq!(got, stream_pattern(sid, 1_024));
        }

        let raw_bytes = ctrl_b.written_snapshot();
        let records = ctrl_b.write_records_snapshot();
        let data_writes = count_data_carrying_writes(&raw_bytes, &records, writes_before);
        let h2_source = read_h2_source_env()?;
        match h2_source.mode {
            H2SourceMode::Vendored => {
                assert!(
                    (1..=MAX_PATCHED_DATA_WRITES).contains(&data_writes),
                    "COPY_LIMIT=4096 must batch {N_BATCH} ready 1 KiB responses into <= {MAX_PATCHED_DATA_WRITES} \
                     DATA-carrying writes (unpatched h2 chains every >=1024 B DATA frame and needs >= {N_BATCH}); \
                     got {data_writes} (vectored={vectored}, writes={:?})",
                    records.get(writes_before..)
                );
            }
            H2SourceMode::Registry if h2_source.is_vendored_upstream_registry() => {
                // Exact unpatched upstream expectation for the vendored version: CHAIN_THRESHOLD
                // is 256 B (vectored) / 1,024 B (scalar), so every 1,024 B DATA frame chains into
                // Next::Data and forces its own transport write (>= N_BATCH DATA-carrying writes).
                let min_upstream = usize::try_from(N_BATCH).unwrap_or(12);
                assert!(
                    data_writes >= min_upstream,
                    "upstream registry h2 {} chains every 1 KiB DATA frame and must emit >= {min_upstream} \
                     DATA-carrying writes; got {data_writes} (vectored={vectored}, writes={:?})",
                    h2_source.version,
                    records.get(writes_before..)
                );
            }
            H2SourceMode::Registry => {
                assert!(data_writes >= 1, "expected at least one DATA write");
                eprintln!(
                    "h2_batching_tests: [registry h2 {}] skipping COPY_LIMIT=4096 burst packing count assertion \
                     (vectored={vectored}, data_writes={data_writes})",
                    h2_source.version
                );
            }
        }

        ctrl_b.close_client_read();
        let _ = tokio::time::timeout(Duration::from_secs(5), server_task_b).await;
    }

    // Phase C: stream-window-limited DATA piece (2,000-byte initial stream window) with a
    // 3,500-byte remainder (< COPY_LIMIT) plus a healthy sibling stream.
    let (io2, ctrl2) = controlled_transport(vectored);
    ctrl2.set_write_mode(WriteMode::Open {
        max_chunk: max_write_chunk,
    });
    let svc2 = service_fn(|req: Request<Incoming>| async move {
        let body = match req.uri().path() {
            "/s19-win" => {
                FlexBody::from_steps(vec![BodyStep::Data(Bytes::from(stream_pattern(19, 5_500)))])
            }
            _ => FlexBody::from_steps(vec![BodyStep::Data(Bytes::from(stream_pattern(21, 1_024)))]),
        };
        Ok::<_, std::convert::Infallible>(Response::new(body))
    });
    let server_task2 = tokio::spawn(async move {
        let _ = miraserve_h2_builder()
            .serve_connection(TokioIo::new(io2), svc2)
            .await;
    });

    complete_h2_handshake(&ctrl2, &[(SETTINGS_INITIAL_WINDOW_SIZE, 2_000)]).await?;
    let mut win_reqs = encode_request_headers(1, &Method::GET, "/s19-win", true);
    win_reqs.extend_from_slice(&encode_request_headers(3, &Method::GET, "/s21-sib", true));
    ctrl2.push_client(&win_reqs);

    // Stream 1 must send exactly 2,000 bytes without END_STREAM, while sibling stream 3
    // completes with all 1,024 bytes and END_STREAM.
    let partial = ctrl2
        .wait_for_frames(Duration::from_secs(5), |fs| {
            let s1_bytes: usize = fs
                .iter()
                .filter(|f| f.stream_id == 1 && f.frame_type == FRAME_DATA)
                .map(|f| f.payload.len())
                .sum();
            let s3_done = fs
                .iter()
                .any(|f| f.stream_id == 3 && (f.flags & FLAG_END_STREAM) != 0);
            s1_bytes == 2_000 && s3_done
        })
        .await?;

    let s1_ended_early = partial
        .iter()
        .any(|f| f.stream_id == 1 && (f.flags & FLAG_END_STREAM) != 0);
    assert!(
        !s1_ended_early,
        "window-limited nonfinal piece must clear END_STREAM"
    );

    // Grant 4,000 more bytes to stream 1: the remaining 3,500-byte remainder must be
    // requeued and delivered intact with END_STREAM restored.
    ctrl2.push_client(&encode_window_update(1, 4_000));
    let final_frames = ctrl2
        .wait_for_frames(Duration::from_secs(5), |fs| {
            fs.iter()
                .any(|f| f.stream_id == 1 && (f.flags & FLAG_END_STREAM) != 0)
        })
        .await?;

    let mut s1_payload = Vec::new();
    let mut s3_payload = Vec::new();
    for f in &final_frames {
        if f.frame_type == FRAME_DATA {
            if f.stream_id == 1 {
                s1_payload.extend_from_slice(&f.payload);
            } else if f.stream_id == 3 {
                s3_payload.extend_from_slice(&f.payload);
            }
        }
    }
    assert_eq!(s1_payload, stream_pattern(19, 5_500));
    assert_eq!(s3_payload, stream_pattern(21, 1_024));

    ctrl2.close_client_read();
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task2).await;

    // Phase D: exhaust the CONNECTION flow-control window (RFC 9113 default = 65,535 B) while
    // every per-stream window is 100,000 B (so only connection credit can halt progress), then
    // release the remainder with a connection-level WINDOW_UPDATE (stream_id = 0).
    let (io3, ctrl3) = controlled_transport(vectored);
    ctrl3.set_write_mode(WriteMode::Open {
        max_chunk: max_write_chunk,
    });
    let svc3 = service_fn(|req: Request<Incoming>| async move {
        let body = match req.uri().path() {
            "/c1" => FlexBody::from_steps(vec![BodyStep::Data(Bytes::from(stream_pattern(
                101, 35_000,
            )))]),
            "/c3" => FlexBody::from_steps(vec![BodyStep::Data(Bytes::from(stream_pattern(
                103, 30_000,
            )))]),
            _ => FlexBody::from_steps(vec![BodyStep::Data(Bytes::from(stream_pattern(
                105, 2_000,
            )))]),
        };
        Ok::<_, std::convert::Infallible>(Response::new(body))
    });
    let server_task3 = tokio::spawn(async move {
        let _ = miraserve_h2_builder()
            .serve_connection(TokioIo::new(io3), svc3)
            .await;
    });

    // Large per-stream window (100,000 B); NO connection WINDOW_UPDATE so connection window = 65,535 B.
    complete_h2_handshake(&ctrl3, &[(SETTINGS_INITIAL_WINDOW_SIZE, 100_000)]).await?;
    let mut cwin_reqs = encode_request_headers(1, &Method::GET, "/c1", true);
    cwin_reqs.extend_from_slice(&encode_request_headers(3, &Method::GET, "/c3", true));
    cwin_reqs.extend_from_slice(&encode_request_headers(5, &Method::GET, "/c5", true));
    ctrl3.push_client(&cwin_reqs);

    // Wait until the full 65,535-byte connection window has been consumed.
    ctrl3
        .wait_for_frames(Duration::from_secs(10), |fs| {
            let total: usize = fs
                .iter()
                .filter(|f| f.frame_type == FRAME_DATA)
                .map(|f| f.payload.len())
                .sum();
            total == 65_535
        })
        .await?;

    // Hold briefly and verify no byte beyond the 65,535-byte connection window is emitted.
    tokio::time::sleep(Duration::from_millis(30)).await;
    let (stalled_frames, _) = parse_frames(&ctrl3.written_snapshot());
    let stalled_total: usize = stalled_frames
        .iter()
        .filter(|f| f.frame_type == FRAME_DATA)
        .map(|f| f.payload.len())
        .sum();
    assert_eq!(
        stalled_total, 65_535,
        "connection must stop at exact 65,535-byte connection window until connection WINDOW_UPDATE"
    );
    let all_done_before_update = [1_u32, 3, 5].iter().all(|&sid| {
        stalled_frames
            .iter()
            .any(|f| f.stream_id == sid && (f.flags & FLAG_END_STREAM) != 0)
    });
    assert!(
        !all_done_before_update,
        "at least one stream must remain incomplete while connection window is exhausted"
    );

    // Grant connection-level credit (stream_id = 0) and confirm all 67,000 bytes finish cleanly.
    ctrl3.push_client(&encode_window_update(0, 16_384));
    let conn_done = ctrl3
        .wait_for_frames(Duration::from_secs(10), |fs| {
            [1_u32, 3, 5].iter().all(|&sid| {
                fs.iter()
                    .any(|f| f.stream_id == sid && (f.flags & FLAG_END_STREAM) != 0)
            })
        })
        .await?;

    for (sid, pat_id, expected_len) in [
        (1_u32, 101_u32, 35_000_usize),
        (3, 103, 30_000),
        (5, 105, 2_000),
    ] {
        let got: Vec<u8> = conn_done
            .iter()
            .filter(|f| f.stream_id == sid && f.frame_type == FRAME_DATA)
            .flat_map(|f| f.payload.iter().copied())
            .collect();
        assert_eq!(
            got,
            stream_pattern(pat_id, expected_len),
            "connection-window-released payload mismatch on stream {sid}"
        );
    }

    ctrl3.close_client_read();
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task3).await;
    Ok(())
}

async fn burst_sizes_copied_chained_window_limited_empty_terminal_and_trailers_impl() -> TestResult
{
    for vectored in [true, false] {
        // Full-chunk writes (real batching path)
        run_burst_scenario(vectored, usize::MAX).await?;
        // 5-byte split writes (splits inside every 9-byte frame header and payload)
        run_burst_scenario(vectored, 5).await?;
    }
    Ok(())
}

dual_runtime_test!(
    burst_sizes_copied_chained_window_limited_empty_terminal_and_trailers,
    burst_sizes_copied_chained_window_limited_empty_terminal_and_trailers_multi_thread,
    burst_sizes_copied_chained_window_limited_empty_terminal_and_trailers_impl
);

// ---------------------------------------------------------------------------
// 2. Real flush: all plaintext accepted, flush blocked, no new input -> wake,
//    flush error, WriteZero, and gated shutdown
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
async fn blocked_flush_after_all_plaintext_accepted_wakes_and_completes_once_impl() -> TestResult {
    for vectored in [true, false] {
        let (io, ctrl) = controlled_transport(vectored);
        let handed_off = Arc::new(Semaphore::new(0));
        let handed_off_svc = Arc::clone(&handed_off);
        let svc = service_fn(move |_req: Request<Incoming>| {
            let handed_off = Arc::clone(&handed_off_svc);
            async move {
                Ok::<_, std::convert::Infallible>(Response::new(AckBody::new(
                    Bytes::from(vec![0x61_u8; 1_024]),
                    handed_off,
                )))
            }
        });

        let server_task = tokio::spawn(async move {
            miraserve_h2_builder()
                .serve_connection(TokioIo::new(io), svc)
                .await
        });

        complete_h2_handshake(&ctrl, &[]).await?;
        let flushes_before = ctrl.stats().1;

        // Gate writes AND flush while all 4 responses complete body hand-off into h2's
        // Prioritize send queue before opening plaintext writes.
        ctrl.set_write_mode(WriteMode::Blocked);
        ctrl.set_flush_mode(FlushMode::Blocked);

        // Send 4 concurrent 1 KiB requests in one burst.
        let mut reqs = Vec::new();
        for sid in [1_u32, 3, 5, 7] {
            reqs.extend_from_slice(&encode_request_headers(sid, &Method::GET, "/small", true));
        }
        ctrl.push_client(&reqs);

        // Wait for explicit hand-off acknowledgement from all 4 bodies (no sleep inferring
        // scheduler quiescence) plus the blocked transport write gate.
        tokio::time::timeout(Duration::from_secs(5), handed_off.acquire_many(4))
            .await
            .map_err(|_| "timed out waiting for all 4 bodies to hand off to h2")??
            .forget();
        ctrl.wait_for_write_blocked(Duration::from_secs(5)).await?;

        // Open plaintext writes while keeping ONLY poll_flush blocked (zero new client input and
        // zero remaining stream tasks to wake the connection). Patched h2 copies all 4 responses
        // into the 16 KiB buffer and writes all 4 before polling flush; unpatched h2 chains stream
        // 1 into Next::Data, writes stream 1 alone, and parks on flush without accepting streams
        // 3, 5, 7.
        let h2_source = read_h2_source_env()?;
        ctrl.set_write_mode(WriteMode::Open {
            max_chunk: usize::MAX,
        });

        match h2_source.mode {
            H2SourceMode::Vendored => {
                ctrl.wait_for_frames(Duration::from_millis(750), |fs| {
                    [1_u32, 3, 5, 7].iter().all(|&sid| {
                        fs.iter()
                            .any(|f| f.stream_id == sid && (f.flags & FLAG_END_STREAM) != 0)
                    })
                })
                .await?;
            }
            H2SourceMode::Registry => {
                ctrl.wait_for_frames(Duration::from_secs(5), |fs| {
                    [1_u32, 3, 5, 7].iter().any(|&sid| {
                        fs.iter()
                            .any(|f| f.stream_id == sid && (f.flags & FLAG_END_STREAM) != 0)
                    })
                })
                .await?;
            }
        }
        ctrl.wait_for_flush_blocked(1, Duration::from_secs(5))
            .await?;

        let blocked_polls_at_park = ctrl.stats().0;
        // Feed NO new client input; verify the flush stays pending and does not spin.
        tokio::time::sleep(Duration::from_millis(40)).await;
        let (blocked_after_wait, completed_while_blocked, _, _, _, _) = ctrl.stats();
        assert_eq!(
            completed_while_blocked, flushes_before,
            "flush must not complete while blocked (vectored={vectored})"
        );
        assert!(
            blocked_after_wait <= blocked_polls_at_park + 4,
            "blocked flush must park on waker instead of busy-spinning ({blocked_polls_at_park} -> {blocked_after_wait})"
        );
        if h2_source.mode == H2SourceMode::Registry {
            let (frames_while_blocked, _) = parse_frames(&ctrl.written_snapshot());
            let ended_before_flush = [1_u32, 3, 5, 7]
                .iter()
                .filter(|&&sid| {
                    frames_while_blocked
                        .iter()
                        .any(|f| f.stream_id == sid && (f.flags & FLAG_END_STREAM) != 0)
                })
                .count();
            if h2_source.is_vendored_upstream_registry() {
                // Exact unpatched upstream expectation for the vendored version: chaining the
                // first 1 KiB DATA frame into Next::Data forces poll_flush after stream 1 before
                // streams 3, 5, 7 can drain.
                assert_eq!(
                    ended_before_flush, 1,
                    "upstream registry h2 {} must park on poll_flush after exactly 1 chained 1 KiB stream \
                     (got {ended_before_flush}, vectored={vectored})",
                    h2_source.version
                );
            } else {
                eprintln!(
                    "h2_batching_tests: [registry h2 {}] skipping 4-stream pre-flush packing count assertion \
                     (vectored={vectored}, ended_before_flush={ended_before_flush})",
                    h2_source.version
                );
            }
        }

        // Release flush by waking the stored waker (ZERO new client input, ZERO manual repoll).
        ctrl.set_flush_mode(FlushMode::Open);
        ctrl.wait_for_flush_completed(flushes_before + 1, Duration::from_secs(5))
            .await?;
        let final_frames = ctrl
            .wait_for_frames(Duration::from_secs(5), |fs| {
                [1_u32, 3, 5, 7].iter().all(|&sid| {
                    fs.iter()
                        .any(|f| f.stream_id == sid && (f.flags & FLAG_END_STREAM) != 0)
                })
            })
            .await?;
        for sid in [1_u32, 3, 5, 7] {
            let payload: Vec<u8> = final_frames
                .iter()
                .filter(|f| f.stream_id == sid && f.frame_type == FRAME_DATA)
                .flat_map(|f| f.payload.iter().copied())
                .collect();
            assert_eq!(
                payload,
                vec![0x61_u8; 1_024],
                "stream {sid} payload mismatch after flush wake (vectored={vectored})"
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        match h2_source.mode {
            H2SourceMode::Vendored => {
                assert_eq!(
                    ctrl.stats().1,
                    flushes_before + 1,
                    "released flush must complete exactly once with no further input (vectored={vectored})"
                );
            }
            H2SourceMode::Registry if h2_source.is_vendored_upstream_registry() => {
                assert!(
                    ctrl.stats().1 >= flushes_before + 4,
                    "upstream registry h2 {} flushes each chained 1 KiB response separately (>= 4 flushes), \
                     got {} (before={flushes_before}, vectored={vectored})",
                    h2_source.version,
                    ctrl.stats().1
                );
            }
            H2SourceMode::Registry => {
                eprintln!(
                    "h2_batching_tests: [registry h2 {}] skipping exact flush-count packing assertion \
                     (vectored={vectored}, flushes={})",
                    h2_source.version,
                    ctrl.stats().1.saturating_sub(flushes_before)
                );
            }
        }

        ctrl.close_client_read();
        let outcome = tokio::time::timeout(Duration::from_secs(5), server_task)
            .await
            .map_err(|_| "server task did not finish after client EOF")??;
        assert!(outcome.is_ok(), "clean close should succeed: {outcome:?}");
    }
    Ok(())
}

dual_runtime_test!(
    blocked_flush_after_all_plaintext_accepted_wakes_and_completes_once,
    blocked_flush_after_all_plaintext_accepted_wakes_and_completes_once_multi_thread,
    blocked_flush_after_all_plaintext_accepted_wakes_and_completes_once_impl
);

#[allow(clippy::too_many_lines)]
async fn blocked_flush_error_write_zero_and_gated_shutdown_impl() -> TestResult {
    for vectored in [true, false] {
        // Subcase A: all plaintext accepted, flush blocked, no new input, released with error.
        {
            let (io, ctrl) = controlled_transport(vectored);
            let svc = service_fn(|_req: Request<Incoming>| async move {
                Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(vec![
                    0x62_u8;
                    512
                ]))))
            });
            let server_task = tokio::spawn(async move {
                miraserve_h2_builder()
                    .serve_connection(TokioIo::new(io), svc)
                    .await
            });
            complete_h2_handshake(&ctrl, &[]).await?;
            ctrl.set_flush_mode(FlushMode::Blocked);
            ctrl.push_client(&encode_request_headers(1, &Method::GET, "/err", true));
            ctrl.wait_for_frames(Duration::from_secs(5), |fs| {
                fs.iter()
                    .any(|f| f.stream_id == 1 && (f.flags & FLAG_END_STREAM) != 0)
            })
            .await?;
            ctrl.wait_for_flush_blocked(1, Duration::from_secs(5))
                .await?;
            ctrl.set_flush_mode(FlushMode::Error(io::ErrorKind::BrokenPipe));
            let res = tokio::time::timeout(Duration::from_secs(5), server_task)
                .await
                .map_err(|_| "server task hung after flush error")??;
            assert!(
                res.is_err(),
                "flush BrokenPipe must terminate connection with error (vectored={vectored})"
            );
            assert!(ctrl.stats().2 >= 1, "expected at least one flush error");
        }

        // Subcase B: WriteZero on nonempty write AND terminal write error fail cleanly (no spin).
        for mode in [
            WriteMode::WriteZero,
            WriteMode::Error(io::ErrorKind::BrokenPipe),
        ] {
            let (io, ctrl) = controlled_transport(vectored);
            let svc = service_fn(|_req: Request<Incoming>| async move {
                Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(vec![
                    0x63_u8;
                    1_024
                ]))))
            });
            let server_task = tokio::spawn(async move {
                miraserve_h2_builder()
                    .serve_connection(TokioIo::new(io), svc)
                    .await
            });
            complete_h2_handshake(&ctrl, &[]).await?;
            ctrl.set_write_mode(mode);
            ctrl.push_client(&encode_request_headers(1, &Method::GET, "/wz", true));
            let res = tokio::time::timeout(Duration::from_secs(5), server_task)
                .await
                .map_err(|_| format!("server task hung on {mode:?}"))??;
            assert!(
                res.is_err(),
                "{mode:?} must fail the connection (vectored={vectored})"
            );
        }

        // Subcase C: gated shutdown — final_flush_done runs before poll_shutdown, and zero polls
        // happen after shutdown completes (also test a shutdown error release).
        for release_shutdown in [
            ShutdownMode::Open,
            ShutdownMode::Error(io::ErrorKind::BrokenPipe),
        ] {
            let (io, ctrl) = controlled_transport(vectored);
            let svc = service_fn(|_req: Request<Incoming>| async move {
                Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(
                    b"bye",
                ))))
            });
            let (shut_tx, shut_rx) = tokio::sync::oneshot::channel::<()>();
            let server_task = tokio::spawn(async move {
                let builder = miraserve_h2_builder();
                let conn = builder.serve_connection(TokioIo::new(io), svc);
                tokio::pin!(conn);
                tokio::select! {
                    res = conn.as_mut() => res,
                    _ = shut_rx => {
                        conn.as_mut().graceful_shutdown();
                        conn.await
                    }
                }
            });

            complete_h2_handshake(&ctrl, &[]).await?;
            ctrl.push_client(&encode_request_headers(1, &Method::GET, "/bye", true));
            ctrl.wait_for_frames(Duration::from_secs(5), |fs| {
                fs.iter()
                    .any(|f| f.stream_id == 1 && (f.flags & FLAG_END_STREAM) != 0)
            })
            .await?;

            // Gate both flush and shutdown, then request graceful shutdown (before EOF so
            // GOAWAY is definitely encoded and enters the blocked flush barrier first).
            ctrl.set_flush_mode(FlushMode::Blocked);
            ctrl.set_shutdown_mode(ShutdownMode::Blocked);
            let _ = shut_tx.send(());

            // Wait until GOAWAY is flushed to the write buffer and blocked on poll_flush.
            ctrl.wait_for_frames(Duration::from_secs(5), |fs| {
                fs.iter().any(|f| f.frame_type == FRAME_GOAWAY)
            })
            .await?;
            ctrl.wait_for_flush_blocked(1, Duration::from_secs(5))
                .await?;
            assert_eq!(
                ctrl.stats().3,
                0,
                "poll_shutdown must NOT run before final flush completes (vectored={vectored})"
            );

            // Release flush and close client read so h2 finishes its final flush and enters
            // `poll_shutdown`, parking on `shutdown_waker`.
            ctrl.set_flush_mode(FlushMode::Open);
            ctrl.close_client_read();
            ctrl.wait_for_shutdown_blocked(1, Duration::from_secs(5))
                .await?;
            assert_eq!(ctrl.stats().4, 0, "shutdown must still be pending");

            // Release shutdown (either Ok or BrokenPipe).
            ctrl.set_shutdown_mode(release_shutdown);
            let res = tokio::time::timeout(Duration::from_secs(5), server_task)
                .await
                .map_err(|_| "server task did not exit after shutdown release")??;
            if matches!(release_shutdown, ShutdownMode::Open) {
                assert!(res.is_ok(), "graceful shutdown should return Ok: {res:?}");
                let (_, _, _, _, shut_done, after_shut) = ctrl.stats();
                assert_eq!(shut_done, 1, "poll_shutdown must complete once");
                assert_eq!(
                    after_shut, 0,
                    "no write/flush/shutdown poll allowed after shutdown completes"
                );
            } else {
                assert!(
                    res.is_err(),
                    "shutdown BrokenPipe must surface as connection error: {res:?}"
                );
            }
        }
    }
    Ok(())
}

dual_runtime_test!(
    blocked_flush_error_write_zero_and_gated_shutdown,
    blocked_flush_error_write_zero_and_gated_shutdown_multi_thread,
    blocked_flush_error_write_zero_and_gated_shutdown_impl
);

// ---------------------------------------------------------------------------
// 3. RST_STREAM before DATA selection and after DATA is committed to output
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
async fn rst_stream_before_selection_and_after_buffered_impl() -> TestResult {
    for vectored in [true, false] {
        let gate_before = Arc::new(Semaphore::new(0));
        let gate_before_svc = Arc::clone(&gate_before);
        let gate_mid = Arc::new(Semaphore::new(0));
        let gate_mid_svc = Arc::clone(&gate_mid);
        let seen_s1 = Arc::new(Notify::new());
        let seen_s1_svc = Arc::clone(&seen_s1);

        let (io, ctrl) = controlled_transport(vectored);
        let svc = service_fn(move |req: Request<Incoming>| {
            let gate_before = Arc::clone(&gate_before_svc);
            let gate_mid = Arc::clone(&gate_mid_svc);
            let seen_s1 = Arc::clone(&seen_s1_svc);
            async move {
                let body = match req.uri().path() {
                    "/rst-before" => {
                        seen_s1.notify_one();
                        FlexBody::from_steps(vec![
                            BodyStep::Wait(gate_before),
                            BodyStep::Data(Bytes::from(stream_pattern(1, 2_048))),
                        ])
                    }
                    "/rst-buffered" => FlexBody::from_steps(vec![
                        BodyStep::Data(Bytes::from(stream_pattern(5, 2_048))),
                        BodyStep::Wait(gate_mid),
                        BodyStep::Data(Bytes::from(stream_pattern(5, 2_048))),
                    ]),
                    _ => FlexBody::from_steps(vec![BodyStep::Data(Bytes::from(stream_pattern(
                        7, 1_024,
                    )))]),
                };
                Ok::<_, std::convert::Infallible>(Response::new(body))
            }
        });

        let server_task = tokio::spawn(async move {
            let _ = miraserve_h2_builder()
                .serve_connection(TokioIo::new(io), svc)
                .await;
        });

        complete_h2_handshake(&ctrl, &[]).await?;

        // Part A: RST_STREAM before stream 1's DATA is selected.
        ctrl.push_client(&encode_request_headers(
            1,
            &Method::GET,
            "/rst-before",
            true,
        ));
        tokio::time::timeout(Duration::from_secs(5), seen_s1.notified())
            .await
            .map_err(|_| "stream 1 never reached service")?;
        ctrl.push_client(&encode_rst_stream(1, 0x8)); // CANCEL
        tokio::time::sleep(Duration::from_millis(25)).await;
        gate_before.add_permits(1);

        // Send a healthy sibling on stream 3 to force connection progress.
        ctrl.push_client(&encode_request_headers(3, &Method::GET, "/ok", true));
        let after_a = ctrl
            .wait_for_frames(Duration::from_secs(5), |fs| {
                fs.iter()
                    .any(|f| f.stream_id == 3 && (f.flags & FLAG_END_STREAM) != 0)
            })
            .await?;
        let s1_data_bytes: usize = after_a
            .iter()
            .filter(|f| f.stream_id == 1 && f.frame_type == FRAME_DATA)
            .map(|f| f.payload.len())
            .sum();
        assert_eq!(
            s1_data_bytes, 0,
            "RST_STREAM before selection must suppress stream 1 DATA (vectored={vectored})"
        );

        // Part B: RST_STREAM after stream 5's first copied DATA chunk (2,048 B) is genuinely
        // committed to ordered output (verified by observing an actual DATA frame on stream 5,
        // NOT merely a blocked write or HEADERS) while flush is blocked and chunk 2 is gated.
        ctrl.set_flush_mode(FlushMode::Blocked);
        ctrl.push_client(&encode_request_headers(
            5,
            &Method::GET,
            "/rst-buffered",
            true,
        ));
        let committed_b = ctrl
            .wait_for_frames(Duration::from_secs(5), |fs| {
                let s5_bytes: usize = fs
                    .iter()
                    .filter(|f| f.stream_id == 5 && f.frame_type == FRAME_DATA)
                    .map(|f| f.payload.len())
                    .sum();
                s5_bytes == 2_048
            })
            .await?;
        assert!(
            !committed_b
                .iter()
                .any(|f| f.stream_id == 5 && (f.flags & FLAG_END_STREAM) != 0),
            "stream 5 must still be open after its first 2,048 B chunk"
        );
        ctrl.wait_for_flush_blocked(1, Duration::from_secs(5))
            .await?;

        // Now send RST_STREAM(5, CANCEL) + healthy sibling stream 7, release flush, and release
        // stream 5's second chunk gate.
        let mut rst_and_sib = encode_rst_stream(5, 0x8);
        rst_and_sib.extend_from_slice(&encode_request_headers(7, &Method::GET, "/ok", true));
        ctrl.push_client(&rst_and_sib);
        ctrl.set_flush_mode(FlushMode::Open);
        tokio::time::sleep(Duration::from_millis(20)).await;
        gate_mid.add_permits(1);

        let after_b = ctrl
            .wait_for_frames(Duration::from_secs(5), |fs| {
                fs.iter()
                    .any(|f| f.stream_id == 7 && (f.flags & FLAG_END_STREAM) != 0)
            })
            .await?;

        let s7_payload: Vec<u8> = after_b
            .iter()
            .filter(|f| f.stream_id == 7 && f.frame_type == FRAME_DATA)
            .flat_map(|f| f.payload.iter().copied())
            .collect();
        assert_eq!(s7_payload, stream_pattern(7, 1_024));

        // Committed bytes of stream 5 must remain intact (not retracted) and its second chunk
        // must never be emitted after RST_STREAM.
        let s5_payload: Vec<u8> = after_b
            .iter()
            .filter(|f| f.stream_id == 5 && f.frame_type == FRAME_DATA)
            .flat_map(|f| f.payload.iter().copied())
            .collect();
        assert_eq!(
            s5_payload,
            stream_pattern(5, 2_048),
            "committed 2,048 B of stream 5 must stay intact and cancelled second chunk must never be sent (vectored={vectored})"
        );
        let raw_b = ctrl.written_snapshot();
        let (_, consumed_b) = parse_frames(&raw_b);
        assert_eq!(
            consumed_b,
            raw_b.len(),
            "wire stream must remain cleanly framed after RST_STREAM"
        );

        ctrl.close_client_read();
        let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    }
    Ok(())
}

dual_runtime_test!(
    rst_stream_before_selection_and_after_buffered,
    rst_stream_before_selection_and_after_buffered_multi_thread,
    rst_stream_before_selection_and_after_buffered_impl
);

// ---------------------------------------------------------------------------
// 4. Large header block behind copied DATA (CONTINUATION), default & enlarged
//    peer MAX_FRAME_SIZE, and observed buffer packing capacity before/after
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
async fn run_large_header_continuation_case(peer_max_frame_size: u32) -> TestResult {
    let (io, ctrl) = controlled_transport(true);

    // Build a large (~72 KiB raw, > 48 KiB after HPACK Huffman encoding) header map of unique
    // names and values so it exceeds both default 16,384 B and enlarged 32,768 B MAX_FRAME_SIZE,
    // forcing HEADERS + CONTINUATION behind copied DATA.
    let big_headers: Arc<Vec<(HeaderName, HeaderValue)>> = Arc::new(
        (0_usize..320)
            .map(|i| {
                let name = HeaderName::from_bytes(format!("x-large-hdr-{i:03}").as_bytes())
                    .unwrap_or_else(|_| HeaderName::from_static("x-fallback"));
                let val = HeaderValue::from_str(&format!(
                    "v{i:03}-{}",
                    "QwErTyUiOpAsDfGhJkLzXcVbNm0123456789".repeat(6)
                ))
                .unwrap_or_else(|_| HeaderValue::from_static("v"));
                (name, val)
            })
            .collect(),
    );

    let hdrs_svc = Arc::clone(&big_headers);
    let s31_returned = Arc::new(Notify::new());
    let s31_returned_svc = Arc::clone(&s31_returned);
    let s33_returned = Arc::new(Notify::new());
    let s33_returned_svc = Arc::clone(&s33_returned);
    let p3_served = Arc::new(AtomicUsize::new(0));
    let p3_served_svc = Arc::clone(&p3_served);
    let svc = service_fn(move |req: Request<Incoming>| {
        let hdrs = Arc::clone(&hdrs_svc);
        let s31_done = Arc::clone(&s31_returned_svc);
        let s33_done = Arc::clone(&s33_returned_svc);
        let p3_cnt = Arc::clone(&p3_served_svc);
        async move {
            let path = req.uri().path().to_owned();
            let mut builder = Response::builder().status(StatusCode::OK);
            let body = if path == "/big-headers" {
                for (k, v) in hdrs.iter() {
                    builder = builder.header(k.clone(), v.clone());
                }
                s33_done.notify_one();
                Full::new(Bytes::from(stream_pattern(99, 512)))
            } else if path == "/small-ahead" {
                s31_done.notify_one();
                Full::new(Bytes::from(stream_pattern(31, 1_024)))
            } else if path == "/small-p3" {
                p3_cnt.fetch_add(1, Ordering::AcqRel);
                Full::new(Bytes::from(stream_pattern(1, 1_024)))
            } else {
                Full::new(Bytes::from(stream_pattern(1, 1_024)))
            };
            let resp = builder
                .body(body)
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())));
            Ok::<_, std::convert::Infallible>(resp)
        }
    });

    let server_task = tokio::spawn(async move {
        let _ = miraserve_h2_builder()
            .serve_connection(TokioIo::new(io), svc)
            .await;
    });

    let mut settings = vec![(SETTINGS_INITIAL_WINDOW_SIZE, 256 * 1024)];
    if peer_max_frame_size != 16_384 {
        settings.push((SETTINGS_MAX_FRAME_SIZE, peer_max_frame_size));
    }
    complete_h2_handshake(&ctrl, &settings).await?;

    // Phase 1: pre-growth burst (14 x 1 KiB). Initial encoder buffer is 16,384 B, so no single
    // non-chained write can exceed 16,384 B before the large header block grows `BytesMut`.
    let writes_before_p1 = ctrl.write_records_snapshot().len();
    let mut p1 = Vec::new();
    for i in 0_u32..14 {
        p1.extend_from_slice(&encode_request_headers(
            1 + i * 2,
            &Method::GET,
            "/small",
            true,
        ));
    }
    ctrl.push_client(&p1);
    ctrl.wait_for_frames(Duration::from_secs(5), |fs| {
        (0_u32..14).all(|i| {
            let sid = 1 + i * 2;
            fs.iter()
                .any(|f| f.stream_id == sid && (f.flags & FLAG_END_STREAM) != 0)
        })
    })
    .await?;
    let p1_max_write = ctrl
        .write_records_snapshot()
        .get(writes_before_p1..)
        .unwrap_or(&[])
        .iter()
        .map(|w| w.bytes)
        .max()
        .unwrap_or(0);
    assert!(
        p1_max_write <= 16_384,
        "before large HEADERS, initial 16 KiB buffer must cap single copied write <= 16384 (got {p1_max_write})"
    );

    // Phase 2: copied DATA of stream 31 (1,024 B) strictly ahead of stream 33's large header
    // block (HEADERS without END_HEADERS + CONTINUATION) in the EXACT SAME drain / transport write.
    // Push stream 31 first under WriteMode::Blocked so its HEADERS + copied 1,024 B DATA are
    // definitely buffered in FramedWrite::buf before stream 33 arrives; because 16,384 - ~1,048 >=
    // min_buffer_capacity (4,105), h2 then encodes stream 33's HEADERS right behind it in the
    // exact same write buffer before draining.
    ctrl.set_write_mode(WriteMode::Blocked);
    let writes_before_p2 = ctrl.write_records_snapshot().len();
    ctrl.push_client(&encode_request_headers(
        31,
        &Method::GET,
        "/small-ahead",
        true,
    ));
    tokio::time::timeout(Duration::from_secs(5), s31_returned.notified())
        .await
        .map_err(|_| "stream 31 small-ahead handler did not run")?;
    ctrl.wait_for_write_blocked(Duration::from_secs(5)).await?;
    tokio::time::sleep(Duration::from_millis(25)).await;

    ctrl.push_client(&encode_request_headers(
        33,
        &Method::GET,
        "/big-headers",
        true,
    ));
    tokio::time::timeout(Duration::from_secs(5), s33_returned.notified())
        .await
        .map_err(|_| "stream 33 big-headers handler did not run")?;
    tokio::time::sleep(Duration::from_millis(25)).await;
    ctrl.set_write_mode(WriteMode::Open {
        max_chunk: usize::MAX,
    });

    let frames_p2 = ctrl
        .wait_for_frames(Duration::from_secs(5), |fs| {
            [31_u32, 33].iter().all(|&sid| {
                fs.iter()
                    .any(|f| f.stream_id == sid && (f.flags & FLAG_END_STREAM) != 0)
            })
        })
        .await?;

    // Verify stream 31's copied DATA (1,024 B) shared the exact same transport write ahead of
    // stream 33's HEADERS (without END_HEADERS).
    let raw_p2 = ctrl.written_snapshot();
    let records_p2 = ctrl.write_records_snapshot();
    let (spanned_p2, _) = parse_frames_with_spans(&raw_p2);
    let shared_write_found = records_p2
        .get(writes_before_p2..)
        .unwrap_or(&[])
        .iter()
        .any(|w| {
            let w_start = w.start_offset;
            let w_end = w.start_offset.saturating_add(w.bytes);
            let mut s31_data_pos = None;
            let mut s33_hdr_pos = None;
            for (idx, &(f_start, f_end, ref f)) in spanned_p2.iter().enumerate() {
                if f_start >= w_start && f_end <= w_end {
                    if f.stream_id == 31 && f.frame_type == FRAME_DATA && f.payload.len() == 1_024 {
                        s31_data_pos = Some(idx);
                    }
                    if f.stream_id == 33
                        && f.frame_type == FRAME_HEADERS
                        && (f.flags & FLAG_END_HEADERS) == 0
                    {
                        s33_hdr_pos = Some(idx);
                    }
                }
            }
            matches!((s31_data_pos, s33_hdr_pos), (Some(a), Some(b)) if a < b)
        });
    let h2_source = read_h2_source_env()?;
    match h2_source.mode {
        H2SourceMode::Vendored => {
            assert!(
                shared_write_found,
                "expected stream 31 copied DATA (1,024 B) ahead of stream 33 HEADERS (no END_HEADERS) in the same transport write (max_frame_size={peer_max_frame_size})"
            );
        }
        H2SourceMode::Registry if h2_source.is_vendored_upstream_registry() => {
            // Exact unpatched upstream expectation for the vendored version: on vectored
            // transport, stream 31's 1,024 B DATA (>= 256 B) chains into Next::Data and drains
            // before stream 33's HEADERS is encoded.
            assert!(
                !shared_write_found,
                "upstream registry h2 {} chains stream 31's 1,024 B DATA separately from stream 33 HEADERS \
                 (max_frame_size={peer_max_frame_size})",
                h2_source.version
            );
        }
        H2SourceMode::Registry => {
            eprintln!(
                "h2_batching_tests: [registry h2 {}] skipping same-write DATA+HEADERS packing assertion \
                 (max_frame_size={peer_max_frame_size}, shared_write_found={shared_write_found})",
                h2_source.version
            );
        }
    }
    let s31_data: Vec<u8> = frames_p2
        .iter()
        .filter(|f| f.stream_id == 31 && f.frame_type == FRAME_DATA)
        .flat_map(|f| f.payload.iter().copied())
        .collect();
    assert_eq!(s31_data, stream_pattern(31, 1_024));

    // Verify stream 33 emitted HEADERS (without END_HEADERS) followed immediately by
    // contiguous CONTINUATION frame(s) ending with END_HEADERS, each <= peer_max_frame_size.
    let hdr_idx = frames_p2
        .iter()
        .position(|f| f.stream_id == 33 && f.frame_type == FRAME_HEADERS)
        .ok_or("missing HEADERS frame for stream 33")?;
    let hdr_frame = frames_p2
        .get(hdr_idx)
        .ok_or("missing HEADERS frame at hdr_idx")?;
    assert_eq!(
        hdr_frame.flags & FLAG_END_HEADERS,
        0,
        "large header block must omit END_HEADERS on initial HEADERS (max_frame_size={peer_max_frame_size})"
    );
    assert!(
        hdr_frame.payload.len() <= usize::try_from(peer_max_frame_size).unwrap_or(16_384),
        "HEADERS payload exceeded peer MAX_FRAME_SIZE"
    );

    let mut cont_count = 0_usize;
    let mut saw_end_headers = false;
    let mut idx = hdr_idx + 1;
    while let Some(f) = frames_p2.get(idx) {
        assert_eq!(
            f.stream_id, 33,
            "no other stream may interleave between HEADERS and CONTINUATION"
        );
        assert_eq!(
            f.frame_type, FRAME_CONTINUATION,
            "expected CONTINUATION frame directly after HEADERS"
        );
        assert!(
            f.payload.len() <= usize::try_from(peer_max_frame_size).unwrap_or(16_384),
            "CONTINUATION payload exceeded peer MAX_FRAME_SIZE"
        );
        cont_count += 1;
        if (f.flags & FLAG_END_HEADERS) != 0 {
            saw_end_headers = true;
            break;
        }
        idx += 1;
    }
    assert!(
        cont_count >= 1 && saw_end_headers,
        "expected >= 1 CONTINUATION ending with END_HEADERS (got {cont_count}, end={saw_end_headers})"
    );

    let s33_data: Vec<u8> = frames_p2
        .iter()
        .filter(|f| f.stream_id == 33 && f.frame_type == FRAME_DATA)
        .flat_map(|f| f.payload.iter().copied())
        .collect();
    assert_eq!(s33_data, stream_pattern(99, 512));

    // Phase 3: post-growth burst (24 x 1 KiB) gated behind WriteMode::Blocked so all 24 ready
    // responses queue before draining, deterministically observing retained BytesMut capacity
    // after clear() plus idle readiness recovery.
    ctrl.set_write_mode(WriteMode::Blocked);
    let writes_before_p3 = ctrl.write_records_snapshot().len();
    let mut p3 = Vec::new();
    for i in 0_u32..24 {
        p3.extend_from_slice(&encode_request_headers(
            41 + i * 2,
            &Method::GET,
            "/small-p3",
            true,
        ));
    }
    ctrl.push_client(&p3);
    let p3_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while p3_served.load(Ordering::Acquire) < 24 {
        assert!(
            tokio::time::Instant::now() < p3_deadline,
            "timed out waiting for all 24 Phase-3 handlers to return"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    ctrl.wait_for_write_blocked(Duration::from_secs(5)).await?;
    tokio::time::sleep(Duration::from_millis(25)).await;
    ctrl.set_write_mode(WriteMode::Open {
        max_chunk: usize::MAX,
    });

    let frames_p3 = ctrl
        .wait_for_frames(Duration::from_secs(5), |fs| {
            (0_u32..24).all(|i| {
                let sid = 41 + i * 2;
                fs.iter()
                    .any(|f| f.stream_id == sid && (f.flags & FLAG_END_STREAM) != 0)
            })
        })
        .await?;

    for i in 0_u32..24 {
        let sid = 41 + i * 2;
        let data: Vec<u8> = frames_p3
            .iter()
            .filter(|f| f.stream_id == sid && f.frame_type == FRAME_DATA)
            .flat_map(|f| f.payload.iter().copied())
            .collect();
        assert_eq!(data, stream_pattern(1, 1_024));
    }

    let p3_max_write = ctrl
        .write_records_snapshot()
        .get(writes_before_p3..)
        .unwrap_or(&[])
        .iter()
        .map(|w| w.bytes)
        .max()
        .unwrap_or(0);
    assert!(
        p3_max_write > 0,
        "post-growth burst must make write progress (pre={p1_max_write}, post={p3_max_write})"
    );
    // With an enlarged 32 KiB peer MAX_FRAME_SIZE, the large HEADERS frame grew the encoder's
    // `BytesMut` beyond 16 KiB, and `clear()` retains that capacity so a queued 24 x 1 KiB burst
    // packs strictly more than the initial 16,384-byte buffer in one write under COPY_LIMIT=4096.
    if peer_max_frame_size > 16_384 {
        match h2_source.mode {
            H2SourceMode::Vendored => {
                assert!(
                    p3_max_write > 16_384,
                    "retained capacity after enlarged 32 KiB HEADERS should allow a single queued write > 16384 B (pre={p1_max_write}, post={p3_max_write})"
                );
            }
            H2SourceMode::Registry if h2_source.is_vendored_upstream_registry() => {
                // Exact unpatched upstream expectation for the vendored version: each 1 KiB DATA
                // chains individually (>= 256 B), so a 24 x 1 KiB burst cannot pack > 16,384 B
                // into a single transport write.
                assert!(
                    p3_max_write <= 16_384,
                    "upstream registry h2 {} chains each 1 KiB DATA separately (expected post <= 16384 B; pre={p1_max_write}, post={p3_max_write})",
                    h2_source.version
                );
            }
            H2SourceMode::Registry => {
                eprintln!(
                    "h2_batching_tests: [registry h2 {}] skipping post-growth >16KiB packing assertion \
                     (pre={p1_max_write}, post={p3_max_write})",
                    h2_source.version
                );
            }
        }
    }

    // Idle pause then one final request: readiness remains healthy after idle.
    tokio::time::sleep(Duration::from_millis(25)).await;
    ctrl.push_client(&encode_request_headers(99, &Method::GET, "/small", true));
    ctrl.wait_for_frames(Duration::from_secs(5), |fs| {
        fs.iter()
            .any(|f| f.stream_id == 99 && (f.flags & FLAG_END_STREAM) != 0)
    })
    .await?;

    ctrl.close_client_read();
    let _ = tokio::time::timeout(Duration::from_secs(5), server_task).await;
    Ok(())
}

async fn large_header_block_behind_copied_data_continuation_and_capacity_impl() -> TestResult {
    run_large_header_continuation_case(16_384).await?;
    run_large_header_continuation_case(32_768).await?;
    Ok(())
}

dual_runtime_test!(
    large_header_block_behind_copied_data_continuation_and_capacity,
    large_header_block_behind_copied_data_continuation_and_capacity_multi_thread,
    large_header_block_behind_copied_data_continuation_and_capacity_impl
);

// ---------------------------------------------------------------------------
// 5. Lone control frames (SETTINGS ACK, PING ACK, WINDOW_UPDATE, graceful GOAWAY)
//    make progress with NO DATA pending
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
async fn control_frames_make_progress_with_no_data_pending_impl() -> TestResult {
    for vectored in [true, false] {
        let (io, ctrl) = controlled_transport(vectored);
        let (shut_tx, shut_rx) = tokio::sync::oneshot::channel::<()>();

        let svc = service_fn(|mut req: Request<Incoming>| async move {
            // Drain the incoming POST upload body without writing response DATA until EOF.
            let mut total = 0_usize;
            while let Some(frame) = req.body_mut().frame().await {
                if let Ok(frame) = frame
                    && let Ok(data) = frame.into_data()
                {
                    total += data.len();
                }
            }
            Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(format!(
                "uploaded={total}"
            )))))
        });

        let server_task = tokio::spawn(async move {
            let builder = miraserve_h2_builder();
            let conn = builder.serve_connection(TokioIo::new(io), svc);
            tokio::pin!(conn);
            tokio::select! {
                res = conn.as_mut() => res,
                _ = shut_rx => {
                    conn.as_mut().graceful_shutdown();
                    conn.await
                }
            }
        });

        complete_h2_handshake(&ctrl, &[]).await?;

        // 1. Lone SETTINGS -> SETTINGS ACK (2nd ACK overall, with zero DATA pending).
        let acks_before = parse_frames(&ctrl.written_snapshot())
            .0
            .iter()
            .filter(|f| f.frame_type == FRAME_SETTINGS && (f.flags & FLAG_ACK) != 0)
            .count();
        ctrl.push_client(&encode_settings(&[(SETTINGS_MAX_CONCURRENT_STREAMS, 64)]));
        ctrl.wait_for_frames(Duration::from_secs(5), |fs| {
            fs.iter()
                .filter(|f| f.frame_type == FRAME_SETTINGS && (f.flags & FLAG_ACK) != 0)
                .count()
                > acks_before
        })
        .await?;

        // 2. Lone PING -> PING ACK with matching 8-byte opaque payload, zero DATA pending.
        let opaque = [0x11_u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        ctrl.push_client(&encode_ping(false, opaque));
        ctrl.wait_for_frames(Duration::from_secs(5), |fs| {
            fs.iter().any(|f| {
                f.frame_type == FRAME_PING
                    && (f.flags & FLAG_ACK) != 0
                    && f.payload.as_slice() == opaque
            })
        })
        .await?;

        // 3. Lone WINDOW_UPDATE: upload > half of MiraServe's 256 KiB stream window (without
        //    ending the request, so zero response DATA is queued) -> server emits WINDOW_UPDATE.
        let mut upload = encode_request_headers(1, &Method::POST, "/upload", false);
        let chunk = vec![0x7a_u8; 16_384];
        for _ in 0..10 {
            upload.extend_from_slice(&encode_data(1, false, &chunk));
        }
        ctrl.push_client(&upload);
        ctrl.wait_for_frames(Duration::from_secs(5), |fs| {
            fs.iter()
                .any(|f| f.frame_type == FRAME_WINDOW_UPDATE && f.stream_id == 1)
        })
        .await?;

        // Finish stream 1 cleanly so no DATA is pending before testing lone graceful GOAWAY.
        ctrl.push_client(&encode_data(1, true, &[]));
        let after_upload = ctrl
            .wait_for_frames(Duration::from_secs(5), |fs| {
                fs.iter()
                    .any(|f| f.stream_id == 1 && (f.flags & FLAG_END_STREAM) != 0)
            })
            .await?;
        let resp_body: Vec<u8> = after_upload
            .iter()
            .filter(|f| f.stream_id == 1 && f.frame_type == FRAME_DATA)
            .flat_map(|f| f.payload.iter().copied())
            .collect();
        assert_eq!(resp_body, b"uploaded=163840");

        // 4. Lone graceful GOAWAY with zero DATA pending.
        let _ = shut_tx.send(());
        ctrl.wait_for_frames(Duration::from_secs(5), |fs| {
            fs.iter().any(|f| f.frame_type == FRAME_GOAWAY)
        })
        .await?;

        ctrl.close_client_read();
        let res = tokio::time::timeout(Duration::from_secs(5), server_task)
            .await
            .map_err(|_| "graceful shutdown did not complete")??;
        assert!(res.is_ok(), "graceful shutdown failed: {res:?}");
    }
    Ok(())
}

dual_runtime_test!(
    control_frames_make_progress_with_no_data_pending,
    control_frames_make_progress_with_no_data_pending_multi_thread,
    control_frames_make_progress_with_no_data_pending_impl
);

// ---------------------------------------------------------------------------
// 6. MiraServe observer: access-log outcome recorded exactly once per response
//    in a batched burst (and failed once per response on flush error)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct AccessEvent {
    target: String,
    fields: BTreeMap<String, String>,
}

#[derive(Default)]
struct MapVisitor(BTreeMap<String, String>);

impl Visit for MapVisitor {
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().to_owned(), value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.insert(field.name().to_owned(), value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().to_owned(), value.to_string());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
}

#[derive(Clone, Default)]
struct AccessCapture(Arc<Mutex<Vec<AccessEvent>>>);

impl AccessCapture {
    fn events_for_host(&self, host: &str) -> Vec<AccessEvent> {
        self.0.lock().map_or_else(
            |_| Vec::new(),
            |g| {
                g.iter()
                    .filter(|e| {
                        e.target == "miraserve::access"
                            && e.fields.get("host").map(String::as_str) == Some(host)
                    })
                    .cloned()
                    .collect()
            },
        )
    }
}

fn global_access_capture() -> AccessCapture {
    static GLOBAL: std::sync::OnceLock<AccessCapture> = std::sync::OnceLock::new();
    GLOBAL
        .get_or_init(|| {
            let cap = AccessCapture::default();
            let _ = tracing::subscriber::set_global_default(cap.clone());
            tracing::callsite::rebuild_interest_cache();
            cap
        })
        .clone()
}

impl Subscriber for AccessCapture {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target() == "miraserve::access"
    }

    fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}

    fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        if event.metadata().target() != "miraserve::access" {
            return;
        }
        let mut visitor = MapVisitor::default();
        event.record(&mut visitor);
        if let Ok(mut g) = self.0.lock() {
            g.push(AccessEvent {
                target: event.metadata().target().to_owned(),
                fields: visitor.0,
            });
        }
    }

    fn enter(&self, _span: &span::Id) {}

    fn exit(&self, _span: &span::Id) {}
}

fn next_test_seq() -> usize {
    static SEQ: AtomicUsize = AtomicUsize::new(1);
    SEQ.fetch_add(1, Ordering::Relaxed)
}

#[allow(clippy::too_many_lines)]
async fn batched_burst_records_access_log_exactly_once_per_response_and_fails_on_flush_error_impl()
-> TestResult {
    let capture = global_access_capture();

    let seq = next_test_seq();
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "miraserve-h2-batch-log-{}-{seq}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root)?;
    for i in 0_usize..8 {
        std::fs::write(root.join(format!("f{i}.txt")), vec![b'x'; 1_024])?;
    }

    let ok_host = format!("h2-ok-{seq}-{nanos}.example.test");
    let err_host = format!("h2-err-{seq}-{nanos}.example.test");
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "{ok_host}" {{
    root "{root}"
}}
site "{err_host}" {{
    root "{root}"
}}
"#,
        root = root.to_string_lossy().replace('\\', "/"),
    );
    let (cfg, _) = parse_kdl("h2-batch-log.kdl", &kdl)?;
    let engine = Arc::new(HttpEngine::from_config(
        &cfg,
        Arc::new(AcmeChallengeStore::new()),
        None,
        8443,
    )?);

    let peer: SocketAddr = "198.51.100.77:51000".parse()?;
    let local: SocketAddr = "127.0.0.1:8443".parse()?;

    // Subcase A: 8 batched 1 KiB responses -> exactly 8 access-log events, completed=true.
    {
        let (io, ctrl) = controlled_transport(true);
        let (_shut_tx, shut_rx) = watch::channel(false);
        let srv = tokio::spawn(
            Arc::clone(&engine).serve_hyper_connection(io, peer, local, true, false, None, shut_rx),
        );

        complete_h2_handshake(&ctrl, &[]).await?;
        let mut burst = Vec::new();
        for i in 0_u32..8 {
            burst.extend_from_slice(&encode_request_headers_for_host(
                1 + i * 2,
                &Method::GET,
                &ok_host,
                &format!("/f{i}.txt"),
                true,
            ));
        }
        ctrl.push_client(&burst);

        ctrl.wait_for_frames(Duration::from_secs(5), |fs| {
            (0_u32..8).all(|i| {
                let sid = 1 + i * 2;
                fs.iter()
                    .any(|f| f.stream_id == sid && (f.flags & FLAG_END_STREAM) != 0)
            })
        })
        .await?;

        ctrl.close_client_read();
        let _ = tokio::time::timeout(Duration::from_secs(5), srv).await;
    }

    let ok_events = capture.events_for_host(&ok_host);
    assert_eq!(
        ok_events.len(),
        8,
        "expected exactly 1 access-log record per response in 8-stream burst, got {}: {ok_events:?}",
        ok_events.len()
    );
    for i in 0_usize..8 {
        let target = format!("/f{i}.txt");
        let matched: Vec<&AccessEvent> = ok_events
            .iter()
            .filter(|e| e.fields.get("target").map(String::as_str) == Some(target.as_str()))
            .collect();
        assert_eq!(
            matched.len(),
            1,
            "target {target} must be logged exactly once"
        );
        if let Some(ev) = matched.first() {
            assert_eq!(ev.fields.get("status").map(String::as_str), Some("200"));
            assert_eq!(
                ev.fields.get("bytes_sent").map(String::as_str),
                Some("1024")
            );
            assert_eq!(
                ev.fields.get("body_complete").map(String::as_str),
                Some("true")
            );
            assert_eq!(ev.fields.get("completed").map(String::as_str), Some("true"));
            assert_eq!(
                ev.fields.get("transport_delivery").map(String::as_str),
                Some("unconfirmed_multiplexed")
            );
        }
    }

    // Subcase B: 4 batched 1 KiB responses with flush blocked, then flush fails ->
    // zero records emitted while flush is pending, then failed responses emit completed=false.
    let h2_source = read_h2_source_env()?;
    let data_sent_sids_before_err: Vec<u32>;
    {
        let (io, ctrl) = controlled_transport(true);
        let (_shut_tx, shut_rx) = watch::channel(false);
        let srv = tokio::spawn(
            Arc::clone(&engine).serve_hyper_connection(io, peer, local, true, false, None, shut_rx),
        );

        complete_h2_handshake(&ctrl, &[]).await?;
        ctrl.set_flush_mode(FlushMode::Blocked);

        let mut burst = Vec::new();
        for i in 0_u32..4 {
            burst.extend_from_slice(&encode_request_headers_for_host(
                1 + i * 2,
                &Method::GET,
                &err_host,
                &format!("/f{i}.txt"),
                true,
            ));
        }
        ctrl.push_client(&burst);

        let frames_before_err = match h2_source.mode {
            H2SourceMode::Vendored => {
                ctrl.wait_for_frames(Duration::from_secs(5), |fs| {
                    (0_u32..4).all(|i| {
                        let sid = 1 + i * 2;
                        fs.iter()
                            .any(|f| f.stream_id == sid && (f.flags & FLAG_END_STREAM) != 0)
                    })
                })
                .await?
            }
            H2SourceMode::Registry => {
                // Static responses through HttpEngine emit HEADERS + 1,024 B DATA + empty
                // DATA(END_STREAM). Under unpatched upstream h2's 256 B vectored chain threshold,
                // the first 1,024 B DATA frame chains into Next::Data and parks on poll_flush
                // BEFORE its trailing empty DATA(END_STREAM) frame (or the other 3 streams'
                // DATA frames) can be encoded.
                ctrl.wait_for_frames(Duration::from_secs(5), |fs| {
                    (0_u32..4).any(|i| {
                        let sid = 1 + i * 2;
                        let bytes: usize = fs
                            .iter()
                            .filter(|f| f.stream_id == sid && f.frame_type == FRAME_DATA)
                            .map(|f| f.payload.len())
                            .sum();
                        bytes == 1_024
                    })
                })
                .await?
            }
        };
        ctrl.wait_for_flush_blocked(1, Duration::from_secs(5))
            .await?;

        data_sent_sids_before_err = (0_u32..4)
            .map(|i| 1 + i * 2)
            .filter(|&sid| {
                let bytes: usize = frames_before_err
                    .iter()
                    .filter(|f| f.stream_id == sid && f.frame_type == FRAME_DATA)
                    .map(|f| f.payload.len())
                    .sum();
                bytes == 1_024
            })
            .collect();
        if h2_source.mode == H2SourceMode::Registry {
            let ended_before_err = (0_u32..4)
                .map(|i| 1 + i * 2)
                .filter(|&sid| {
                    frames_before_err
                        .iter()
                        .any(|f| f.stream_id == sid && (f.flags & FLAG_END_STREAM) != 0)
                })
                .count();
            if h2_source.is_vendored_upstream_registry() {
                assert_eq!(
                    data_sent_sids_before_err.len(),
                    1,
                    "upstream registry h2 {} must block on poll_flush after 1 chained 1 KiB DATA frame, \
                     got {data_sent_sids_before_err:?}",
                    h2_source.version
                );
                assert_eq!(
                    ended_before_err, 0,
                    "upstream registry h2 {} parks on poll_flush before the trailing empty DATA(END_STREAM) frame, \
                     got {ended_before_err}",
                    h2_source.version
                );
            } else {
                eprintln!(
                    "h2_batching_tests: [registry h2 {}] skipping 4-stream pre-flush packing count in access-log \
                     error test (data_sent_sids={data_sent_sids_before_err:?}, ended={ended_before_err})",
                    h2_source.version
                );
            }
        }

        assert_eq!(
            capture.events_for_host(&err_host).len(),
            0,
            "batched access-log records must wait for real flush completion"
        );

        ctrl.set_flush_mode(FlushMode::Error(io::ErrorKind::BrokenPipe));
        let _ = tokio::time::timeout(Duration::from_secs(5), srv).await;
    }

    let err_events = capture.events_for_host(&err_host);
    match h2_source.mode {
        H2SourceMode::Vendored => {
            assert_eq!(
                err_events.len(),
                4,
                "all 4 pending records must be emitted once on flush error, got {}: {err_events:?}",
                err_events.len()
            );
            for i in 0_usize..4 {
                let target = format!("/f{i}.txt");
                let matched: Vec<&AccessEvent> = err_events
                    .iter()
                    .filter(|e| e.fields.get("target").map(String::as_str) == Some(target.as_str()))
                    .collect();
                assert_eq!(
                    matched.len(),
                    1,
                    "failed target {target} must be logged exactly once, got {matched:?}"
                );
                if let Some(ev) = matched.first() {
                    assert_eq!(ev.fields.get("status").map(String::as_str), Some("200"));
                    assert_eq!(
                        ev.fields.get("bytes_sent").map(String::as_str),
                        Some("1024")
                    );
                    assert_eq!(
                        ev.fields.get("completed").map(String::as_str),
                        Some("false"),
                        "flush error must record completed=false: {ev:?}"
                    );
                }
            }
        }
        H2SourceMode::Registry => {
            assert!(
                !err_events.is_empty() && err_events.len() <= 4,
                "expected 1..=4 failed access-log records in registry mode, got {}: {err_events:?}",
                err_events.len()
            );
            // Every stream whose 1,024 B DATA frame was written before the flush error must be
            // logged exactly once with status=200, bytes_sent=1024, completed=false.
            for &sid in &data_sent_sids_before_err {
                let idx = usize::try_from((sid - 1) / 2).unwrap_or(0);
                let target = format!("/f{idx}.txt");
                let matched: Vec<&AccessEvent> = err_events
                    .iter()
                    .filter(|e| e.fields.get("target").map(String::as_str) == Some(target.as_str()))
                    .collect();
                assert_eq!(
                    matched.len(),
                    1,
                    "flush-failed target {target} (stream {sid}) must be logged exactly once, got {matched:?}"
                );
                if let Some(ev) = matched.first() {
                    assert_eq!(ev.fields.get("status").map(String::as_str), Some("200"));
                    assert_eq!(
                        ev.fields.get("bytes_sent").map(String::as_str),
                        Some("1024")
                    );
                    assert_eq!(
                        ev.fields.get("completed").map(String::as_str),
                        Some("false"),
                        "flush error must record completed=false: {ev:?}"
                    );
                }
            }
            // No target may be logged twice, and no event may falsely report completed=true.
            let mut seen_targets = std::collections::BTreeSet::new();
            for ev in &err_events {
                let target = ev
                    .fields
                    .get("target")
                    .map(String::as_str)
                    .ok_or("access-log event missing target")?;
                assert!(
                    seen_targets.insert(target.to_owned()),
                    "duplicate access-log record for {target}: {err_events:?}"
                );
                assert_eq!(ev.fields.get("status").map(String::as_str), Some("200"));
                assert_eq!(
                    ev.fields.get("completed").map(String::as_str),
                    Some("false"),
                    "flush error must record completed=false for every stream: {ev:?}"
                );
            }
        }
    }

    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

dual_runtime_test!(
    batched_burst_records_access_log_exactly_once_per_response_and_fails_on_flush_error,
    batched_burst_records_access_log_exactly_once_per_response_and_fails_on_flush_error_multi_thread,
    batched_burst_records_access_log_exactly_once_per_response_and_fails_on_flush_error_impl
);

// ---------------------------------------------------------------------------
// 7. HTTP/1.1 request and WebSocket upgrade parity smoke
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
async fn http1_request_and_websocket_upgrade_parity_smoke_impl() -> TestResult {
    let _ = global_access_capture();
    // Raw HTTP/1.1 WebSocket upgrade echo backend.
    let up_listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = up_listener.local_addr()?;
    let up_task = tokio::spawn(async move {
        if let Ok((mut stream, _)) = up_listener.accept().await {
            let mut req_buf = vec![0_u8; 4_096];
            let mut filled = 0_usize;
            while filled < req_buf.len() {
                let Ok(n) = stream
                    .read(req_buf.get_mut(filled..).unwrap_or(&mut []))
                    .await
                else {
                    return;
                };
                if n == 0 {
                    return;
                }
                filled += n;
                if req_buf
                    .get(..filled)
                    .is_some_and(|b| b.windows(4).any(|w| w == b"\r\n\r\n"))
                {
                    break;
                }
            }
            let reply = concat!(
                "HTTP/1.1 101 Switching Protocols\r\n",
                "Upgrade: websocket\r\n",
                "Connection: Upgrade\r\n",
                "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
            );
            if stream.write_all(reply.as_bytes()).await.is_err() {
                return;
            }
            let _ = stream.flush().await;
            let mut msg = [0_u8; 7];
            if stream.read_exact(&mut msg).await.is_ok() {
                let mut echoed = b"echo:".to_vec();
                echoed.extend_from_slice(&msg);
                let _ = stream.write_all(&echoed).await;
                let _ = stream.flush().await;
            }
        }
    });

    let seq = next_test_seq();
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "miraserve-h1-parity-{}-{seq}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("hello.txt"), b"hello-http1-parity")?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "parity.example.test" {{
    root "{root}"
    route "/ws" {{
        reverse-proxy {{
            upstream "http://{up_addr}"
        }}
    }}
}}
"#,
        root = root.to_string_lossy().replace('\\', "/"),
    );
    let (cfg, _) = parse_kdl("h1-parity.kdl", &kdl)?;
    let engine = Arc::new(HttpEngine::from_config(
        &cfg,
        Arc::new(AcmeChallengeStore::new()),
        None,
        8443,
    )?);

    let peer: SocketAddr = "198.51.100.88:52000".parse()?;
    let local: SocketAddr = "127.0.0.1:8443".parse()?;

    // Subcase A: plain HTTP/1.1 keep-alive GET.
    {
        let (mut client, server) = tokio::io::duplex(32 * 1024);
        let (_shut_tx, shut_rx) = watch::channel(false);
        let srv = tokio::spawn(
            Arc::clone(&engine)
                .serve_hyper_connection(server, peer, local, true, false, None, shut_rx),
        );
        let req = concat!(
            "GET /hello.txt HTTP/1.1\r\n",
            "Host: parity.example.test\r\n",
            "Connection: close\r\n\r\n"
        );
        client.write_all(req.as_bytes()).await?;
        client.flush().await?;
        let mut resp = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut resp)).await??;
        let text = String::from_utf8_lossy(&resp);
        assert!(
            text.starts_with("HTTP/1.1 200 OK\r\n"),
            "unexpected H1 status: {text}"
        );
        assert!(
            text.ends_with("hello-http1-parity"),
            "unexpected H1 body: {text}"
        );
        let _ = tokio::time::timeout(Duration::from_secs(5), srv).await;
    }

    // Subcase B: HTTP/1.1 WebSocket 101 upgrade + bidirectional tunnel exchange.
    {
        let (mut client, server) = tokio::io::duplex(32 * 1024);
        let (_shut_tx, shut_rx) = watch::channel(false);
        let srv = tokio::spawn(
            Arc::clone(&engine)
                .serve_hyper_connection(server, peer, local, true, false, None, shut_rx),
        );
        let upgrade_req = concat!(
            "GET /ws HTTP/1.1\r\n",
            "Host: parity.example.test\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "Sec-WebSocket-Version: 13\r\n\r\n"
        );
        client.write_all(upgrade_req.as_bytes()).await?;
        client.flush().await?;

        let mut head = Vec::new();
        let mut tmp = [0_u8; 512];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut tmp)).await??;
            assert!(n > 0, "EOF before 101 Switching Protocols");
            if let Some(part) = tmp.get(..n) {
                head.extend_from_slice(part);
            }
            if head.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let head_str = String::from_utf8_lossy(&head);
        assert!(
            head_str.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
            "expected 101 Switching Protocols, got: {head_str}"
        );

        client.write_all(b"ping-ws").await?;
        client.flush().await?;
        let mut echoed = [0_u8; 12];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut echoed)).await??;
        assert_eq!(&echoed, b"echo:ping-ws");
        drop(client);
        let _ = tokio::time::timeout(Duration::from_secs(5), srv).await;
    }

    let _ = tokio::time::timeout(Duration::from_secs(5), up_task).await;
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

dual_runtime_test!(
    http1_request_and_websocket_upgrade_parity_smoke,
    http1_request_and_websocket_upgrade_parity_smoke_multi_thread,
    http1_request_and_websocket_upgrade_parity_smoke_impl
);

// ---------------------------------------------------------------------------
// 8. Mixed large + small responses on one connection under a slow reader,
//    concurrently with an unrelated fast connection and a stopped reader
// ---------------------------------------------------------------------------

struct PacedWriteIo<T> {
    inner: T,
    burst: usize,
    interval: Duration,
    stop_after: Option<usize>,
    written: usize,
    burst_left: usize,
    next_ready: Instant,
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
    bytes_written: Arc<AtomicUsize>,
    progress_notify: Arc<Notify>,
}

impl<T> PacedWriteIo<T> {
    fn new(
        inner: T,
        burst: usize,
        interval: Duration,
        stop_after: Option<usize>,
        bytes_written: Arc<AtomicUsize>,
        progress_notify: Arc<Notify>,
    ) -> Self {
        Self {
            inner,
            burst,
            interval,
            stop_after,
            written: 0,
            burst_left: burst,
            next_ready: Instant::now() + interval,
            timer: None,
            bytes_written,
            progress_notify,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for PacedWriteIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for PacedWriteIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(cap) = this.stop_after
            && this.written >= cap
        {
            // Stopped reader: stay pending until WriteGuardedIo cuts the connection.
            return Poll::Pending;
        }
        let now = Instant::now();
        if now >= this.next_ready {
            this.next_ready = now + this.interval;
            this.burst_left = this.burst;
            this.timer = None;
        }
        if this.burst_left > 0 {
            let mut limit = buf.len().min(this.burst_left);
            if let Some(cap) = this.stop_after {
                limit = limit.min(cap.saturating_sub(this.written));
            }
            if limit == 0 {
                return Poll::Pending;
            }
            let Some(slice) = buf.get(..limit) else {
                return Poll::Pending;
            };
            match Pin::new(&mut this.inner).poll_write(cx, slice) {
                Poll::Ready(Ok(n)) => {
                    this.burst_left = this.burst_left.saturating_sub(n);
                    this.written = this.written.saturating_add(n);
                    this.bytes_written.store(this.written, Ordering::Release);
                    this.progress_notify.notify_waiters();
                    return Poll::Ready(Ok(n));
                }
                other => return other,
            }
        }
        let mut sleep = Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(
            this.next_ready,
        )));
        let _ = sleep.as_mut().poll(cx);
        this.timer = Some(sleep);
        Poll::Pending
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[allow(clippy::too_many_lines)]
async fn mixed_large_and_small_under_slow_reader_with_unrelated_fast_connection_impl() -> TestResult
{
    const MIXED_TOTAL_PAYLOAD: usize = 65_536 * 2 + 1_024 * 6;
    let _ = global_access_capture();
    let seq = next_test_seq();
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "miraserve-h2-mixed-{}-{seq}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root)?;

    let large0 = Arc::new(stream_pattern(11, 65_536));
    let large1 = Arc::new(stream_pattern(13, 65_536));
    std::fs::write(root.join("large0.bin"), large0.as_slice())?;
    std::fs::write(root.join("large1.bin"), large1.as_slice())?;
    let mut smalls_vec = Vec::new();
    for i in 0_u32..6 {
        let data = stream_pattern(20 + i, 1_024);
        std::fs::write(root.join(format!("small{i}.txt")), &data)?;
        smalls_vec.push(data);
    }
    let smalls = Arc::new(smalls_vec);

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
    timeouts {{
        response-write-idle "400ms"
        min-response-rate-bps 4096
        graceful-drain "800ms"
        idle-keepalive "5s"
    }}
}}
site "mixed.example.test" {{
    root "{root}"
}}
"#,
        root = root.to_string_lossy().replace('\\', "/"),
    );
    let (cfg, _) = parse_kdl("h2-mixed.kdl", &kdl)?;
    let engine = Arc::new(HttpEngine::from_config(
        &cfg,
        Arc::new(AcmeChallengeStore::new()),
        None,
        8443,
    )?);

    let local: SocketAddr = "127.0.0.1:8443".parse()?;
    let (_shut_tx, shut_rx) = watch::channel(false);

    // Connection A: paced reader (4 KiB every 15 ms) carrying mixed 64 KiB and 1 KiB responses
    // concurrently under WriteGuardedIo.
    let a_bytes_written = Arc::new(AtomicUsize::new(0));
    let a_progress_notify = Arc::new(Notify::new());
    let (client_a, server_a) = tokio::io::duplex(256 * 1024);
    let guarded_a = WriteGuardedIo::new(
        PacedWriteIo::new(
            server_a,
            4_096,
            Duration::from_millis(15),
            None,
            Arc::clone(&a_bytes_written),
            Arc::clone(&a_progress_notify),
        ),
        Duration::from_millis(400),
        4_096,
    )
    .with_send_buffer_probe(Box::new(|_: &PacedWriteIo<tokio::io::DuplexStream>| {
        Some(16_384)
    }));
    let srv_a = tokio::spawn(Arc::clone(&engine).serve_hyper_connection(
        guarded_a,
        "198.51.100.11:51001".parse()?,
        local,
        true,
        false,
        None,
        shut_rx.clone(),
    ));

    // Connection B: unrelated fast HTTP/2 connection to the same HttpEngine.
    let (client_b, server_b) = tokio::io::duplex(256 * 1024);
    let srv_b = tokio::spawn(Arc::clone(&engine).serve_hyper_connection(
        server_b,
        "198.51.100.12:51002".parse()?,
        local,
        true,
        false,
        None,
        shut_rx.clone(),
    ));

    // Connection C: stopped reader cut by WriteGuardedIo while A & B remain unaffected.
    let c_bytes_written = Arc::new(AtomicUsize::new(0));
    let c_progress_notify = Arc::new(Notify::new());
    let (client_c, server_c) = tokio::io::duplex(256 * 1024);
    let guarded_c = WriteGuardedIo::new(
        PacedWriteIo::new(
            server_c,
            1_024,
            Duration::from_millis(5),
            Some(1_024),
            c_bytes_written,
            c_progress_notify,
        ),
        Duration::from_millis(200),
        32_768,
    )
    .with_rate_grace(Duration::from_millis(50))
    .with_send_buffer_probe(Box::new(|_: &PacedWriteIo<tokio::io::DuplexStream>| {
        Some(8_192)
    }));
    let srv_c = tokio::spawn(Arc::clone(&engine).serve_hyper_connection(
        guarded_c,
        "198.51.100.13:51003".parse()?,
        local,
        true,
        false,
        None,
        shut_rx,
    ));

    let make_client = |stream: tokio::io::DuplexStream| async move {
        let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
        builder
            .initial_stream_window_size(256 * 1024)
            .initial_connection_window_size(4 * 1024 * 1024);
        let (sender, conn) = builder
            .handshake::<_, http_body_util::Empty<Bytes>>(TokioIo::new(stream))
            .await?;
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok::<_, Box<dyn std::error::Error>>((sender, driver))
    };

    let (mut sender_a, driver_a) = make_client(client_a).await?;
    let (mut sender_b, driver_b) = make_client(client_b).await?;
    let (mut sender_c, driver_c) = make_client(client_c).await?;

    let mk_req = |path: &str| {
        Request::builder()
            .uri(format!("https://mixed.example.test{path}"))
            .body(http_body_util::Empty::<Bytes>::new())
    };

    // Start mixed large + small burst on slow Connection A (134 KiB payload total)
    // and collect it concurrently in a background task so we can observe overlap with B.
    let slow_started = Instant::now();
    let mut a_futs = Vec::new();
    for path in [
        "/large0.bin",
        "/small0.txt",
        "/small1.txt",
        "/small2.txt",
        "/large1.bin",
        "/small3.txt",
        "/small4.txt",
        "/small5.txt",
    ] {
        let req = mk_req(path)?;
        a_futs.push((path.to_owned(), sender_a.send_request(req)));
    }
    let a_finished = Arc::new(AtomicBool::new(false));
    let a_finished_task = Arc::clone(&a_finished);
    let large0_a = Arc::clone(&large0);
    let large1_a = Arc::clone(&large1);
    let smalls_a = Arc::clone(&smalls);
    let a_collector = tokio::spawn(async move {
        for (path, fut) in a_futs {
            let resp = tokio::time::timeout(Duration::from_secs(10), fut)
                .await
                .map_err(|_| format!("Connection A response timeout for {path}"))?
                .map_err(|e| format!("Connection A response error for {path}: {e}"))?;
            if resp.status() != StatusCode::OK {
                return Err(format!("Connection A status {} for {path}", resp.status()));
            }
            let body = tokio::time::timeout(Duration::from_secs(10), resp.into_body().collect())
                .await
                .map_err(|_| format!("Connection A body timeout for {path}"))?
                .map_err(|e| format!("Connection A body error for {path}: {e}"))?
                .to_bytes();
            let expected = match path.as_str() {
                "/large0.bin" => large0_a.as_slice(),
                "/large1.bin" => large1_a.as_slice(),
                p => {
                    let idx: usize = p
                        .trim_start_matches("/small")
                        .trim_end_matches(".txt")
                        .parse()
                        .map_err(|e| format!("bad path {p}: {e}"))?;
                    smalls_a
                        .get(idx)
                        .map(Vec::as_slice)
                        .ok_or_else(|| "missing small fixture".to_owned())?
                }
            };
            if body.as_ref() != expected {
                return Err(format!("slow Connection A mismatch for {path}"));
            }
        }
        a_finished_task.store(true, Ordering::Release);
        Ok::<(), String>(())
    });

    // Wait until Connection A is in flight (has written at least 4 KiB while remaining below
    // `MIXED_TOTAL_PAYLOAD`, 134 KiB).
    let a_start_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while a_bytes_written.load(Ordering::Acquire) < 4_096 {
        let notified = a_progress_notify.notified();
        if a_bytes_written.load(Ordering::Acquire) >= 4_096 {
            break;
        }
        let now = tokio::time::Instant::now();
        assert!(
            now < a_start_deadline,
            "timed out waiting for paced Connection A to enter flight"
        );
        let _ = tokio::time::timeout(a_start_deadline - now, notified).await;
    }
    let a_written_at_b_start = a_bytes_written.load(Ordering::Acquire);
    assert!(
        (4_096..MIXED_TOTAL_PAYLOAD).contains(&a_written_at_b_start),
        "Connection A must already be in flight and incomplete when Connection B starts (written={a_written_at_b_start})"
    );

    // Start stopped reader on Connection C simultaneously.
    let c_req = sender_c.send_request(mk_req("/large0.bin")?);

    // While Connection A is actively backpressured in flight, run a full mixed burst on unrelated
    // Connection B and assert B completes BEFORE Connection A finishes.
    let fast_started = Instant::now();
    let mut b_futs = Vec::new();
    for path in [
        "/small0.txt",
        "/large0.bin",
        "/small1.txt",
        "/small2.txt",
        "/small3.txt",
        "/small4.txt",
        "/small5.txt",
        "/large1.bin",
    ] {
        b_futs.push((path.to_owned(), sender_b.send_request(mk_req(path)?)));
    }
    for (path, fut) in b_futs {
        let resp = tokio::time::timeout(Duration::from_secs(2), fut).await??;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = tokio::time::timeout(Duration::from_secs(2), resp.into_body().collect())
            .await??
            .to_bytes();
        let expected = match path.as_str() {
            "/large0.bin" => large0.as_slice(),
            "/large1.bin" => large1.as_slice(),
            p => {
                let idx: usize = p
                    .trim_start_matches("/small")
                    .trim_end_matches(".txt")
                    .parse()?;
                smalls
                    .get(idx)
                    .map(Vec::as_slice)
                    .ok_or("missing small fixture")?
            }
        };
        assert_eq!(body.as_ref(), expected, "Connection B mismatch for {path}");
    }
    let fast_elapsed = fast_started.elapsed();
    let a_written_at_b_end = a_bytes_written.load(Ordering::Acquire);
    let a_done_at_b_end = a_finished.load(Ordering::Acquire);
    assert!(
        !a_done_at_b_end && a_written_at_b_end < MIXED_TOTAL_PAYLOAD,
        "simultaneous progress violated: unrelated fast Connection B finished in {fast_elapsed:?}, \
         but paced Connection A was no longer in flight (a_done={a_done_at_b_end}, a_written={a_written_at_b_end}/{MIXED_TOTAL_PAYLOAD})"
    );
    assert!(
        fast_elapsed < Duration::from_secs(2),
        "unrelated fast Connection B must finish promptly while Connection A is backpressured (took {fast_elapsed:?})"
    );

    // Now verify all 8 mixed large + small responses on slow steady Connection A finish intact.
    tokio::time::timeout(Duration::from_secs(10), a_collector)
        .await
        .map_err(|_| "slow Connection A collector task timed out")??
        .map_err(|msg| -> Box<dyn std::error::Error> { msg.into() })?;
    assert!(
        a_finished.load(Ordering::Acquire),
        "Connection A collector must have marked completion"
    );
    assert!(
        slow_started.elapsed() >= Duration::from_millis(250),
        "Connection A must actually experience sustained write backpressure (finished in {:?})",
        slow_started.elapsed()
    );

    // Stopped Connection C must be cut promptly by WriteGuardedIo without disturbing B.
    let c_body_outcome = tokio::time::timeout(Duration::from_secs(4), async {
        match c_req.await {
            Ok(resp) => resp.into_body().collect().await.map(|c| c.to_bytes().len()),
            Err(err) => Err(err),
        }
    })
    .await
    .map_err(|_| "stopped Connection C hung instead of being cut by WriteGuardedIo")?;
    assert!(
        c_body_outcome.is_err() || c_body_outcome.is_ok_and(|len| len < large0.len()),
        "stopped Connection C must fail or end short"
    );
    tokio::time::timeout(Duration::from_secs(4), srv_c)
        .await
        .map_err(|_| "stopped Connection C server task did not exit")??;

    // Unrelated Connection B remains healthy after Connection C was cut.
    let follow_resp = tokio::time::timeout(
        Duration::from_secs(2),
        sender_b.send_request(mk_req("/small0.txt")?),
    )
    .await??;
    assert_eq!(follow_resp.status(), StatusCode::OK);
    let follow_body = follow_resp.into_body().collect().await?.to_bytes();
    assert_eq!(
        follow_body.as_ref(),
        smalls.first().map_or(&[][..], Vec::as_slice)
    );

    drop(sender_a);
    drop(sender_b);
    drop(sender_c);
    let _ = tokio::time::timeout(Duration::from_secs(5), driver_a).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), driver_b).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), driver_c).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), srv_a).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), srv_b).await;
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

dual_runtime_test!(
    mixed_large_and_small_under_slow_reader_with_unrelated_fast_connection,
    mixed_large_and_small_under_slow_reader_with_unrelated_fast_connection_multi_thread,
    mixed_large_and_small_under_slow_reader_with_unrelated_fast_connection_impl
);

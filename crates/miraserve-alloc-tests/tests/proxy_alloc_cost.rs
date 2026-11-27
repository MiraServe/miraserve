//! Dev-only end-to-end allocation-cost measuring harness and regression test.
//!
//! Installs a counting `#[global_allocator]` wrapping [`std::alloc::System`] and drives the real
//! [`MiraServeServer`] end-to-end over loopback (real KDL config, real `CompiledRouter`, real
//! `ReverseProxy`, real static file server, and a real persistent HTTP/1.1 keep-alive upstream).
//!
//! Exactness of server-only attribution:
//! - A `const`-initialized thread-local `EXCLUDE_THREAD: Cell<bool>` (zero heap allocation, zero
//!   destructor, single TLS load) marks the main test thread, the client Tokio runtime thread(s),
//!   and the upstream Tokio runtime thread(s) as excluded.
//! - The server runs on its own dedicated Tokio runtime (and, in Linux worker mode, its own
//!   `miraserve-loop-*` OS threads and per-worker blocking pools), none of which set
//!   `EXCLUDE_THREAD`, so every allocation made on any serving thread is counted and zero client
//!   or upstream allocations are included.
//! - Each scenario warms up first (`WARMUP_REQS = 256` requests), then measures two run lengths
//!   (`SHORT_REQS = 100` and `LONG_REQS = 500`) on the same already-warmed connection(s), waiting
//!   after each window until `TelemetryRegistry` confirms all requests finished
//!   `AccessLogBody::drop` / socket flush. Taking `(long - short) / (LONG_REQS - SHORT_REQS)`
//!   cancels out any residual setup or constant per-window noise.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::fs;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::{
    ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG, HOST, IF_NONE_MATCH,
    LOCATION,
};
use http::{HeaderValue, Method, Request, StatusCode};
use http_body_util::{BodyExt as _, Empty, Full};
use hyper::client::conn::{http1 as h1_client, http2 as h2_client};
use hyper_util::rt::{TokioExecutor, TokioIo};
use miraserve_config::{ConfigStore, parse_kdl};
use miraserve_core::{CoreError, ListenerKind, MiraServeServer, RunningServer, ServerOptions};
use miraserve_telemetry::TelemetryRegistry;
use miraserve_tls::build_crypto_provider;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct CountingAllocator;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

static COUNTING_ACTIVE: AtomicBool = AtomicBool::new(false);
static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
static REALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static REALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static PROFILING: AtomicBool = AtomicBool::new(false);
static PROFILE: std::sync::Mutex<Option<std::collections::HashMap<String, (u64, u64)>>> =
    std::sync::Mutex::new(None);

thread_local! {
    /// Set to `true` on client, upstream, and test-driver threads so only serving threads
    /// (shared server runtime, server blocking pool, and Linux `miraserve-loop-*` worker threads)
    /// are attributed to the per-request allocation counts.
    static EXCLUDE_THREAD: Cell<bool> = const { Cell::new(false) };
    /// Reentrancy guard set while the call-site profiler captures and records a backtrace so the
    /// profiler's own allocations are neither counted nor profiled.
    static IN_HOOK: Cell<bool> = const { Cell::new(false) };
}

struct InHookGuard;

impl InHookGuard {
    #[inline]
    fn try_enter() -> Option<Self> {
        let already = IN_HOOK.try_with(|c| c.replace(true)).unwrap_or(true);
        if already { None } else { Some(Self) }
    }
}

impl Drop for InHookGuard {
    #[inline]
    fn drop(&mut self) {
        let _ = IN_HOOK.try_with(|c| c.set(false));
    }
}

const KNOWN_ROWS: &[&str] = &[
    "proxy_get_h1_shared",
    "proxy_get_h2_shared",
    "proxy_post_4k_h1_shared",
    "static_1k_h1_shared",
    "static_1k_h2_shared",
    "static_1k_h1_browser_shared",
    "static_304_h1_shared",
    "redirect_h1_shared",
    "proxy_get_h1_browser_shared",
    #[cfg(target_os = "linux")]
    "proxy_get_h1_workers2",
    #[cfg(target_os = "linux")]
    "proxy_get_h2_workers2",
];

#[derive(Debug, PartialEq, Eq)]
enum ProfileFilter {
    None,
    All,
    Selected(Vec<String>),
}

impl ProfileFilter {
    fn matches(&self, label: &str) -> bool {
        match self {
            Self::None => false,
            Self::All => true,
            Self::Selected(items) => items.iter().any(|item| item == label),
        }
    }
}

fn parse_alloc_profile_filter(
    raw: Option<&str>,
    valid_rows: &[&str],
) -> Result<ProfileFilter, String> {
    let Some(val) = raw else {
        return Ok(ProfileFilter::None);
    };
    let trimmed = val.trim();
    if trimmed.is_empty() {
        return Ok(ProfileFilter::None);
    }
    let mut all = false;
    let mut selected = Vec::new();
    for part in trimmed.split(',') {
        let token = part.trim();
        if token.is_empty() {
            return Err(format!(
                "empty row name in ALLOC_PROFILE={val:?}; valid rows: {valid_rows:?} (or \"all\")"
            ));
        }
        if token == "all" {
            all = true;
            continue;
        }
        if !valid_rows.contains(&token) {
            return Err(format!(
                "unknown row name {token:?} in ALLOC_PROFILE={val:?}; valid rows: {valid_rows:?} (or \"all\")"
            ));
        }
        if !selected.iter().any(|existing| existing == token) {
            selected.push(token.to_owned());
        }
    }
    if all {
        Ok(ProfileFilter::All)
    } else {
        Ok(ProfileFilter::Selected(selected))
    }
}

fn profile_hit(kind: &str, size: usize) {
    let Some(_guard) = InHookGuard::try_enter() else {
        return;
    };
    let bt = std::backtrace::Backtrace::force_capture().to_string();
    let mut frames: Vec<&str> = Vec::new();
    for line in bt.lines() {
        let l = line.trim_start();
        if l.starts_with("at ") {
            continue;
        }
        let name = l.split_once(": ").map_or(l, |(_, n)| n);
        if name.contains("proxy_alloc_cost::")
            || name.contains("backtrace")
            || name.starts_with("__rust")
            || name.starts_with("__rustc")
            || name.starts_with("alloc::alloc")
            || name.contains("GlobalAlloc")
            || name.starts_with("alloc::")
            || name.starts_with("<alloc::")
            || name.starts_with("hashbrown::")
            || name.starts_with("core::ptr")
            || name.starts_with("core::mem")
            || name.starts_with("std::collections")
            || name.starts_with("core::ops::function")
        {
            continue;
        }
        frames.push(name);
        if frames.len() >= 9 {
            break;
        }
    }
    let key = format!("{kind} {size}\n    {}", frames.join("\n    "));
    if let Ok(mut guard) = PROFILE.lock() {
        let entry = guard
            .get_or_insert_with(std::collections::HashMap::new)
            .entry(key)
            .or_insert((0, 0));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = entry.1.saturating_add(size as u64);
    }
}

#[allow(clippy::cast_precision_loss)]
fn profile_dump(label: &str, n: usize) {
    let Ok(mut guard) = PROFILE.lock() else {
        return;
    };
    let Some(map) = guard.take() else {
        return;
    };
    let mut rows: Vec<_> = map.into_iter().collect();
    rows.sort_by(|a, b| b.1.0.cmp(&a.1.0).then(b.1.1.cmp(&a.1.1)));
    println!("ALLOC_PROFILE {label} over {n} requests");
    let denom = n.max(1) as f64;
    for (site, (count, bytes)) in rows {
        let per_req = count as f64 / denom;
        if per_req < 0.2 {
            continue;
        }
        println!(
            "== {:.2}/req {:.0} B/req  {site}",
            per_req,
            bytes as f64 / denom
        );
    }
}

/// Returns `(should_count, should_profile)` for the current allocation. When `PROFILING` is
/// `false` (all normal runs and measurement windows), avoids touching `IN_HOOK` TLS completely.
#[inline]
fn should_count_and_profile() -> (bool, bool) {
    if !COUNTING_ACTIVE.load(Ordering::Relaxed)
        || EXCLUDE_THREAD.try_with(Cell::get).unwrap_or(false)
    {
        return (false, false);
    }
    if PROFILING.load(Ordering::Relaxed) {
        if IN_HOOK.try_with(Cell::get).unwrap_or(true) {
            return (false, false);
        }
        (true, true)
    } else {
        (true, false)
    }
}

#[allow(unsafe_code)]
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: Delegates directly to the system allocator with the caller's layout.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let (count, profile) = should_count_and_profile();
            if count {
                ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
                ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
                if profile {
                    profile_hit("alloc", layout.size());
                }
            }
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: Delegates directly to the system allocator with the caller's layout.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            let (count, profile) = should_count_and_profile();
            if count {
                ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
                ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
                if profile {
                    profile_hit("zeroed", layout.size());
                }
            }
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: Delegates directly to the system allocator with the caller's pointer and layout.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: Delegates directly to the system allocator with the caller's arguments.
        let next = unsafe { System.realloc(ptr, layout, new_size) };
        if !next.is_null() {
            let (count, profile) = should_count_and_profile();
            if count {
                REALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
                REALLOC_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
                if profile {
                    profile_hit("realloc", new_size);
                }
            }
        }
        next
    }
}

struct ExcludeThreadGuard {
    prev: bool,
}

impl ExcludeThreadGuard {
    fn enter() -> Self {
        let prev = EXCLUDE_THREAD.with(|slot| slot.replace(true));
        Self { prev }
    }
}

impl Drop for ExcludeThreadGuard {
    fn drop(&mut self) {
        EXCLUDE_THREAD.with(|slot| slot.set(self.prev));
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct AllocSnapshot {
    allocs: u64,
    reallocs: u64,
    alloc_bytes: u64,
    realloc_bytes: u64,
}

impl AllocSnapshot {
    fn reset_and_start() {
        ALLOC_COUNT.store(0, Ordering::SeqCst);
        REALLOC_COUNT.store(0, Ordering::SeqCst);
        ALLOC_BYTES.store(0, Ordering::SeqCst);
        REALLOC_BYTES.store(0, Ordering::SeqCst);
        COUNTING_ACTIVE.store(true, Ordering::SeqCst);
    }

    fn stop_and_read() -> Self {
        COUNTING_ACTIVE.store(false, Ordering::SeqCst);
        Self {
            allocs: ALLOC_COUNT.load(Ordering::SeqCst),
            reallocs: REALLOC_COUNT.load(Ordering::SeqCst),
            alloc_bytes: ALLOC_BYTES.load(Ordering::SeqCst),
            realloc_bytes: REALLOC_BYTES.load(Ordering::SeqCst),
        }
    }

    const fn total_ops(self) -> u64 {
        self.allocs.saturating_add(self.reallocs)
    }

    const fn total_bytes(self) -> u64 {
        self.alloc_bytes.saturating_add(self.realloc_bytes)
    }
}

#[derive(Debug, Clone, Copy)]
struct RowMetrics {
    label: &'static str,
    short_n: u64,
    long_n: u64,
    short: AllocSnapshot,
    long: AllocSnapshot,
}

impl RowMetrics {
    fn delta_n(self) -> u64 {
        self.long_n.saturating_sub(self.short_n).max(1)
    }

    #[allow(clippy::cast_precision_loss)]
    fn allocs_per_req(self) -> f64 {
        self.long.allocs.saturating_sub(self.short.allocs) as f64 / self.delta_n() as f64
    }

    #[allow(clippy::cast_precision_loss)]
    fn reallocs_per_req(self) -> f64 {
        self.long.reallocs.saturating_sub(self.short.reallocs) as f64 / self.delta_n() as f64
    }

    #[allow(clippy::cast_precision_loss)]
    fn ops_per_req(self) -> f64 {
        self.long.total_ops().saturating_sub(self.short.total_ops()) as f64 / self.delta_n() as f64
    }

    #[allow(clippy::cast_precision_loss)]
    fn bytes_per_req(self) -> f64 {
        self.long
            .total_bytes()
            .saturating_sub(self.short.total_bytes()) as f64
            / self.delta_n() as f64
    }

    #[allow(clippy::cast_precision_loss)]
    fn short_ops_per_req(self) -> f64 {
        self.short.total_ops() as f64 / self.short_n.max(1) as f64
    }

    #[allow(clippy::cast_precision_loss)]
    fn long_ops_per_req(self) -> f64 {
        self.long.total_ops() as f64 / self.long_n.max(1) as f64
    }
}

const WARMUP_REQS: usize = 256;
const SHORT_REQS: usize = 100;
const LONG_REQS: usize = 500;
const H2_BATCH_STREAMS: usize = 10;
const POST_BODY_LEN: usize = 4096;
const UPSTREAM_RESP_LEN: usize = 2048;

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
            "miraserve-alloc-cost-{tag}-{}-{}-{nanos}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed),
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

fn reserve_free_listen_addr() -> Result<SocketAddr, std::io::Error> {
    #[cfg(target_os = "linux")]
    {
        // Bijective per-PID loopback IP in `127.1..=254.0..=255.1..=254` prevents `SO_REUSEPORT`
        // listener collisions across 40 simultaneous parallel test processes on Linux.
        let pid = std::process::id();
        let d = u8::try_from((pid % 254) + 1).unwrap_or(1);
        let c = u8::try_from((pid / 254) % 256).unwrap_or(0);
        let b = u8::try_from(((pid / (254 * 256)) % 254) + 1).unwrap_or(1);
        let ip = std::net::Ipv4Addr::new(127, b, c, d);
        if let Ok(sock) = StdTcpListener::bind((ip, 0)) {
            return sock.local_addr();
        }
    }
    let sock = StdTcpListener::bind("127.0.0.1:0")?;
    sock.local_addr()
}

/// Real persistent HTTP/1.1 keep-alive upstream running on its own excluded OS thread and
/// `current_thread` Tokio runtime so zero upstream allocations are counted.
struct ExcludedUpstream {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ExcludedUpstream {
    #[allow(clippy::too_many_lines)]
    fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let std_listener = StdTcpListener::bind("127.0.0.1:0")?;
        std_listener.set_nonblocking(true)?;
        let addr = std_listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_c = Arc::clone(&stop);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let thread = std::thread::Builder::new()
            .name("alloc-cost-upstream".to_owned())
            .spawn(move || {
                let _exclude = ExcludeThreadGuard::enter();
                let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                rt.block_on(async move {
                    let Ok(listener) = TcpListener::from_std(std_listener) else {
                        return;
                    };
                    let mut get_resp = Vec::with_capacity(128 + UPSTREAM_RESP_LEN);
                    get_resp.extend_from_slice(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {UPSTREAM_RESP_LEN}\r\nConnection: keep-alive\r\n\r\n"
                        )
                        .as_bytes(),
                    );
                    get_resp.resize(get_resp.len() + UPSTREAM_RESP_LEN, b'A');
                    let get_resp: Arc<[u8]> = Arc::from(get_resp);
                    let post_resp: Arc<[u8]> = Arc::from(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok"
                            .as_slice(),
                    );

                    tokio::pin!(shutdown_rx);
                    loop {
                        let accepted = tokio::select! {
                            _ = &mut shutdown_rx => break,
                            res = listener.accept() => res,
                        };
                        let Ok((mut sock, _)) = accepted else {
                            break;
                        };
                        let _ = sock.set_nodelay(true);
                        let get_resp_c = Arc::clone(&get_resp);
                        let post_resp_c = Arc::clone(&post_resp);
                        let stop_inner = Arc::clone(&stop_c);
                        tokio::spawn(async move {
                            let mut buf = Vec::with_capacity(8192);
                            let mut tmp = [0_u8; 8192];
                            while !stop_inner.load(Ordering::Relaxed) {
                                let head_end = loop {
                                    if let Some(pos) = find_header_end(&buf) {
                                        break Some(pos);
                                    }
                                    let Ok(n) = sock.read(&mut tmp).await else {
                                        break None;
                                    };
                                    if n == 0 {
                                        break None;
                                    }
                                    if let Some(slice) = tmp.get(..n) {
                                        buf.extend_from_slice(slice);
                                    }
                                    if buf.len() > 128 * 1024 {
                                        break None;
                                    }
                                };
                                let Some(end) = head_end else {
                                    break;
                                };
                                let is_post = buf.starts_with(b"POST ");
                                let content_len =
                                    parse_content_length(buf.get(..end).unwrap_or(&[]));
                                let total_needed = end.saturating_add(content_len);
                                while buf.len() < total_needed {
                                    let Ok(n) = sock.read(&mut tmp).await else {
                                        return;
                                    };
                                    if n == 0 {
                                        return;
                                    }
                                    if let Some(slice) = tmp.get(..n) {
                                        buf.extend_from_slice(slice);
                                    }
                                }
                                buf.drain(..total_needed);
                                let reply = if is_post {
                                    &post_resp_c[..]
                                } else {
                                    &get_resp_c[..]
                                };
                                if sock.write_all(reply).await.is_err() {
                                    break;
                                }
                            }
                        });
                    }
                });
            })?;

        Ok(Self {
            addr,
            stop,
            shutdown_tx: Some(shutdown_tx),
            thread: Some(thread),
        })
    }
}

impl Drop for ExcludedUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

fn parse_content_length(head: &[u8]) -> usize {
    let Ok(text) = std::str::from_utf8(head) else {
        return 0;
    };
    for line in text.split("\r\n").skip(1) {
        if let Some((name, val)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
            && let Ok(n) = val.trim().parse::<usize>()
        {
            return n;
        }
    }
    0
}

fn total_recorded_requests(telemetry: &TelemetryRegistry) -> u64 {
    let text = telemetry.render_prometheus();
    let mut total = 0_u64;
    for line in text.lines() {
        if line.starts_with("miraserve_http_requests_total{")
            && let Some(val_str) = line.split_whitespace().last()
            && let Ok(v) = val_str.parse::<u64>()
        {
            total = total.saturating_add(v);
        }
    }
    total
}

async fn wait_for_recorded_requests(telemetry: &TelemetryRegistry, expected: u64) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(5);
    while total_recorded_requests(telemetry) < expected {
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for telemetry requests: got {}, expected {expected}",
                total_recorded_requests(telemetry)
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    Ok(())
}

fn build_tls_client_config(
    server: &RunningServer,
    alpn: &[u8],
) -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
    let cert_pem = server.dev_cert_pem().ok_or("expected dev cert PEM")?;
    let mut roots = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<_, _>>()?;
    roots.add_parsable_certificates(certs);

    let mut cfg = ClientConfig::builder_with_provider(build_crypto_provider(true))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![alpn.to_vec()];
    Ok(Arc::new(cfg))
}

/// Encodes an arbitrary string (such as a Windows temporary path `C:\Users\...`) as a quoted KDL
/// string literal so backslashes, quotes, and control characters always parse cleanly.
fn encode_kdl_string(s: &str) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn start_server_on_runtime(
    server_rt: &tokio::runtime::Runtime,
    docroot: &std::path::Path,
    upstream_addr: SocketAddr,
    workers_line: &str,
) -> Result<(RunningServer, SocketAddr), Box<dyn std::error::Error>> {
    let docroot_kdl = encode_kdl_string(&docroot.to_string_lossy());
    server_rt.block_on(async move {
        for attempt in 0..16_usize {
            let listen_addr = reserve_free_listen_addr()?;
            let kdl = format!(
                r#"
                server {{
                    {workers_line}
                    listen "{listen_addr}" protocols="h1,h2"
                    timeouts {{
                        idle-keepalive "60s"
                        header-read "10s"
                    }}
                }}
                site "bench.test" {{
                    root {docroot_kdl}
                    route "/old" {{
                        redirect "https://bench.test/hello.txt" status=301
                    }}
                    route "/api/*" {{
                        reverse-proxy {{
                            upstream "http://{upstream_addr}"
                        }}
                    }}
                }}
                "#
            );
            let (cfg, _) = parse_kdl("<alloc-cost>", &kdl)?;
            match MiraServeServer::start(
                Arc::new(ConfigStore::new(cfg)),
                ServerOptions {
                    dev_tls: true,
                    ..ServerOptions::default()
                },
            )
            .await
            {
                Ok(srv) => {
                    let bound = srv
                        .bound_listeners()
                        .iter()
                        .find(|b| b.kind == ListenerKind::HttpsTcp)
                        .ok_or("missing HttpsTcp listener")?
                        .local_addr;
                    return Ok((srv, bound));
                }
                Err(CoreError::Bind { source, .. })
                    if source.kind() == std::io::ErrorKind::AddrInUse && attempt + 1 < 16 => {}
                Err(err) => return Err(err.into()),
            }
        }
        Err("could not bind ephemeral test port after 16 attempts".into())
    })
}

async fn connect_h1_get(
    addr: SocketAddr,
    tls_cfg: &Arc<ClientConfig>,
) -> Result<
    (
        h1_client::SendRequest<Empty<Bytes>>,
        tokio::task::JoinHandle<Result<(), hyper::Error>>,
    ),
    Box<dyn std::error::Error>,
> {
    let tcp = TcpStream::connect(addr).await?;
    let _ = tcp.set_nodelay(true);
    let tls = TlsConnector::from(Arc::clone(tls_cfg))
        .connect(ServerName::try_from("bench.test".to_owned())?, tcp)
        .await?;
    let (sender, conn) = h1_client::handshake(TokioIo::new(tls)).await?;
    let task = tokio::spawn(conn);
    Ok((sender, task))
}

async fn connect_h1_post(
    addr: SocketAddr,
    tls_cfg: &Arc<ClientConfig>,
) -> Result<
    (
        h1_client::SendRequest<Full<Bytes>>,
        tokio::task::JoinHandle<Result<(), hyper::Error>>,
    ),
    Box<dyn std::error::Error>,
> {
    let tcp = TcpStream::connect(addr).await?;
    let _ = tcp.set_nodelay(true);
    let tls = TlsConnector::from(Arc::clone(tls_cfg))
        .connect(ServerName::try_from("bench.test".to_owned())?, tcp)
        .await?;
    let (sender, conn) = h1_client::handshake(TokioIo::new(tls)).await?;
    let task = tokio::spawn(conn);
    Ok((sender, task))
}

async fn connect_h2_get(
    addr: SocketAddr,
    tls_cfg: &Arc<ClientConfig>,
) -> Result<
    (
        h2_client::SendRequest<Empty<Bytes>>,
        tokio::task::JoinHandle<Result<(), hyper::Error>>,
    ),
    Box<dyn std::error::Error>,
> {
    let tcp = TcpStream::connect(addr).await?;
    let _ = tcp.set_nodelay(true);
    let tls = TlsConnector::from(Arc::clone(tls_cfg))
        .connect(ServerName::try_from("bench.test".to_owned())?, tcp)
        .await?;
    let (sender, conn) = h2_client::Builder::new(TokioExecutor::new())
        .handshake(TokioIo::new(tls))
        .await?;
    let task = tokio::spawn(conn);
    Ok((sender, task))
}

/// Realistic browser request headers (11 headers + `Host` = 12 total request headers).
const BROWSER_EXTRA_HEADERS: [(&str, &str); 11] = [
    (
        "user-agent",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    ),
    (
        "accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    ),
    ("accept-language", "en-US,en;q=0.9"),
    ("accept-encoding", "gzip, deflate, br"),
    ("referer", "https://bench.test/index.html"),
    ("cache-control", "max-age=0"),
    (
        "sec-ch-ua",
        "\"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
    ),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", "\"macOS\""),
    ("sec-fetch-dest", "document"),
    ("sec-fetch-mode", "navigate"),
];

async fn run_h1_get_batch(
    sender: &mut h1_client::SendRequest<Empty<Bytes>>,
    path: &'static str,
    send_gzip_ae: bool,
    expected_len: usize,
    count: usize,
) -> TestResult {
    for _ in 0..count {
        sender.ready().await?;
        let mut builder = Request::builder()
            .method(Method::GET)
            .uri(path)
            .header(HOST, "bench.test");
        if send_gzip_ae {
            builder = builder.header(ACCEPT_ENCODING, "gzip");
        }
        let resp = sender
            .send_request(builder.body(Empty::<Bytes>::new())?)
            .await?;
        assert_eq!(resp.status(), StatusCode::OK, "GET {path} failed");
        let body = resp.into_body().collect().await?.to_bytes();
        assert_eq!(body.len(), expected_len, "unexpected body len for {path}");
    }
    Ok(())
}

async fn run_h1_browser_get_batch(
    sender: &mut h1_client::SendRequest<Empty<Bytes>>,
    path: &'static str,
    expected_len: Option<usize>,
    expected_encoding: Option<&'static str>,
    count: usize,
) -> TestResult {
    for _ in 0..count {
        sender.ready().await?;
        let mut builder = Request::builder()
            .method(Method::GET)
            .uri(path)
            .header(HOST, "bench.test");
        for &(name, val) in &BROWSER_EXTRA_HEADERS {
            builder = builder.header(name, val);
        }
        let resp = sender
            .send_request(builder.body(Empty::<Bytes>::new())?)
            .await?;
        assert_eq!(resp.status(), StatusCode::OK, "browser GET {path} failed");
        if let Some(enc) = expected_encoding {
            assert_eq!(
                resp.headers().get(CONTENT_ENCODING),
                Some(&HeaderValue::from_static(enc)),
                "unexpected Content-Encoding for {path}"
            );
        }
        let body = resp.into_body().collect().await?.to_bytes();
        if let Some(len) = expected_len {
            assert_eq!(body.len(), len, "unexpected body len for {path}");
        } else {
            assert!(!body.is_empty(), "expected non-empty body for {path}");
        }
    }
    Ok(())
}

async fn run_h1_304_batch(
    sender: &mut h1_client::SendRequest<Empty<Bytes>>,
    path: &'static str,
    etag: &HeaderValue,
    count: usize,
) -> TestResult {
    for _ in 0..count {
        sender.ready().await?;
        let req = Request::builder()
            .method(Method::GET)
            .uri(path)
            .header(HOST, "bench.test")
            .header(IF_NONE_MATCH, etag.clone())
            .body(Empty::<Bytes>::new())?;
        let resp = sender.send_request(req).await?;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_MODIFIED,
            "304 GET {path} failed"
        );
        let body = resp.into_body().collect().await?.to_bytes();
        assert!(body.is_empty(), "expected empty body for 304 {path}");
    }
    Ok(())
}

async fn run_h1_redirect_batch(
    sender: &mut h1_client::SendRequest<Empty<Bytes>>,
    path: &'static str,
    expected_location: &'static str,
    count: usize,
) -> TestResult {
    let expected = HeaderValue::from_static(expected_location);
    for _ in 0..count {
        sender.ready().await?;
        let req = Request::builder()
            .method(Method::GET)
            .uri(path)
            .header(HOST, "bench.test")
            .body(Empty::<Bytes>::new())?;
        let resp = sender.send_request(req).await?;
        assert_eq!(
            resp.status(),
            StatusCode::MOVED_PERMANENTLY,
            "redirect GET {path} failed"
        );
        assert_eq!(resp.headers().get(LOCATION), Some(&expected));
        let body = resp.into_body().collect().await?.to_bytes();
        assert!(body.is_empty(), "expected empty body for redirect {path}");
    }
    Ok(())
}

async fn run_h1_post_batch(
    sender: &mut h1_client::SendRequest<Full<Bytes>>,
    payload: &Bytes,
    count: usize,
) -> TestResult {
    for _ in 0..count {
        sender.ready().await?;
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/upload")
            .header(HOST, "bench.test")
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(CONTENT_LENGTH, payload.len().to_string())
            .header(ACCEPT_ENCODING, "gzip")
            .body(Full::new(payload.clone()))?;
        let resp = sender.send_request(req).await?;
        assert_eq!(resp.status(), StatusCode::OK, "POST /api/upload failed");
        let body = resp.into_body().collect().await?.to_bytes();
        assert_eq!(&body[..], b"ok");
    }
    Ok(())
}

async fn run_h2_get_batch(
    sender: &mut h2_client::SendRequest<Empty<Bytes>>,
    path: &'static str,
    send_gzip_ae: bool,
    expected_len: usize,
    total_reqs: usize,
) -> TestResult {
    let mut remaining = total_reqs;
    while remaining > 0 {
        let batch = remaining.min(H2_BATCH_STREAMS);
        let mut futs = Vec::with_capacity(batch);
        for _ in 0..batch {
            sender.ready().await?;
            let mut builder = Request::builder()
                .method(Method::GET)
                .uri(format!("https://bench.test{path}"));
            if send_gzip_ae {
                builder = builder.header(ACCEPT_ENCODING, "gzip");
            }
            let fut = sender.send_request(builder.body(Empty::<Bytes>::new())?);
            futs.push(fut);
        }
        for fut in futs {
            let resp = fut.await?;
            assert_eq!(resp.status(), StatusCode::OK, "H2 GET {path} failed");
            let body = resp.into_body().collect().await?.to_bytes();
            assert_eq!(
                body.len(),
                expected_len,
                "unexpected H2 body len for {path}"
            );
        }
        remaining -= batch;
    }
    Ok(())
}

async fn measure_row<F>(
    label: &'static str,
    telemetry: &TelemetryRegistry,
    profile_filter: &ProfileFilter,
    mut run_n: F,
) -> Result<RowMetrics, Box<dyn std::error::Error>>
where
    F: AsyncFnMut(usize) -> TestResult,
{
    let base_reqs = total_recorded_requests(telemetry);
    run_n(WARMUP_REQS).await?;
    let after_warmup = base_reqs + WARMUP_REQS as u64;
    wait_for_recorded_requests(telemetry, after_warmup).await?;

    AllocSnapshot::reset_and_start();
    run_n(SHORT_REQS).await?;
    let after_short = after_warmup + SHORT_REQS as u64;
    wait_for_recorded_requests(telemetry, after_short).await?;
    let short = AllocSnapshot::stop_and_read();

    AllocSnapshot::reset_and_start();
    run_n(LONG_REQS).await?;
    let after_long = after_short + LONG_REQS as u64;
    wait_for_recorded_requests(telemetry, after_long).await?;
    let long = AllocSnapshot::stop_and_read();

    if profile_filter.matches(label) {
        const PROFILE_REQS: usize = 200;
        AllocSnapshot::reset_and_start();
        PROFILING.store(true, Ordering::SeqCst);
        let profile_res = async {
            run_n(PROFILE_REQS).await?;
            wait_for_recorded_requests(telemetry, after_long + PROFILE_REQS as u64).await
        }
        .await;
        PROFILING.store(false, Ordering::SeqCst);
        let _ = AllocSnapshot::stop_and_read();
        profile_dump(label, PROFILE_REQS);
        profile_res?;
    }

    Ok(RowMetrics {
        label,
        short_n: SHORT_REQS as u64,
        long_n: LONG_REQS as u64,
        short,
        long,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(clippy::too_many_lines)]
fn verify_allocator_attribution_is_exact() {
    // Excluded thread allocations must register as strictly 0.
    AllocSnapshot::reset_and_start();
    let mut excluded_vecs = Vec::with_capacity(32);
    for _ in 0..32 {
        excluded_vecs.push(vec![1_u8; 64]);
    }
    let excluded_snap = AllocSnapshot::stop_and_read();
    drop(excluded_vecs);
    assert_eq!(
        excluded_snap.total_ops(),
        0,
        "excluded thread allocations leaked into server counter: {excluded_snap:?}"
    );

    // Non-excluded thread allocations must register exact count and bytes.
    // Signal with lock-free atomics (never `std::sync::Barrier` / `Mutex` / `Condvar` inside the
    // counting window): on macOS `std` lazily boxes a pthread mutex (64 B) and condvar (48 B) the
    // first time a `Barrier` is waited on, which would attribute +2 allocs / +112 B whenever the
    // counted thread reaches `b_done` first.
    let ready = Arc::new(AtomicBool::new(false));
    let go = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let ready_c = Arc::clone(&ready);
    let go_c = Arc::clone(&go);
    let done_c = Arc::clone(&done);
    let release_c = Arc::clone(&release);
    let handle = std::thread::spawn(move || {
        // Complete Rust thread startup before the counting window opens.
        ready_c.store(true, Ordering::Release);
        while !go_c.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
        let mut v = Vec::with_capacity(10);
        for _ in 0..10 {
            v.push(Box::new([7_u8; 128]));
        }
        done_c.store(true, Ordering::Release);
        while !release_c.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
        drop(v);
    });
    while !ready.load(Ordering::Acquire) {
        std::thread::yield_now();
    }
    AllocSnapshot::reset_and_start();
    go.store(true, Ordering::Release);
    while !done.load(Ordering::Acquire) {
        std::thread::yield_now();
    }
    let counted_snap = AllocSnapshot::stop_and_read();
    release.store(true, Ordering::Release);
    let _ = handle.join();
    assert_eq!(
        counted_snap.allocs, 11,
        "expected 1 Vec + 10 Box allocations on counted thread, got {counted_snap:?}"
    );
    assert_eq!(
        counted_snap.alloc_bytes,
        (10 * std::mem::size_of::<Box<[u8; 128]>>() + 10 * 128) as u64,
        "expected exact byte count on counted thread, got {counted_snap:?}"
    );
    assert!(
        PROFILE.lock().is_ok_and(|g| g.is_none()),
        "profiler must record nothing while PROFILING is off"
    );

    // Profiler reentrancy guard: profiling a single allocation must count and profile ONLY the
    // target allocation, never the backtrace/HashMap allocations made inside `profile_hit`.
    // Uses atomic flags for the same lazy-pthread-init reason as the check above.
    let prof_ready = Arc::new(AtomicBool::new(false));
    let prof_go = Arc::new(AtomicBool::new(false));
    let prof_done = Arc::new(AtomicBool::new(false));
    let prof_release = Arc::new(AtomicBool::new(false));
    let prof_ready_bg = Arc::clone(&prof_ready);
    let prof_go_bg = Arc::clone(&prof_go);
    let prof_done_bg = Arc::clone(&prof_done);
    let prof_release_bg = Arc::clone(&prof_release);
    let prof_thread = std::thread::spawn(move || {
        prof_ready_bg.store(true, Ordering::Release);
        while !prof_go_bg.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
        let boxed = Box::new([9_u8; 64]);
        std::hint::black_box(&boxed);
        prof_done_bg.store(true, Ordering::Release);
        while !prof_release_bg.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
        drop(boxed);
    });
    while !prof_ready.load(Ordering::Acquire) {
        std::thread::yield_now();
    }
    AllocSnapshot::reset_and_start();
    PROFILING.store(true, Ordering::SeqCst);
    prof_go.store(true, Ordering::Release);
    while !prof_done.load(Ordering::Acquire) {
        std::thread::yield_now();
    }
    PROFILING.store(false, Ordering::SeqCst);
    let profiled_snap = AllocSnapshot::stop_and_read();
    prof_release.store(true, Ordering::Release);
    let _ = prof_thread.join();
    let profiled_map = PROFILE
        .lock()
        .ok()
        .and_then(|mut g| g.take())
        .unwrap_or_default();
    let profiled_hits: u64 = profiled_map.values().map(|&(c, _)| c).sum();
    let profiled_bytes: u64 = profiled_map.values().map(|&(_, b)| b).sum();
    assert_eq!(
        profiled_snap.allocs, 1,
        "profiler own allocations leaked into ALLOC_COUNT: {profiled_snap:?}"
    );
    assert_eq!(
        profiled_snap.reallocs, 0,
        "profiler own reallocs leaked into REALLOC_COUNT: {profiled_snap:?}"
    );
    assert_eq!(
        profiled_snap.alloc_bytes, 64,
        "profiler own bytes leaked into ALLOC_BYTES: {profiled_snap:?}"
    );
    assert_eq!(
        profiled_hits, 1,
        "profiler own allocations were recursively profiled: {profiled_map:?}"
    );
    assert_eq!(
        profiled_bytes, 64,
        "profiler recorded wrong byte total: {profiled_map:?}"
    );
}

/// Returns `(max_ops_per_req, max_bytes_per_req)` regression ceilings for `label` on platforms
/// with configured ceilings (Linux and macOS). Returns `None` on other platforms so the harness
/// still prints the table without asserting platform-specific ceilings.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn regression_ceiling(label: &str) -> Option<(f64, f64)> {
    #[cfg(target_os = "linux")]
    let table: &[(&str, f64, f64)] = &[
        // Regression ceilings guarding against per-request allocation ops/bytes regressions on Linux.
        ("proxy_get_h1_shared", 22.5, 31_500.0),
        ("proxy_get_h2_shared", 21.0, 24_900.0),
        ("proxy_post_4k_h1_shared", 27.5, 47_100.0),
        ("static_1k_h1_shared", 13.0, 21_200.0),
        ("static_1k_h2_shared", 7.5, 13_300.0),
        ("proxy_get_h1_workers2", 22.5, 31_500.0),
        ("proxy_get_h2_workers2", 21.0, 24_900.0),
        ("static_1k_h1_browser_shared", 21.5, 20_200.0),
        ("static_304_h1_shared", 11.5, 18_000.0),
        ("redirect_h1_shared", 15.5, 17_500.0),
        ("proxy_get_h1_browser_shared", 26.5, 32_000.0),
    ];

    #[cfg(target_os = "macos")]
    let table: &[(&str, f64, f64)] = &[
        // Regression ceilings guarding against per-request allocation ops/bytes regressions on macOS.
        ("proxy_get_h1_shared", 24.0, 31_500.0),
        ("proxy_get_h2_shared", 22.5, 24_800.0),
        ("proxy_post_4k_h1_shared", 39.0, 48_100.0),
        ("static_1k_h1_shared", 37.0, 23_200.0),
        ("static_1k_h2_shared", 29.5, 14_700.0),
        ("static_1k_h1_browser_shared", 50.0, 23_200.0),
        ("static_304_h1_shared", 35.0, 20_000.0),
        ("redirect_h1_shared", 16.0, 18_000.0),
        ("proxy_get_h1_browser_shared", 28.0, 32_500.0),
    ];

    table
        .iter()
        .find(|&&(name, _, _)| name == label)
        .map(|&(_, max_ops, max_bytes)| (max_ops, max_bytes))
}

fn verify_kdl_string_encoding_handles_windows_paths() -> TestResult {
    let win_path = r#"C:\Users\runner\AppData\Local\Temp\miraserve "alloc"\docroot"#;
    let encoded = encode_kdl_string(win_path);
    let kdl = format!(
        r#"
        server {{
            listen "127.0.0.1:8443" protocols="h1,h2"
        }}
        site "win.test" {{
            root {encoded}
        }}
        "#
    );
    let (cfg, _) = parse_kdl("<win-kdl>", &kdl)?;
    let parsed_root = cfg.sites.first().and_then(|s| s.root.as_deref());
    assert_eq!(parsed_root, Some(win_path));
    Ok(())
}

fn verify_alloc_profile_filter_validation() -> TestResult {
    assert_eq!(
        parse_alloc_profile_filter(None, KNOWN_ROWS)?,
        ProfileFilter::None
    );
    assert_eq!(
        parse_alloc_profile_filter(Some(""), KNOWN_ROWS)?,
        ProfileFilter::None
    );
    assert_eq!(
        parse_alloc_profile_filter(Some("   "), KNOWN_ROWS)?,
        ProfileFilter::None
    );
    assert_eq!(
        parse_alloc_profile_filter(Some("all"), KNOWN_ROWS)?,
        ProfileFilter::All
    );
    let sel =
        parse_alloc_profile_filter(Some("static_1k_h1_shared, proxy_get_h2_shared"), KNOWN_ROWS)?;
    assert!(sel.matches("static_1k_h1_shared"));
    assert!(sel.matches("proxy_get_h2_shared"));
    assert!(!sel.matches("redirect_h1_shared"));
    assert!(
        parse_alloc_profile_filter(Some("misspelled_row"), KNOWN_ROWS).is_err(),
        "unknown row name in ALLOC_PROFILE must return an error"
    );
    assert!(
        parse_alloc_profile_filter(Some("static_1k_h1_shared,no_such_row"), KNOWN_ROWS).is_err(),
        "mixed known + unknown row names in ALLOC_PROFILE must return an error"
    );
    assert!(
        parse_alloc_profile_filter(Some("static_1k_h1_shared,"), KNOWN_ROWS).is_err(),
        "empty trailing token in ALLOC_PROFILE must return an error"
    );
    Ok(())
}

/// Note: this integration test binary installs a process-wide counting `#[global_allocator]`, so
/// it intentionally exposes a single `#[test]` entry point to prevent sibling libtest threads from
/// allocating concurrently during measurement windows.
#[test]
#[allow(clippy::too_many_lines)]
fn proxy_and_static_allocation_cost_report() -> TestResult {
    let _exclude_main = ExcludeThreadGuard::enter();
    verify_kdl_string_encoding_handles_windows_paths()?;
    verify_alloc_profile_filter_validation()?;
    let raw_profile = std::env::var("ALLOC_PROFILE").ok();
    let profile_filter = parse_alloc_profile_filter(raw_profile.as_deref(), KNOWN_ROWS)?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    verify_allocator_attribution_is_exact();

    let docroot = TempDir::new("docroot")?;
    fs::write(docroot.path.join("hello.txt"), vec![b'x'; 1024])?;

    let upstream = ExcludedUpstream::start()?;
    let client_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let mut rows: Vec<RowMetrics> = Vec::new();

    // -------------------------------------------------------------------------
    // Default shared-runtime server: rows (a), (b), (c), (d1), (d2)
    // -------------------------------------------------------------------------
    {
        let server_rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("alloc-cost-srv")
            .enable_all()
            .build()?;

        let (server, addr) = start_server_on_runtime(&server_rt, &docroot.path, upstream.addr, "")?;
        let telemetry = Arc::clone(server.telemetry());
        let h1_tls = build_tls_client_config(&server, b"http/1.1")?;
        let h2_tls = build_tls_client_config(&server, b"h2")?;

        client_rt.block_on(async {
            // (a) Proxied GET, client HTTP/1.1 keep-alive (TLS 1.3)
            let (mut s_a, t_a) = connect_h1_get(addr, &h1_tls).await?;
            rows.push(
                measure_row(
                    "proxy_get_h1_shared",
                    &telemetry,
                    &profile_filter,
                    async |n| {
                        run_h1_get_batch(&mut s_a, "/api/item", true, UPSTREAM_RESP_LEN, n).await
                    },
                )
                .await?,
            );
            drop(s_a);
            let _ = t_a.await;

            // (b) Proxied GET, client HTTP/2 multiplexed (TLS 1.3, 10 streams/batch)
            let (mut s_b, t_b) = connect_h2_get(addr, &h2_tls).await?;
            rows.push(
                measure_row(
                    "proxy_get_h2_shared",
                    &telemetry,
                    &profile_filter,
                    async |n| {
                        run_h2_get_batch(&mut s_b, "/api/item", true, UPSTREAM_RESP_LEN, n).await
                    },
                )
                .await?,
            );
            drop(s_b);
            let _ = t_b.await;

            // (c) Proxied POST with 4 KiB body, client HTTP/1.1 keep-alive (TLS 1.3)
            let post_payload = Bytes::from(vec![b'P'; POST_BODY_LEN]);
            let (mut s_c, t_c) = connect_h1_post(addr, &h1_tls).await?;
            rows.push(
                measure_row(
                    "proxy_post_4k_h1_shared",
                    &telemetry,
                    &profile_filter,
                    async |n| run_h1_post_batch(&mut s_c, &post_payload, n).await,
                )
                .await?,
            );
            drop(s_c);
            let _ = t_c.await;

            // (d1) Static small file (1 KiB), client HTTP/1.1 keep-alive (TLS 1.3)
            let (mut s_d1, t_d1) = connect_h1_get(addr, &h1_tls).await?;
            rows.push(
                measure_row(
                    "static_1k_h1_shared",
                    &telemetry,
                    &profile_filter,
                    async |n| run_h1_get_batch(&mut s_d1, "/hello.txt", false, 1024, n).await,
                )
                .await?,
            );
            drop(s_d1);
            let _ = t_d1.await;

            // (d2) Static small file (1 KiB), client HTTP/2 multiplexed (TLS 1.3)
            let (mut s_d2, t_d2) = connect_h2_get(addr, &h2_tls).await?;
            rows.push(
                measure_row(
                    "static_1k_h2_shared",
                    &telemetry,
                    &profile_filter,
                    async |n| run_h2_get_batch(&mut s_d2, "/hello.txt", false, 1024, n).await,
                )
                .await?,
            );
            drop(s_d2);
            let _ = t_d2.await;

            // (d3) Static small file (1 KiB), HTTP/1.1 keep-alive with realistic 12-header browser request
            let (mut s_d3, t_d3) = connect_h1_get(addr, &h1_tls).await?;
            rows.push(
                measure_row(
                    "static_1k_h1_browser_shared",
                    &telemetry,
                    &profile_filter,
                    async |n| {
                        run_h1_browser_get_batch(&mut s_d3, "/hello.txt", None, Some("br"), n).await
                    },
                )
                .await?,
            );
            drop(s_d3);
            let _ = t_d3.await;

            // (d4) Static 304 revalidation (If-None-Match), HTTP/1.1 keep-alive
            let (mut s_d4, t_d4) = connect_h1_get(addr, &h1_tls).await?;
            let etag = {
                let before = total_recorded_requests(&telemetry);
                s_d4.ready().await?;
                let probe_req = Request::builder()
                    .method(Method::GET)
                    .uri("/hello.txt")
                    .header(HOST, "bench.test")
                    .body(Empty::<Bytes>::new())?;
                let probe_resp = s_d4.send_request(probe_req).await?;
                assert_eq!(probe_resp.status(), StatusCode::OK);
                let tag = probe_resp
                    .headers()
                    .get(ETAG)
                    .cloned()
                    .ok_or("expected ETag header on /hello.txt")?;
                let _ = probe_resp.into_body().collect().await?;
                wait_for_recorded_requests(&telemetry, before + 1).await?;
                tag
            };
            rows.push(
                measure_row(
                    "static_304_h1_shared",
                    &telemetry,
                    &profile_filter,
                    async |n| run_h1_304_batch(&mut s_d4, "/hello.txt", &etag, n).await,
                )
                .await?,
            );
            drop(s_d4);
            let _ = t_d4.await;

            // (d5) Redirect route (301), HTTP/1.1 keep-alive
            let (mut s_d5, t_d5) = connect_h1_get(addr, &h1_tls).await?;
            rows.push(
                measure_row(
                    "redirect_h1_shared",
                    &telemetry,
                    &profile_filter,
                    async |n| {
                        run_h1_redirect_batch(&mut s_d5, "/old", "https://bench.test/hello.txt", n)
                            .await
                    },
                )
                .await?,
            );
            drop(s_d5);
            let _ = t_d5.await;

            // (d6) Proxied GET, HTTP/1.1 keep-alive with the same 12 browser headers
            let (mut s_d6, t_d6) = connect_h1_get(addr, &h1_tls).await?;
            rows.push(
                measure_row(
                    "proxy_get_h1_browser_shared",
                    &telemetry,
                    &profile_filter,
                    async |n| {
                        run_h1_browser_get_batch(
                            &mut s_d6,
                            "/api/item",
                            Some(UPSTREAM_RESP_LEN),
                            None,
                            n,
                        )
                        .await
                    },
                )
                .await?,
            );
            drop(s_d6);
            let _ = t_d6.await;

            Ok::<_, Box<dyn std::error::Error>>(())
        })?;

        server_rt.block_on(async move {
            let _ = server.shutdown_with_report().await;
        });
        drop(server_rt);
    }

    // -------------------------------------------------------------------------
    // (e) Linux dedicated worker loops (`workers 2`): proxied GET H1 & H2
    // -------------------------------------------------------------------------
    #[cfg(target_os = "linux")]
    {
        let server_rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("alloc-cost-wsrv")
            .enable_all()
            .build()?;

        let (server, addr) =
            start_server_on_runtime(&server_rt, &docroot.path, upstream.addr, "workers 2")?;
        let telemetry = Arc::clone(server.telemetry());
        let h1_tls = build_tls_client_config(&server, b"http/1.1")?;
        let h2_tls = build_tls_client_config(&server, b"h2")?;

        client_rt.block_on(async {
            let (mut s_e1, t_e1) = connect_h1_get(addr, &h1_tls).await?;
            rows.push(
                measure_row(
                    "proxy_get_h1_workers2",
                    &telemetry,
                    &profile_filter,
                    async |n| {
                        run_h1_get_batch(&mut s_e1, "/api/item", true, UPSTREAM_RESP_LEN, n).await
                    },
                )
                .await?,
            );
            drop(s_e1);
            let _ = t_e1.await;

            let (mut s_e2, t_e2) = connect_h2_get(addr, &h2_tls).await?;
            rows.push(
                measure_row(
                    "proxy_get_h2_workers2",
                    &telemetry,
                    &profile_filter,
                    async |n| {
                        run_h2_get_batch(&mut s_e2, "/api/item", true, UPSTREAM_RESP_LEN, n).await
                    },
                )
                .await?,
            );
            drop(s_e2);
            let _ = t_e2.await;

            Ok::<_, Box<dyn std::error::Error>>(())
        })?;

        server_rt.block_on(async move {
            let _ = server.shutdown_with_report().await;
        });
        drop(server_rt);
    }

    println!();
    println!(
        "ALLOC_COST_TABLE (delta = {} - {} = {} reqs, warmup = {}, platform = {})",
        LONG_REQS,
        SHORT_REQS,
        LONG_REQS - SHORT_REQS,
        WARMUP_REQS,
        std::env::consts::OS
    );
    println!(
        "{:<28} {:>9} {:>9} {:>10} {:>11} {:>10} {:>10}",
        "scenario", "alloc/req", "realc/req", "total/req", "bytes/req", "short/req", "long/req"
    );
    // Assert regression ceilings unconditionally even when `ALLOC_PROFILE` is active: the `short`
    // and `long` measurement windows finish completely with `PROFILING = false` before any
    // separate profiling pass runs.
    for row in &rows {
        println!(
            "{:<28} {:>9.2} {:>9.2} {:>10.2} {:>11.1} {:>10.2} {:>10.2}",
            row.label,
            row.allocs_per_req(),
            row.reallocs_per_req(),
            row.ops_per_req(),
            row.bytes_per_req(),
            row.short_ops_per_req(),
            row.long_ops_per_req(),
        );
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            assert!(
                row.ops_per_req() > 0.0 && row.bytes_per_req() > 0.0,
                "row {} recorded zero allocations: {row:?}",
                row.label
            );
            let (max_ops, max_bytes) = regression_ceiling(row.label)
                .ok_or_else(|| format!("missing regression ceiling for row {}", row.label))?;
            assert!(
                row.ops_per_req() <= max_ops,
                "allocation count regression on {}: measured {:.2} ops/req > ceiling {:.2} ({row:?})",
                row.label,
                row.ops_per_req(),
                max_ops,
            );
            assert!(
                row.bytes_per_req() <= max_bytes,
                "allocated bytes regression on {}: measured {:.1} B/req > ceiling {:.1} ({row:?})",
                row.label,
                row.bytes_per_req(),
                max_bytes,
            );
        }
    }
    println!();

    Ok(())
}

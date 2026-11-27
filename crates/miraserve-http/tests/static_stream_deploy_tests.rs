//! Real-TCP integration tests for large streamed static files over HTTP/1.1 and HTTP/2:
//! - Live-site deploy styles with in-flight requests and
//!   SHA-256 body hash verification:
//!   1. `rsync`-style write-to-temp-and-rename
//!   2. `rsync --inplace`-style overwrite (shorter -> protocol failed/short; equal-length ->
//!      explicitly asserts 0.1.4/POSIX no-snapshot visibility)
//!   3. `unzip -o`-style truncate-and-rewrite (`O_TRUNC` + partial/shorter rewrite -> protocol
//!      failed/short)
//!   4. `cp -f` (writable destination shorter overwrite -> protocol failed/short; read-only
//!      destination unlink-and-recreate -> complete old file)
//! - HTTP/2 flow control (synchronized zero-window read-count bound: at most one 4-chunk /
//!   256 KiB batch while the window is closed, plus budget release on completion and `RST_STREAM`)
//! - HTTP/1.1 `WriteGuardedIo` cuts a stalled reader on a large streamed file
//! - Large non-zero `Range`, `If-Range`, and `HEAD` over real TCP (HTTP/1.1 and HTTP/2)

use std::io::{Seek as _, SeekFrom, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_RANGE, ETAG, IF_RANGE, RANGE};
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use miraserve_config::parse_kdl;
use miraserve_http::{HttpEngine, WriteGuardedIo};
use miraserve_tls::AcmeChallengeStore;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{RwLock, watch};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Serializes only the zero-window read-count test (`write()`) against the other streaming tests
/// in this integration binary (`read()`), so process-wide speculative-byte and debug read counters
/// are observed deterministically with zero cross-test noise while all other tests run in parallel.
static STREAM_COUNTER_LOCK: RwLock<()> = RwLock::const_new(());

/// 4 MiB file (> 256 KiB streaming threshold and well above small TCP socket buffers).
const OLD_LEN: usize = 4 * 1024 * 1024;
const SHORT_NEW_LEN: usize = 512 * 1024;
const LONG_NEW_LEN: usize = 4 * 1024 * 1024 + 128 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Result<Self, std::io::Error> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "miraserve-stream-deploy-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Pure-Rust FIPS 180-4 SHA-256 so integration tests check cryptographic body hashes without
/// adding any dependency.
#[allow(clippy::many_single_char_names, clippy::too_many_lines)]
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for block in padded.as_chunks::<64>().0 {
        let mut w = [0_u32; 64];
        for (i, word) in block.as_chunks::<4>().0.iter().enumerate() {
            if let Some(slot) = w.get_mut(i) {
                *slot = u32::from_be_bytes(*word);
            }
        }
        for i in 16..64 {
            let w15 = w.get(i - 15).copied().unwrap_or(0);
            let w2 = w.get(i - 2).copied().unwrap_or(0);
            let w16 = w.get(i - 16).copied().unwrap_or(0);
            let w7 = w.get(i - 7).copied().unwrap_or(0);
            let s0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
            let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
            if let Some(slot) = w.get_mut(i) {
                *slot = w16.wrapping_add(s0).wrapping_add(w7).wrapping_add(s1);
            }
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let k_i = K.get(i).copied().unwrap_or(0);
            let w_i = w.get(i).copied().unwrap_or(0);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k_i)
                .wrapping_add(w_i);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        let add = [a, b, c, d, e, f, g, hh];
        for (dst, delta) in h.iter_mut().zip(add) {
            *dst = dst.wrapping_add(delta);
        }
    }

    let mut out = [0_u8; 32];
    for (i, word) in h.iter().enumerate() {
        if let Some(slot) = out.get_mut(i * 4..i * 4 + 4) {
            slot.copy_from_slice(&word.to_be_bytes());
        }
    }
    out
}

#[allow(clippy::cast_possible_truncation)]
fn make_payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|idx| (((idx.wrapping_mul(131) ^ (idx >> 8) ^ usize::from(seed)) & 0x3f) as u8) + b'!')
        .collect()
}

fn start_tcp_server(
    root: &Path,
    small_send_buf: bool,
    write_guard_idle: Option<Duration>,
) -> Result<(SocketAddr, watch::Sender<bool>), Box<dyn std::error::Error>> {
    let root_str = root.to_string_lossy().replace('\\', "/");
    let idle_ms = write_guard_idle.map_or(5_000, |d| d.as_millis());
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
    timeouts {{
        response-write-idle "{idle_ms}ms"
        graceful-drain "800ms"
        idle-keepalive "5s"
    }}
}}
site "deploy.example.test" {{
    root "{root_str}"
}}
"#
    );
    let (cfg, _) = parse_kdl("deploy.kdl", &kdl)?;
    let engine = Arc::new(HttpEngine::from_config(
        &cfg,
        Arc::new(AcmeChallengeStore::new()),
        None,
        8443,
    )?);

    let socket = TcpSocket::new_v4()?;
    if small_send_buf {
        let _ = socket.set_send_buffer_size(16 * 1024);
    }
    socket.bind("127.0.0.1:0".parse()?)?;
    let listener: TcpListener = socket.listen(32)?;
    let addr = listener.local_addr()?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let mut rx = shutdown_rx;
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((stream, peer)) = accepted else {
                        break;
                    };
                    let engine_clone = Arc::clone(&engine);
                    let conn_rx = rx.clone();
                    if let Some(idle) = write_guard_idle {
                        let guarded = WriteGuardedIo::new(stream, idle, 0);
                        tokio::spawn(engine_clone.serve_hyper_connection(
                            guarded,
                            peer,
                            addr,
                            true,
                            false,
                            None,
                            conn_rx,
                        ));
                    } else {
                        tokio::spawn(engine_clone.serve_hyper_connection(
                            stream,
                            peer,
                            addr,
                            true,
                            false,
                            None,
                            conn_rx,
                        ));
                    }
                }
                _ = rx.changed() => break,
            }
        }
    });

    Ok((addr, shutdown_tx))
}

async fn connect_small_h1(addr: SocketAddr) -> Result<TcpStream, std::io::Error> {
    let sock = TcpSocket::new_v4()?;
    let _ = sock.set_recv_buffer_size(16 * 1024);
    sock.connect(addr).await
}

async fn read_h1_head(
    stream: &mut TcpStream,
) -> Result<(String, Vec<u8>), Box<dyn std::error::Error>> {
    let mut raw = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 1024];
    loop {
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8(raw.get(..pos).unwrap_or(&[]).to_vec())?;
            let tail = raw.get(pos + 4..).unwrap_or(&[]).to_vec();
            return Ok((head, tail));
        }
        let n = tokio::time::timeout(IO_TIMEOUT, stream.read(&mut chunk))
            .await
            .map_err(|_| "timed out reading HTTP/1.1 head")??;
        if n == 0 {
            return Err("EOF before end of HTTP/1.1 head".into());
        }
        raw.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
    }
}

fn parse_content_length(head: &str) -> Option<usize> {
    head.lines().find_map(|line| {
        line.to_ascii_lowercase()
            .strip_prefix("content-length:")
            .and_then(|v| v.trim().parse::<usize>().ok())
    })
}

async fn drain_h1_until_eof_or_len(
    stream: &mut TcpStream,
    body: &mut Vec<u8>,
    expected_len: usize,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut buf = vec![0_u8; 32 * 1024];
    let deadline = tokio::time::Instant::now() + IO_TIMEOUT;
    while body.len() < expected_len {
        let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
        if rem.is_zero() {
            return Err(format!(
                "HTTP/1.1 read timed out at {} / {expected_len} bytes",
                body.len()
            )
            .into());
        }
        match tokio::time::timeout(rem, stream.read(&mut buf)).await {
            Ok(Ok(0) | Err(_)) => return Ok(false),
            Ok(Ok(n)) => body.extend_from_slice(buf.get(..n).unwrap_or(&[])),
            Err(_) => {
                return Err(
                    format!("HTTP/1.1 hung at {} / {expected_len} bytes", body.len()).into(),
                );
            }
        }
    }
    Ok(body.len() == expected_len)
}

async fn fetch_h1_full(
    addr: SocketAddr,
    path: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut s = TcpStream::connect(addr).await?;
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: deploy.example.test\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await?;
    let (head, mut body) = read_h1_head(&mut s).await?;
    assert!(
        head.starts_with("HTTP/1.1 200 OK"),
        "unexpected head: {head:?}"
    );
    let expected = parse_content_length(&head).ok_or("missing Content-Length")?;
    tokio::time::timeout(IO_TIMEOUT, s.read_to_end(&mut body)).await??;
    assert_eq!(body.len(), expected);
    Ok(body)
}

async fn connect_h2_small_window(
    addr: SocketAddr,
) -> Result<
    (
        http2::SendRequest<Empty<Bytes>>,
        tokio::task::JoinHandle<()>,
    ),
    Box<dyn std::error::Error>,
> {
    let sock = TcpSocket::new_v4()?;
    let _ = sock.set_recv_buffer_size(16 * 1024);
    let stream = sock.connect(addr).await?;
    let mut builder = http2::Builder::new(TokioExecutor::new());
    builder
        .initial_stream_window_size(65_535)
        .initial_connection_window_size(128 * 1024);
    let (sender, conn) = builder
        .handshake::<_, Empty<Bytes>>(TokioIo::new(stream))
        .await?;
    let task = tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok((sender, task))
}

async fn fetch_h2_full(
    sender: &mut http2::SendRequest<Empty<Bytes>>,
    path: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    sender.ready().await?;
    let req = Request::builder()
        .uri(format!("https://deploy.example.test{path}"))
        .body(Empty::new())?;
    let resp = tokio::time::timeout(IO_TIMEOUT, sender.send_request(req)).await??;
    assert_eq!(resp.status(), StatusCode::OK);
    let expected = resp
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .ok_or("missing Content-Length")?;
    let body = tokio::time::timeout(IO_TIMEOUT, resp.into_body().collect())
        .await??
        .to_bytes()
        .to_vec();
    assert_eq!(body.len(), expected);
    Ok(body)
}

/// 1. `rsync`-style write-to-temp-and-rename over live HTTP/1.1 & HTTP/2 requests in flight
///    (tested for both shorter and longer replacement files).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_deploy_rsync_temp_and_rename_http1_and_http2() -> TestResult {
    let _stream_guard = STREAM_COUNTER_LOCK.read().await;
    let dir = TempDir::new("rsync-rename")?;
    let old_bytes = make_payload(OLD_LEN, 0x11);
    let old_hash = sha256(&old_bytes);
    let (addr, shutdown) = start_tcp_server(&dir.path, true, None)?;

    for (tag, new_len, seed) in [
        ("shorter", SHORT_NEW_LEN, 0x22),
        ("longer", LONG_NEW_LEN, 0x33),
    ] {
        let rel = format!("/asset-{tag}.js");
        let target = dir.path.join(format!("asset-{tag}.js"));
        let new_bytes = make_payload(new_len, seed);
        let new_hash = sha256(&new_bytes);
        std::fs::write(&target, &old_bytes)?;

        // Start in-flight HTTP/1.1 request and read response head (mid-stream).
        let mut h1 = connect_small_h1(addr).await?;
        h1.write_all(format!("GET {rel} HTTP/1.1\r\nHost: deploy.example.test\r\n\r\n").as_bytes())
            .await?;
        let (h1_head, mut h1_body) = read_h1_head(&mut h1).await?;
        assert!(h1_head.starts_with("HTTP/1.1 200 OK"));
        assert_eq!(parse_content_length(&h1_head), Some(OLD_LEN));

        // Start in-flight HTTP/2 request and hold after headers (window closed at 64 KiB).
        let (mut h2_tx, h2_conn) = connect_h2_small_window(addr).await?;
        let h2_resp = tokio::time::timeout(
            IO_TIMEOUT,
            h2_tx.send_request(
                Request::builder()
                    .uri(format!("https://deploy.example.test{rel}"))
                    .body(Empty::new())?,
            ),
        )
        .await??;
        assert_eq!(h2_resp.status(), StatusCode::OK);

        // Deploy: rsync-style write to temp file in same directory + atomic rename.
        let tmp = dir.path.join(format!(".asset-{tag}.js.tmp"));
        std::fs::write(&tmp, &new_bytes)?;
        std::fs::rename(&tmp, &target)?;

        // Both in-flight requests MUST finish with 100% complete old file and exact old SHA-256.
        assert!(
            drain_h1_until_eof_or_len(&mut h1, &mut h1_body, OLD_LEN).await?,
            "rename ({tag}): HTTP/1.1 in-flight must finish completely"
        );
        assert_eq!(sha256(&h1_body), old_hash, "rename ({tag}): H1 old hash");

        let h2_body = tokio::time::timeout(IO_TIMEOUT, h2_resp.into_body().collect())
            .await??
            .to_bytes();
        assert_eq!(h2_body.len(), OLD_LEN);
        assert_eq!(sha256(&h2_body), old_hash, "rename ({tag}): H2 old hash");

        // Post-deploy requests on HTTP/1.1 and HTTP/2 get 100% new file and exact new SHA-256.
        let post_h1 = fetch_h1_full(addr, &rel).await?;
        assert_eq!(sha256(&post_h1), new_hash, "rename ({tag}): H1 new hash");
        let post_h2 = fetch_h2_full(&mut h2_tx, &rel).await?;
        assert_eq!(sha256(&post_h2), new_hash, "rename ({tag}): H2 new hash");

        drop(h2_tx);
        let _ = h2_conn.await;
    }

    let _ = shutdown.send(true);
    Ok(())
}

/// 2. `rsync --inplace`-style overwrite (open `O_WRONLY` without `O_TRUNC`, overwrite blocks,
///    then `set_len` when shorter):
///    - Shorter replacement -> both HTTP/1.1 and HTTP/2 mark the in-flight transfer failed/short.
///    - Same-length replacement -> explicitly verifies the 0.1.4/POSIX no-snapshot outcome
///      (`SPEC.md`): open fd reads overwritten blocks of the same inode, yielding mixed old+new
///      bytes matching `OLD_LEN`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn live_deploy_rsync_inplace_overwrite_http1_and_http2() -> TestResult {
    let _stream_guard = STREAM_COUNTER_LOCK.read().await;
    let dir = TempDir::new("rsync-inplace")?;
    let old_bytes = make_payload(OLD_LEN, 0x41);
    let old_hash = sha256(&old_bytes);
    let short_new = make_payload(SHORT_NEW_LEN, 0x42);
    let short_new_hash = sha256(&short_new);
    let same_new = make_payload(OLD_LEN, 0x43);
    let same_new_hash = sha256(&same_new);
    let (addr, shutdown) = start_tcp_server(&dir.path, true, None)?;

    // (a) Shorter rsync --inplace -> protocol marks in-flight transfer failed/short.
    {
        let target = dir.path.join("inplace-short.js");
        std::fs::write(&target, &old_bytes)?;

        let mut h1 = connect_small_h1(addr).await?;
        h1.write_all(b"GET /inplace-short.js HTTP/1.1\r\nHost: deploy.example.test\r\n\r\n")
            .await?;
        let (h1_head, mut h1_body) = read_h1_head(&mut h1).await?;
        assert_eq!(parse_content_length(&h1_head), Some(OLD_LEN));

        let (mut h2_tx, h2_conn) = connect_h2_small_window(addr).await?;
        let h2_resp = tokio::time::timeout(
            IO_TIMEOUT,
            h2_tx.send_request(
                Request::builder()
                    .uri("https://deploy.example.test/inplace-short.js")
                    .body(Empty::new())?,
            ),
        )
        .await??;
        assert_eq!(h2_resp.status(), StatusCode::OK);

        // rsync --inplace (no O_TRUNC): overwrite from offset 0, then truncate to shorter length.
        {
            let mut f = std::fs::OpenOptions::new().write(true).open(&target)?;
            f.write_all(&short_new)?;
            f.set_len(u64::try_from(SHORT_NEW_LEN)?)?;
        }

        // HTTP/1.1 ends strictly short of Content-Length and closes.
        let h1_complete = drain_h1_until_eof_or_len(&mut h1, &mut h1_body, OLD_LEN).await?;
        assert!(
            !h1_complete && h1_body.len() < OLD_LEN,
            "rsync --inplace shorter: HTTP/1.1 must end short and close (got {})",
            h1_body.len()
        );

        // HTTP/2 rejects the short stream or delivers < OLD_LEN (never valid OLD_LEN).
        let h2_res = tokio::time::timeout(IO_TIMEOUT, h2_resp.into_body().collect()).await?;
        match h2_res {
            Err(_) => {}
            Ok(collected) => {
                let got = collected.to_bytes();
                assert!(
                    got.len() < OLD_LEN,
                    "rsync --inplace shorter: HTTP/2 must never deliver complete {OLD_LEN} bytes"
                );
            }
        }

        // Post-deploy requests serve complete new file.
        assert_eq!(
            sha256(&fetch_h1_full(addr, "/inplace-short.js").await?),
            short_new_hash
        );
        let (mut h2_post, h2_post_conn) = connect_h2_small_window(addr).await?;
        assert_eq!(
            sha256(&fetch_h2_full(&mut h2_post, "/inplace-short.js").await?),
            short_new_hash
        );
        drop(h2_tx);
        drop(h2_post);
        let _ = h2_conn.await;
        let _ = h2_post_conn.await;
    }

    // (b) Same-length rsync --inplace (no O_TRUNC): synchronized on observed old DATA bytes
    //     BEFORE overwriting, exercised on BOTH HTTP/1.1 and HTTP/2. Verifies 0.1.4/POSIX
    //     no-snapshot visibility: observed prefix stays old bytes, tail reflects the overwrite.
    {
        // HTTP/1.1 equal-length in-place overwrite.
        let target_h1 = dir.path.join("inplace-same-h1.js");
        std::fs::write(&target_h1, &old_bytes)?;
        let mut h1 = connect_small_h1(addr).await?;
        h1.write_all(b"GET /inplace-same-h1.js HTTP/1.1\r\nHost: deploy.example.test\r\n\r\n")
            .await?;
        let (h1_head, mut h1_body) = read_h1_head(&mut h1).await?;
        assert!(h1_head.starts_with("HTTP/1.1 200 OK"));
        assert_eq!(parse_content_length(&h1_head), Some(OLD_LEN));
        // Synchronize on actual old DATA bytes observed on the wire before overwriting.
        let mut first_buf = [0_u8; 4096];
        while h1_body.is_empty() {
            let n = tokio::time::timeout(IO_TIMEOUT, h1.read(&mut first_buf))
                .await
                .map_err(|_| "timed out waiting for first HTTP/1.1 body bytes")??;
            assert!(n > 0, "unexpected EOF before first HTTP/1.1 body byte");
            h1_body.extend_from_slice(first_buf.get(..n).unwrap_or(&[]));
        }
        let observed_h1_prefix = h1_body.len();
        assert_eq!(
            Some(h1_body.as_slice()),
            old_bytes.get(..observed_h1_prefix),
            "observed HTTP/1.1 prefix must be old bytes before overwrite"
        );
        {
            let mut f = std::fs::OpenOptions::new().write(true).open(&target_h1)?;
            f.write_all(&same_new)?;
            f.flush()?;
        }
        assert!(
            drain_h1_until_eof_or_len(&mut h1, &mut h1_body, OLD_LEN).await?,
            "same-length in-place HTTP/1.1 stream must complete OLD_LEN bytes"
        );
        assert_eq!(
            h1_body.get(..observed_h1_prefix),
            old_bytes.get(..observed_h1_prefix)
        );
        assert_eq!(
            h1_body.get(OLD_LEN - 64 * 1024..),
            same_new.get(OLD_LEN - 64 * 1024..),
            "HTTP/1.1 tail after overwrite must reflect new content"
        );
        let h1_mixed_hash = sha256(&h1_body);
        assert_ne!(h1_mixed_hash, old_hash);
        assert_ne!(h1_mixed_hash, same_new_hash);
        assert_eq!(
            sha256(&fetch_h1_full(addr, "/inplace-same-h1.js").await?),
            same_new_hash
        );

        // HTTP/2 equal-length in-place overwrite.
        let target_h2 = dir.path.join("inplace-same-h2.js");
        std::fs::write(&target_h2, &old_bytes)?;
        let (mut h2_tx, h2_conn) = connect_h2_small_window(addr).await?;
        let h2_resp = tokio::time::timeout(
            IO_TIMEOUT,
            h2_tx.send_request(
                Request::builder()
                    .uri("https://deploy.example.test/inplace-same-h2.js")
                    .body(Empty::new())?,
            ),
        )
        .await??;
        assert_eq!(h2_resp.status(), StatusCode::OK);
        let mut h2_body = h2_resp.into_body();
        // Synchronize on actual observed old DATA frame before overwriting.
        let mut mixed = Vec::with_capacity(OLD_LEN);
        while mixed.is_empty() {
            let frame = tokio::time::timeout(IO_TIMEOUT, h2_body.frame())
                .await
                .map_err(|_| "timed out waiting for first HTTP/2 DATA frame")?
                .ok_or("HTTP/2 stream ended before first DATA frame")??;
            if let Ok(data) = frame.into_data() {
                mixed.extend_from_slice(&data);
            }
        }
        let observed_h2_prefix = mixed.len();
        assert_eq!(
            Some(mixed.as_slice()),
            old_bytes.get(..observed_h2_prefix),
            "observed HTTP/2 prefix must be old bytes before overwrite"
        );

        {
            let mut f = std::fs::OpenOptions::new().write(true).open(&target_h2)?;
            f.write_all(&same_new)?;
            f.flush()?;
        }

        while let Some(frame) = tokio::time::timeout(IO_TIMEOUT, h2_body.frame()).await? {
            if let Ok(data) = frame?.into_data() {
                mixed.extend_from_slice(&data);
            }
        }
        assert_eq!(mixed.len(), OLD_LEN);
        assert_eq!(
            mixed.get(..observed_h2_prefix),
            old_bytes.get(..observed_h2_prefix)
        );
        assert_eq!(
            mixed.get(OLD_LEN - 64 * 1024..),
            same_new.get(OLD_LEN - 64 * 1024..),
            "HTTP/2 tail after overwrite must reflect new content"
        );
        let mixed_hash = sha256(&mixed);
        assert_ne!(
            mixed_hash, old_hash,
            "same-length in-place overwrite is visible to in-flight stream (no snapshot, as in 0.1.4)"
        );
        assert_ne!(
            mixed_hash, same_new_hash,
            "prefix observed before overwrite remains old bytes, tail is new bytes (as in 0.1.4)"
        );
        assert_eq!(
            sha256(&fetch_h2_full(&mut h2_tx, "/inplace-same-h2.js").await?),
            same_new_hash
        );
        drop(h2_tx);
        let _ = h2_conn.await;
    }

    let _ = shutdown.send(true);
    Ok(())
}

/// 3. `unzip -o`-style truncate-and-rewrite (`O_WRONLY | O_TRUNC`, then rewrite):
///    When the in-flight request reads while truncated or when the rewritten file is shorter,
///    HTTP/1.1 closes short of `Content-Length` and HTTP/2 fails the stream; subsequent requests
///    after rewrite finish cleanly with the exact new SHA-256.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_deploy_unzip_o_truncate_and_rewrite_http1_and_http2() -> TestResult {
    let _stream_guard = STREAM_COUNTER_LOCK.read().await;
    let dir = TempDir::new("unzip-trunc")?;
    let old_bytes = make_payload(OLD_LEN, 0x51);
    let new_bytes = make_payload(SHORT_NEW_LEN, 0x52);
    let new_hash = sha256(&new_bytes);
    let (addr, shutdown) = start_tcp_server(&dir.path, true, None)?;

    let target = dir.path.join("archive-asset.js");
    std::fs::write(&target, &old_bytes)?;

    let mut h1 = connect_small_h1(addr).await?;
    h1.write_all(b"GET /archive-asset.js HTTP/1.1\r\nHost: deploy.example.test\r\n\r\n")
        .await?;
    let (h1_head, mut h1_body) = read_h1_head(&mut h1).await?;
    assert_eq!(parse_content_length(&h1_head), Some(OLD_LEN));

    let (mut h2_tx, h2_conn) = connect_h2_small_window(addr).await?;
    let h2_resp = tokio::time::timeout(
        IO_TIMEOUT,
        h2_tx.send_request(
            Request::builder()
                .uri("https://deploy.example.test/archive-asset.js")
                .body(Empty::new())?,
        ),
    )
    .await??;
    assert_eq!(h2_resp.status(), StatusCode::OK);

    // Truncate to 0 (O_TRUNC) and begin rewriting first 32 KiB while in-flight streams drain.
    let mut writer = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&target)?;
    writer.write_all(new_bytes.get(..32 * 1024).unwrap_or(&[]))?;
    writer.flush()?;

    let h1_complete = drain_h1_until_eof_or_len(&mut h1, &mut h1_body, OLD_LEN).await?;
    assert!(
        !h1_complete && h1_body.len() < OLD_LEN,
        "unzip -o truncate-and-rewrite: HTTP/1.1 must end short (got {})",
        h1_body.len()
    );

    let h2_res = tokio::time::timeout(IO_TIMEOUT, h2_resp.into_body().collect()).await?;
    match h2_res {
        Err(_) => {}
        Ok(collected) => {
            assert!(
                collected.to_bytes().len() < OLD_LEN,
                "unzip -o truncate-and-rewrite: HTTP/2 must never deliver complete {OLD_LEN} bytes"
            );
        }
    }

    // Finish writing the replacement asset; next HTTP/1.1 and HTTP/2 requests get exact new hash.
    writer.write_all(new_bytes.get(32 * 1024..).unwrap_or(&[]))?;
    writer.flush()?;
    drop(writer);

    assert_eq!(
        sha256(&fetch_h1_full(addr, "/archive-asset.js").await?),
        new_hash
    );
    let (mut h2_post, h2_post_conn) = connect_h2_small_window(addr).await?;
    assert_eq!(
        sha256(&fetch_h2_full(&mut h2_post, "/archive-asset.js").await?),
        new_hash
    );

    drop(h2_tx);
    drop(h2_post);
    let _ = h2_conn.await;
    let _ = h2_post_conn.await;
    let _ = shutdown.send(true);
    Ok(())
}

/// 4. `cp -f`:
///    - Writable destination with shorter source (`cp -f` truncates in place): in-flight HTTP/1.1
///      closes short and HTTP/2 fails the stream; post-deploy gets exact new hash.
///    - Read-only `0o444` destination (`cp -f` unlinks and creates a new inode): in-flight
///      HTTP/1.1 and HTTP/2 complete with 100% old file and exact old SHA-256; post-deploy gets
///      exact new SHA-256.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn live_deploy_cp_f_http1_and_http2() -> TestResult {
    use std::os::unix::fs::PermissionsExt as _;
    let _stream_guard = STREAM_COUNTER_LOCK.read().await;

    let dir = TempDir::new("cp-f")?;
    let old_bytes = make_payload(OLD_LEN, 0x61);
    let old_hash = sha256(&old_bytes);
    let new_bytes = make_payload(SHORT_NEW_LEN, 0x62);
    let new_hash = sha256(&new_bytes);
    let src_dir = TempDir::new("cp-f-src")?;
    let src_file = src_dir.path.join("new.js");
    std::fs::write(&src_file, &new_bytes)?;

    let (addr, shutdown) = start_tcp_server(&dir.path, true, None)?;

    // (a) Writable destination: `cp -f` opens O_WRONLY | O_TRUNC on the same inode -> short/failed.
    {
        let dst = dir.path.join("writable.js");
        std::fs::write(&dst, &old_bytes)?;

        let mut h1 = connect_small_h1(addr).await?;
        h1.write_all(b"GET /writable.js HTTP/1.1\r\nHost: deploy.example.test\r\n\r\n")
            .await?;
        let (h1_head, mut h1_body) = read_h1_head(&mut h1).await?;
        assert_eq!(parse_content_length(&h1_head), Some(OLD_LEN));

        let (mut h2_tx, h2_conn) = connect_h2_small_window(addr).await?;
        let h2_resp = tokio::time::timeout(
            IO_TIMEOUT,
            h2_tx.send_request(
                Request::builder()
                    .uri("https://deploy.example.test/writable.js")
                    .body(Empty::new())?,
            ),
        )
        .await??;
        assert_eq!(h2_resp.status(), StatusCode::OK);

        let status = std::process::Command::new("cp")
            .arg("-f")
            .arg(&src_file)
            .arg(&dst)
            .status()?;
        assert!(status.success(), "cp -f writable failed: {status}");

        let h1_complete = drain_h1_until_eof_or_len(&mut h1, &mut h1_body, OLD_LEN).await?;
        assert!(
            !h1_complete && h1_body.len() < OLD_LEN,
            "cp -f writable shorter: HTTP/1.1 must end short (got {})",
            h1_body.len()
        );
        let h2_res = tokio::time::timeout(IO_TIMEOUT, h2_resp.into_body().collect()).await?;
        match h2_res {
            Err(_) => {}
            Ok(c) => assert!(c.to_bytes().len() < OLD_LEN),
        }

        assert_eq!(
            sha256(&fetch_h1_full(addr, "/writable.js").await?),
            new_hash
        );
        let (mut h2_post, h2_post_conn) = connect_h2_small_window(addr).await?;
        assert_eq!(
            sha256(&fetch_h2_full(&mut h2_post, "/writable.js").await?),
            new_hash
        );
        drop(h2_tx);
        drop(h2_post);
        let _ = h2_conn.await;
        let _ = h2_post_conn.await;
    }

    // (b) Read-only `0o444` destination: when the OS refuses `O_WRONLY` on `0o444` (non-root),
    //     `cp -f` unlinks and creates a new inode -> in-flight completes with 100% old file!
    {
        let dst = dir.path.join("readonly.js");
        std::fs::write(&dst, &old_bytes)?;
        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o444))?;
        if std::fs::OpenOptions::new().write(true).open(&dst).is_err() {
            let mut h1 = connect_small_h1(addr).await?;
            h1.write_all(b"GET /readonly.js HTTP/1.1\r\nHost: deploy.example.test\r\n\r\n")
                .await?;
            let (h1_head, mut h1_body) = read_h1_head(&mut h1).await?;
            assert_eq!(parse_content_length(&h1_head), Some(OLD_LEN));

            let (mut h2_tx, h2_conn) = connect_h2_small_window(addr).await?;
            let h2_resp = tokio::time::timeout(
                IO_TIMEOUT,
                h2_tx.send_request(
                    Request::builder()
                        .uri("https://deploy.example.test/readonly.js")
                        .body(Empty::new())?,
                ),
            )
            .await??;
            assert_eq!(h2_resp.status(), StatusCode::OK);

            let status = std::process::Command::new("cp")
                .arg("-f")
                .arg(&src_file)
                .arg(&dst)
                .status()?;
            assert!(status.success(), "cp -f readonly failed: {status}");

            assert!(drain_h1_until_eof_or_len(&mut h1, &mut h1_body, OLD_LEN).await?);
            assert_eq!(sha256(&h1_body), old_hash, "cp -f readonly: H1 old hash");
            let h2_body = tokio::time::timeout(IO_TIMEOUT, h2_resp.into_body().collect())
                .await??
                .to_bytes();
            assert_eq!(h2_body.len(), OLD_LEN);
            assert_eq!(sha256(&h2_body), old_hash, "cp -f readonly: H2 old hash");

            assert_eq!(
                sha256(&fetch_h1_full(addr, "/readonly.js").await?),
                new_hash
            );
            assert_eq!(
                sha256(&fetch_h2_full(&mut h2_tx, "/readonly.js").await?),
                new_hash
            );
            drop(h2_tx);
            let _ = h2_conn.await;
        }
    }

    let _ = shutdown.send(true);
    Ok(())
}

/// Minimal RFC 7540 HTTP/2 frame I/O helper for driving an exact `INITIAL_WINDOW_SIZE = 0`
/// stream without relying on client-library window-management heuristics.
async fn read_h2_frame(
    stream: &mut TcpStream,
) -> Result<(u8, u8, u32, Vec<u8>), Box<dyn std::error::Error>> {
    let mut hdr = [0_u8; 9];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut hdr))
        .await
        .map_err(|_| "timed out reading HTTP/2 frame header")??;
    let [l0, l1, l2, frame_type, flags, s0, s1, s2, s3] = hdr;
    let len = (usize::from(l0) << 16) | (usize::from(l1) << 8) | usize::from(l2);
    let stream_id = u32::from_be_bytes([s0 & 0x7f, s1, s2, s3]);
    let mut payload = vec![0_u8; len];
    if len > 0 {
        tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut payload))
            .await
            .map_err(|_| "timed out reading HTTP/2 frame payload")??;
    }
    Ok((frame_type, flags, stream_id, payload))
}

async fn write_h2_frame(
    stream: &mut TcpStream,
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let len = u32::try_from(payload.len())?;
    let [s0, s1, s2, s3] = (stream_id & 0x7fff_ffff).to_be_bytes();
    let hdr = [
        u8::try_from((len >> 16) & 0xff)?,
        u8::try_from((len >> 8) & 0xff)?,
        u8::try_from(len & 0xff)?,
        frame_type,
        flags,
        s0,
        s1,
        s2,
        s3,
    ];
    stream.write_all(&hdr).await?;
    if !payload.is_empty() {
        stream.write_all(payload).await?;
    }
    Ok(())
}

/// Encodes an HPACK header block for `GET https://deploy.example.test<path>` (static table +
/// literal without indexing, un-Huffman).
fn encode_h2_get_headers(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let authority = b"deploy.example.test";
    let path_bytes = path.as_bytes();
    let mut block = Vec::with_capacity(6 + authority.len() + path_bytes.len());
    block.push(0x82); // :method: GET (static index 2)
    block.push(0x87); // :scheme: https (static index 7)
    block.push(0x01); // literal without indexing, name :authority (static index 1)
    block.push(u8::try_from(authority.len())?);
    block.extend_from_slice(authority);
    block.push(0x04); // literal without indexing, name :path (static index 4)
    block.push(u8::try_from(path_bytes.len())?);
    block.extend_from_slice(path_bytes);
    Ok(block)
}

/// Synchronized HTTP/2 zero-window test asserting bounded batch reads:
/// - Client advertises `SETTINGS_INITIAL_WINDOW_SIZE = 0`.
/// - Hyper polls once before reserving capacity, triggering at most one batched pool read
///   (4 chunks = 256 KiB total: 1 chunk held by hyper/`PieceBody`, 3 speculative chunks = 192 KiB
///   held in `StaticFileStream` and counted in the process-wide speculative budget).
/// - In debug-assertion builds, synchronizes on batch completion AND delivery of frame 0 (no blind
///   sleep), round-trips an HTTP/2 PING/PONG, and asserts exact read counters (`1` batch, `4`
///   chunks, `256 KiB` read, `1` frame delivered) alongside the `192 KiB` speculative reservation.
///   In release-profile test builds where debug counters are compiled out, asserts only what is
///   observable there: the `192 KiB` speculative reservation, zero DATA frames while the window is
///   `0`, the exact `256 KiB` overwrite boundary after `WINDOW_UPDATE`, and budget release to `0`
///   after `RST_STREAM`.
/// - Repeats on stream 3 cancelled via `RST_STREAM`, using the same completion predicate against a
///   fresh stream-3 baseline before asserting counts and resetting.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn http2_closed_stream_window_reads_at_most_one_batch() -> TestResult {
    const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    const FRAME_DATA: u8 = 0x0;
    const FRAME_HEADERS: u8 = 0x1;
    const FRAME_RST_STREAM: u8 = 0x3;
    const FRAME_SETTINGS: u8 = 0x4;
    const FRAME_PING: u8 = 0x6;
    const FRAME_WINDOW_UPDATE: u8 = 0x8;
    const FLAG_ACK_OR_EOS: u8 = 0x1;
    const FLAG_END_HEADERS: u8 = 0x4;
    const BATCH_BYTES: usize = 256 * 1024;
    const SPECULATIVE_BYTES: usize = 192 * 1024;

    let _exclusive_counter_guard = STREAM_COUNTER_LOCK.write().await;

    let dir = TempDir::new("h2-zero-window")?;
    let target = dir.path.join("window.bin");
    std::fs::write(&target, vec![0xAA_u8; OLD_LEN])?;

    let (addr, shutdown) = start_tcp_server(&dir.path, false, None)?;
    assert_eq!(miraserve_static::stream_speculative_used_bytes(), 0);
    #[cfg(debug_assertions)]
    let stats_0 = miraserve_static::stream_pool_debug_stats();

    let mut conn = TcpStream::connect(addr).await?;
    conn.write_all(H2_PREFACE).await?;
    // SETTINGS_INITIAL_WINDOW_SIZE (0x0004) = 0 -> zero stream credit!
    write_h2_frame(&mut conn, FRAME_SETTINGS, 0, 0, &[0x00, 0x04, 0, 0, 0, 0]).await?;
    let headers_block = encode_h2_get_headers("/window.bin")?;
    write_h2_frame(
        &mut conn,
        FRAME_HEADERS,
        FLAG_ACK_OR_EOS | FLAG_END_HEADERS,
        1,
        &headers_block,
    )
    .await?;

    // Drive HTTP/2 handshake and wait for server's HEADERS on stream 1 (asserting 0 DATA frames).
    let mut got_headers = false;
    while !got_headers {
        let (ftype, flags, sid, _payload) = read_h2_frame(&mut conn).await?;
        match ftype {
            FRAME_SETTINGS if (flags & FLAG_ACK_OR_EOS) == 0 => {
                write_h2_frame(&mut conn, FRAME_SETTINGS, FLAG_ACK_OR_EOS, 0, &[]).await?;
            }
            FRAME_HEADERS if sid == 1 => {
                got_headers = true;
            }
            FRAME_DATA if sid == 1 => {
                return Err("server sent DATA on a zero-window HTTP/2 stream".into());
            }
            _ => {}
        }
    }

    // Synchronize deterministically until Batch 1 has finished and returned chunk 0 to hyper.
    let sync_deadline = Instant::now() + IO_TIMEOUT;
    loop {
        let spec_ready = miraserve_static::stream_speculative_used_bytes() == SPECULATIVE_BYTES;
        #[cfg(debug_assertions)]
        let stats_ready = {
            let s = miraserve_static::stream_pool_debug_stats();
            s.batches_completed
                .saturating_sub(stats_0.batches_completed)
                == 1
                && s.frames_delivered.saturating_sub(stats_0.frames_delivered) == 1
        };
        #[cfg(not(debug_assertions))]
        let stats_ready = true;
        if spec_ready && stats_ready {
            break;
        }
        assert!(
            Instant::now() < sync_deadline,
            "timed out waiting for zero-window Batch 1 completion"
        );
        tokio::task::yield_now().await;
    }

    // Round-trip an HTTP/2 PING/PONG so the server connection task executes additional turns while
    // stream 1's window stays closed at 0.
    let ping_bytes = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    write_h2_frame(&mut conn, FRAME_PING, 0, 0, &ping_bytes).await?;
    loop {
        let (ftype, flags, sid, payload) = read_h2_frame(&mut conn).await?;
        if ftype == FRAME_PING && (flags & FLAG_ACK_OR_EOS) != 0 {
            assert_eq!(payload, ping_bytes);
            break;
        }
        if ftype == FRAME_SETTINGS && (flags & FLAG_ACK_OR_EOS) == 0 {
            write_h2_frame(&mut conn, FRAME_SETTINGS, FLAG_ACK_OR_EOS, 0, &[]).await?;
        }
        assert!(
            !(ftype == FRAME_DATA && sid == 1),
            "server must not send DATA while stream 1 window is 0"
        );
    }

    // Assert EXACT read count while window is closed: 1 batch, 4 chunks, 256 KiB read, 192 KiB
    // speculative bytes held in the body.
    assert_eq!(
        miraserve_static::stream_speculative_used_bytes(),
        SPECULATIVE_BYTES,
        "zero-window stream must hold exactly 3 speculative chunks (192 KiB) in body"
    );
    #[cfg(debug_assertions)]
    {
        let s = miraserve_static::stream_pool_debug_stats();
        assert_eq!(
            s.batches_started.saturating_sub(stats_0.batches_started),
            1,
            "zero-window stream must submit exactly 1 batch task"
        );
        assert_eq!(
            s.batches_completed
                .saturating_sub(stats_0.batches_completed),
            1,
            "zero-window stream must complete exactly 1 batch task"
        );
        assert_eq!(
            s.chunks_read.saturating_sub(stats_0.chunks_read),
            4,
            "zero-window stream must read at most 4 chunks (1 batch)"
        );
        assert_eq!(
            s.bytes_read.saturating_sub(stats_0.bytes_read),
            BATCH_BYTES,
            "zero-window stream must read at most 256 KiB while window is closed"
        );
        assert_eq!(
            s.frames_delivered.saturating_sub(stats_0.frames_delivered),
            1,
            "hyper must poll only its 1 lookahead frame while window is closed"
        );
    }

    // Overwrite the file from EXACT offset 256 KiB onward with 0xBB while window is still 0.
    {
        let mut f = std::fs::OpenOptions::new().write(true).open(&target)?;
        f.seek(SeekFrom::Start(u64::try_from(BATCH_BYTES)?))?;
        f.write_all(&vec![0xBB_u8; OLD_LEN - BATCH_BYTES])?;
        f.flush()?;
    }

    // Grant flow-control window for the entire 4 MiB body (connection + stream 1) and drain.
    let inc = u32::try_from(OLD_LEN)?.to_be_bytes();
    write_h2_frame(&mut conn, FRAME_WINDOW_UPDATE, 0, 0, &inc).await?;
    write_h2_frame(&mut conn, FRAME_WINDOW_UPDATE, 0, 1, &inc).await?;

    let mut body = Vec::with_capacity(OLD_LEN);
    loop {
        let (ftype, flags, sid, payload) = read_h2_frame(&mut conn).await?;
        if ftype == FRAME_DATA && sid == 1 {
            body.extend_from_slice(&payload);
            if (flags & FLAG_ACK_OR_EOS) != 0 {
                break;
            }
        } else if ftype == FRAME_SETTINGS && (flags & FLAG_ACK_OR_EOS) == 0 {
            write_h2_frame(&mut conn, FRAME_SETTINGS, FLAG_ACK_OR_EOS, 0, &[]).await?;
        }
    }
    assert_eq!(body.len(), OLD_LEN);
    assert!(
        body.get(..BATCH_BYTES)
            .is_some_and(|prefix| prefix.iter().all(|&b| b == 0xAA)),
        "first 256 KiB batch read before window opened must be 0xAA"
    );
    assert!(
        body.get(BATCH_BYTES..)
            .is_some_and(|tail| tail.iter().all(|&b| b == 0xBB)),
        "every byte from 256 KiB onward must be 0xBB, proving nothing past 1 batch was read"
    );
    assert_eq!(miraserve_static::stream_speculative_used_bytes(), 0);

    // Part 2: a second zero-window stream reset via RST_STREAM reads at most 1 batch and releases
    // its speculative budget back to 0.
    #[cfg(debug_assertions)]
    let stats_1 = miraserve_static::stream_pool_debug_stats();
    write_h2_frame(
        &mut conn,
        FRAME_HEADERS,
        FLAG_ACK_OR_EOS | FLAG_END_HEADERS,
        3,
        &headers_block,
    )
    .await?;
    let mut got_h3 = false;
    while !got_h3 {
        let (ftype, flags, sid, _) = read_h2_frame(&mut conn).await?;
        match ftype {
            FRAME_HEADERS if sid == 3 => {
                got_h3 = true;
            }
            FRAME_SETTINGS if (flags & FLAG_ACK_OR_EOS) == 0 => {
                write_h2_frame(&mut conn, FRAME_SETTINGS, FLAG_ACK_OR_EOS, 0, &[]).await?;
            }
            FRAME_DATA if sid == 3 => {
                return Err("server sent DATA on zero-window HTTP/2 stream 3".into());
            }
            _ => {}
        }
    }
    // Wait with the same predicate used for stream 1: speculative budget reserved AND (where debug
    // counters are compiled in) stream 3's batch completed and its first frame delivered.
    let sync2 = Instant::now() + IO_TIMEOUT;
    loop {
        let spec_ready = miraserve_static::stream_speculative_used_bytes() == SPECULATIVE_BYTES;
        #[cfg(debug_assertions)]
        let stats_ready = {
            let s = miraserve_static::stream_pool_debug_stats();
            s.batches_completed
                .saturating_sub(stats_1.batches_completed)
                == 1
                && s.frames_delivered.saturating_sub(stats_1.frames_delivered) == 1
        };
        #[cfg(not(debug_assertions))]
        let stats_ready = true;
        if spec_ready && stats_ready {
            break;
        }
        assert!(
            Instant::now() < sync2,
            "timed out waiting for zero-window stream 3 Batch 1 completion"
        );
        tokio::task::yield_now().await;
    }
    // Round-trip a PING/PONG while stream 3's window stays 0 to confirm no DATA is sent and (in
    // debug builds) no second batch starts before RST_STREAM.
    let ping_bytes_s3 = [0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28];
    write_h2_frame(&mut conn, FRAME_PING, 0, 0, &ping_bytes_s3).await?;
    loop {
        let (ftype, flags, sid, payload) = read_h2_frame(&mut conn).await?;
        if ftype == FRAME_PING && (flags & FLAG_ACK_OR_EOS) != 0 {
            assert_eq!(payload, ping_bytes_s3);
            break;
        }
        if ftype == FRAME_SETTINGS && (flags & FLAG_ACK_OR_EOS) == 0 {
            write_h2_frame(&mut conn, FRAME_SETTINGS, FLAG_ACK_OR_EOS, 0, &[]).await?;
        }
        assert!(
            !(ftype == FRAME_DATA && sid == 3),
            "server must not send DATA while stream 3 window is 0"
        );
    }
    assert_eq!(
        miraserve_static::stream_speculative_used_bytes(),
        SPECULATIVE_BYTES,
        "zero-window stream 3 must hold 192 KiB of speculative budget before RST_STREAM"
    );
    #[cfg(debug_assertions)]
    {
        let s = miraserve_static::stream_pool_debug_stats();
        assert_eq!(
            s.batches_started.saturating_sub(stats_1.batches_started),
            1,
            "zero-window stream 3 must submit exactly 1 batch task"
        );
        assert_eq!(
            s.batches_completed
                .saturating_sub(stats_1.batches_completed),
            1,
            "zero-window stream 3 must complete exactly 1 batch task"
        );
        assert_eq!(
            s.chunks_read.saturating_sub(stats_1.chunks_read),
            4,
            "zero-window stream 3 must read at most 4 chunks (1 batch)"
        );
        assert_eq!(
            s.bytes_read.saturating_sub(stats_1.bytes_read),
            BATCH_BYTES,
            "zero-window stream 3 must read at most 256 KiB before RST_STREAM"
        );
        assert_eq!(
            s.frames_delivered.saturating_sub(stats_1.frames_delivered),
            1,
            "hyper must poll only its 1 lookahead frame on stream 3 while window is closed"
        );
    }
    // Cancel stream 3 with RST_STREAM(CANCEL = 0x8) and confirm budget drops back to 0.
    write_h2_frame(&mut conn, FRAME_RST_STREAM, 0, 3, &8_u32.to_be_bytes()).await?;
    write_h2_frame(&mut conn, FRAME_PING, 0, 0, &ping_bytes).await?;
    loop {
        let (ftype, flags, sid, payload) = read_h2_frame(&mut conn).await?;
        if ftype == FRAME_PING && (flags & FLAG_ACK_OR_EOS) != 0 {
            assert_eq!(payload, ping_bytes);
            break;
        }
        if ftype == FRAME_SETTINGS && (flags & FLAG_ACK_OR_EOS) == 0 {
            write_h2_frame(&mut conn, FRAME_SETTINGS, FLAG_ACK_OR_EOS, 0, &[]).await?;
        }
        assert!(
            !(ftype == FRAME_DATA && sid == 3),
            "server must not send DATA on reset zero-window stream 3"
        );
    }
    let release_deadline = Instant::now() + IO_TIMEOUT;
    while miraserve_static::stream_speculative_used_bytes() != 0 {
        assert!(
            Instant::now() < release_deadline,
            "RST_STREAM must release speculative stream budget back to 0"
        );
        tokio::task::yield_now().await;
    }
    #[cfg(debug_assertions)]
    {
        let s = miraserve_static::stream_pool_debug_stats();
        assert_eq!(
            s.batches_started.saturating_sub(stats_1.batches_started),
            1,
            "resetting zero-window stream 3 must not start a second batch"
        );
    }

    drop(conn);
    let _ = shutdown.send(true);
    Ok(())
}

/// Verifies `WriteGuardedIo` cuts a stalled HTTP/1.1 reader on a large streamed static file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http1_write_guard_cuts_stalled_reader_on_large_streamed_file() -> TestResult {
    let _stream_guard = STREAM_COUNTER_LOCK.read().await;
    let dir = TempDir::new("h1-write-guard")?;
    std::fs::write(dir.path.join("huge.bin"), vec![0x55_u8; 8 * 1024 * 1024])?;

    let idle = Duration::from_millis(300);
    let (addr, shutdown) = start_tcp_server(&dir.path, true, Some(idle))?;

    let mut client = connect_small_h1(addr).await?;
    client
        .write_all(b"GET /huge.bin HTTP/1.1\r\nHost: deploy.example.test\r\n\r\n")
        .await?;
    let (head, _initial) = read_h1_head(&mut client).await?;
    assert!(head.starts_with("HTTP/1.1 200 OK"));

    // Stop reading for > 3x `response-write-idle` so `WriteGuardedIo` trips on backpressure.
    let started = Instant::now();
    tokio::time::sleep(idle * 3).await;

    // Drain any already-queued loopback bytes; connection MUST hit EOF/reset far short of 8 MiB.
    let mut drained = Vec::new();
    let mut buf = vec![0_u8; 32 * 1024];
    let deadline = tokio::time::Instant::now() + IO_TIMEOUT;
    loop {
        let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!rem.is_zero(), "stalled HTTP/1.1 connection never closed");
        match tokio::time::timeout(rem, client.read(&mut buf)).await {
            Ok(Ok(0) | Err(_)) => break,
            Ok(Ok(n)) => drained.extend_from_slice(buf.get(..n).unwrap_or(&[])),
            Err(_) => return Err("stalled HTTP/1.1 connection hung".into()),
        }
    }
    assert!(
        drained.len() < 4 * 1024 * 1024,
        "WriteGuardedIo must cut stalled 8 MiB stream well before completion (got {} bytes in {:?})",
        drained.len(),
        started.elapsed()
    );

    let _ = shutdown.send(true);
    Ok(())
}

/// Verifies large non-zero `Range`, `If-Range`, and `HEAD` over real TCP for HTTP/1.1 and HTTP/2.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_file_range_if_range_and_head_over_tcp_http1_and_http2() -> TestResult {
    let _stream_guard = STREAM_COUNTER_LOCK.read().await;
    let dir = TempDir::new("tcp-range")?;
    let payload = make_payload(600 * 1024, 0x71);
    let full_hash = sha256(&payload);
    let slice_hash = sha256(payload.get(70_000..=450_000).unwrap_or(&[]));
    std::fs::write(dir.path.join("video.bin"), &payload)?;

    let (addr, shutdown) = start_tcp_server(&dir.path, false, None)?;
    let (mut h2_tx, h2_conn) = connect_h2_small_window(addr).await?;

    // HEAD over HTTP/2 -> gets ETag, exact Content-Length, empty body.
    let head_resp = h2_tx
        .send_request(
            Request::builder()
                .method(Method::HEAD)
                .uri("https://deploy.example.test/video.bin")
                .body(Empty::new())?,
        )
        .await?;
    assert_eq!(head_resp.status(), StatusCode::OK);
    assert_eq!(
        head_resp
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some("614400")
    );
    let etag = head_resp
        .headers()
        .get(ETAG)
        .cloned()
        .ok_or("HEAD missing ETag")?;
    assert_eq!(
        head_resp.into_body().collect().await?.to_bytes(),
        Bytes::new()
    );

    // Large non-zero Range + matching If-Range over HTTP/2 -> 206 exact slice hash.
    let r_match = h2_tx
        .send_request(
            Request::builder()
                .uri("https://deploy.example.test/video.bin")
                .header(RANGE, "bytes=70000-450000")
                .header(IF_RANGE, etag.clone())
                .body(Empty::new())?,
        )
        .await?;
    assert_eq!(r_match.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        r_match
            .headers()
            .get(CONTENT_RANGE)
            .and_then(|v| v.to_str().ok()),
        Some("bytes 70000-450000/614400")
    );
    assert_eq!(
        sha256(&r_match.into_body().collect().await?.to_bytes()),
        slice_hash
    );

    // Mismatching If-Range over HTTP/2 -> 200 full body hash.
    let r_miss = h2_tx
        .send_request(
            Request::builder()
                .uri("https://deploy.example.test/video.bin")
                .header(RANGE, "bytes=70000-450000")
                .header(IF_RANGE, "\"stale-etag\"")
                .body(Empty::new())?,
        )
        .await?;
    assert_eq!(r_miss.status(), StatusCode::OK);
    assert_eq!(
        sha256(&r_miss.into_body().collect().await?.to_bytes()),
        full_hash
    );

    // Large non-zero Range over HTTP/1.1 -> 206 exact slice hash.
    let mut h1 = TcpStream::connect(addr).await?;
    h1.write_all(
        format!(
            "GET /video.bin HTTP/1.1\r\nHost: deploy.example.test\r\nRange: bytes=70000-450000\r\nIf-Range: {}\r\nConnection: close\r\n\r\n",
            etag.to_str()?
        )
        .as_bytes(),
    )
    .await?;
    let (head, mut body) = read_h1_head(&mut h1).await?;
    assert!(head.starts_with("HTTP/1.1 206 Partial Content"));
    tokio::time::timeout(IO_TIMEOUT, h1.read_to_end(&mut body)).await??;
    assert_eq!(body.len(), 380_001);
    assert_eq!(sha256(&body), slice_hash);

    drop(h2_tx);
    let _ = h2_conn.await;
    let _ = shutdown.send(true);
    Ok(())
}

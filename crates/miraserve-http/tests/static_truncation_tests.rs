//! Real-TCP in-place file truncation tests (HTTP/1.1 and HTTP/2).
//!
//! Verifies what a client observes over a real TCP socket when a static file is truncated in place
//! after selection and after the server has advertised the original `Content-Length`:
//! - the body ends short of the advertised length,
//! - the HTTP/1.1 connection is closed, or the HTTP/2 stream fails, within a short timeout (the
//!   body ends early as in v0.1.3: hyper closes an HTTP/1.1 connection whose body is shorter than
//!   its `Content-Length`, and an HTTP/2 client rejects a stream that ends short of it),
//! - the transfer never hangs,
//! - every byte in the surviving prefix (`0..TRUNCATED_LEN`) and on the follow-up request is an
//!   exact byte of the file, and
//! - every byte received beyond `TRUNCATED_LEN` during the concurrent truncation race is either an
//!   authentic byte of the original file or `0x00` from Linux kernel `filemap_read` /
//!   `copy_folio_to_iter` racing with `ftruncate` page-cache zeroing inside the kernel's returned
//!   read count (never uninitialized memory or another file's data).

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::CONTENT_LENGTH;
use http::{Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use miraserve_config::parse_kdl;
use miraserve_http::HttpEngine;
use miraserve_tls::AcmeChallengeStore;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::watch;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// 4 MiB streaming file (> 256 KiB in-memory threshold and far larger than small TCP buffers).
const ORIGINAL_LEN: usize = 4 * 1024 * 1024;
const TRUNCATED_LEN: usize = 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Deterministic printable non-zero byte at file offset `idx` so any non-file byte (e.g. NUL
/// padding or garbage) is immediately detected.
#[allow(clippy::cast_possible_truncation)]
const fn pattern_byte(idx: usize) -> u8 {
    (((idx.wrapping_mul(131) ^ (idx >> 8)) & 0x3f) as u8) + b'!'
}

fn make_pattern_file(len: usize) -> Vec<u8> {
    (0..len).map(pattern_byte).collect()
}

fn assert_all_bytes_from_file(received: &[u8], context: &str) {
    for (idx, &got) in received.iter().enumerate() {
        let want = pattern_byte(idx);
        assert_eq!(
            got, want,
            "{context}: byte at offset {idx} does not match original file (got 0x{got:02x}, want 0x{want:02x})"
        );
    }
}

/// Validates bytes observed over TCP during a live in-place truncation race (`ORIGINAL_LEN` ->
/// `TRUNCATED_LEN`):
/// - Every byte in the surviving prefix (`0..TRUNCATED_LEN`) must match `pattern_byte(idx)`
///   strictly (no NULs).
/// - At `idx >= TRUNCATED_LEN`, Linux's lockless `filemap_read` / `copy_folio_to_iter` can
///   observe `0x00` inside `pread(2)`'s returned byte count when `ftruncate` concurrently zeroes
///   and invalidates truncated page-cache folios. Every byte in that region must therefore be
///   either `pattern_byte(idx)` or `0x00` — never uninitialized heap bytes or another file's data.
fn assert_truncated_stream_bytes(received: &[u8], context: &str) {
    for (idx, &got) in received.iter().enumerate() {
        let want = pattern_byte(idx);
        if idx < TRUNCATED_LEN {
            assert_eq!(
                got, want,
                "{context}: surviving prefix byte at offset {idx} (< {TRUNCATED_LEN}) does not match original file (got 0x{got:02x}, want 0x{want:02x})"
            );
        } else {
            assert!(
                got == want || got == 0x00,
                "{context}: truncated-region byte at offset {idx} is neither original file byte (0x{want:02x}) nor kernel zero-fill (0x00): got 0x{got:02x}"
            );
        }
    }
}

fn start_tcp_server(
    root: &Path,
    small_send_buf: bool,
) -> Result<(SocketAddr, watch::Sender<bool>), Box<dyn std::error::Error>> {
    let root_str = root.to_string_lossy().replace('\\', "/");
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
    timeouts {{
        response-write-idle "5s"
        graceful-drain "1s"
        idle-keepalive "5s"
    }}
}}
site "trunc.example.test" {{
    root "{root_str}"
}}
"#
    );
    let (cfg, _) = parse_kdl("trunc.kdl", &kdl)?;
    let engine = Arc::new(HttpEngine::from_config(
        &cfg,
        Arc::new(AcmeChallengeStore::new()),
        None,
        8443,
    )?);

    let socket = TcpSocket::new_v4()?;
    if small_send_buf {
        // Cap kernel send buffer on accepted sockets so the server cannot drain the entire
        // 4 MiB file into loopback buffers before the client reads the response headers and
        // truncates the file in place.
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
                _ = rx.changed() => {
                    break;
                }
            }
        }
    });

    Ok((addr, shutdown_tx))
}

/// Reads an HTTP/1.1 response head up to `\r\n\r\n`, returning `(header_text, initial_body_bytes)`.
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
            .map_err(|_| "timed out reading HTTP/1.1 response head")??;
        if n == 0 {
            return Err("EOF before end of HTTP/1.1 response head".into());
        }
        raw.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
    }
}

fn parse_content_length_from_head(head: &str) -> Option<usize> {
    head.lines().find_map(|line| {
        line.to_ascii_lowercase()
            .strip_prefix("content-length:")
            .and_then(|v| v.trim().parse::<usize>().ok())
    })
}

#[tokio::test]
async fn in_place_truncation_over_tcp_http1_ends_short_and_closes_without_hanging() -> TestResult {
    let root = std::env::temp_dir().join(format!(
        "miraserve-tcp-trunc-h1-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(&root)?;
    let file_path = root.join("trunc.bin");
    std::fs::write(&file_path, make_pattern_file(ORIGINAL_LEN))?;

    let (addr, shutdown_tx) = start_tcp_server(&root, true)?;

    // Connect with a small receive buffer so the server stays mid-stream when we receive headers.
    let sock = TcpSocket::new_v4()?;
    let _ = sock.set_recv_buffer_size(16 * 1024);
    let mut client = sock.connect(addr).await?;

    client
        .write_all(b"GET /trunc.bin HTTP/1.1\r\nHost: trunc.example.test\r\n\r\n")
        .await?;

    // Wait for response headers: selection has completed and the original length is advertised.
    let (head, mut body) = read_h1_head(&mut client).await?;
    assert!(
        head.starts_with("HTTP/1.1 200 OK"),
        "expected HTTP/1.1 200 OK, got: {head:?}"
    );
    assert_eq!(
        parse_content_length_from_head(&head),
        Some(ORIGINAL_LEN),
        "response must advertise the original selected length"
    );

    // Truncate the selected file in place after selection while the response body is streaming.
    std::fs::OpenOptions::new()
        .write(true)
        .open(&file_path)?
        .set_len(u64::try_from(TRUNCATED_LEN)?)?;

    // Drain until the server closes or resets the TCP connection; must complete within timeout.
    let mut buf = [0_u8; 16 * 1024];
    let deadline = tokio::time::Instant::now() + IO_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !remaining.is_zero(),
            "HTTP/1.1 client hung after in-place truncation (received {} / {} bytes)",
            body.len(),
            ORIGINAL_LEN
        );
        match tokio::time::timeout(remaining, client.read(&mut buf)).await {
            Ok(Ok(0) | Err(_)) => break,
            Ok(Ok(n)) => {
                body.extend_from_slice(buf.get(..n).unwrap_or(&[]));
                assert!(
                    body.len() <= ORIGINAL_LEN,
                    "server must never emit more bytes than advertised"
                );
            }
            Err(_) => {
                return Err(format!(
                    "HTTP/1.1 connection hung instead of closing after truncation (received {} bytes)",
                    body.len()
                )
                .into());
            }
        }
    }

    assert!(
        body.len() < ORIGINAL_LEN,
        "HTTP/1.1 body must end strictly short of advertised {ORIGINAL_LEN} bytes (got {})",
        body.len()
    );
    assert_truncated_stream_bytes(&body, "HTTP/1.1 truncated stream");

    // Next request on a fresh TCP connection sees the truncated file cleanly with length 1024.
    let mut next = TcpStream::connect(addr).await?;
    next.write_all(
        b"GET /trunc.bin HTTP/1.1\r\nHost: trunc.example.test\r\nConnection: close\r\n\r\n",
    )
    .await?;
    let (next_head, mut next_body) = read_h1_head(&mut next).await?;
    assert!(next_head.starts_with("HTTP/1.1 200 OK"));
    assert_eq!(
        parse_content_length_from_head(&next_head),
        Some(TRUNCATED_LEN)
    );
    tokio::time::timeout(IO_TIMEOUT, next.read_to_end(&mut next_body)).await??;
    assert_eq!(next_body.len(), TRUNCATED_LEN);
    assert_all_bytes_from_file(&next_body, "HTTP/1.1 post-truncation request");

    let _ = shutdown_tx.send(true);
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn in_place_truncation_over_tcp_http2_ends_short_and_fails_the_stream_without_hanging()
-> TestResult {
    let root = std::env::temp_dir().join(format!(
        "miraserve-tcp-trunc-h2-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(&root)?;
    let file_path = root.join("trunc_h2.bin");
    std::fs::write(&file_path, make_pattern_file(ORIGINAL_LEN))?;

    let (addr, shutdown_tx) = start_tcp_server(&root, false)?;

    let stream = TcpStream::connect(addr).await?;
    let mut client_builder = http2::Builder::new(TokioExecutor::new());
    client_builder
        .initial_stream_window_size(65_535)
        .initial_connection_window_size(8 * 1024 * 1024);
    let (mut sender, conn) = client_builder
        .handshake::<_, Empty<Bytes>>(TokioIo::new(stream))
        .await?;
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .uri("https://trunc.example.test/trunc_h2.bin")
        .body(Empty::new())?;
    let resp = tokio::time::timeout(IO_TIMEOUT, sender.send_request(req))
        .await
        .map_err(|_| "timed out awaiting HTTP/2 response headers")??;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some(ORIGINAL_LEN.to_string().as_str()),
        "HTTP/2 response must advertise the original selected length"
    );

    // Selection has completed and headers have arrived while the stream is flow-control paused
    // after at most 64 KiB. Truncate the file in place to 1024 bytes.
    std::fs::OpenOptions::new()
        .write(true)
        .open(&file_path)?
        .set_len(u64::try_from(TRUNCATED_LEN)?)?;

    // Drain DATA frames until stream reset / error; must not hang and must not finish cleanly.
    let mut body_stream = resp.into_body();
    let mut received = Vec::new();
    let mut saw_stream_reset_or_error = false;
    let deadline = tokio::time::Instant::now() + IO_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !remaining.is_zero(),
            "HTTP/2 client hung after in-place truncation (received {} / {} bytes)",
            received.len(),
            ORIGINAL_LEN
        );
        match tokio::time::timeout(remaining, body_stream.frame()).await {
            Ok(Some(Ok(frame))) => {
                if let Ok(data) = frame.into_data() {
                    received.extend_from_slice(&data);
                    assert!(
                        received.len() <= ORIGINAL_LEN,
                        "HTTP/2 server must never emit more bytes than advertised"
                    );
                }
            }
            Ok(Some(Err(_))) => {
                saw_stream_reset_or_error = true;
                break;
            }
            Ok(None) => {
                break;
            }
            Err(_) => {
                return Err(format!(
                    "HTTP/2 stream hung instead of failing after truncation (received {} bytes)",
                    received.len()
                )
                .into());
            }
        }
    }

    assert!(
        saw_stream_reset_or_error,
        "HTTP/2 stream must be reset/errored (not cleanly closed) when truncated short of Content-Length"
    );
    assert!(
        received.len() < ORIGINAL_LEN,
        "HTTP/2 body must end strictly short of advertised {ORIGINAL_LEN} bytes (got {})",
        received.len()
    );
    assert_truncated_stream_bytes(&received, "HTTP/2 truncated stream");

    // Next HTTP/2 request sees the truncated 1024-byte file cleanly.
    let next_req = Request::builder()
        .uri("https://trunc.example.test/trunc_h2.bin")
        .body(Empty::new())?;
    let next_resp = tokio::time::timeout(IO_TIMEOUT, sender.send_request(next_req))
        .await
        .map_err(|_| "timed out awaiting follow-up HTTP/2 response")??;
    assert_eq!(next_resp.status(), StatusCode::OK);
    assert_eq!(
        next_resp
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some(TRUNCATED_LEN.to_string().as_str())
    );
    let next_bytes = tokio::time::timeout(IO_TIMEOUT, next_resp.into_body().collect())
        .await??
        .to_bytes();
    assert_eq!(next_bytes.len(), TRUNCATED_LEN);
    assert_all_bytes_from_file(&next_bytes, "HTTP/2 post-truncation request");

    drop(sender);
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(IO_TIMEOUT, conn_task).await;
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

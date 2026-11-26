//! Paused-time regression suite for the released per-phase `HeadDeadlineIo` and
//! `first_req_deadline` HTTP/1.1 connection timers.
//!
//! Every test runs under `#[tokio::test(start_paused = true)]` (or pauses explicitly after the
//! loopback TCP upgrade handshake) so Tokio's virtual clock advances to exact millisecond
//! boundaries with zero wall-clock jitter. Close observations verify EOF with a non-blocking poll,
//! assert that virtual time did NOT auto-advance across the observation, verify exact virtual
//! elapsed time since the phase started, and identify the closing timer from the connection close
//! path's baseline outcomes (without adding production log fields).

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use miraserve_config::parse_kdl;
use miraserve_http::HttpEngine;
use miraserve_tls::AcmeChallengeStore;
use tokio::io::{AsyncRead as _, AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::instrument::WithSubscriber as _;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const REQ_OK: &[u8] = b"GET /ok HTTP/1.1\r\nHost: pt.example.test\r\n\r\n";

#[derive(Clone, Default)]
struct LogCapture(Arc<Mutex<Vec<u8>>>);

impl io::Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Ok(mut guard) = self.0.lock() {
            guard.extend_from_slice(buf);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl LogCapture {
    fn text(&self) -> String {
        let bytes = self.0.lock().map(|g| g.clone()).unwrap_or_default();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

#[derive(Clone, Copy, Debug)]
enum ExpectedTimer {
    /// `HeadDeadlineIo`'s keep-alive idle timer (`idle-keepalive`) with an empty read buffer
    /// (hyper treats the I/O `TimedOut` between requests as clean EOF).
    IdleKeepaliveCleanEof,
    /// `HeadDeadlineIo`'s keep-alive idle timer (`idle-keepalive`) while partial pipelined bytes
    /// are buffered in hyper (hyper surfaces the `TimedOut` error to the connection close path).
    IdleKeepaliveMidParse,
    /// `HeadDeadlineIo`'s header-read timer (`header-read`).
    HeaderRead,
    /// Connection-level `first_req_deadline` before the first request reaches the service.
    FirstRequest,
}

struct EngineFixture {
    client: DuplexStream,
    server_task: tokio::task::JoinHandle<()>,
    logs: LogCapture,
    _shutdown: watch::Sender<bool>,
}

fn build_engine(
    header_read: &str,
    idle_keepalive: &str,
    extra_routes: &str,
) -> Result<Arc<HttpEngine>, Box<dyn std::error::Error>> {
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
    timeouts {{
        header-read "{header_read}"
        idle-keepalive "{idle_keepalive}"
    }}
}}
site "pt.example.test" {{
    route "/ok" {{
        redirect "https://pt.example.test/dest" status=301
    }}
    {extra_routes}
}}
"#
    );
    let (cfg, _) = parse_kdl("paused-head-deadline.kdl", &kdl)?;
    Ok(Arc::new(HttpEngine::from_config(
        &cfg,
        Arc::new(AcmeChallengeStore::new()),
        None,
        8443,
    )?))
}

fn spawn_conn(
    header_read: &str,
    idle_keepalive: &str,
) -> Result<EngineFixture, Box<dyn std::error::Error>> {
    let engine = build_engine(header_read, idle_keepalive, "")?;
    let (client, server) = tokio::io::duplex(64 * 1024);
    let peer: SocketAddr = "198.51.100.21:50000".parse()?;
    let local: SocketAddr = "127.0.0.1:8443".parse()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let logs = LogCapture::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(false)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let server_task = tokio::spawn(
        engine
            .serve_hyper_connection(server, peer, local, true, false, None, shutdown_rx)
            .with_subscriber(subscriber),
    );
    Ok(EngineFixture {
        client,
        server_task,
        logs,
        _shutdown: shutdown_tx,
    })
}

/// Yield several times so spawned connection tasks run to a parked state without advancing time.
async fn settle() {
    let before = tokio::time::Instant::now();
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        tokio::time::Instant::now(),
        before,
        "settle() must never advance paused virtual time"
    );
}

/// Reads one HTTP/1.1 response from `buf`/`client`, preserving any pipelined tail bytes in `buf`.
async fn read_one_response(
    client: &mut DuplexStream,
    buf: &mut Vec<u8>,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut chunk = [0_u8; 4096];
    loop {
        if let Some(head_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(buf.get(..head_end).unwrap_or(&[])).into_owned();
            let content_len = head
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|v| v.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            let total = head_end + 4 + content_len;
            if buf.len() >= total {
                let status_line = head.lines().next().unwrap_or("").to_owned();
                buf.drain(..total);
                return Ok(status_line);
            }
        }
        let n = client.read(&mut chunk).await?;
        if n == 0 {
            return Err("server closed connection before response completed".into());
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
    }
}

/// Confirms the server has NOT closed the connection right now without advancing paused time.
async fn assert_still_open(fx: &mut EngineFixture) -> TestResult {
    let before = tokio::time::Instant::now();
    settle().await;
    assert_eq!(
        tokio::time::Instant::now(),
        before,
        "paused time advanced during assert_still_open"
    );
    assert!(
        !fx.server_task.is_finished(),
        "connection task exited prematurely; logs:\n{}",
        fx.logs.text()
    );
    let noop = Waker::noop();
    let mut cx = Context::from_waker(noop);
    let mut byte = [0_u8; 16];
    let mut rb = ReadBuf::new(&mut byte);
    let poll = Pin::new(&mut fx.client).poll_read(&mut cx, &mut rb);
    assert!(
        matches!(poll, Poll::Pending),
        "expected open quiet connection (Poll::Pending), got {poll:?} (filled={}); logs:\n{}",
        rb.filled().len(),
        fx.logs.text()
    );
    Ok(())
}

fn assert_closing_timer_logged(
    logs: &str,
    expected_elapsed: Duration,
    expected_timer: ExpectedTimer,
) {
    // Identify the winning timer strictly from the baseline `416f01f` connection close outcomes:
    // - `HeadDeadlineIo` idle expiry on an empty read buffer is treated by hyper as clean EOF
    //   (`conn.await == Ok(())`), emitting none of the error/timeout close events (whereas hyper's
    //   backstop returns `Err(read header from client timeout)` at `idle + header`).
    // - `HeadDeadlineIo` idle expiry with buffered pipelined bytes surfaces an I/O `TimedOut`
    //   while `idle_since_ms > 0 && !head_in_progress`, emitting `closing idle keep-alive connection`.
    // - `HeadDeadlineIo` head expiry surfaces an I/O `TimedOut` (`error=connection error`) while
    //   `head_in_progress == true`, emitting `closing slow client HTTP connection` without hyper's
    //   `read header from client timeout` message.
    // - `first_req_deadline` emits `closing slow/idle client connection before initial request`.
    match expected_timer {
        ExpectedTimer::IdleKeepaliveCleanEof => {
            assert!(
                !logs.contains("closing idle keep-alive connection")
                    && !logs.contains("closing slow client HTTP connection")
                    && !logs.contains("before initial request")
                    && !logs.contains("HTTP connection closed with error")
                    && !logs.contains("read header from client timeout"),
                "expected clean-EOF HeadDeadlineIo idle-keepalive close at {expected_elapsed:?}, got logs:\n{logs}"
            );
        }
        ExpectedTimer::IdleKeepaliveMidParse => {
            assert!(
                logs.contains("closing idle keep-alive connection"),
                "expected HeadDeadlineIo mid-parse idle-keepalive close at {expected_elapsed:?}, got logs:\n{logs}"
            );
            assert!(
                !logs.contains("before initial request")
                    && !logs.contains("closing slow client HTTP connection")
                    && !logs.contains("read header from client timeout"),
                "unexpected timer fired alongside mid-parse idle-keepalive:\n{logs}"
            );
        }
        ExpectedTimer::HeaderRead => {
            assert!(
                logs.contains("closing slow client HTTP connection")
                    && logs.contains("error=connection error"),
                "expected HeadDeadlineIo header-read I/O close at {expected_elapsed:?}, got logs:\n{logs}"
            );
            assert!(
                !logs.contains("read header from client timeout")
                    && !logs.contains("closing idle keep-alive connection")
                    && !logs.contains("before initial request"),
                "unexpected timer fired alongside header-read:\n{logs}"
            );
        }
        ExpectedTimer::FirstRequest => {
            assert!(
                logs.contains("closing slow/idle client connection before initial request"),
                "expected first_req_deadline close at {expected_elapsed:?}, got logs:\n{logs}"
            );
            assert!(
                !logs.contains("closing idle keep-alive connection")
                    && !logs.contains("closing slow client HTTP connection")
                    && !logs.contains("read header from client timeout"),
                "unexpected HeadDeadlineIo timer fired before first request:\n{logs}"
            );
        }
    }
}

/// Confirms the server closed the connection at the EXACT current virtual time (`phase_start +
/// expected_elapsed`) with zero virtual-clock auto-advance, non-blocking EOF observation, and the
/// exact expected timer outcome in the connection task's logs.
async fn assert_closed_now_by(
    fx: &mut EngineFixture,
    phase_start: tokio::time::Instant,
    expected_elapsed: Duration,
    expected_timer: ExpectedTimer,
) -> TestResult {
    let before = tokio::time::Instant::now();
    assert_eq!(
        before.duration_since(phase_start),
        expected_elapsed,
        "virtual clock mismatch before close observation"
    );
    settle().await;
    assert_eq!(
        tokio::time::Instant::now(),
        before,
        "paused virtual time auto-advanced during close observation"
    );
    assert!(
        fx.server_task.is_finished(),
        "connection task did not finish immediately at {expected_elapsed:?} (would have relied on a later timer such as hyper's backstop); logs:\n{}",
        fx.logs.text()
    );
    let noop = Waker::noop();
    let mut cx = Context::from_waker(noop);
    let mut byte = [0_u8; 16];
    let mut rb = ReadBuf::new(&mut byte);
    match Pin::new(&mut fx.client).poll_read(&mut cx, &mut rb) {
        Poll::Ready(Ok(())) => {
            assert_eq!(
                rb.filled().len(),
                0,
                "expected server EOF after timeout, read {} bytes",
                rb.filled().len()
            );
        }
        other => {
            return Err(format!(
                "expected immediate non-blocking EOF at {expected_elapsed:?}, got {other:?}; logs:\n{}",
                fx.logs.text()
            )
            .into());
        }
    }
    (&mut fx.server_task).await?;
    assert_eq!(
        tokio::time::Instant::now(),
        before,
        "paused virtual time advanced while joining already-finished server task"
    );
    assert_closing_timer_logged(&fx.logs.text(), expected_elapsed, expected_timer);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn idle_expiry_at_exact_idle_timeout_after_flush() -> TestResult {
    let mut fx = spawn_conn("5s", "20s")?;
    let mut buf = Vec::new();

    fx.client.write_all(REQ_OK).await?;
    assert!(
        read_one_response(&mut fx.client, &mut buf)
            .await?
            .contains("301")
    );
    settle().await;
    let idle_start = tokio::time::Instant::now();

    // 1 ms before idle_timeout: connection MUST still be alive.
    tokio::time::advance(Duration::from_millis(19_999)).await;
    assert_still_open(&mut fx).await?;

    // Crossing idle_timeout (Tokio 1 ms tick): `HeadDeadlineIo`'s idle timer MUST close at 20.001 s
    // (strictly before hyper's 25 s backstop, with zero virtual-clock auto-advance).
    tokio::time::advance(Duration::from_millis(2)).await;
    assert_closed_now_by(
        &mut fx,
        idle_start,
        Duration::from_millis(20_001),
        ExpectedTimer::IdleKeepaliveCleanEof,
    )
    .await?;

    // Reverse ordering (`idle_keepalive < header_read`): still closes at exact idle_keepalive.
    let mut fx_short = spawn_conn("20s", "3s")?;
    let mut buf2 = Vec::new();
    fx_short.client.write_all(REQ_OK).await?;
    assert!(
        read_one_response(&mut fx_short.client, &mut buf2)
            .await?
            .contains("301")
    );
    settle().await;
    let short_idle_start = tokio::time::Instant::now();
    tokio::time::advance(Duration::from_millis(2_999)).await;
    assert_still_open(&mut fx_short).await?;
    tokio::time::advance(Duration::from_millis(2)).await;
    assert_closed_now_by(
        &mut fx_short,
        short_idle_start,
        Duration::from_millis(3_001),
        ExpectedTimer::IdleKeepaliveCleanEof,
    )
    .await?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn head_expiry_at_exact_header_timeout_after_first_byte() -> TestResult {
    // 1. Head starts early in idle (`idle = 20s`, `header = 5s`): starts at +2s, expires at +7s.
    let mut fx = spawn_conn("5s", "20s")?;
    let mut buf = Vec::new();
    fx.client.write_all(REQ_OK).await?;
    assert!(
        read_one_response(&mut fx.client, &mut buf)
            .await?
            .contains("301")
    );
    settle().await;

    tokio::time::advance(Duration::from_secs(2)).await;
    fx.client.write_all(b"GET /ok ").await?;
    settle().await;
    let head_start = tokio::time::Instant::now();

    tokio::time::advance(Duration::from_millis(4_999)).await;
    assert_still_open(&mut fx).await?;

    tokio::time::advance(Duration::from_millis(2)).await;
    assert_closed_now_by(
        &mut fx,
        head_start,
        Duration::from_millis(5_001),
        ExpectedTimer::HeaderRead,
    )
    .await?;

    // 2. Head starts late in idle (`idle = 20s`, `header = 5s`): starts at +18s.
    //    Reading the first byte replaces the +20s idle Sleep with a fresh +5s head Sleep (+23s).
    let mut fx_late = spawn_conn("5s", "20s")?;
    let mut buf2 = Vec::new();
    fx_late.client.write_all(REQ_OK).await?;
    assert!(
        read_one_response(&mut fx_late.client, &mut buf2)
            .await?
            .contains("301")
    );
    settle().await;

    tokio::time::advance(Duration::from_secs(18)).await;
    fx_late.client.write_all(b"GET /ok ").await?;
    settle().await;
    let late_head_start = tokio::time::Instant::now();

    // Cross the old +20s idle deadline (+2.5s into head = +20.5s total): MUST stay open!
    tokio::time::advance(Duration::from_millis(2_500)).await;
    assert_still_open(&mut fx_late).await?;

    // 1 ms before +23s (+4,999ms into head): still open.
    tokio::time::advance(Duration::from_millis(2_499)).await;
    assert_still_open(&mut fx_late).await?;

    // Cross +23s (+5,001ms into head): MUST close via HeadDeadlineIo header-read timer!
    tokio::time::advance(Duration::from_millis(2)).await;
    assert_closed_now_by(
        &mut fx_late,
        late_head_start,
        Duration::from_millis(5_001),
        ExpectedTimer::HeaderRead,
    )
    .await?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn request_arriving_just_before_idle_expiry_succeeds() -> TestResult {
    let mut fx = spawn_conn("5s", "20s")?;
    let mut buf = Vec::new();

    fx.client.write_all(REQ_OK).await?;
    assert!(
        read_one_response(&mut fx.client, &mut buf)
            .await?
            .contains("301")
    );
    settle().await;

    // Arrive 5 ms before idle expiry twice in a row.
    for _ in 0..2 {
        tokio::time::advance(Duration::from_millis(19_995)).await;
        fx.client.write_all(REQ_OK).await?;
        assert!(
            read_one_response(&mut fx.client, &mut buf)
                .await?
                .contains("301")
        );
        settle().await;
    }

    // Finally let it sit idle past idle_timeout -> closes cleanly via idle-keepalive at 20.001 s.
    let final_idle_start = tokio::time::Instant::now();
    tokio::time::advance(Duration::from_millis(19_999)).await;
    assert_still_open(&mut fx).await?;
    tokio::time::advance(Duration::from_millis(2)).await;
    assert_closed_now_by(
        &mut fx,
        final_idle_start,
        Duration::from_millis(20_001),
        ExpectedTimer::IdleKeepaliveCleanEof,
    )
    .await?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn back_to_back_requests_outlive_both_timeouts_without_expiry() -> TestResult {
    // `header = 2s`, `idle = 5s`; send 30 requests spaced 500 ms apart = 15 s > both timeouts.
    let mut fx = spawn_conn("2s", "5s")?;
    let mut buf = Vec::new();

    for i in 0..30_usize {
        fx.client.write_all(REQ_OK).await?;
        let status = read_one_response(&mut fx.client, &mut buf).await?;
        assert!(status.contains("301"), "request {i} failed: {status}");
        settle().await;
        tokio::time::advance(Duration::from_millis(500)).await;
    }

    // Also verify a rapid burst (10 ms spacing) crossing a 2s boundary after a 1.9s idle gap.
    tokio::time::advance(Duration::from_millis(1_400)).await;
    for i in 0..40_usize {
        fx.client.write_all(REQ_OK).await?;
        let status = read_one_response(&mut fx.client, &mut buf).await?;
        assert!(status.contains("301"), "burst request {i} failed: {status}");
        settle().await;
        tokio::time::advance(Duration::from_millis(10)).await;
    }
    assert_still_open(&mut fx).await?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn pipelined_requests_full_and_partial() -> TestResult {
    // 1. Three full pipelined requests in one write all succeed and leave the connection healthy.
    let mut fx = spawn_conn("2s", "10s")?;
    let mut buf = Vec::new();
    let mut three = Vec::with_capacity(REQ_OK.len() * 3);
    for _ in 0..3 {
        three.extend_from_slice(REQ_OK);
    }
    fx.client.write_all(&three).await?;
    for i in 0..3 {
        let status = read_one_response(&mut fx.client, &mut buf).await?;
        assert!(status.contains("301"), "pipelined {i}: {status}");
    }
    settle().await;
    // Wait longer than header_read (2s) but inside idle_keepalive (10s): must stay open and serve #4.
    tokio::time::advance(Duration::from_secs(6)).await;
    fx.client.write_all(REQ_OK).await?;
    assert!(
        read_one_response(&mut fx.client, &mut buf)
            .await?
            .contains("301")
    );
    settle().await;

    // 2. Request 1 + partial Request 2 in one write: partial bytes read in-flight do NOT expire
    //    at header_read (2s), and completing Request 2 before idle_keepalive (10s) succeeds.
    let mut partial = Vec::from(REQ_OK);
    partial.extend_from_slice(b"GET /ok ");
    fx.client.write_all(&partial).await?;
    assert!(
        read_one_response(&mut fx.client, &mut buf)
            .await?
            .contains("301")
    );
    settle().await;

    tokio::time::advance(Duration::from_secs(4)).await;
    assert_still_open(&mut fx).await?;
    fx.client
        .write_all(b"HTTP/1.1\r\nHost: pt.example.test\r\n\r\n")
        .await?;
    assert!(
        read_one_response(&mut fx.client, &mut buf)
            .await?
            .contains("301")
    );
    settle().await;

    // 3. Stalled pipelined partial request still closes at exact idle_keepalive (10.001 s) via
    //    HeadDeadlineIo's idle timer (before hyper's 12 s backstop).
    fx.client.write_all(&partial).await?;
    assert!(
        read_one_response(&mut fx.client, &mut buf)
            .await?
            .contains("301")
    );
    settle().await;
    let partial_idle_start = tokio::time::Instant::now();
    tokio::time::advance(Duration::from_millis(9_999)).await;
    assert_still_open(&mut fx).await?;
    tokio::time::advance(Duration::from_millis(2)).await;
    assert_closed_now_by(
        &mut fx,
        partial_idle_start,
        Duration::from_millis(10_001),
        ExpectedTimer::IdleKeepaliveMidParse,
    )
    .await?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn head_split_across_reads_completes_or_expires_from_first_byte() -> TestResult {
    let mut fx = spawn_conn("5s", "20s")?;
    let mut buf = Vec::new();
    fx.client.write_all(REQ_OK).await?;
    assert!(
        read_one_response(&mut fx.client, &mut buf)
            .await?
            .contains("301")
    );
    settle().await;

    // Sit idle 18 s, then drip a valid head over 3 s (crossing the 20 s idle mark!).
    tokio::time::advance(Duration::from_secs(18)).await;
    let parts: &[&[u8]] = &[
        b"GET /ok ",
        b"HTTP/1.1\r\n",
        b"Host: pt.example.test\r\n",
        b"\r\n",
    ];
    for (idx, part) in parts.iter().enumerate() {
        fx.client.write_all(part).await?;
        settle().await;
        if idx + 1 < parts.len() {
            tokio::time::advance(Duration::from_secs(1)).await;
            assert_still_open(&mut fx).await?;
        }
    }
    assert!(
        read_one_response(&mut fx.client, &mut buf)
            .await?
            .contains("301")
    );
    settle().await;

    // Split head that stalls after chunk 2 MUST expire at header_read (5s) from chunk 1, not chunk 2.
    fx.client.write_all(b"GET /ok ").await?;
    settle().await;
    let split_head_start = tokio::time::Instant::now();
    tokio::time::advance(Duration::from_secs(2)).await;
    fx.client.write_all(b"HTTP/1.1\r\n").await?;
    settle().await;

    tokio::time::advance(Duration::from_millis(2_999)).await; // 4,999 ms from first byte
    assert_still_open(&mut fx).await?;
    tokio::time::advance(Duration::from_millis(2)).await; // 5,001 ms from first byte
    assert_closed_now_by(
        &mut fx,
        split_head_start,
        Duration::from_millis(5_001),
        ExpectedTimer::HeaderRead,
    )
    .await?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn first_request_bounded_by_first_req_deadline() -> TestResult {
    // 1. Zero bytes sent after connect -> expires at header_read (4.001 s) via `first_req_deadline`.
    let mut fx_silent = spawn_conn("4s", "30s")?;
    settle().await;
    let silent_start = tokio::time::Instant::now();
    tokio::time::advance(Duration::from_millis(3_999)).await;
    assert_still_open(&mut fx_silent).await?;
    tokio::time::advance(Duration::from_millis(2)).await;
    assert_closed_now_by(
        &mut fx_silent,
        silent_start,
        Duration::from_millis(4_001),
        ExpectedTimer::FirstRequest,
    )
    .await?;

    // 2. Partial first head sent immediately and stalled -> expires at 4.001 s via `first_req_deadline`.
    let mut fx_partial = spawn_conn("4s", "30s")?;
    let partial_start = tokio::time::Instant::now();
    fx_partial.client.write_all(b"GET /ok ").await?;
    settle().await;
    tokio::time::advance(Duration::from_millis(3_999)).await;
    assert_still_open(&mut fx_partial).await?;
    tokio::time::advance(Duration::from_millis(2)).await;
    assert_closed_now_by(
        &mut fx_partial,
        partial_start,
        Duration::from_millis(4_001),
        ExpectedTimer::FirstRequest,
    )
    .await?;

    // 3. Complete first head arriving just before first_req_deadline succeeds, then enters idle.
    let mut fx_ok = spawn_conn("4s", "30s")?;
    let mut buf = Vec::new();
    // Let the spawned connection task poll once and arm its 4 s first-request deadline at t = 0
    // before advancing virtual time (on current-thread runtime, `advance` jumps the clock first).
    settle().await;
    tokio::time::advance(Duration::from_millis(3_950)).await;
    fx_ok.client.write_all(REQ_OK).await?;
    assert!(
        read_one_response(&mut fx_ok.client, &mut buf)
            .await?
            .contains("301")
    );
    settle().await;
    // Now idle for 20s (> header_read, < idle_keepalive): MUST survive!
    tokio::time::advance(Duration::from_secs(20)).await;
    assert_still_open(&mut fx_ok).await?;
    fx_ok.client.write_all(REQ_OK).await?;
    assert!(
        read_one_response(&mut fx_ok.client, &mut buf)
            .await?
            .contains("301")
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn upgraded_websocket_connection_outlives_both_timeouts() -> TestResult {
    // Tiny loopback upstream that completes a 101 Switching Protocols upgrade and echoes bytes.
    // Note: keep the clock unpaused during the loopback TCP handshake/echo so Tokio's paused-time
    // auto-advance cannot fire the reverse proxy's response timeout while the OS socket briefly
    // parks; pause explicitly once the 101 upgrade has completed to advance 120 s instantaneously.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = listener.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let mut req_buf = Vec::new();
        let mut tmp = [0_u8; 1024];
        while !req_buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let Ok(n) = sock.read(&mut tmp).await else {
                return;
            };
            if n == 0 {
                return;
            }
            req_buf.extend_from_slice(tmp.get(..n).unwrap_or(&[]));
        }
        let resp = concat!(
            "HTTP/1.1 101 Switching Protocols\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
            "\r\n"
        );
        if sock.write_all(resp.as_bytes()).await.is_err() {
            return;
        }
        let mut echo = [0_u8; 64];
        while let Ok(n) = sock.read(&mut echo).await {
            if n == 0 {
                break;
            }
            if sock.write_all(echo.get(..n).unwrap_or(&[])).await.is_err() {
                break;
            }
        }
    });

    let route = format!(
        r#"
    route "/ws" {{
        reverse-proxy {{
            upstream "http://{upstream_addr}"
        }}
    }}
"#
    );
    let engine = build_engine("2s", "5s", &route)?;
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    let peer: SocketAddr = "198.51.100.22:50000".parse()?;
    let local: SocketAddr = "127.0.0.1:8443".parse()?;
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(engine.serve_hyper_connection(
        server,
        peer,
        local,
        true,
        false,
        None,
        shutdown_rx,
    ));

    // Perform a normal request first so `HeadDeadlineIo` arms an idle phase timer, then upgrade.
    let mut buf = Vec::new();
    client.write_all(REQ_OK).await?;
    assert!(
        read_one_response(&mut client, &mut buf)
            .await?
            .contains("301")
    );
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }

    let ws_req = concat!(
        "GET /ws HTTP/1.1\r\n",
        "Host: pt.example.test\r\n",
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        "Sec-WebSocket-Version: 13\r\n",
        "\r\n"
    );
    client.write_all(ws_req.as_bytes()).await?;
    let status = read_one_response(&mut client, &mut buf).await?;
    assert!(status.contains("101"), "expected 101 upgrade, got {status}");

    // Pause Tokio time now that the upgraded tunnel is established and advance far past BOTH
    // header_read (2s) and idle_keepalive (5s), then resume before loopback TCP echo I/O.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(120)).await;
    settle().await;
    tokio::time::resume();

    client.write_all(b"ping-after-upgrade").await?;
    let mut echoed = [0_u8; 18];
    client.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"ping-after-upgrade");

    drop(client);
    let _ = upstream_task.await;
    Ok(())
}

/// Proves that HTTP/1.1 `HeadDeadlineIo` phase deadlines (`header_read = 2s`, `idle_keepalive = 5s`)
/// and `first_req_deadline` do NOT apply once a connection speaks HTTP/2.
///
/// Note on clocks: `h2_watch`'s HTTP/2 idle-age check measures elapsed time with `std::time::Instant`
/// (`monotonic_idle_ms`), which does NOT advance under paused Tokio virtual time. Advancing
/// Tokio's virtual clock by 120 s therefore proves specifically that HTTP/1.1 Tokio-clock phase
/// timers (`HeadDeadlineIo` and `first_req_deadline`) never fire on HTTP/2 connections — NOT that
/// an HTTP/2 connection survived 120 s of real HTTP/2 idleness.
#[tokio::test(start_paused = true)]
async fn connection_going_http2_never_triggers_h1_phase_timers() -> TestResult {
    let engine = build_engine("2s", "5s", "")?;
    let (client, server) = tokio::io::duplex(64 * 1024);
    let peer: SocketAddr = "198.51.100.23:50000".parse()?;
    let local: SocketAddr = "127.0.0.1:8443".parse()?;
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(engine.serve_hyper_connection(
        server,
        peer,
        local,
        true,
        false,
        None,
        shutdown_rx,
    ));

    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), TokioIo::new(client)).await?;
    let driver = tokio::spawn(async move {
        let _ = conn.await;
    });

    let req1 = Request::builder()
        .uri("https://pt.example.test/ok")
        .body(Empty::<Bytes>::new())?;
    let resp1 = sender.send_request(req1).await?;
    assert_eq!(resp1.status(), StatusCode::MOVED_PERMANENTLY);
    let _ = resp1.into_body().collect().await?;
    settle().await;

    // Advance paused Tokio virtual time far past both H1 timeouts (`header_read = 2s`,
    // `idle_keepalive = 5s`). Because HTTP/2 idle age uses `std::time::Instant`, this proves that
    // HTTP/1.1 Tokio-clock deadlines do not apply to H2 (not 120 s of real H2 idleness).
    tokio::time::advance(Duration::from_secs(120)).await;
    settle().await;

    let req2 = Request::builder()
        .uri("https://pt.example.test/ok")
        .body(Empty::<Bytes>::new())?;
    let resp2 = sender.send_request(req2).await?;
    assert_eq!(resp2.status(), StatusCode::MOVED_PERMANENTLY);
    let _ = resp2.into_body().collect().await?;

    driver.abort();
    Ok(())
}

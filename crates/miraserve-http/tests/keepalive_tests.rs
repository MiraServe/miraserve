//! HTTP/1.1 keep-alive timing. Staging finding: an idle keep-alive connection was closed after
//! `header-read` (10 s) instead of `idle-keepalive` (60 s), with a warning each time. An idle
//! connection must wait the idle limit, while a client that starts a request head and stalls
//! must still be cut after `header-read`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use miraserve_config::parse_kdl;
use miraserve_http::HttpEngine;
use miraserve_tls::AcmeChallengeStore;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};
use tokio::sync::watch;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const HEADER_READ: Duration = Duration::from_millis(400);
const IDLE_KEEPALIVE: Duration = Duration::from_millis(2_000);
const REQUEST: &[u8] = b"GET /hello.txt HTTP/1.1\r\nHost: ka.example.test\r\n\r\n";

struct Fixture {
    client: DuplexStream,
    _shutdown: watch::Sender<bool>,
    root: std::path::PathBuf,
}

fn start(tag: &str) -> Result<Fixture, Box<dyn std::error::Error>> {
    start_with(tag, "400ms", "2s")
}

fn start_with(
    tag: &str,
    header_read: &str,
    idle_keepalive: &str,
) -> Result<Fixture, Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!("miraserve-ka-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("hello.txt"), b"hello keep-alive")?;
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
site "ka.example.test" {{
    root "{}"
}}
"#,
        root.display()
    );
    let (cfg, _) = parse_kdl("keepalive.kdl", &kdl)?;
    let engine = Arc::new(HttpEngine::from_config(
        &cfg,
        Arc::new(AcmeChallengeStore::new()),
        None,
        8443,
    )?);
    let (client, server) = tokio::io::duplex(64 * 1024);
    let peer: SocketAddr = "198.51.100.7:50000".parse()?;
    let local: SocketAddr = "127.0.0.1:8443".parse()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(engine.serve_hyper_connection(
        server,
        peer,
        local,
        true,
        false,
        None,
        shutdown_rx,
    ));
    Ok(Fixture {
        client,
        _shutdown: shutdown_tx,
        root,
    })
}

/// Reads one response and returns its status line. Fails if the server closes first.
async fn read_response(client: &mut DuplexStream) -> Result<String, Box<dyn std::error::Error>> {
    let mut data = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let text = String::from_utf8_lossy(&data).into_owned();
        if let Some(head_end) = text.find("\r\n\r\n") {
            let body_len = text
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|v| v.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            if data.len() >= head_end + 4 + body_len {
                return Ok(text.lines().next().unwrap_or("").to_owned());
            }
        }
        let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut chunk)).await??;
        if n == 0 {
            return Err(format!("server closed the connection; received so far: {text:?}").into());
        }
        data.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
    }
}

/// Time until the server closes the connection (EOF), up to `limit`.
async fn time_until_closed(client: &mut DuplexStream, limit: Duration) -> Option<Duration> {
    let started = Instant::now();
    let mut chunk = [0_u8; 1024];
    loop {
        match tokio::time::timeout(
            limit.saturating_sub(started.elapsed()),
            client.read(&mut chunk),
        )
        .await
        {
            Ok(Ok(0) | Err(_)) => return Some(started.elapsed()),
            Ok(Ok(_)) => {}
            Err(_) => return None,
        }
    }
}

#[tokio::test]
async fn idle_keepalive_connection_outlives_header_read_and_serves_the_next_request() -> TestResult
{
    let mut fx = start("idle")?;
    fx.client.write_all(REQUEST).await?;
    assert!(read_response(&mut fx.client).await?.contains("200"));

    // Idle for three times `header-read`, well inside `idle-keepalive`.
    tokio::time::sleep(HEADER_READ * 3).await;
    fx.client.write_all(REQUEST).await?;
    let status = read_response(&mut fx.client).await.map_err(|err| {
        format!("an idle keep-alive connection must survive past header-read: {err}")
    })?;
    assert!(status.contains("200"), "{status}");

    // With no further request it is closed at about `idle-keepalive`, not kept forever.
    let closed = time_until_closed(&mut fx.client, IDLE_KEEPALIVE * 3)
        .await
        .ok_or("an idle connection must be closed at idle-keepalive")?;
    assert!(
        closed >= IDLE_KEEPALIVE.mul_f32(0.7),
        "closed after {closed:?}, expected about {IDLE_KEEPALIVE:?}"
    );
    let _ = std::fs::remove_dir_all(&fx.root);
    Ok(())
}

#[tokio::test]
async fn stalled_request_head_on_a_keepalive_connection_is_cut_after_header_read() -> TestResult {
    let mut fx = start("stall")?;
    fx.client.write_all(REQUEST).await?;
    assert!(read_response(&mut fx.client).await?.contains("200"));

    // Sit idle a while, then start a request head and never finish it.
    tokio::time::sleep(HEADER_READ).await;
    fx.client.write_all(b"GET /hello.txt HT").await?;
    let closed = time_until_closed(&mut fx.client, IDLE_KEEPALIVE)
        .await
        .ok_or("a stalled request head must be cut after header-read, not at idle-keepalive")?;
    assert!(
        closed >= HEADER_READ.mul_f32(0.7) && closed <= HEADER_READ * 3,
        "cut after {closed:?}, expected about {HEADER_READ:?}"
    );
    let _ = std::fs::remove_dir_all(&fx.root);
    Ok(())
}

/// Review 12, finding 10: a request that starts late in the idle phase still has the whole
/// `header-read` budget. Idle 2 s, header-read 800 ms: the head starts after 1.7 s of idle and
/// is completed 500 ms later, 200 ms past the idle deadline.
#[tokio::test]
async fn request_head_that_starts_late_in_the_idle_phase_gets_its_full_header_budget() -> TestResult
{
    let mut fx = start_with("late-head", "800ms", "2s")?;
    fx.client.write_all(REQUEST).await?;
    assert!(read_response(&mut fx.client).await?.contains("200"));

    tokio::time::sleep(Duration::from_millis(1_700)).await;
    let (first, rest) = REQUEST.split_at(10);
    fx.client.write_all(first).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    fx.client.write_all(rest).await?;
    let status = read_response(&mut fx.client).await.map_err(|err| {
        format!("a head completed within header-read must be answered even past the idle deadline: {err}")
    })?;
    assert!(status.contains("200"), "{status}");
    let _ = std::fs::remove_dir_all(&fx.root);
    Ok(())
}

/// Review 12, finding 10, the other ordering: with `idle-keepalive` shorter than `header-read`
/// an idle connection is closed at the idle limit, not kept for the header limit.
#[tokio::test]
async fn idle_connection_is_closed_at_idle_keepalive_when_header_read_is_longer() -> TestResult {
    let mut fx = start_with("short-idle", "5s", "600ms")?;
    fx.client.write_all(REQUEST).await?;
    assert!(read_response(&mut fx.client).await?.contains("200"));

    let closed = time_until_closed(&mut fx.client, Duration::from_secs(4))
        .await
        .ok_or(
            "an idle connection must be closed at idle-keepalive (600 ms), not header-read (5 s)",
        )?;
    assert!(
        closed >= Duration::from_millis(400) && closed <= Duration::from_millis(2_500),
        "closed after {closed:?}, expected about 600 ms"
    );
    let _ = std::fs::remove_dir_all(&fx.root);
    Ok(())
}

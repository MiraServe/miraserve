//! Review 12, finding 5: an HTTP/2 client can close the flow-control window of one stream while
//! the connection stays healthy. The socket never blocks, so the TCP write guard sees nothing;
//! the response body (here an open file) must still not be held for as long as the client
//! likes. Also: an idle HTTP/2 connection is closed at `idle-keepalive`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use miraserve_config::parse_kdl;
use miraserve_http::HttpEngine;
use miraserve_tls::AcmeChallengeStore;
use tokio::sync::watch;
use tokio::task::JoinHandle;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn next_dir_seq() -> u64 {
    static SEQ: AtomicU64 = AtomicU64::new(1);
    SEQ.fetch_add(1, Ordering::Relaxed)
}

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

const BIG_BYTES: usize = 2 * 1024 * 1024;
const WRITE_IDLE: Duration = Duration::from_millis(400);
const DRAIN: Duration = Duration::from_millis(800);
const IDLE_KEEPALIVE: Duration = Duration::from_millis(1_500);

struct Fixture {
    sender: http2::SendRequest<Empty<Bytes>>,
    /// Resolves when the client side sees the connection end.
    connection: JoinHandle<()>,
    _shutdown: watch::Sender<bool>,
    root: std::path::PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

async fn start(tag: &str) -> Result<Fixture, Box<dyn std::error::Error>> {
    start_with(tag, None).await
}

/// `client_keepalive`: send HTTP/2 keep-alive PINGs at this interval, also while idle.
async fn start_with(
    tag: &str,
    client_keepalive: Option<Duration>,
) -> Result<Fixture, Box<dyn std::error::Error>> {
    start_custom(tag, client_keepalive, "").await
}

/// `server_kdl`: more lines for the `server` block.
async fn start_custom(
    tag: &str,
    client_keepalive: Option<Duration>,
    server_kdl: &str,
) -> Result<Fixture, Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "miraserve-h2s-{tag}-{}-{}",
        std::process::id(),
        next_dir_seq()
    ));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("big.bin"), vec![0x5a_u8; BIG_BYTES])?;
    std::fs::write(root.join("small.txt"), b"small")?;
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
    timeouts {{
        response-write-idle "400ms"
        graceful-drain "800ms"
        idle-keepalive "1500ms"
    }}
    {server_kdl}
}}
site "h2.example.test" {{
    root "{root}"
}}
"#,
        root = root.to_string_lossy().replace('\\', "/"),
    );
    let (cfg, _) = parse_kdl("h2-stall.kdl", &kdl)?;
    let engine = Arc::new(HttpEngine::from_config(
        &cfg,
        Arc::new(AcmeChallengeStore::new()),
        None,
        8443,
    )?);
    let (client, server) = tokio::io::duplex(256 * 1024);
    let peer: SocketAddr = "198.51.100.8:50000".parse()?;
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

    // A small stream window and a large connection window: one unread stream stops after
    // 64 KiB without holding back its siblings.
    let mut client_builder = http2::Builder::new(TokioExecutor::new());
    client_builder
        .initial_stream_window_size(65_535)
        .initial_connection_window_size(8 * 1024 * 1024);
    if let Some(interval) = client_keepalive {
        client_builder
            .timer(hyper_util::rt::TokioTimer::new())
            .keep_alive_interval(interval)
            .keep_alive_while_idle(true);
    }
    let (sender, conn) = client_builder
        .handshake::<_, Empty<Bytes>>(TokioIo::new(client))
        .await?;
    let connection = tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(Fixture {
        sender,
        connection,
        _shutdown: shutdown_tx,
        root,
    })
}

fn request(path: &str) -> Result<Request<Empty<Bytes>>, http::Error> {
    Request::builder()
        .uri(format!("https://h2.example.test{path}"))
        .body(Empty::new())
}

async fn stalled_stream_is_released_and_a_healthy_sibling_finishes_impl() -> TestResult {
    let mut fx = start("stall").await?;

    // Stream A: take the response head and never read the body. Its window stays closed.
    let stalled = fx.sender.send_request(request("/big.bin")?).await?;
    assert_eq!(stalled.status(), StatusCode::OK);
    let started = Instant::now();

    // Stream B on the same connection is read normally and must arrive complete.
    let healthy = fx.sender.send_request(request("/big.bin")?).await?;
    assert_eq!(healthy.status(), StatusCode::OK);
    let body = healthy.into_body().collect().await?.to_bytes();
    assert_eq!(body.len(), BIG_BYTES, "the healthy sibling must finish");

    // The server gives the stalled stream `response-write-idle`, then shuts the connection down
    // and drops it after `graceful-drain`: the client sees the connection end.
    let limit = WRITE_IDLE + DRAIN + Duration::from_secs(4);
    tokio::time::timeout(limit, &mut fx.connection)
        .await
        .map_err(|_| "a stalled HTTP/2 stream must not keep its connection open for ever")??;
    let lived = started.elapsed();
    assert!(
        lived >= WRITE_IDLE.mul_f32(0.8),
        "the stream had {WRITE_IDLE:?} to make progress, connection ended after {lived:?}"
    );

    // The unread stream did not complete.
    let stalled_body = stalled.into_body().collect().await;
    assert!(
        stalled_body.is_err() || stalled_body.is_ok_and(|b| b.to_bytes().len() < BIG_BYTES),
        "the stalled stream must not be reported complete"
    );
    Ok(())
}

dual_runtime_test!(
    stalled_stream_is_released_and_a_healthy_sibling_finishes,
    stalled_stream_is_released_and_a_healthy_sibling_finishes_multi_thread,
    stalled_stream_is_released_and_a_healthy_sibling_finishes_impl
);

async fn slow_but_steady_stream_is_not_cut_impl() -> TestResult {
    let mut fx = start("steady").await?;
    let resp = fx.sender.send_request(request("/big.bin")?).await?;
    assert_eq!(resp.status(), StatusCode::OK);

    // Read a frame, pause, read the next: the transfer takes several times
    // `response-write-idle`, but the stream advances all the time.
    let started = Instant::now();
    let mut body = resp.into_body();
    let mut received = 0_usize;
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame?.into_data() {
            received = received.saturating_add(data.len());
        }
        if started.elapsed() < WRITE_IDLE * 4 {
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
    }
    assert_eq!(
        received, BIG_BYTES,
        "a stream that keeps advancing must be delivered in full"
    );
    assert!(
        started.elapsed() >= WRITE_IDLE * 2,
        "the test must outlast the stall deadline to mean anything ({:?})",
        started.elapsed()
    );
    Ok(())
}

dual_runtime_test!(
    slow_but_steady_stream_is_not_cut,
    slow_but_steady_stream_is_not_cut_multi_thread,
    slow_but_steady_stream_is_not_cut_impl
);

async fn idle_http2_connection_is_closed_at_idle_keepalive_impl() -> TestResult {
    let mut fx = start("idle").await?;
    let resp = fx.sender.send_request(request("/small.txt")?).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(&resp.into_body().collect().await?.to_bytes()[..], b"small");

    let started = Instant::now();
    tokio::time::timeout(IDLE_KEEPALIVE * 4, &mut fx.connection)
        .await
        .map_err(|_| "an idle HTTP/2 connection must be closed at idle-keepalive")??;
    let lived = started.elapsed();
    assert!(
        lived >= IDLE_KEEPALIVE.mul_f32(0.7),
        "closed after {lived:?}, expected about {IDLE_KEEPALIVE:?}"
    );
    Ok(())
}

dual_runtime_test!(
    idle_http2_connection_is_closed_at_idle_keepalive,
    idle_http2_connection_is_closed_at_idle_keepalive_multi_thread,
    idle_http2_connection_is_closed_at_idle_keepalive_impl
);

/// Review of section 4d: a client's keep-alive PINGs (and the server's replies) are not
/// activity; an HTTP/2 connection with no request still closes at `idle-keepalive`.
async fn client_keepalive_pings_do_not_keep_an_idle_connection_open_impl() -> TestResult {
    let mut fx = start_with("pings", Some(Duration::from_millis(200))).await?;
    let resp = fx.sender.send_request(request("/small.txt")?).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let _ = resp.into_body().collect().await?;

    let started = Instant::now();
    tokio::time::timeout(IDLE_KEEPALIVE * 4, &mut fx.connection)
        .await
        .map_err(|_| "keep-alive PINGs must not keep an idle HTTP/2 connection open")??;
    let lived = started.elapsed();
    assert!(
        lived >= IDLE_KEEPALIVE.mul_f32(0.7),
        "closed after {lived:?}, expected about {IDLE_KEEPALIVE:?}"
    );
    Ok(())
}

dual_runtime_test!(
    client_keepalive_pings_do_not_keep_an_idle_connection_open,
    client_keepalive_pings_do_not_keep_an_idle_connection_open_multi_thread,
    client_keepalive_pings_do_not_keep_an_idle_connection_open_impl
);

/// Streams reset after their request was accepted count against `max-h2-rst-stream-per-sec`
/// (Cloudflare-skills audit of v0.1.0, claim 6): h2 itself only counts resets of streams it has
/// not handed over yet, so opening streams and resetting them once the work has started was
/// never limited.
async fn resets_after_acceptance_close_the_connection_impl() -> TestResult {
    let mut fx = start_custom(
        "resets",
        None,
        "limits {\n        max-h2-rst-stream-per-sec 3\n    }",
    )
    .await?;
    let started = Instant::now();
    let mut reset = 0_u32;
    // Each response is larger than the stream window: dropping it resets the stream.
    while reset < 40 && !fx.connection.is_finished() {
        match fx.sender.send_request(request("/big.bin")?).await {
            Ok(resp) => {
                assert_eq!(resp.status(), StatusCode::OK);
                drop(resp);
                reset += 1;
            }
            Err(_) => break,
        }
    }
    tokio::time::timeout(DRAIN * 2, &mut fx.connection)
        .await
        .map_err(|_| "the connection must be closed after too many resets")??;
    assert!(reset < 40, "{reset} resets were accepted");
    // Not the idle timer: it was closed while in use.
    assert!(
        started.elapsed() < IDLE_KEEPALIVE + DRAIN,
        "{:?}",
        started.elapsed()
    );
    Ok(())
}

dual_runtime_test!(
    resets_after_acceptance_close_the_connection,
    resets_after_acceptance_close_the_connection_multi_thread,
    resets_after_acceptance_close_the_connection_impl
);

/// Even a small response body that fits in a single `h2_stall` piece (and therefore skips
/// `PieceBody`) MUST still be guarded by `H2StallBody`: if the client advertises a zero stream
/// window and never grants capacity, the stream expires at `response-write-idle`.
async fn small_single_chunk_body_still_stalls_when_stream_window_is_zero_impl() -> TestResult {
    let root = std::env::temp_dir().join(format!(
        "miraserve-h2s-small-zero-win-{}-{}",
        std::process::id(),
        next_dir_seq()
    ));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("1k.txt"), vec![b'a'; 1024])?;
    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
    timeouts {{
        response-write-idle "400ms"
        graceful-drain "800ms"
        idle-keepalive "5s"
    }}
}}
site "h2.example.test" {{
    root "{root}"
}}
"#,
        root = root.to_string_lossy().replace('\\', "/"),
    );
    let (cfg, _) = parse_kdl("h2-small-stall.kdl", &kdl)?;
    let engine = Arc::new(HttpEngine::from_config(
        &cfg,
        Arc::new(AcmeChallengeStore::new()),
        None,
        8443,
    )?);
    let (client, server) = tokio::io::duplex(256 * 1024);
    let peer: SocketAddr = "198.51.100.9:50001".parse()?;
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

    // Advertise initial stream window = 0 so even a 1 KiB body cannot be sent without WINDOW_UPDATE.
    let mut client_builder = http2::Builder::new(TokioExecutor::new());
    client_builder
        .initial_stream_window_size(0)
        .initial_connection_window_size(8 * 1024 * 1024);
    let (mut sender, conn) = client_builder
        .handshake::<_, Empty<Bytes>>(TokioIo::new(client))
        .await?;
    let connection = tokio::spawn(async move {
        let _ = conn.await;
    });

    let stalled = sender.send_request(request("/1k.txt")?).await?;
    assert_eq!(stalled.status(), StatusCode::OK);
    let started = Instant::now();

    let limit = WRITE_IDLE + DRAIN + Duration::from_secs(2);
    let conn_res = tokio::time::timeout(limit, connection).await;
    let _ = std::fs::remove_dir_all(&root);
    conn_res.map_err(
        |_| "small single-chunk H2 body with zero window must expire at response-write-idle",
    )??;
    let lived = started.elapsed();
    assert!(
        lived >= WRITE_IDLE.mul_f32(0.8) && lived < Duration::from_secs(4),
        "expected expiry near response-write-idle ({WRITE_IDLE:?}), got {lived:?}"
    );
    Ok(())
}

dual_runtime_test!(
    small_single_chunk_body_still_stalls_when_stream_window_is_zero,
    small_single_chunk_body_still_stalls_when_stream_window_is_zero_multi_thread,
    small_single_chunk_body_still_stalls_when_stream_window_is_zero_impl
);

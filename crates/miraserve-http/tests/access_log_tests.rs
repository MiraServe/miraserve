//! Dedicated regression tests for handover Section 4 & Section 5 #4/#7:
//! - `miraserve::access` records `host`, `referer`, `bytes_sent`, clean `client_ip`/`peer_ip`
//!   (no `Some(...)`), and end-of-response `latency_us` (measured after streaming completes).
//! - `WARN` lines on rejected requests emit clean `client_ip` with zero `Some(...)`.
//! - Slow-reader `WriteGuardedIo` kills emit a `WARN` log line.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::{HOST, REFERER};
use http::{Method, Request, Response, StatusCode};
use http_body_util::BodyExt as _;
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use miraserve_config::parse_kdl;
use miraserve_http::{HttpEngine, RequestContext, WriteGuardedIo, empty_http_body};
use miraserve_tls::AcmeChallengeStore;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Metadata, Subscriber, span};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Debug, Clone)]
struct CapturedEvent {
    level: Level,
    target: String,
    fields: BTreeMap<String, String>,
}

#[derive(Default)]
struct FieldRecorder {
    fields: BTreeMap<String, String>,
}

impl Visit for FieldRecorder {
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .insert(field.name().to_owned(), value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields
            .insert(field.name().to_owned(), value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .insert(field.name().to_owned(), value.to_string());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields
            .insert(field.name().to_owned(), value.to_owned());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.fields
            .insert(field.name().to_owned(), format!("{value:?}"));
    }
}

#[derive(Clone, Default)]
struct CaptureSubscriber {
    events: Arc<Mutex<Vec<CapturedEvent>>>,
}

impl CaptureSubscriber {
    fn snapshot(&self) -> Vec<CapturedEvent> {
        self.events
            .lock()
            .map_or_else(|_| Vec::new(), |g| g.clone())
    }
}

impl Subscriber for CaptureSubscriber {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}

    fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut rec = FieldRecorder::default();
        event.record(&mut rec);
        let captured = CapturedEvent {
            level: *event.metadata().level(),
            target: event.metadata().target().to_owned(),
            fields: rec.fields,
        };
        if let Ok(mut g) = self.events.lock() {
            g.push(captured);
        }
    }

    fn enter(&self, _span: &span::Id) {}

    fn exit(&self, _span: &span::Id) {}
}

struct AlwaysPendingWriter;

impl AsyncRead for AlwaysPendingWriter {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for AlwaysPendingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

struct ChannelBody {
    rx: tokio::sync::mpsc::Receiver<Bytes>,
}

impl http_body::Body for ChannelBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(chunk)) => Poll::Ready(Some(Ok(Frame::data(chunk)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[tokio::test(flavor = "current_thread")]
#[allow(clippy::too_many_lines)]
async fn access_log_records_bytes_sent_end_of_response_latency_host_referer_and_clean_warns()
-> TestResult {
    let capture = CaptureSubscriber::default();
    let _guard = tracing::subscriber::set_default(capture.clone());

    // Upstream that streams two chunks separated by 60ms so we prove `latency_us` is measured at
    // end-of-response (not header send!) and `bytes_sent` sums every streamed chunk.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = listener.local_addr()?;
    let up_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|_req: Request<Incoming>| async move {
                    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(4);
                    tokio::spawn(async move {
                        let _ = tx.send(Bytes::from_static(b"chunk-one-")).await;
                        tokio::time::sleep(Duration::from_millis(60)).await;
                        let _ = tx.send(Bytes::from_static(b"chunk-two!")).await;
                    });
                    Ok::<_, std::convert::Infallible>(Response::new(ChannelBody { rx }))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "miraserve-access-log-test-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root)?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/tmp/c.crt"; key "/tmp/c.key" }}
}}
site "logs.example.test" {{
    root "{}"
    route "/stream/*" {{
        reverse-proxy {{
            upstream "http://{}"
        }}
    }}
}}
"#,
        root.display(),
        up_addr,
    );
    let (cfg, _) = parse_kdl("access-log.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;

    let ctx = RequestContext {
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77))),
        remote_port: Some(50123),
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 8443,
        is_https: true,
        tls: None,
    };

    // 1. Streaming response: access log must fire AFTER body finishes, with exact bytes_sent=20
    //    and latency_us >= 50_000 (proving end-of-response timing, not header-only!).
    let req = Request::builder()
        .method(Method::GET)
        .uri("/stream/slow")
        .header(HOST, "logs.example.test")
        .header(REFERER, "https://referrer.example/page")
        .body(empty_http_body())?;
    let resp = engine.handle_request(req, &ctx).await;
    assert_eq!(resp.status(), StatusCode::OK);
    // Access log must NOT have fired yet while body is still streaming!
    assert!(
        !capture
            .snapshot()
            .iter()
            .any(|e| e.target == "miraserve::access"),
        "access log must wait until response body finishes streaming"
    );
    let body = resp.into_body().collect().await?.to_bytes();
    assert_eq!(body.as_ref(), b"chunk-one-chunk-two!");

    let events = capture.snapshot();
    let access = events
        .iter()
        .find(|e| e.target == "miraserve::access")
        .ok_or("missing miraserve::access event")?;
    assert_eq!(
        access.fields.get("host").map(String::as_str),
        Some("logs.example.test")
    );
    assert_eq!(
        access.fields.get("referer").map(String::as_str),
        Some("https://referrer.example/page")
    );
    assert_eq!(
        access.fields.get("bytes_sent").map(String::as_str),
        Some("20")
    );
    assert_eq!(
        access.fields.get("client_ip").map(String::as_str),
        Some("198.51.100.77")
    );
    assert_eq!(
        access.fields.get("peer_ip").map(String::as_str),
        Some("198.51.100.77")
    );
    let latency_us: u64 = access
        .fields
        .get("latency_us")
        .ok_or("missing latency_us")?
        .parse()?;
    assert!(
        latency_us >= 50_000,
        "latency_us ({latency_us}) must reflect end-of-response streaming time (>= 50ms)"
    );

    // 2. Rejected request WARN line must NOT print `Some(...)` for client_ip!
    let bad_req = Request::builder()
        .method(Method::GET)
        .uri("/../etc/passwd")
        .header(HOST, "logs.example.test")
        .body(empty_http_body())?;
    let bad_resp = engine.handle_request(bad_req, &ctx).await;
    assert_eq!(bad_resp.status(), StatusCode::BAD_REQUEST);
    let _ = bad_resp.into_body().collect().await;

    let warn_events: Vec<CapturedEvent> = capture
        .snapshot()
        .into_iter()
        .filter(|e| e.level == Level::WARN)
        .collect();
    assert!(
        warn_events
            .iter()
            .any(|e| e.fields.get("client_ip").map(String::as_str) == Some("198.51.100.77")),
        "expected clean WARN client_ip without Some(...), got: {warn_events:?}"
    );
    for ev in &warn_events {
        for (k, v) in &ev.fields {
            assert!(
                !v.contains("Some("),
                "WARN field {k} must not contain Debug `Some(...)`: {v}"
            );
        }
    }

    // 3. Slow-reader WriteGuardedIo close must emit a WARN log line!
    let mut guarded = WriteGuardedIo::new(AlwaysPendingWriter, Duration::from_millis(40), 0)
        .with_peer_addr(SocketAddr::from(([198, 51, 100, 99], 44444)));
    let err = guarded.write_all(b"hello").await;
    assert!(err.is_err(), "WriteGuardedIo must time out stalled writer");
    assert!(
        capture.snapshot().iter().any(|e| {
            e.level == Level::WARN
                && e.fields.get("peer").map(String::as_str) == Some("198.51.100.99:44444")
                && e.fields.get("reason").map(String::as_str) == Some("response_write_idle")
        }),
        "slow-reader WriteGuardedIo close must emit a WARN log with peer and reason"
    );

    up_task.abort();
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

/// Codex G8: `AccessLogBody` must NOT log completion early before the transport finishes
/// consuming/dropping the final frame, and an interrupted multi-chunk transfer dropped mid-stream
/// MUST report only the bytes yielded prior to disconnect with `completed=false`.
#[tokio::test]
async fn g8_access_log_distinguishes_interrupted_transfer_and_defers_final_frame_completion()
-> TestResult {
    let capture = CaptureSubscriber::default();
    let _guard = tracing::subscriber::set_default(capture.clone());

    let gate = Arc::new(tokio::sync::Notify::new());
    let gate_srv = Arc::clone(&gate);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = listener.local_addr()?;
    let up_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let gate = Arc::clone(&gate_srv);
            tokio::spawn(async move {
                let svc = service_fn(move |_req: Request<Incoming>| {
                    let gate = Arc::clone(&gate);
                    async move {
                        let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(4);
                        tokio::spawn(async move {
                            let _ = tx
                                .send(Bytes::from_static(b"first-chunk-24-bytes!!!!"))
                                .await;
                            gate.notified().await;
                            let _ = tx
                                .send(Bytes::from_static(b"second-chunk-never-sent!"))
                                .await;
                        });
                        Ok::<_, std::convert::Infallible>(Response::new(ChannelBody { rx }))
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "miraserve-g8-access-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("hello.txt"), b"hello-full-body")?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/tmp/c.crt"; key "/tmp/c.key" }}
}}
site "g8.example.test" {{
    root "{}"
    route "/stream/*" {{
        reverse-proxy {{
            upstream "http://{}"
        }}
    }}
}}
"#,
        root.display(),
        up_addr,
    );
    let (cfg, _) = parse_kdl("g8-access.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let ctx = RequestContext {
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 88))),
        remote_port: Some(50888),
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 8443,
        is_https: true,
        tls: None,
    };

    // 1. Single-frame response (`Full` body): polling the frame MUST NOT log completion early
    //    before the transport finishes writing and drops the body!
    let full_req = Request::builder()
        .method(Method::GET)
        .uri("/hello.txt")
        .header(HOST, "g8.example.test")
        .body(empty_http_body())?;
    let full_resp = engine.handle_request(full_req, &ctx).await;
    assert_eq!(full_resp.status(), StatusCode::OK);
    let mut full_body = full_resp.into_body();
    let frame = full_body
        .frame()
        .await
        .ok_or("missing single frame")??
        .into_data()
        .map_err(|_| "expected data frame")?;
    assert_eq!(frame.as_ref(), b"hello-full-body");
    assert!(
        !capture
            .snapshot()
            .iter()
            .any(|e| e.target == "miraserve::access"),
        "G8: access log must NOT emit on Poll::Ready(Some(frame)) before transport drops/finishes the body"
    );
    drop(full_body);
    let full_events = capture.snapshot();
    let full_log = full_events
        .iter()
        .find(|e| e.target == "miraserve::access")
        .ok_or("missing access log after Full body drop")?;
    assert_eq!(
        full_log.fields.get("bytes_sent").map(String::as_str),
        Some("15")
    );
    assert_eq!(
        full_log.fields.get("completed").map(String::as_str),
        Some("true")
    );

    // 2. Interrupted multi-chunk transfer: consume chunk 1 (24 bytes), then drop the body before
    //    chunk 2 arrives (simulating mid-transfer client disconnect).
    let stream_req = Request::builder()
        .method(Method::GET)
        .uri("/stream/abort")
        .header(HOST, "g8.example.test")
        .body(empty_http_body())?;
    let stream_resp = engine.handle_request(stream_req, &ctx).await;
    assert_eq!(stream_resp.status(), StatusCode::OK);
    let mut stream_body = stream_resp.into_body();
    let chunk1 = stream_body
        .frame()
        .await
        .ok_or("missing chunk 1")??
        .into_data()
        .map_err(|_| "expected chunk 1 data")?;
    assert_eq!(chunk1.len(), 24);
    // Drop before chunk 2 / EOF!
    drop(stream_body);
    gate.notify_waiters();

    let all_events = capture.snapshot();
    let interrupted = all_events
        .iter()
        .filter(|e| e.target == "miraserve::access")
        .nth(1)
        .ok_or("missing access log for interrupted transfer")?;
    assert_eq!(
        interrupted.fields.get("bytes_sent").map(String::as_str),
        Some("24"),
        "interrupted transfer must report only the bytes yielded prior to disconnect"
    );
    assert_eq!(
        interrupted.fields.get("completed").map(String::as_str),
        Some("false"),
        "interrupted transfer must report completed=false"
    );
    assert!(
        interrupted
            .fields
            .get("message")
            .is_some_and(|m| m.contains("interrupted")),
        "interrupted transfer message should indicate interruption, got: {:?}",
        interrupted.fields
    );

    up_task.abort();
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

/// Codex G8 (final write failure): When a real HTTP/1.1 connection fails to write or flush the
/// final frame of a single-frame response (`BrokenPipe`), `WriteOutcomeIo` feeds the transport
/// error into `AccessLogRecord` so the access log records `completed=false` (`"http request
/// interrupted"`) instead of overstating completion.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn g8_final_socket_write_failure_records_interrupted_even_for_single_frame_body() -> TestResult
{
    use std::io;
    use std::net::SocketAddr;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::sync::watch;

    struct ScriptedIo {
        input: Vec<u8>,
        read_pos: usize,
        fail_after_bytes: Option<usize>,
        written_bytes: usize,
        output: Vec<u8>,
    }

    impl AsyncRead for ScriptedIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.read_pos >= self.input.len() {
                // Keep read half open (like a real client awaiting the server's response)
                // so Hyper does not cancel the request future due to half-close before writing.
                return Poll::Pending;
            }
            let avail = self.input.len().saturating_sub(self.read_pos);
            let n = avail.min(buf.remaining());
            if let Some(slice) = self.input.get(self.read_pos..self.read_pos + n) {
                buf.put_slice(slice);
                self.read_pos = self.read_pos.saturating_add(n);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ScriptedIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if let Some(limit) = self.fail_after_bytes
                && self.written_bytes.saturating_add(buf.len()) > limit
            {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "simulated peer disconnect during final write",
                )));
            }
            self.output.extend_from_slice(buf);
            self.written_bytes = self.written_bytes.saturating_add(buf.len());
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    let capture = CaptureSubscriber::default();
    let _guard = tracing::subscriber::set_default(capture.clone());

    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "miraserve-g8-final-write-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("hello.txt"), b"hello-full-body")?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/tmp/c.crt"; key "/tmp/c.key" }}
}}
site "g8-wire.example.test" {{
    root "{}"
}}
"#,
        root.display()
    );
    let (cfg, _) = parse_kdl("g8-wire.kdl", &kdl)?;
    let engine = Arc::new(HttpEngine::from_config(
        &cfg,
        Arc::new(AcmeChallengeStore::new()),
        None,
        8443,
    )?);

    let req_wire =
        b"GET /hello.txt HTTP/1.1\r\nHost: g8-wire.example.test\r\nConnection: close\r\n\r\n"
            .to_vec();
    let peer: SocketAddr = "198.51.100.99:51000".parse()?;
    let local: SocketAddr = "127.0.0.1:8443".parse()?;
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);

    // 1. Failing final write (limit = 16 bytes -> fails mid-response write with BrokenPipe!).
    let failing_io = ScriptedIo {
        input: req_wire.clone(),
        read_pos: 0,
        fail_after_bytes: Some(16),
        written_bytes: 0,
        output: Vec::new(),
    };
    Arc::clone(&engine)
        .serve_hyper_connection(
            failing_io,
            peer,
            local,
            true,
            false,
            None,
            shutdown_rx.clone(),
        )
        .await;

    let events_after_fail = capture.snapshot();
    let fail_log = events_after_fail
        .iter()
        .find(|e| e.target == "miraserve::access")
        .ok_or("missing access log after failed final write")?;
    assert_eq!(
        fail_log.fields.get("completed").map(String::as_str),
        Some("false"),
        "failed final socket write MUST record completed=false, got: {:?}",
        fail_log.fields
    );
    assert!(
        fail_log
            .fields
            .get("message")
            .is_some_and(|m| m.contains("interrupted")),
        "failed final socket write message must say interrupted, got: {:?}",
        fail_log.fields
    );

    // 2. Clean final write & flush -> records completed=true and bytes_sent=15.
    let ok_io = ScriptedIo {
        input: req_wire,
        read_pos: 0,
        fail_after_bytes: None,
        written_bytes: 0,
        output: Vec::new(),
    };
    Arc::clone(&engine)
        .serve_hyper_connection(ok_io, peer, local, true, false, None, shutdown_rx)
        .await;

    let events_after_ok = capture.snapshot();
    let ok_log = events_after_ok
        .iter()
        .filter(|e| e.target == "miraserve::access")
        .nth(1)
        .ok_or("missing access log after clean write")?;
    assert_eq!(
        ok_log.fields.get("completed").map(String::as_str),
        Some("true"),
        "clean flushed H1 response must record completed=true, got: {:?}",
        ok_log.fields
    );
    assert_eq!(
        ok_log.fields.get("transport_delivery").map(String::as_str),
        Some("confirmed"),
        "clean flushed H1 response must record transport_delivery=confirmed, got: {:?}",
        ok_log.fields
    );
    assert_eq!(
        ok_log.fields.get("bytes_sent").map(String::as_str),
        Some("15")
    );

    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

/// Codex Round-3 P2 #3 (G8): Cancelling `serve_hyper_connection` while `poll_write` is returning
/// `Poll::Pending` (before transport flush confirmation) MUST log `completed=false` ("interrupted")
/// instead of falsely logging `completed=true` on `WriteOutcomeIo::drop`.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn g8_r3_p2_cancellation_while_poll_write_is_pending_records_interrupted() -> TestResult {
    use std::io;
    use tokio::io::{AsyncRead, ReadBuf};
    use tokio::sync::watch;

    struct PendingWriteIo {
        input: Vec<u8>,
        read_pos: usize,
        allow_bytes: usize,
        written_bytes: usize,
        stalled: Arc<tokio::sync::Notify>,
        signalled: bool,
    }

    impl AsyncRead for PendingWriteIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.read_pos >= self.input.len() {
                return Poll::Pending;
            }
            let avail = self.input.len().saturating_sub(self.read_pos);
            let n = avail.min(buf.remaining());
            if let Some(slice) = self.input.get(self.read_pos..self.read_pos + n) {
                buf.put_slice(slice);
                self.read_pos = self.read_pos.saturating_add(n);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for PendingWriteIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.written_bytes < self.allow_bytes {
                let take = (self.allow_bytes - self.written_bytes).min(buf.len());
                self.written_bytes = self.written_bytes.saturating_add(take);
                return Poll::Ready(Ok(take));
            }
            if !self.signalled {
                self.signalled = true;
                self.stalled.notify_one();
            }
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    let capture = CaptureSubscriber::default();
    let _guard = tracing::subscriber::set_default(capture.clone());

    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "miraserve-g8-r3-cancel-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("hello.txt"), b"hello-pending-write-body")?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/tmp/c.crt"; key "/tmp/c.key" }}
}}
site "g8-cancel.example.test" {{
    root "{}"
}}
"#,
        root.display()
    );
    let (cfg, _) = parse_kdl("g8-cancel.kdl", &kdl)?;
    let engine = Arc::new(HttpEngine::from_config(
        &cfg,
        Arc::new(AcmeChallengeStore::new()),
        None,
        8443,
    )?);

    let stalled = Arc::new(tokio::sync::Notify::new());
    let io = PendingWriteIo {
        input:
            b"GET /hello.txt HTTP/1.1\r\nHost: g8-cancel.example.test\r\nConnection: close\r\n\r\n"
                .to_vec(),
        read_pos: 0,
        allow_bytes: 8,
        written_bytes: 0,
        stalled: Arc::clone(&stalled),
        signalled: false,
    };
    let peer: SocketAddr = "198.51.100.91:51111".parse()?;
    let local: SocketAddr = "127.0.0.1:8443".parse()?;
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut conn_fut = Box::pin(Arc::clone(&engine).serve_hyper_connection(
        io,
        peer,
        local,
        true,
        false,
        None,
        shutdown_rx,
    ));

    // Drive the connection until `poll_write` stalls with `Poll::Pending`, then cancel by dropping.
    tokio::select! {
        () = &mut conn_fut => {
            return Err("connection should have stayed pending on stalled poll_write".into());
        }
        () = stalled.notified() => {}
    }
    drop(conn_fut);

    let events = capture.snapshot();
    let cancel_log = events
        .iter()
        .find(|e| e.target == "miraserve::access")
        .ok_or("missing access log after cancelled pending write")?;
    assert_eq!(
        cancel_log.fields.get("completed").map(String::as_str),
        Some("false"),
        "cancellation during Poll::Pending write MUST log completed=false, got: {:?}",
        cancel_log.fields
    );
    assert_eq!(
        cancel_log.fields.get("body_complete").map(String::as_str),
        Some("true"),
        "body was produced in full even though transport flush never completed: {:?}",
        cancel_log.fields
    );
    assert!(
        cancel_log
            .fields
            .get("message")
            .is_some_and(|m| m.contains("interrupted")),
        "cancelled pending write must log interrupted message, got: {:?}",
        cancel_log.fields
    );

    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

/// Codex Round-3 & Round-4 P2 #3 (G8): On a multiplexed HTTP/2 connection carrying three
/// concurrent streams:
/// 1. `/stream/ok`: completes cleanly -> `body_complete=true`,
///    `transport_delivery="unconfirmed_multiplexed"`, `completed=true` (the body was fully
///    produced; the connection-wide H2 flush is never reported as per-stream confirmation).
/// 2. `/stream/cancel`: reset BEFORE body exhaustion -> `body_complete=false`,
///    `transport_delivery="failed"`, `completed=false`, partial `bytes_sent=16`.
/// 3. `/stream/cancel-after-eof`: server exhausts the body immediately and client resets/drops
///    the stream while `/stream/ok` continues and flushes the H2 connection -> `body_complete=true`,
///    `transport_delivery="unconfirmed_multiplexed"`, `completed=true` (NEVER claiming
///    `transport_delivery="confirmed"`).
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn g8_r3_p2_http2_completed_and_cancelled_streams_log_independently() -> TestResult {
    use tokio::sync::watch;

    let capture = CaptureSubscriber::default();
    let _guard = tracing::subscriber::set_default(capture.clone());

    let release_reset_stream = Arc::new(tokio::sync::Notify::new());
    let release_srv = Arc::clone(&release_reset_stream);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = listener.local_addr()?;
    let up_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let release = Arc::clone(&release_srv);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let release = Arc::clone(&release);
                    async move {
                        let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(4);
                        match req.uri().path() {
                            "/stream/cancel" => {
                                tokio::spawn(async move {
                                    let _ = tx.send(Bytes::from_static(b"chunk1-16-bytes!")).await;
                                    release.notified().await;
                                    let _ = tx
                                        .send(Bytes::from_static(b"chunk2-never-delivered"))
                                        .await;
                                });
                            }
                            "/stream/cancel-after-eof" => {
                                // Body exhausts immediately on the server (EOF reached right away)
                                // so dropping it on the client tests a reset AFTER body exhaustion
                                // while `/stream/ok` continues flushing the H2 connection!
                                tokio::spawn(async move {
                                    let _ = tx
                                        .send(Bytes::from_static(b"exhausted-22-byte-body"))
                                        .await;
                                });
                            }
                            _ => {
                                tokio::spawn(async move {
                                    let _ = tx.send(Bytes::from_static(b"healthy-")).await;
                                    tokio::time::sleep(Duration::from_millis(40)).await;
                                    let _ = tx.send(Bytes::from_static(b"complete-stream!")).await;
                                });
                            }
                        }
                        Ok::<_, std::convert::Infallible>(Response::new(ChannelBody { rx }))
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root =
        std::env::temp_dir().join(format!("miraserve-g8-r3-h2-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&root)?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/tmp/c.crt"; key "/tmp/c.key" }}
}}
site "g8-h2.example.test" {{
    root "{}"
    route "/stream/*" {{
        reverse-proxy {{
            upstream "http://{up_addr}"
        }}
    }}
}}
"#,
        root.display(),
    );
    let (cfg, _) = parse_kdl("g8-h2.kdl", &kdl)?;
    let engine = Arc::new(HttpEngine::from_config(
        &cfg,
        Arc::new(AcmeChallengeStore::new()),
        None,
        8443,
    )?);

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let peer: SocketAddr = "198.51.100.92:52222".parse()?;
    let local: SocketAddr = "127.0.0.1:8443".parse()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let server_task = tokio::spawn(Arc::clone(&engine).serve_hyper_connection(
        server_io,
        peer,
        local,
        true,
        false,
        None,
        shutdown_rx,
    ));

    let (mut sender, client_conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        TokioIo::new(client_io),
    )
    .await?;
    let client_conn_task = tokio::spawn(async move {
        let _ = client_conn.await;
    });

    // Launch all three streams concurrently on the SAME HTTP/2 connection!
    let ok_fut = sender.send_request(
        Request::builder()
            .method(Method::GET)
            .uri("https://g8-h2.example.test/stream/ok")
            .body(empty_http_body())?,
    );
    let cancel_fut = sender.send_request(
        Request::builder()
            .method(Method::GET)
            .uri("https://g8-h2.example.test/stream/cancel")
            .body(empty_http_body())?,
    );
    let cancel_after_eof_fut = sender.send_request(
        Request::builder()
            .method(Method::GET)
            .uri("https://g8-h2.example.test/stream/cancel-after-eof")
            .body(empty_http_body())?,
    );
    let (ok_resp, cancel_resp, cancel_after_eof_resp) =
        tokio::try_join!(ok_fut, cancel_fut, cancel_after_eof_fut)?;
    assert_eq!(ok_resp.status(), StatusCode::OK);
    assert_eq!(cancel_resp.status(), StatusCode::OK);
    assert_eq!(cancel_after_eof_resp.status(), StatusCode::OK);

    // Stream 3: wait until the whole 22-byte body has arrived (so the server has produced all of
    // it and reached EOF; dropping right after the headers raced the upstream task under load),
    // then drop it so the H2 client resets the stream while `/stream/ok` continues flushing.
    let mut after_eof_body = cancel_after_eof_resp.into_body();
    let mut received = 0_usize;
    while received < 22 {
        let Some(frame) = after_eof_body.frame().await else {
            break;
        };
        if let Ok(data) = frame?.into_data() {
            received += data.len();
        }
    }
    assert_eq!(
        received, 22,
        "the post-EOF stream delivers its whole body first"
    );
    drop(after_eof_body);

    // Stream 2: read ONLY chunk 1, then drop the response body -> HTTP/2 client sends RST_STREAM!
    let mut cancel_body = cancel_resp.into_body();
    let first = cancel_body
        .frame()
        .await
        .ok_or("expected first H2 DATA frame on /stream/cancel")??
        .into_data()
        .map_err(|_| "expected data frame on /stream/cancel")?;
    assert_eq!(first.as_ref(), b"chunk1-16-bytes!");
    drop(cancel_body);

    // Stream 1: read to completion cleanly on the same H2 connection!
    let ok_bytes = ok_resp.into_body().collect().await?.to_bytes();
    assert_eq!(ok_bytes.as_ref(), b"healthy-complete-stream!");

    // Give the server a moment to process the RST_STREAM & flush access logs, then shut down.
    release_reset_stream.notify_waiters();
    tokio::time::sleep(Duration::from_millis(80)).await;
    drop(sender);
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), server_task).await;
    client_conn_task.abort();
    up_task.abort();

    let access_events: Vec<CapturedEvent> = capture
        .snapshot()
        .into_iter()
        .filter(|e| e.target == "miraserve::access")
        .collect();

    let ok_log = access_events
        .iter()
        .find(|e| e.fields.get("target").map(String::as_str) == Some("/stream/ok"))
        .ok_or_else(|| format!("missing /stream/ok access log, got: {access_events:?}"))?;
    assert_eq!(
        ok_log.fields.get("body_complete").map(String::as_str),
        Some("true"),
        "completed H2 stream must log body_complete=true: {:?}",
        ok_log.fields
    );
    assert_eq!(
        ok_log.fields.get("transport_delivery").map(String::as_str),
        Some("unconfirmed_multiplexed"),
        "multiplexed H2 flush must report unconfirmed_multiplexed, not confirmed: {:?}",
        ok_log.fields
    );
    assert_eq!(
        ok_log.fields.get("completed").map(String::as_str),
        Some("true"),
        "a fully produced H2 response is completed; the per-stream uncertainty is in transport_delivery: {:?}",
        ok_log.fields
    );
    assert_eq!(
        ok_log.fields.get("bytes_sent").map(String::as_str),
        Some("24")
    );

    let cancel_log = access_events
        .iter()
        .find(|e| e.fields.get("target").map(String::as_str) == Some("/stream/cancel"))
        .ok_or_else(|| format!("missing /stream/cancel access log, got: {access_events:?}"))?;
    assert_eq!(
        cancel_log.fields.get("body_complete").map(String::as_str),
        Some("false"),
        "cancelled/reset H2 stream must log body_complete=false: {:?}",
        cancel_log.fields
    );
    assert_eq!(
        cancel_log
            .fields
            .get("transport_delivery")
            .map(String::as_str),
        Some("failed"),
        "mid-body reset H2 stream must log transport_delivery=failed: {:?}",
        cancel_log.fields
    );
    assert_eq!(
        cancel_log.fields.get("completed").map(String::as_str),
        Some("false"),
        "cancelled/reset H2 stream must log completed=false: {:?}",
        cancel_log.fields
    );
    assert_eq!(
        cancel_log.fields.get("bytes_sent").map(String::as_str),
        Some("16"),
        "cancelled/reset H2 stream must record only bytes yielded before reset: {:?}",
        cancel_log.fields
    );

    let post_eof_log = access_events
        .iter()
        .find(|e| e.fields.get("target").map(String::as_str) == Some("/stream/cancel-after-eof"))
        .ok_or_else(|| {
            format!("missing /stream/cancel-after-eof access log, got: {access_events:?}")
        })?;
    // The server produced the whole body and saw no write error, so this is `completed`; that a
    // reset after the last byte cannot be observed per stream is what
    // `transport_delivery="unconfirmed_multiplexed"` (asserted below as "not confirmed") says.
    assert_eq!(
        post_eof_log.fields.get("completed").map(String::as_str),
        Some("true"),
        "H2 stream whose body was fully produced logs completed=true with unconfirmed delivery: {:?}",
        post_eof_log.fields
    );
    assert_ne!(
        post_eof_log
            .fields
            .get("transport_delivery")
            .map(String::as_str),
        Some("confirmed"),
        "H2 stream reset after body exhaustion MUST NEVER log transport_delivery=confirmed: {:?}",
        post_eof_log.fields
    );

    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

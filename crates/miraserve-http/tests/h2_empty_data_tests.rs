//! An HTTP/2 client may send an empty DATA frame without `END_STREAM` after its payload (a framing
//! pattern seen from GCP). h2 0.4.20 charged every such frame against a counter that lasts as
//! long as the connection and closed the connection with `GOAWAY(ENHANCE_YOUR_CALM)` after 100 of
//! them, however much real payload came with them; h2 0.4.21 allows one per stream after a
//! non-empty frame. A long-lived connection that uploads many small bodies must stay open.
//!
//! The uploads go to a reverse-proxy route, so the server reads each body to its end before it
//! answers. (An upload to a handler that answers without reading the body is a different case:
//! frames that arrive for a stream the server has already answered get no allowance, in 0.4.21
//! as before.)

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use http_body::Frame;
use http_body_util::BodyExt as _;
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use miraserve_config::parse_kdl;
use miraserve_http::HttpEngine;
use miraserve_tls::AcmeChallengeStore;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::watch;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A request body sent as the given DATA frames, none of them marked as the last one: the stream
/// ends with a separate empty DATA frame carrying `END_STREAM`.
struct Pieces(VecDeque<Bytes>);

impl http_body::Body for Pieces {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.0.pop_front().map(|piece| Ok(Frame::data(piece))))
    }
}

fn upload(path: &str) -> Result<Request<Pieces>, http::Error> {
    // payload, then an empty DATA frame that is not the end of the stream
    Request::builder()
        .method(Method::POST)
        .uri(format!("https://h2.example.test{path}"))
        .body(Pieces(VecDeque::from([
            Bytes::from_static(b"payload"),
            Bytes::new(),
        ])))
}

#[tokio::test]
async fn many_uploads_with_an_empty_data_frame_keep_the_connection_open() -> TestResult {
    let root = std::env::temp_dir().join(format!("miraserve-h2-empty-{}", std::process::id()));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("small.txt"), b"small")?;

    // An HTTP/1.1 upstream that answers once it has read the whole request body, and counts the
    // bodies that carried the payload.
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    let received = Arc::new(AtomicUsize::new(0));
    let received_by_upstream = Arc::clone(&received);
    let upstream = tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let received = Arc::clone(&received_by_upstream);
            tokio::spawn(async move {
                let mut seen = Vec::new();
                let mut chunk = [0_u8; 4096];
                loop {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(chunk.get(..n).unwrap_or(&[])),
                    }
                    if request_is_complete(&seen) {
                        break;
                    }
                }
                if seen.windows(7).any(|w| w == b"payload") {
                    received.fetch_add(1, Ordering::Relaxed);
                }
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });

    let kdl = format!(
        r#"
server {{
    listen ":8443"
    tls {{ cert "/c.pem"; key "/k.pem" }}
}}
site "h2.example.test" {{
    root "{}"
    route "/up/*" {{
        reverse-proxy {{
            upstream "http://127.0.0.1:{port}"
        }}
    }}
}}
"#,
        root.to_string_lossy().replace('\\', "/")
    );
    let (cfg, _) = parse_kdl("h2-empty.kdl", &kdl)?;
    let engine = Arc::new(HttpEngine::from_config(
        &cfg,
        Arc::new(AcmeChallengeStore::new()),
        None,
        8443,
    )?);
    let (client, server) = tokio::io::duplex(256 * 1024);
    let peer: SocketAddr = "198.51.100.8:50000".parse()?;
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
    let (mut sender, conn) = http2::Builder::new(TokioExecutor::new())
        .handshake::<_, Pieces>(TokioIo::new(client))
        .await?;
    let connection = tokio::spawn(async move {
        let _ = conn.await;
    });

    // Well past the 100 that h2 0.4.20 tolerated per connection.
    for n in 0..250 {
        sender
            .ready()
            .await
            .map_err(|e| format!("upload {n}: connection not ready: {e}"))?;
        let resp = sender
            .send_request(upload("/up/item")?)
            .await
            .map_err(|e| format!("upload {n} failed: {e}"))?;
        assert_eq!(resp.status(), StatusCode::OK, "upload {n}");
        assert_eq!(resp.into_body().collect().await?.to_bytes().as_ref(), b"ok");
    }
    assert_eq!(
        received.load(Ordering::Relaxed),
        250,
        "the upstream must have received every upload's payload"
    );

    assert!(
        !connection.is_finished(),
        "the connection must still be open after 250 uploads"
    );
    sender.ready().await?;
    let resp = sender
        .send_request(
            Request::builder()
                .uri("https://h2.example.test/small.txt")
                .body(Pieces(VecDeque::new()))?,
        )
        .await?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.into_body().collect().await?.to_bytes().as_ref(),
        b"small"
    );

    upstream.abort();
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

/// Whether `seen` holds a whole HTTP/1.1 request: the head, then a chunked body up to its last
/// chunk or a body of `content-length` bytes.
fn request_is_complete(seen: &[u8]) -> bool {
    let Some(head_end) = seen.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(seen.get(..head_end).unwrap_or(&[])).to_ascii_lowercase();
    let body = seen.get(head_end.saturating_add(4)..).unwrap_or(&[]);
    if head.contains("transfer-encoding: chunked") {
        return body.ends_with(b"0\r\n\r\n");
    }
    let length = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    body.len() >= length
}

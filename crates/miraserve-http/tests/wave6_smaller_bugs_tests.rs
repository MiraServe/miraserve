//! Wave 6 integration tests (HANDOVER §5 #11):
//! - Proxied compressible text/JSON responses are compressed on the fly (`zstd` > `br` > `gzip`),
//!   emit `Vary: Accept-Encoding`, and weaken strong `ETag`s (`W/"..."`), while leaving SSE
//!   (`text/event-stream`), `Cache-Control: no-transform`, and already-encoded upstreams untouched.
//! - IPv6 literal site names (`[::1]`, `2001:db8::1`) validate cleanly and route incoming
//!   requests regardless of IPv6 zero-compression/case formatting.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::{
    ACCEPT_ENCODING, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_TYPE, ETAG, HOST, VARY,
};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use miraserve_config::parse_kdl;
use miraserve_http::{HttpEngine, RequestContext, empty_http_body};
use miraserve_tls::AcmeChallengeStore;
use tokio::net::TcpListener;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Result<Self, std::io::Error> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path =
            std::env::temp_dir().join(format!("miraserve-w6-{tag}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn test_ctx() -> RequestContext {
    RequestContext {
        client_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        remote_port: Some(54_321),
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 443,
        is_https: true,
        tls: None,
    }
}

async fn spawn_proxy_test_upstream(
    large_text: Arc<String>,
) -> Result<(SocketAddr, tokio::task::AbortHandle), std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let payload = Arc::clone(&large_text);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let payload = Arc::clone(&payload);
                    async move {
                        let resp = match req.uri().path() {
                            "/api/json" => Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, "application/json; charset=utf-8")
                                .header(ETAG, "\"strong-v1\"")
                                .body(Full::new(Bytes::from(payload.as_bytes().to_vec())))
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                            "/api/sse" => Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, "text/event-stream")
                                .body(Full::new(Bytes::from(payload.as_bytes().to_vec())))
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                            "/api/no-transform" => Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                                .header(CACHE_CONTROL, "public, no-transform")
                                .body(Full::new(Bytes::from(payload.as_bytes().to_vec())))
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                            "/api/preencoded" => Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                                .header(CONTENT_ENCODING, "gzip")
                                .body(Full::new(Bytes::from_static(b"ALREADY_GZIPPED")))
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                            _ => Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(Full::new(Bytes::from_static(b"nope")))
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                        };
                        Ok::<_, std::convert::Infallible>(resp)
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    Ok((addr, task.abort_handle()))
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn proxied_text_responses_compress_with_zstd_br_gzip_and_preserve_sse_and_no_transform()
-> TestResult {
    let tmp = TempDir::new("proxy-compress")?;
    fs::write(tmp.path.join("index.html"), b"ok")?;
    let large_json = Arc::new(format!(
        "{{\"items\":[{}]}}",
        "\"miraserve-edge-proxy-compression-payload\",".repeat(150)
    ));
    let (up_addr, up_abort) = spawn_proxy_test_upstream(Arc::clone(&large_json)).await?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
}}
site "api.example" {{
    root "{root}"
    route "/api/*" {{
        reverse-proxy {{
            upstream "http://{up_addr}"
        }}
    }}
}}
"#,
        root = tmp.path.to_string_lossy().replace('\\', "/"),
    );

    let (cfg, _) = parse_kdl("proxy-compress.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 443)?;
    let ctx = test_ctx();

    // 1. Zstd preferred when client advertises `zstd, br, gzip`, strong ETag weakened, Vary added!
    let req_zstd = Request::builder()
        .uri("/api/json")
        .header(HOST, "api.example")
        .header(ACCEPT_ENCODING, "zstd, br, gzip")
        .body(empty_http_body())?;
    let resp_zstd = engine.handle_request(req_zstd, &ctx).await;
    assert_eq!(resp_zstd.status(), StatusCode::OK);
    assert_eq!(
        resp_zstd
            .headers()
            .get(CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("zstd")
    );
    assert_eq!(
        resp_zstd.headers().get(ETAG).and_then(|v| v.to_str().ok()),
        Some("W/\"strong-v1\""),
        "strong ETag must be weakened when compressing proxied response"
    );
    assert!(
        resp_zstd
            .headers()
            .get(VARY)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("Accept-Encoding")),
        "Vary: Accept-Encoding must be set on compressed proxy response"
    );
    let zstd_body = resp_zstd.into_body().collect().await?.to_bytes();
    assert!(zstd_body.len() < large_json.len());
    let decoded_zstd = miraserve_static::compress::decompress_zstd(&zstd_body)?;
    assert_eq!(decoded_zstd.as_slice(), large_json.as_bytes());

    // 2. Brotli selected when `br, gzip` accepted.
    let req_br = Request::builder()
        .uri("/api/json")
        .header(HOST, "api.example")
        .header(ACCEPT_ENCODING, "br, gzip")
        .body(empty_http_body())?;
    let resp_br = engine.handle_request(req_br, &ctx).await;
    assert_eq!(
        resp_br
            .headers()
            .get(CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("br")
    );
    let br_body = resp_br.into_body().collect().await?.to_bytes();
    assert!(br_body.len() < large_json.len());

    // 3. Gzip selected when only `gzip` accepted.
    let req_gz = Request::builder()
        .uri("/api/json")
        .header(HOST, "api.example")
        .header(ACCEPT_ENCODING, "gzip")
        .body(empty_http_body())?;
    let resp_gz = engine.handle_request(req_gz, &ctx).await;
    assert_eq!(
        resp_gz
            .headers()
            .get(CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("gzip")
    );
    let gz_body = resp_gz.into_body().collect().await?.to_bytes();
    assert!(gz_body.len() < large_json.len());

    // 4. SSE (`text/event-stream`) MUST NOT be compressed!
    let req_sse = Request::builder()
        .uri("/api/sse")
        .header(HOST, "api.example")
        .header(ACCEPT_ENCODING, "zstd, br, gzip")
        .body(empty_http_body())?;
    let resp_sse = engine.handle_request(req_sse, &ctx).await;
    assert!(
        resp_sse.headers().get(CONTENT_ENCODING).is_none(),
        "SSE text/event-stream must never be buffered/compressed"
    );

    // 5. `Cache-Control: no-transform` MUST NOT be compressed!
    let req_nt = Request::builder()
        .uri("/api/no-transform")
        .header(HOST, "api.example")
        .header(ACCEPT_ENCODING, "zstd, br, gzip")
        .body(empty_http_body())?;
    let resp_nt = engine.handle_request(req_nt, &ctx).await;
    assert!(
        resp_nt.headers().get(CONTENT_ENCODING).is_none(),
        "Cache-Control: no-transform response must never be compressed"
    );

    // 6. Upstream response with existing Content-Encoding MUST NOT be double-compressed!
    let req_pre = Request::builder()
        .uri("/api/preencoded")
        .header(HOST, "api.example")
        .header(ACCEPT_ENCODING, "zstd, br, gzip")
        .body(empty_http_body())?;
    let resp_pre = engine.handle_request(req_pre, &ctx).await;
    assert_eq!(
        resp_pre
            .headers()
            .get(CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("gzip")
    );
    assert_eq!(
        resp_pre.into_body().collect().await?.to_bytes().as_ref(),
        b"ALREADY_GZIPPED"
    );

    up_abort.abort();
    Ok(())
}

#[tokio::test]
async fn ipv6_literal_site_names_validate_and_route_canonical_host_headers() -> TestResult {
    let tmp_a = TempDir::new("ipv6-a")?;
    let tmp_b = TempDir::new("ipv6-b")?;
    fs::write(tmp_a.path.join("index.html"), b"ipv6-bracketed-ok")?;
    fs::write(tmp_b.path.join("index.html"), b"ipv6-bare-loopback-ok")?;

    let kdl = format!(
        r#"
server {{
    listen "[::1]:8443"
}}
site "[2001:db8::1]" {{
    root "{root_a}"
}}
site "::1" {{
    root "{root_b}"
}}
"#,
        root_a = tmp_a.path.to_string_lossy().replace('\\', "/"),
        root_b = tmp_b.path.to_string_lossy().replace('\\', "/"),
    );

    let (cfg, _) = parse_kdl("ipv6-sites.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 443)?;
    let ctx = test_ctx();

    // Non-canonical uppercase/expanded IPv6 Host header with port matches `[2001:db8::1]`!
    let req_a = Request::builder()
        .uri("/")
        .header(HOST, "[2001:DB8:0:0::1]:8443")
        .body(empty_http_body())?;
    let resp_a = engine.handle_request(req_a, &ctx).await;
    assert_eq!(resp_a.status(), StatusCode::OK);
    assert_eq!(
        resp_a.into_body().collect().await?.to_bytes().as_ref(),
        b"ipv6-bracketed-ok"
    );

    // Bracketed loopback `[::1]` matches bare `site "::1"`!
    let req_b = Request::builder()
        .uri("/")
        .header(HOST, "[::1]")
        .body(empty_http_body())?;
    let resp_b = engine.handle_request(req_b, &ctx).await;
    assert_eq!(resp_b.status(), StatusCode::OK);
    assert_eq!(
        resp_b.into_body().collect().await?.to_bytes().as_ref(),
        b"ipv6-bare-loopback-ok"
    );

    Ok(())
}

/// Codex G6: Unknown-length proxied text streams MUST NOT buffer until EOF before returning
/// headers. The client must receive response headers and the decoded first chunk immediately
/// while the upstream remains open, then receive subsequent chunks until EOF.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn g6_unknown_length_proxied_text_stream_delivers_headers_and_first_chunk_before_eof()
-> TestResult {
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use http_body::{Body, Frame};
    use tokio::sync::{Notify, mpsc};

    struct ChannelBody {
        rx: mpsc::Receiver<Bytes>,
    }

    impl Body for ChannelBody {
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

    let gate = Arc::new(Notify::new());
    let gate_srv = Arc::clone(&gate);

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = listener.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let gate = Arc::clone(&gate_srv);
            tokio::spawn(async move {
                let svc = service_fn(move |_req: Request<Incoming>| {
                    let gate = Arc::clone(&gate);
                    async move {
                        let (tx, rx) = mpsc::channel::<Bytes>(4);
                        tokio::spawn(async move {
                            let _ = tx
                                .send(Bytes::from_static(b"log-line-1: live streaming output\n"))
                                .await;
                            // Keep the upstream open until the test proves the client already
                            // received headers AND decoded chunk 1!
                            gate.notified().await;
                            let _ = tx
                                .send(Bytes::from_static(b"log-line-2: stream finished\n"))
                                .await;
                        });
                        // Deliberately NO Content-Length header (chunked unknown-length stream).
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                                .body(ChannelBody { rx })
                                .unwrap_or_else(|_| {
                                    let (_, empty_rx) = mpsc::channel::<Bytes>(1);
                                    Response::new(ChannelBody { rx: empty_rx })
                                }),
                        )
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let root = TempDir::new("g6-stream")?;
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/tmp/c.crt"; key "/tmp/c.key" }}
}}
site "logs.example.test" {{
    root "{root}"
    route "/live/*" {{
        reverse-proxy {{
            upstream "http://{upstream_addr}"
        }}
    }}
}}
"#,
        root = root.path.display(),
    );
    let (cfg, _) = parse_kdl("g6-stream.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let ctx = RequestContext {
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 66))),
        remote_port: Some(41000),
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 8443,
        is_https: true,
        tls: None,
    };

    for (accept_enc, expected_ce) in [("gzip", Some("gzip")), ("br", Some("br")), ("zstd", None)] {
        let req = Request::builder()
            .uri("/live/build.log")
            .header(HOST, "logs.example.test")
            .header(ACCEPT_ENCODING, accept_enc)
            .body(empty_http_body())?;

        // Headers MUST return promptly while upstream is still blocked on `gate`!
        let resp = tokio::time::timeout(Duration::from_secs(2), engine.handle_request(req, &ctx))
            .await
            .map_err(|_| format!("headers delayed until EOF for Accept-Encoding: {accept_enc}"))?;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok()),
            expected_ce,
            "unexpected Content-Encoding for Accept-Encoding: {accept_enc}"
        );

        let mut body = resp.into_body();
        // First chunk MUST arrive immediately while upstream is still open!
        let first_frame = tokio::time::timeout(Duration::from_secs(2), body.frame())
            .await
            .map_err(|_| {
                format!("first chunk delayed until EOF for Accept-Encoding: {accept_enc}")
            })?
            .ok_or("stream ended before first chunk")??
            .into_data()
            .map_err(|_| "expected data frame for chunk 1")?;

        let decoded_first = match expected_ce {
            Some("gzip") => miraserve_static::compress::decompress_gzip(&first_frame)?,
            Some("br") => miraserve_static::compress::decompress_brotli(&first_frame)?,
            _ => first_frame.to_vec(),
        };
        assert_eq!(
            decoded_first.as_slice(),
            b"log-line-1: live streaming output\n",
            "chunk 1 must decode cleanly while upstream is still open ({accept_enc})"
        );

        // Now release upstream to emit chunk 2 and close.
        gate.notify_one();
        let mut all_wire = first_frame.to_vec();
        while let Some(next_frame) = tokio::time::timeout(Duration::from_secs(2), body.frame())
            .await
            .map_err(|_| format!("stream hung after releasing gate ({accept_enc})"))?
        {
            let frame = next_frame?;
            if let Some(data) = frame.data_ref() {
                all_wire.extend_from_slice(data);
            }
        }
        let decoded_full = match expected_ce {
            Some("gzip") => miraserve_static::compress::decompress_gzip(&all_wire)?,
            Some("br") => miraserve_static::compress::decompress_brotli(&all_wire)?,
            _ => all_wire,
        };
        assert_eq!(
            decoded_full.as_slice(),
            b"log-line-1: live streaming output\nlog-line-2: stream finished\n",
            "full decoded stream mismatch for Accept-Encoding: {accept_enc}"
        );
    }

    upstream_task.abort();
    Ok(())
}

/// Codex G6 (P1): Compressing a proxied response with repeated upstream `Vary` header lines
/// (e.g. `Vary: Origin` and `Vary: Cookie`) MUST preserve every upstream `Vary` value while
/// adding `Accept-Encoding`, for BOTH buffered (known `Content-Length`) and streaming
/// (unknown-length chunked) responses.
#[tokio::test]
async fn g6_p1_compression_preserves_repeated_vary_headers_for_buffered_and_streaming() -> TestResult
{
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use http_body::{Body, Frame};
    use tokio::sync::mpsc;

    struct StreamBody {
        rx: mpsc::Receiver<Bytes>,
    }

    impl Body for StreamBody {
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

    let payload = "personalized-json-entry-".repeat(120);
    let payload_srv = payload.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = listener.local_addr()?;
    let up_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let body_text = payload_srv.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let body_text = body_text.clone();
                    async move {
                        if req.uri().path() == "/api/buffered" {
                            let bytes = Bytes::from(body_text);
                            let mut resp = Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, "application/json")
                                .header(http::header::CONTENT_LENGTH, bytes.len())
                                .body(Full::new(bytes).map_err(|never| match never {}).boxed())
                                .unwrap_or_else(|_| {
                                    Response::new(
                                        Full::new(Bytes::new())
                                            .map_err(|never| match never {})
                                            .boxed(),
                                    )
                                });
                            resp.headers_mut()
                                .append(VARY, http::HeaderValue::from_static("Origin"));
                            resp.headers_mut()
                                .append(VARY, http::HeaderValue::from_static("Cookie"));
                            Ok::<_, std::convert::Infallible>(resp)
                        } else {
                            let (tx, rx) = mpsc::channel::<Bytes>(2);
                            tokio::spawn(async move {
                                let _ = tx.send(Bytes::from(body_text)).await;
                            });
                            let mut resp = Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                                .body(StreamBody { rx }.map_err(|never| match never {}).boxed())
                                .unwrap_or_else(|_| {
                                    Response::new(
                                        Full::new(Bytes::new())
                                            .map_err(|never| match never {})
                                            .boxed(),
                                    )
                                });
                            resp.headers_mut()
                                .append(VARY, http::HeaderValue::from_static("Origin"));
                            resp.headers_mut()
                                .append(VARY, http::HeaderValue::from_static("Cookie"));
                            Ok::<_, std::convert::Infallible>(resp)
                        }
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let root = TempDir::new("g6-p1-vary")?;
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/tmp/c.crt"; key "/tmp/c.key" }}
}}
site "vary.example.test" {{
    root "{}"
    route "/api/*" {{
        reverse-proxy {{
            upstream "http://{up_addr}"
        }}
    }}
}}
"#,
        root.path.display(),
    );
    let (cfg, _) = parse_kdl("g6-p1-vary.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let ctx = RequestContext {
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 70))),
        remote_port: Some(41001),
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 8443,
        is_https: true,
        tls: None,
    };

    for path in ["/api/buffered", "/api/streaming"] {
        let req = Request::builder()
            .uri(path)
            .header(HOST, "vary.example.test")
            .header(ACCEPT_ENCODING, "gzip")
            .body(empty_http_body())?;
        let resp = engine.handle_request(req, &ctx).await;
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        assert_eq!(
            resp.headers()
                .get(CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok()),
            Some("gzip"),
            "{path} must be gzip-compressed"
        );
        let vary_tokens: Vec<String> = resp
            .headers()
            .get_all(VARY)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|s| s.split(','))
            .map(|t| t.trim().to_ascii_lowercase())
            .collect();
        for required in ["origin", "cookie", "accept-encoding"] {
            assert!(
                vary_tokens.iter().any(|t| t == required),
                "{path} must preserve Vary token `{required}`, got: {vary_tokens:?}"
            );
        }
        let wire = resp.into_body().collect().await?.to_bytes();
        let decoded = miraserve_static::compress::decompress_gzip(&wire)?;
        assert_eq!(decoded.as_slice(), payload.as_bytes());
    }

    up_task.abort();
    Ok(())
}

/// Codex G6 (RFC 9530 §2): Proxied responses carrying `Content-Digest` (or advertising
/// `Trailer: Content-Digest`) MUST NOT have their representation bytes altered by compression,
/// preserving the original encoding and digest on both buffered and streaming responses.
#[tokio::test]
async fn g6_integrity_protected_responses_with_content_digest_are_not_compressed() -> TestResult {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use http_body::{Body, Frame};
    use tokio::sync::mpsc;

    struct StreamBody {
        rx: mpsc::Receiver<Bytes>,
    }

    impl Body for StreamBody {
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

    let payload = "integrity-protected-payload-".repeat(120);
    let payload_srv = payload.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = listener.local_addr()?;
    let up_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let body_text = payload_srv.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let body_text = body_text.clone();
                    async move {
                        if req.uri().path() == "/api/digest-header" {
                            let bytes = Bytes::from(body_text);
                            return Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header(CONTENT_TYPE, "application/json")
                                    .header(http::header::CONTENT_LENGTH, bytes.len())
                                    .header("content-digest", "sha-256=:dGVzdA==:")
                                    .body(Full::new(bytes).map_err(|never| match never {}).boxed())
                                    .unwrap_or_else(|_| {
                                        Response::new(
                                            Full::new(Bytes::new())
                                                .map_err(|never| match never {})
                                                .boxed(),
                                        )
                                    }),
                            );
                        }
                        let (tx, rx) = mpsc::channel::<Bytes>(2);
                        tokio::spawn(async move {
                            let _ = tx.send(Bytes::from(body_text)).await;
                        });
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                                .header(http::header::TRAILER, "Content-Digest")
                                .body(StreamBody { rx }.map_err(|never| match never {}).boxed())
                                .unwrap_or_else(|_| {
                                    Response::new(
                                        Full::new(Bytes::new())
                                            .map_err(|never| match never {})
                                            .boxed(),
                                    )
                                }),
                        )
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let root = TempDir::new("g6-digest")?;
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/tmp/c.crt"; key "/tmp/c.key" }}
}}
site "digest.example.test" {{
    root "{}"
    route "/api/*" {{
        reverse-proxy {{
            upstream "http://{up_addr}"
        }}
    }}
}}
"#,
        root.path.display(),
    );
    let (cfg, _) = parse_kdl("g6-digest.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let ctx = RequestContext {
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 71))),
        remote_port: Some(41002),
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 8443,
        is_https: true,
        tls: None,
    };

    for path in ["/api/digest-header", "/api/digest-trailer"] {
        let req = Request::builder()
            .uri(path)
            .header(HOST, "digest.example.test")
            .header(ACCEPT_ENCODING, "zstd, br, gzip")
            .body(empty_http_body())?;
        let resp = engine.handle_request(req, &ctx).await;
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        assert!(
            !resp.headers().contains_key(CONTENT_ENCODING),
            "{path} must NOT be compressed when Content-Digest integrity protection is present"
        );
        let body = resp.into_body().collect().await?.to_bytes();
        assert_eq!(body.as_ref(), payload.as_bytes(), "{path} body altered");
    }

    up_task.abort();
    Ok(())
}

/// Codex Round-3 P2 #4 (G6): Real chunked HTTP/1.1 upstream emitting actual `Frame::trailers`:
/// 1. When upstream advertises `Trailer: Content-Digest`, MiraServe preserves the uncompressed
///    representation AND forwards the real `Content-Digest`, `Repr-Digest`, and benign trailers.
/// 2. When upstream omits `Trailer` (so MiraServe streams gzip compression) and then appends a
///    late unadvertised `Repr-Digest` + `Content-Digest` alongside benign `X-Stream-Status: ok`,
///    MiraServe MUST strip both `Repr-Digest` and `Content-Digest` while keeping `X-Stream-Status`
///    and producing valid gzip-compressed bytes.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn g6_r3_p2_streaming_compression_preserves_advertised_digest_trailers_and_strips_late_repr_digest()
-> TestResult {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let payload = "chunked-trailer-integrity-payload-".repeat(120);
    let payload_srv = payload.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = listener.local_addr()?;
    // Raw HTTP/1.1 chunked upstream that emits REAL wire-level trailers (`0\r\n...\r\n\r\n`)
    // for both advertised (`Trailer: Content-Digest, ...`) and unadvertised late trailers!
    let up_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let body_text = payload_srv.clone();
            tokio::spawn(async move {
                let mut req_buf = vec![0u8; 4096];
                let n = stream.read(&mut req_buf).await.unwrap_or(0);
                let req_head = String::from_utf8_lossy(req_buf.get(..n).unwrap_or_default());
                let advertise = req_head.contains("GET /api/advertised-trailer ");
                let mid = body_text.len() / 2;
                let part1 = body_text.as_bytes().get(..mid).unwrap_or_default();
                let part2 = body_text.as_bytes().get(mid..).unwrap_or_default();
                let trailer_hdr = if advertise {
                    "Trailer: Content-Digest, Repr-Digest, X-Stream-Status\r\n"
                } else {
                    ""
                };
                let head = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: text/plain; charset=utf-8\r\n\
                     Transfer-Encoding: chunked\r\n\
                     Connection: close\r\n\
                     {trailer_hdr}\r\n"
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream
                    .write_all(format!("{:x}\r\n", part1.len()).as_bytes())
                    .await;
                let _ = stream.write_all(part1).await;
                let _ = stream.write_all(b"\r\n").await;
                let _ = stream
                    .write_all(format!("{:x}\r\n", part2.len()).as_bytes())
                    .await;
                let _ = stream.write_all(part2).await;
                let _ = stream
                    .write_all(
                        b"\r\n0\r\n\
                          Content-Digest: sha-256=:Y29udGVudA==:\r\n\
                          Repr-Digest: sha-256=:cmVwcg==:\r\n\
                          X-Stream-Status: ok\r\n\r\n",
                    )
                    .await;
                let _ = stream.flush().await;
            });
        }
    });

    let root = TempDir::new("g6-r3-trailers")?;
    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/tmp/c.crt"; key "/tmp/c.key" }}
}}
site "trailers.example.test" {{
    root "{}"
    route "/api/*" {{
        reverse-proxy {{
            upstream "http://{up_addr}"
        }}
    }}
}}
"#,
        root.path.display(),
    );
    let (cfg, _) = parse_kdl("g6-r3-trailers.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;
    let ctx = RequestContext {
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 72))),
        remote_port: Some(41003),
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 8443,
        is_https: true,
        tls: None,
    };

    // 1. Advertised `Trailer: Content-Digest`: NOT compressed, real trailers preserved intact!
    let adv_req = Request::builder()
        .uri("/api/advertised-trailer")
        .header(HOST, "trailers.example.test")
        .header(ACCEPT_ENCODING, "gzip")
        .body(empty_http_body())?;
    let adv_resp = engine.handle_request(adv_req, &ctx).await;
    assert_eq!(adv_resp.status(), StatusCode::OK);
    assert!(
        adv_resp.headers().get(CONTENT_ENCODING).is_none(),
        "advertised digest trailer response must not be compressed"
    );
    let adv_collected = adv_resp.into_body().collect().await?;
    let adv_trailers = adv_collected
        .trailers()
        .ok_or("expected real HTTP/1.1 trailer frame on advertised response")?
        .clone();
    assert_eq!(
        adv_trailers
            .get("content-digest")
            .and_then(|v| v.to_str().ok()),
        Some("sha-256=:Y29udGVudA==:")
    );
    assert_eq!(
        adv_trailers
            .get("repr-digest")
            .and_then(|v| v.to_str().ok()),
        Some("sha-256=:cmVwcg==:")
    );
    assert_eq!(
        adv_trailers
            .get("x-stream-status")
            .and_then(|v| v.to_str().ok()),
        Some("ok")
    );
    assert_eq!(adv_collected.to_bytes().as_ref(), payload.as_bytes());

    // 2. Unadvertised late `Repr-Digest` & `Content-Digest` on a gzip-compressed stream:
    //    digest trailers MUST be stripped while benign `X-Stream-Status: ok` & gzip body survive!
    let late_req = Request::builder()
        .uri("/api/late-unadvertised-repr-digest")
        .header(HOST, "trailers.example.test")
        .header(ACCEPT_ENCODING, "gzip")
        .body(empty_http_body())?;
    let late_resp = engine.handle_request(late_req, &ctx).await;
    assert_eq!(late_resp.status(), StatusCode::OK);
    assert_eq!(
        late_resp
            .headers()
            .get(CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok()),
        Some("gzip"),
        "unadvertised streaming text response should gzip-compress"
    );
    let late_collected = late_resp.into_body().collect().await?;
    let late_trailers = late_collected
        .trailers()
        .ok_or("expected benign X-Stream-Status trailer frame to survive compression")?
        .clone();
    assert!(
        late_trailers.get("repr-digest").is_none(),
        "stale late Repr-Digest trailer MUST be stripped when streaming compression ran, got: {late_trailers:?}"
    );
    assert!(
        late_trailers.get("content-digest").is_none(),
        "stale late Content-Digest trailer MUST be stripped when streaming compression ran, got: {late_trailers:?}"
    );
    assert_eq!(
        late_trailers
            .get("x-stream-status")
            .and_then(|v| v.to_str().ok()),
        Some("ok"),
        "benign trailer X-Stream-Status must be preserved"
    );
    let decoded = miraserve_static::compress::decompress_gzip(&late_collected.to_bytes())?;
    assert_eq!(decoded.as_slice(), payload.as_bytes());

    up_task.abort();
    Ok(())
}

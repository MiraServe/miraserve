//! Live integration tests for `miraserve-proxy`: weighted load balancing, active health-check
//! ejection & recovery, zero-buffer SSE streaming, and bidirectional HTTP Upgrade tunneling.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::{CONNECTION, CONTENT_TYPE, UPGRADE};
use http::{HeaderValue, Request, Response, StatusCode};
use http_body::{Body, Frame};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use miraserve_config::{
    HealthCheckConfig, LoadBalancePolicy, ReverseProxyConfig, StreamingFlushMode, UpstreamConfig,
};
use miraserve_proxy::{ProxyBody, ProxyError, ReverseProxy, empty_body, full_body};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::{Notify, mpsc};

type TestResult = Result<(), Box<dyn std::error::Error>>;

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

async fn spawn_tagged_backend(
    tag: &'static str,
    healthy: Arc<AtomicBool>,
) -> Result<(SocketAddr, tokio::task::AbortHandle), std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let healthy_flag = Arc::clone(&healthy);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: Request<Incoming>| {
                    let is_ok = healthy_flag.load(Ordering::Acquire);
                    async move {
                        if req.uri().path() == "/health" {
                            let status = if is_ok {
                                StatusCode::OK
                            } else {
                                StatusCode::INTERNAL_SERVER_ERROR
                            };
                            let mut resp = Response::new(Full::new(Bytes::from_static(b"health")));
                            *resp.status_mut() = status;
                            return Ok::<_, std::convert::Infallible>(resp);
                        }
                        let xff = req
                            .headers()
                            .get("x-forwarded-for")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        let payload = format!("{tag}|{}|{xff}", req.uri().path());
                        Ok(Response::new(Full::new(Bytes::from(payload))))
                    }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    Ok((addr, handle.abort_handle()))
}

#[tokio::test]
async fn round_robin_and_active_health_check_ejection_and_recovery() -> TestResult {
    let h1 = Arc::new(AtomicBool::new(true));
    let h2 = Arc::new(AtomicBool::new(true));
    let (addr1, abort1) = spawn_tagged_backend("up1", Arc::clone(&h1)).await?;
    let (addr2, abort2) = spawn_tagged_backend("up2", Arc::clone(&h2)).await?;

    let proxy = ReverseProxy::new(&ReverseProxyConfig {
        upstreams: vec![
            UpstreamConfig {
                url: format!("http://{addr1}"),
                weight: 1,
            },
            UpstreamConfig {
                url: format!("http://{addr2}"),
                weight: 1,
            },
        ],
        streaming_flush: StreamingFlushMode::Buffered,
        lb_policy: LoadBalancePolicy::RoundRobin,
        health_check: Some(HealthCheckConfig {
            path: "/health".to_owned(),
            interval: Duration::from_millis(80),
            timeout: Some(Duration::from_millis(50)),
            unhealthy_threshold: 2,
            host: None,
        }),
        upstream_tls: None,
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
        preserve_host: false,
        allow_upgrades: true,
        strip_prefix: false,
    })?;

    let client_ip = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)));

    // 1. Both healthy -> round-robin alternates up1 and up2.
    let mut seen = Vec::new();
    for _ in 0..2 {
        let req = Request::builder().uri("/v1/chat").body(empty_body())?;
        let resp = proxy.forward(req, client_ip, "https").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let text = String::from_utf8(resp.into_body().collect().await?.to_bytes().to_vec())?;
        seen.push(text);
    }
    assert!(seen.iter().any(|s| s == "up1|/v1/chat|203.0.113.9"));
    assert!(seen.iter().any(|s| s == "up2|/v1/chat|203.0.113.9"));

    // 2. Mark up1 unhealthy and wait for health checker to eject it.
    h1.store(false, Ordering::Release);
    tokio::time::sleep(Duration::from_millis(320)).await;

    for _ in 0..4 {
        let req = Request::builder().uri("/v1/chat").body(empty_body())?;
        let resp = proxy.forward(req, client_ip, "https").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let text = String::from_utf8(resp.into_body().collect().await?.to_bytes().to_vec())?;
        assert!(
            text.starts_with("up2|"),
            "expected traffic on up2, got {text}"
        );
    }

    // 3. Recover up1 and confirm traffic returns to both upstreams.
    h1.store(true, Ordering::Release);
    tokio::time::sleep(Duration::from_millis(220)).await;
    let mut recovered = false;
    for _ in 0..4 {
        let req = Request::builder().uri("/v1/chat").body(empty_body())?;
        let resp = proxy.forward(req, client_ip, "https").await;
        let text = String::from_utf8(resp.into_body().collect().await?.to_bytes().to_vec())?;
        if text.starts_with("up1|") {
            recovered = true;
        }
    }
    assert!(
        recovered,
        "expected up1 to recover after /health returned 200"
    );

    abort1.abort();
    abort2.abort();
    Ok(())
}

#[tokio::test]
async fn immediate_sse_streaming_flushes_chunk_one_before_chunk_two_is_sent() -> TestResult {
    let gate = Arc::new(Notify::new());
    let gate_server = Arc::clone(&gate);

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let upstream_task = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |_req: Request<Incoming>| {
                let notify = Arc::clone(&gate_server);
                async move {
                    let (tx, rx) = mpsc::channel::<Bytes>(4);
                    tokio::spawn(async move {
                        let _ = tx.send(Bytes::from_static(b"data: token-1\n\n")).await;
                        // Block until client proves it already received token-1!
                        notify.notified().await;
                        let _ = tx.send(Bytes::from_static(b"data: token-2\n\n")).await;
                    });
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, "text/event-stream")
                        .body(ChannelBody { rx })
                }
            });
            let _ = http1::Builder::new().serve_connection(io, svc).await;
        }
    });

    let proxy = ReverseProxy::new(&ReverseProxyConfig {
        upstreams: vec![UpstreamConfig {
            url: format!("http://{addr}"),
            weight: 1,
        }],
        streaming_flush: StreamingFlushMode::Immediate,
        lb_policy: LoadBalancePolicy::LeastConn,
        health_check: None,
        upstream_tls: None,
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
        preserve_host: false,
        allow_upgrades: true,
        strip_prefix: false,
    })?;

    let req = Request::builder().uri("/v1/stream").body(empty_body())?;
    let resp = proxy.forward(req, None, "https").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-accel-buffering")
            .and_then(|v| v.to_str().ok()),
        Some("no")
    );

    let mut body = resp.into_body();
    // Chunk 1 MUST arrive within 2 seconds even though upstream is waiting on `gate`!
    let first = tokio::time::timeout(Duration::from_secs(2), body.frame())
        .await?
        .ok_or("stream ended before chunk 1")??
        .into_data()
        .map_err(|_| "expected data frame")?;
    assert_eq!(first.as_ref(), b"data: token-1\n\n");

    // Release upstream to send chunk 2.
    gate.notify_one();

    let second = tokio::time::timeout(Duration::from_secs(2), body.frame())
        .await?
        .ok_or("stream ended before chunk 2")??
        .into_data()
        .map_err(|_| "expected data frame")?;
    assert_eq!(second.as_ref(), b"data: token-2\n\n");

    upstream_task.abort();
    Ok(())
}

#[tokio::test]
async fn proxies_bidirectional_http_upgrade_tunnel() -> TestResult {
    // 1. Upstream HTTP/1.1 Upgrade echo server ("echo-proto")
    let up_listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = up_listener.local_addr()?;
    let up_task = tokio::spawn(async move {
        if let Ok((stream, _)) = up_listener.accept().await {
            let io = TokioIo::new(stream);
            let svc = service_fn(|mut req: Request<Incoming>| async move {
                let on_upgrade = hyper::upgrade::on(&mut req);
                tokio::spawn(async move {
                    if let Ok(upgraded) = on_upgrade.await {
                        let mut io = TokioIo::new(upgraded);
                        let mut buf = [0_u8; 5];
                        if io.read_exact(&mut buf).await.is_ok() {
                            let _ = io.write_all(b"ECHO:").await;
                            let _ = io.write_all(&buf).await;
                            let _ = io.shutdown().await;
                        }
                    }
                });
                Response::builder()
                    .status(StatusCode::SWITCHING_PROTOCOLS)
                    .header(CONNECTION, "upgrade")
                    .header(UPGRADE, "websocket")
                    .body(Full::new(Bytes::new()))
            });
            let _ = http1::Builder::new()
                .serve_connection(io, svc)
                .with_upgrades()
                .await;
        }
    });

    // 2. Proxy server exposing ReverseProxy over HTTP/1.1 with upgrades enabled
    let proxy = Arc::new(ReverseProxy::new(&ReverseProxyConfig {
        upstreams: vec![UpstreamConfig {
            url: format!("http://{up_addr}"),
            weight: 1,
        }],
        streaming_flush: StreamingFlushMode::Immediate,
        lb_policy: LoadBalancePolicy::RoundRobin,
        health_check: None,
        upstream_tls: None,
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
        preserve_host: false,
        allow_upgrades: true,
        strip_prefix: false,
    })?);

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_addr = proxy_listener.local_addr()?;
    let proxy_clone = Arc::clone(&proxy);
    let proxy_task = tokio::spawn(async move {
        if let Ok((stream, _)) = proxy_listener.accept().await {
            let io = TokioIo::new(stream);
            let p = Arc::clone(&proxy_clone);
            let svc = service_fn(move |req: Request<Incoming>| {
                let p = Arc::clone(&p);
                async move {
                    let mapped: Request<ProxyBody> =
                        req.map(|b| b.map_err(|err| ProxyError::Body(err.to_string())).boxed());
                    Ok::<_, std::convert::Infallible>(p.forward(mapped, None, "http").await)
                }
            });
            let _ = http1::Builder::new()
                .serve_connection(io, svc)
                .with_upgrades()
                .await;
        }
    });

    // 3. Client performs HTTP/1.1 Upgrade through the proxy and exchanges raw bytes
    let client_stream = tokio::net::TcpStream::connect(proxy_addr).await?;
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(TokioIo::new(client_stream)).await?;
    let conn_task = tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });

    let upgrade_req = Request::builder()
        .uri("/ws")
        .header(CONNECTION, HeaderValue::from_static("upgrade"))
        .header(UPGRADE, HeaderValue::from_static("websocket"))
        .header(
            "sec-websocket-key",
            HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        )
        .header("sec-websocket-version", HeaderValue::from_static("13"))
        .body(full_body(Bytes::new()))?;

    let mut resp = sender.send_request(upgrade_req).await?;
    assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);

    let upgraded = hyper::upgrade::on(&mut resp).await?;
    let mut tunnel = TokioIo::new(upgraded);
    tunnel.write_all(b"hello").await?;
    let mut reply = Vec::new();
    tunnel.read_to_end(&mut reply).await?;
    assert_eq!(reply.as_slice(), b"ECHO:hello");

    conn_task.abort();
    proxy_task.abort();
    up_task.abort();
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn proxy_blocks_dotdot_traversal_h2c_upgrade_xff_spoofing_and_connection_strip() -> TestResult
{
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let up_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let xff = req
                        .headers()
                        .get("x-forwarded-for")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("<none>");
                    let x_real = req
                        .headers()
                        .get("x-real-ip")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("<none>");
                    let auth = req
                        .headers()
                        .get(http::header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("<none>");
                    let upg = req.headers().contains_key(UPGRADE);
                    let h2s = req.headers().contains_key("http2-settings");
                    let body = format!("xff={xff}|xreal={x_real}|auth={auth}|upg={upg}|h2s={h2s}");
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(http::header::ALT_SVC, "h3=\":9999\"")
                            .body(Full::new(Bytes::from(body)))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                    )
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    let proxy = ReverseProxy::new(&ReverseProxyConfig {
        upstreams: vec![UpstreamConfig {
            url: format!("http://{addr}/v1"),
            weight: 1,
        }],
        streaming_flush: StreamingFlushMode::Buffered,
        lb_policy: LoadBalancePolicy::RoundRobin,
        health_check: None,
        upstream_tls: None,
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
        preserve_host: false,
        allow_upgrades: true,
        strip_prefix: false,
    })?;

    // 1. Raw `..`, encoded `..%2f`, `%5c`, and `%00` traversal rejected with 400 before upstream,
    //    while legitimate encoded `%2F` within a segment (GitLab/npm APIs, `R2-HTTP-3`) passes!
    for evil in [
        "/../admin",
        "/api/%2e%2e/secret",
        "/api/..%2fsecret",
        "/api/a%5cb",
        "/api/a%00b",
    ] {
        let req = Request::builder().uri(evil).body(empty_body())?;
        let resp = proxy.forward(req, None, "https").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "evil={evil}");
    }
    let encoded_slash_req = Request::builder()
        .uri("/projects/group%2Frepo/issues")
        .body(empty_body())?;
    let encoded_slash_resp = proxy.forward(encoded_slash_req, None, "https").await;
    assert_eq!(
        encoded_slash_resp.status(),
        StatusCode::OK,
        "encoded %2F within a non-traversal segment must forward cleanly"
    );

    // 2. Untrusted XFF/X-Real-IP overwritten, h2c Upgrade & HTTP2-Settings stripped,
    //    Connection: authorization cannot strip Authorization, upstream Alt-Svc stripped
    let req = Request::builder()
        .uri("/items")
        .header("x-forwarded-for", "127.0.0.1")
        .header("x-real-ip", "127.0.0.1")
        .header(http::header::AUTHORIZATION, "Bearer valid")
        .header(CONNECTION, "upgrade, authorization, x-forwarded-for")
        .header(UPGRADE, "h2c")
        .header("http2-settings", "AAMAAABkAAQAAP__")
        .body(empty_body())?;
    let resp = proxy
        .forward(
            req,
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))),
            "https",
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get(http::header::ALT_SVC).is_none(),
        "upstream Alt-Svc must be stripped"
    );
    let text = String::from_utf8(resp.into_body().collect().await?.to_bytes().to_vec())?;
    assert_eq!(
        text, "xff=198.51.100.7|xreal=198.51.100.7|auth=Bearer valid|upg=false|h2s=false",
        "the spoofed X-Real-IP (127.0.0.1) must be replaced by the real client address"
    );

    up_task.abort();
    Ok(())
}

struct FailingClientBody;

impl Body for FailingClientBody {
    type Data = Bytes;
    type Error = ProxyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(Some(Err(ProxyError::Body(
            "client slowloris abort".to_owned(),
        ))))
    }
}

struct SlowUploadBody(tokio::sync::mpsc::Receiver<Bytes>);

impl Body for SlowUploadBody {
    type Data = Bytes;
    type Error = ProxyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.0.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(b)) => Poll::Ready(Some(Ok(Frame::data(b)))),
        }
    }
}

/// R2-PRX-1 & R2-PRX-2 regression tests:
/// - Client-side request body failure returns 408 and MUST NOT mark a healthy backend unhealthy
/// - Slow client upload exceeding `upstream_timeout` succeeds cleanly because the response-header
///   deadline begins ONLY after the request body upload finishes.
#[tokio::test]
async fn proxy_wave3_client_errors_preserve_health_and_slow_uploads_survive_header_timeout()
-> TestResult {
    let up_listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = up_listener.local_addr()?;
    let up_task = tokio::spawn(async move {
        while let Ok((stream, _)) = up_listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let bytes = req
                        .into_body()
                        .collect()
                        .await
                        .map(http_body_util::Collected::to_bytes)
                        .unwrap_or_default();
                    Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from(format!(
                        "uploaded={}",
                        bytes.len()
                    )))))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    // Configure passive unhealthy_threshold=1 and a tight 200ms response-header timeout!
    let proxy = ReverseProxy::new(&ReverseProxyConfig {
        upstreams: vec![UpstreamConfig {
            url: format!("http://{up_addr}"),
            weight: 1,
        }],
        streaming_flush: StreamingFlushMode::Buffered,
        lb_policy: LoadBalancePolicy::RoundRobin,
        health_check: Some(miraserve_config::HealthCheckConfig {
            path: "/health".to_owned(),
            interval: Duration::from_secs(60),
            timeout: Some(Duration::from_secs(2)),
            unhealthy_threshold: 1,
            host: None,
        }),
        upstream_tls: None,
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
        preserve_host: false,
        allow_upgrades: true,
        strip_prefix: false,
    })?
    .with_upstream_timeout(Duration::from_millis(200));

    // 1. R2-PRX-1: Three failing client request bodies MUST return 408 and keep backend healthy!
    for _ in 0..3 {
        let req = Request::builder()
            .method(http::Method::POST)
            .uri("/upload")
            .body(FailingClientBody.boxed())?;
        let resp = proxy.forward(req, None, "https").await;
        assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
    }
    assert!(
        proxy.pool().select().is_some(),
        "client upload errors must NEVER eject a healthy backend"
    );

    // 2. R2-PRX-2: A multi-chunk upload taking 320ms (> 200ms response-header timeout!) MUST
    //    succeed with 200 OK because response-header timeout starts AFTER upload completes!
    let (body_tx, body_rx) = tokio::sync::mpsc::channel::<Bytes>(4);
    tokio::spawn(async move {
        let _ = body_tx.send(Bytes::from_static(b"part1-")).await;
        tokio::time::sleep(Duration::from_millis(320)).await;
        let _ = body_tx.send(Bytes::from_static(b"part2")).await;
    });
    let slow_req = Request::builder()
        .method(http::Method::POST)
        .uri("/upload")
        .body(SlowUploadBody(body_rx).boxed())?;
    let slow_resp = proxy.forward(slow_req, None, "https").await;
    assert_eq!(
        slow_resp.status(),
        StatusCode::OK,
        "upload taking 320ms with 200ms response-header timeout must NOT fail 504"
    );
    let body_text = String::from_utf8(slow_resp.into_body().collect().await?.to_bytes().to_vec())?;
    assert_eq!(body_text, "uploaded=11");

    up_task.abort();
    Ok(())
}

struct OversizedClientBody;

impl Body for OversizedClientBody {
    type Data = Bytes;
    type Error = ProxyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(Some(Err(ProxyError::PayloadTooLarge(1024))))
    }
}

struct FloodUploadBody(usize);

impl Body for FloodUploadBody {
    type Data = Bytes;
    type Error = ProxyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.0 == 0 {
            return Poll::Ready(None);
        }
        self.0 = self.0.saturating_sub(1);
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![b'x'; 256 * 1024])))))
    }
}

/// R3-HTTP-2 (413 mapping), R3-PRX-1 (stalled upstream during POST upload times out & counts as
/// passive health failure), and R3-PRX-2 (active & passive failure counters separated; 5xx never
/// resets failure counters).
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn round3_proxy_413_stalled_upload_timeout_and_separate_health_counters() -> TestResult {
    // 1. R3-HTTP-2 + R3-PRX-2: Upstream whose `/health` returns 503 while `/ok` returns 200 and
    //    `/boom` returns 500 — active health probes MUST eject it even under steady 200/500 traffic!
    let app_listener = TcpListener::bind("127.0.0.1:0").await?;
    let app_addr = app_listener.local_addr()?;
    let app_task = tokio::spawn(async move {
        while let Ok((stream, _)) = app_listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let status = match req.uri().path() {
                        "/health" => StatusCode::SERVICE_UNAVAILABLE,
                        "/boom" => StatusCode::INTERNAL_SERVER_ERROR,
                        _ => StatusCode::OK,
                    };
                    let mut resp = Response::new(Full::new(Bytes::from_static(b"reply")));
                    *resp.status_mut() = status;
                    Ok::<_, hyper::Error>(resp)
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let proxy = ReverseProxy::new(&ReverseProxyConfig {
        upstreams: vec![UpstreamConfig {
            url: format!("http://{app_addr}"),
            weight: 1,
        }],
        streaming_flush: StreamingFlushMode::Buffered,
        lb_policy: LoadBalancePolicy::RoundRobin,
        health_check: None,
        upstream_tls: None,
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
        preserve_host: false,
        allow_upgrades: true,
        strip_prefix: false,
    })?
    .with_upstream_timeout(Duration::from_millis(200));

    // 1a. R3-HTTP-2: Oversized client body returns 413 Payload Too Large (NOT 408) & preserves health!
    let big_req = Request::builder()
        .method(http::Method::POST)
        .uri("/upload")
        .body(OversizedClientBody.boxed())?;
    let big_resp = proxy.forward(big_req, None, "https").await;
    assert_eq!(big_resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(proxy.pool().select().is_some());

    // 1b. R3-PRX-2: Record 1 active failure, serve both 200 and 500 traffic -> active failure
    //     counter MUST NOT be reset, so the 2nd active failure ejects the backend!
    let backend = Arc::clone(
        proxy
            .pool()
            .backends()
            .first()
            .ok_or("missing backend in pool")?,
    );
    assert!(!backend.record_health_failure(2));
    let ok_resp = proxy
        .forward(
            Request::builder().uri("/ok").body(empty_body())?,
            None,
            "https",
        )
        .await;
    assert_eq!(ok_resp.status(), StatusCode::OK);
    let err_resp = proxy
        .forward(
            Request::builder().uri("/boom").body(empty_body())?,
            None,
            "https",
        )
        .await;
    assert_eq!(err_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        backend.record_health_failure(2),
        "2nd active failure MUST eject backend even after 200/500 passive responses"
    );
    assert!(!backend.is_healthy());

    // Restore and verify passive 500 does NOT reset passive failure counter either!
    backend.record_health_success();
    assert!(!backend.record_passive_health_failure(2));
    let err_resp2 = proxy
        .forward(
            Request::builder().uri("/boom").body(empty_body())?,
            None,
            "https",
        )
        .await;
    assert_eq!(err_resp2.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        backend.record_passive_health_failure(2),
        "passive 500 response MUST NOT reset passive failure counter"
    );

    // 1c. Live active prober ejects backend failing `/health` even while `/boom` returns 500 traffic!
    let live_hc_proxy = ReverseProxy::new(&ReverseProxyConfig {
        upstreams: vec![UpstreamConfig {
            url: format!("http://{app_addr}"),
            weight: 1,
        }],
        streaming_flush: StreamingFlushMode::Buffered,
        lb_policy: LoadBalancePolicy::RoundRobin,
        health_check: Some(miraserve_config::HealthCheckConfig {
            path: "/health".to_owned(),
            interval: Duration::from_millis(60),
            timeout: Some(Duration::from_secs(1)),
            unhealthy_threshold: 2,
            host: None,
        }),
        upstream_tls: None,
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
        preserve_host: false,
        allow_upgrades: true,
        strip_prefix: false,
    })?;
    let mut ejected = false;
    for _ in 0..20 {
        let _ = live_hc_proxy
            .forward(
                Request::builder().uri("/boom").body(empty_body())?,
                None,
                "https",
            )
            .await;
        if live_hc_proxy.pool().select().is_none() {
            ejected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        ejected,
        "active prober MUST eject backend failing /health even under continuous 500 traffic"
    );
    app_task.abort();

    // 2. R3-PRX-1: Upstream accepts TCP then never reads a large POST upload (stalled upstream) ->
    //    MUST time out with 504 Gateway Timeout AND record a passive health failure!
    let stall_listener = TcpListener::bind("127.0.0.1:0").await?;
    let stall_addr = stall_listener.local_addr()?;
    let stall_task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = stall_listener.accept().await {
            // Accept TCP and intentionally NEVER read bytes (simulates stalled upstream/TLS).
            held.push(stream);
        }
    });

    let stall_proxy = ReverseProxy::new(&ReverseProxyConfig {
        upstreams: vec![UpstreamConfig {
            url: format!("http://{stall_addr}"),
            weight: 1,
        }],
        streaming_flush: StreamingFlushMode::Buffered,
        lb_policy: LoadBalancePolicy::RoundRobin,
        health_check: Some(miraserve_config::HealthCheckConfig {
            path: "/health".to_owned(),
            interval: Duration::from_secs(60),
            timeout: Some(Duration::from_secs(2)),
            unhealthy_threshold: 1,
            host: None,
        }),
        upstream_tls: None,
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
        preserve_host: false,
        allow_upgrades: true,
        strip_prefix: false,
    })?
    .with_upstream_timeout(Duration::from_millis(200));

    // Stream chunks continuously (always Ready!) so `client_waiting == false` while upstream stalls!
    let stalled_req = Request::builder()
        .method(http::Method::POST)
        .uri("/big-upload")
        .body(FloodUploadBody(64).boxed())?;
    let stalled_resp = tokio::time::timeout(
        Duration::from_secs(3),
        stall_proxy.forward(stalled_req, None, "https"),
    )
    .await
    .map_err(|_| "proxy hung indefinitely on stalled upstream during POST upload")?;
    assert_eq!(stalled_resp.status(), StatusCode::GATEWAY_TIMEOUT);
    assert!(
        stall_proxy.pool().select().is_none(),
        "stalled upstream during POST upload must record passive health failure and eject backend"
    );

    stall_task.abort();
    Ok(())
}

/// DOS-7 & R2-PRX-2 (upstream response-body idle timeout releases in-flight guard cleanly),
/// R3-PRX-1 (GET stalled TLS handshake bounded by `connect_timeout`, not 60s `response_timeout`),
/// and R4-PRX-1 (`%uXXXX` and overlong/invalid UTF-8 rejected before upstream).
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn round4_proxy_body_idle_timeout_get_tls_handshake_timeout_and_uri_rejects() -> TestResult {
    // 1. DOS-7: Upstream sends 200 headers + first chunk then stalls forever -> `body_idle_timeout`
    //    must terminate the body stream cleanly and release `backend.in_flight()` back to 0!
    let sse_listener = TcpListener::bind("127.0.0.1:0").await?;
    let sse_addr = sse_listener.local_addr()?;
    let sse_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = sse_listener.accept().await {
            tokio::spawn(async move {
                let mut req_buf = [0_u8; 512];
                let _ = stream.read(&mut req_buf).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nhello\n\r\n",
                    )
                    .await;
                // Intentionally hold connection open forever without sending another chunk!
                tokio::time::sleep(Duration::from_secs(30)).await;
            });
        }
    });

    let proxy = ReverseProxy::new_with_timeouts(
        &ReverseProxyConfig {
            upstreams: vec![UpstreamConfig {
                url: format!("http://{sse_addr}"),
                weight: 1,
            }],
            streaming_flush: StreamingFlushMode::Immediate,
            lb_policy: LoadBalancePolicy::RoundRobin,
            health_check: None,
            upstream_tls: None,
            upstream_connect_timeout: None,
            upstream_response_timeout: None,
            upstream_body_idle_timeout: None,
            preserve_host: false,
            allow_upgrades: true,
            strip_prefix: false,
        },
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_millis(150),
    )?;

    // 1a. R4-PRX-1: `%uXXXX` and overlong UTF-8 `%c0%ae` rejected with 400 before upstream!
    for evil in ["/api/%u002e%u002e/admin", "/api/%c0%ae%c0%ae/admin"] {
        let bad_req = Request::builder().uri(evil).body(empty_body())?;
        let bad_resp = proxy.forward(bad_req, None, "https").await;
        assert_eq!(bad_resp.status(), StatusCode::BAD_REQUEST, "evil={evil}");
    }

    // 1b. DOS-7: Stalled upstream body chunk triggers idle timeout error and drops InFlightGuard!
    let sse_req = Request::builder().uri("/stream").body(empty_body())?;
    let sse_resp = proxy.forward(sse_req, None, "https").await;
    assert_eq!(sse_resp.status(), StatusCode::OK);
    let backend = Arc::clone(
        proxy
            .pool()
            .backends()
            .first()
            .ok_or("missing proxy backend")?,
    );
    assert_eq!(backend.in_flight(), 1);
    let mut body = sse_resp.into_body();
    let first_frame = body.frame().await.ok_or("expected first SSE chunk")??;
    assert_eq!(
        first_frame.data_ref().map(Bytes::as_ref),
        Some(b"hello\n".as_slice())
    );
    let second = tokio::time::timeout(Duration::from_secs(2), body.frame())
        .await
        .map_err(|_| "upstream response body hung past body_idle_timeout")?;
    assert!(
        matches!(second, Some(Err(_))),
        "expected idle timeout error on stalled upstream body, got {second:?}"
    );
    drop(body);
    assert_eq!(
        backend.in_flight(),
        0,
        "InFlightGuard must be released when response body times out"
    );
    sse_task.abort();

    // 2. R3-PRX-1 & R2-PRX-2: `GET` against an `https://` upstream that accepts TCP and stalls
    //    the TLS handshake MUST fail at `connect_timeout` (150ms), NOT `response_timeout` (10s)!
    let tls_stall_listener = TcpListener::bind("127.0.0.1:0").await?;
    let tls_stall_addr = tls_stall_listener.local_addr()?;
    let tls_stall_task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = tls_stall_listener.accept().await {
            held.push(stream);
        }
    });
    let tls_proxy = ReverseProxy::new_with_timeouts(
        &ReverseProxyConfig {
            upstreams: vec![UpstreamConfig {
                url: format!("https://{tls_stall_addr}"),
                weight: 1,
            }],
            streaming_flush: StreamingFlushMode::Buffered,
            lb_policy: LoadBalancePolicy::RoundRobin,
            health_check: None,
            upstream_tls: None,
            upstream_connect_timeout: None,
            upstream_response_timeout: None,
            upstream_body_idle_timeout: None,
            preserve_host: false,
            allow_upgrades: true,
            strip_prefix: false,
        },
        Duration::from_millis(150),
        Duration::from_secs(10),
        Duration::from_secs(10),
    )?;
    let started = std::time::Instant::now();
    let get_resp = tokio::time::timeout(
        Duration::from_secs(2),
        tls_proxy.forward(
            Request::builder().uri("/get-stall").body(empty_body())?,
            None,
            "https",
        ),
    )
    .await
    .map_err(|_| "GET TLS handshake hung past connect_timeout")?;
    assert_eq!(get_resp.status(), StatusCode::GATEWAY_TIMEOUT);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "GET TLS handshake should time out at connect_timeout, elapsed={:?}",
        started.elapsed()
    );
    tls_stall_task.abort();

    Ok(())
}

/// Round 5 Wave 4 proxy tests (`R5-PRX-1` and `R5-HTTP-3`):
/// - `R5-PRX-1`: A backend that stalls TCP/TLS handshakes MUST still accrue passive health
///   failures and get ejected even when `in_flight() > 1` (e.g., an existing SSE/in-flight guard
///   is active on that backend)!
/// - `R5-HTTP-3`: Legacy ISO-8859-1 `/fichier%E9.pdf` forwards cleanly through `ReverseProxy`
///   with the raw percent-encoding intact while UTF-16 surrogates (`%ED%A0%80`) still get 400!
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn round5_wave4_dead_backend_ejected_under_load_and_legacy_latin1_uri() -> TestResult {
    // 1. R5-PRX-1: Backend accepts TCP and hangs TLS handshake forever while another request
    //    already holds an `InFlightGuard` (`in_flight() == 2 > 1` during the POST!).
    let dead_listener = TcpListener::bind("127.0.0.1:0").await?;
    let dead_addr = dead_listener.local_addr()?;
    let dead_task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = dead_listener.accept().await {
            held.push(stream);
        }
    });

    let proxy = ReverseProxy::new_with_timeouts(
        &ReverseProxyConfig {
            upstreams: vec![UpstreamConfig {
                url: format!("https://{dead_addr}"),
                weight: 1,
            }],
            streaming_flush: StreamingFlushMode::Buffered,
            lb_policy: LoadBalancePolicy::RoundRobin,
            health_check: Some(miraserve_config::HealthCheckConfig {
                path: "/health".to_owned(),
                interval: Duration::from_secs(60),
                timeout: Some(Duration::from_secs(2)),
                unhealthy_threshold: 1,
                host: None,
            }),
            upstream_tls: None,
            upstream_connect_timeout: None,
            upstream_response_timeout: None,
            upstream_body_idle_timeout: None,
            preserve_host: false,
            allow_upgrades: true,
            strip_prefix: false,
        },
        Duration::from_millis(150),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )?;

    // Hold an active InFlightGuard simulating an open SSE stream on the same backend (`in_flight == 1`).
    let _open_sse_guard = proxy
        .pool()
        .select()
        .ok_or("expected backend healthy initially")?;
    let first_backend = proxy
        .pool()
        .backends()
        .first()
        .ok_or("missing backend in pool")?;
    assert_eq!(first_backend.in_flight(), 1);

    // Send a POST request whose TLS handshake stalls while `in_flight() == 2 > 1`!
    let post_req = Request::builder()
        .method(http::Method::POST)
        .uri("/submit")
        .body(full_body(Bytes::from_static(b"payload")))?;
    let resp = tokio::time::timeout(
        Duration::from_secs(2),
        proxy.forward(post_req, None, "https"),
    )
    .await
    .map_err(|_| "POST against stalled TLS backend hung past connect_timeout")?;
    assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
    assert!(
        proxy.pool().select().is_none(),
        "R5-PRX-1: dead backend stalling TLS handshake MUST be ejected even when in_flight() > 1"
    );
    dead_task.abort();

    // 2. R5-HTTP-3: Echo upstream verifies `/fichier%E9.pdf` passes intact while `%ED%A0%80` -> 400.
    let echo_listener = TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo_listener.local_addr()?;
    let echo_task = tokio::spawn(async move {
        while let Ok((stream, _)) = echo_listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let uri_str = req.uri().to_string();
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from(uri_str)))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                    )
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let echo_proxy = ReverseProxy::new(&ReverseProxyConfig {
        upstreams: vec![UpstreamConfig {
            url: format!("http://{echo_addr}"),
            weight: 1,
        }],
        streaming_flush: StreamingFlushMode::Buffered,
        lb_policy: LoadBalancePolicy::RoundRobin,
        health_check: None,
        upstream_tls: None,
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
        preserve_host: false,
        allow_upgrades: true,
        strip_prefix: false,
    })?;

    let legacy_resp = echo_proxy
        .forward(
            Request::builder()
                .uri("/files/fichier%E9.pdf")
                .body(empty_body())?,
            None,
            "https",
        )
        .await;
    assert_eq!(legacy_resp.status(), StatusCode::OK);
    let echoed = legacy_resp.into_body().collect().await?.to_bytes();
    assert_eq!(
        std::str::from_utf8(&echoed)?,
        "/files/fichier%E9.pdf",
        "R5-HTTP-3: legacy Latin-1 percent-escape must reach upstream unmodified"
    );

    let surrogate_resp = echo_proxy
        .forward(
            Request::builder()
                .uri("/files/%ED%A0%80/bad")
                .body(empty_body())?,
            None,
            "https",
        )
        .await;
    assert_eq!(
        surrogate_resp.status(),
        StatusCode::BAD_REQUEST,
        "R5-HTTP-3: UTF-16 surrogate must still be rejected with 400"
    );

    echo_task.abort();
    Ok(())
}

/// R6-XFF-1: Byte-wise `X-Forwarded-For` peeling preserves valid hops to the right of corrupt/non-UTF-8
/// prefixes (`\xff, 203.0.113.55`), parses `ip:port` / `[v6]:port` / quoted tokens, and stops peeling
/// strictly at `unknown` or malformed tokens at their own position.
#[test]
fn r6_xff_1_bytewise_xff_parser_preserves_rightmost_ip_past_bad_bytes_and_supports_ports()
-> TestResult {
    let trusted = vec![
        miraserve_config::IpCidr::parse("127.0.0.1/32")?,
        miraserve_config::IpCidr::parse("10.0.0.0/8")?,
    ];
    let peer = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));

    // 1. Corrupt non-UTF-8 prefix merged with valid client IP MUST resolve to the real client IP,
    //    NOT collapse onto the trusted proxy's IP!
    let mut h_bad = http::HeaderMap::new();
    h_bad.insert(
        "x-forwarded-for",
        HeaderValue::from_bytes(b"\xff, 203.0.113.55")?,
    );
    assert_eq!(
        miraserve_proxy::resolve_effective_client_ip(peer, &h_bad, &trusted),
        Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 55))),
        "R6-XFF-1: bad bytes on the left must NOT discard the real client IP on the right"
    );

    // 2. `ip:port`, `[v6]:port`, and quoted bracketed IPv6 parse cleanly.
    for (raw, expected) in [
        ("198.51.100.7:44321", "198.51.100.7"),
        ("[2001:db8::9]:54321", "2001:db8::9"),
        ("\"[2001:db8::a]\"", "2001:db8::a"),
    ] {
        let mut h = http::HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_str(raw)?);
        assert_eq!(
            miraserve_proxy::resolve_effective_client_ip(peer, &h, &trusted),
            Some(expected.parse()?),
            "R6-XFF-1: failed to parse XFF token {raw}"
        );
    }

    // 3. `unknown` or `\xff` at a hop position stops peeling at THAT position (never trusts forged
    //    client IPs to its left!).
    let mut h_unk = http::HeaderMap::new();
    h_unk.insert(
        "x-forwarded-for",
        HeaderValue::from_static("1.1.1.1, unknown"),
    );
    assert_eq!(
        miraserve_proxy::resolve_effective_client_ip(peer, &h_unk, &trusted),
        peer
    );

    let mut h_mid = http::HeaderMap::new();
    h_mid.insert(
        "x-forwarded-for",
        HeaderValue::from_bytes(b"1.1.1.1, \xff, 10.0.0.2")?,
    );
    assert_eq!(
        miraserve_proxy::resolve_effective_client_ip(peer, &h_mid, &trusted),
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
    );
    Ok(())
}

/// R6-XFF-2: Behind a trusted peer, `ReverseProxy` joins ALL `X-Forwarded-For` header lines in
/// order before appending the peer IP, strips client-supplied `Forwarded`, and overwrites
/// `X-Real-IP` with the resolved effective client IP.
#[tokio::test]
async fn r6_xff_2_trusted_peer_joins_all_xff_lines_strips_forwarded_and_overwrites_x_real_ip()
-> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let xff = req
                        .headers()
                        .get_all("x-forwarded-for")
                        .iter()
                        .filter_map(|v| v.to_str().ok())
                        .collect::<Vec<_>>()
                        .join(" | ");
                    let x_real = req
                        .headers()
                        .get("x-real-ip")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("<none>");
                    let has_fwd = req.headers().contains_key("forwarded");
                    let body = format!("xff={xff}\nx_real={x_real}\nhas_fwd={has_fwd}");
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from(body)))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                    )
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let proxy = ReverseProxy::new(&ReverseProxyConfig {
        upstreams: vec![UpstreamConfig {
            url: format!("http://{addr}"),
            weight: 1,
        }],
        streaming_flush: StreamingFlushMode::Buffered,
        lb_policy: LoadBalancePolicy::RoundRobin,
        health_check: None,
        upstream_tls: None,
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
        preserve_host: false,
        allow_upgrades: true,
        strip_prefix: false,
    })?
    .with_trusted_proxy_cidrs(vec![miraserve_config::IpCidr::parse("127.0.0.1/32")?]);

    // Case 1: Two separate XFF lines (HAProxy `option forwardfor` pattern) + spoofed X-Real-IP + Forwarded.
    let mut req1 = Request::builder().uri("/multi").body(empty_body())?;
    req1.headers_mut()
        .append("x-forwarded-for", HeaderValue::from_static("6.6.6.6"));
    req1.headers_mut()
        .append("x-forwarded-for", HeaderValue::from_static("5.5.5.5"));
    req1.headers_mut()
        .insert("x-real-ip", HeaderValue::from_static("9.9.9.9"));
    req1.headers_mut()
        .insert("forwarded", HeaderValue::from_static("for=8.8.8.8"));
    let resp1 = proxy
        .forward(req1, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), "https")
        .await;
    assert_eq!(resp1.status(), StatusCode::OK);
    let body1 = String::from_utf8(resp1.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(
        body1.contains("xff=6.6.6.6, 5.5.5.5, 127.0.0.1"),
        "R6-XFF-2: expected all XFF lines joined, got:\n{body1}"
    );
    assert!(
        body1.contains("x_real=5.5.5.5"),
        "R6-XFF-2: expected X-Real-IP overwritten with effective client IP, got:\n{body1}"
    );
    assert!(
        body1.contains("has_fwd=false"),
        "R6-XFF-2: expected spoofable Forwarded header stripped, got:\n{body1}"
    );

    // Case 2: Non-UTF-8 prefix in XFF line preserves real IP on the right as `unknown, 5.5.5.5, 127.0.0.1`.
    let mut req2 = Request::builder().uri("/corrupt").body(empty_body())?;
    req2.headers_mut().insert(
        "x-forwarded-for",
        HeaderValue::from_bytes(b"\xff, 5.5.5.5")?,
    );
    let resp2 = proxy
        .forward(req2, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), "https")
        .await;
    assert_eq!(resp2.status(), StatusCode::OK);
    let body2 = String::from_utf8(resp2.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(
        body2.contains("xff=unknown, 5.5.5.5, 127.0.0.1"),
        "R6-XFF-2: corrupt XFF prefix must preserve valid rightmost hop, got:\n{body2}"
    );
    assert!(
        body2.contains("x_real=5.5.5.5"),
        "R6-XFF-2: X-Real-IP must resolve to 5.5.5.5 past corrupt prefix, got:\n{body2}"
    );

    task.abort();
    Ok(())
}

/// R5-PRX-1 (revert-checked): When `response_deadline` fires BEFORE `TimeoutConnector`
/// (`upstream_timeout < connect_timeout`) during a stalled TLS handshake while `in_flight() > 1`,
/// `was_connecting == true` MUST still record a passive health failure and eject the dead backend!
#[tokio::test]
async fn r5_prx_1_connect_stall_under_load_when_response_deadline_fires_first_ejects_backend()
-> TestResult {
    let dead_listener = TcpListener::bind("127.0.0.1:0").await?;
    let dead_addr = dead_listener.local_addr()?;
    let dead_task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = dead_listener.accept().await {
            held.push(stream);
        }
    });

    // Crucial timing for R5-PRX-1: construct with `connect_timeout = 5s` and `response_timeout = 5s`
    // so `TimeoutConnector` waits 5s, then override `.with_upstream_timeout(120ms)` so
    // `response_deadline` (`pre_poll_limit = 170ms`) DETERMINISTICALLY fires BEFORE
    // `TimeoutConnector` while `connecting_in_flight() == 1` and `in_flight() == 2 > 1`!
    // Without `!was_connecting` in `crates/miraserve-proxy/src/lib.rs`, `queued_on_established_conn`
    // wrongly evaluates to `true` and skips passive health ejection, causing this test to FAIL!
    let proxy = ReverseProxy::new_with_timeouts(
        &ReverseProxyConfig {
            upstreams: vec![UpstreamConfig {
                url: format!("https://{dead_addr}"),
                weight: 1,
            }],
            streaming_flush: StreamingFlushMode::Buffered,
            lb_policy: LoadBalancePolicy::RoundRobin,
            health_check: Some(HealthCheckConfig {
                path: "/health".to_owned(),
                interval: Duration::from_secs(60),
                timeout: Some(Duration::from_secs(2)),
                unhealthy_threshold: 1,
                host: None,
            }),
            upstream_tls: None,
            upstream_connect_timeout: None,
            upstream_response_timeout: None,
            upstream_body_idle_timeout: None,
            preserve_host: false,
            allow_upgrades: true,
            strip_prefix: false,
        },
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )?
    .with_upstream_timeout(Duration::from_millis(120));

    // Hold one active InFlightGuard (`in_flight() == 1`, so during `forward()` `in_flight() == 2 > 1`).
    let _active_guard = proxy
        .pool()
        .select()
        .ok_or("expected backend initially healthy")?;

    let post_req = Request::builder()
        .method(http::Method::POST)
        .uri("/submit-under-load")
        .body(full_body(Bytes::from_static(b"payload")))?;
    let resp = tokio::time::timeout(
        Duration::from_secs(2),
        proxy.forward(post_req, None, "https"),
    )
    .await
    .map_err(|_| "POST hung past response_deadline")?;
    assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
    assert!(
        proxy.pool().select().is_none(),
        "R5-PRX-1: stalled TLS connect firing response_deadline while in_flight > 1 MUST eject backend"
    );

    dead_task.abort();
    Ok(())
}

/// R7-PRX-1: Three concurrent requests to a slow URL (`GET /up/hang`) that hit
/// `upstream-response-timeout` on an established connection return `504` and MUST NOT eject the
/// healthy backend (`/up/ok` continues returning `200`, never `503`).
#[tokio::test]
async fn r7_prx_1_slow_url_response_timeout_does_not_eject_healthy_backend() -> TestResult {
    let up_listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = up_listener.local_addr()?;
    let up_task = tokio::spawn(async move {
        while let Ok((stream, _)) = up_listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<Incoming>| async move {
                    if req.uri().path() == "/up/hang" {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from_static(b"ok")))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                    )
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let proxy = Arc::new(ReverseProxy::new_with_timeouts(
        &ReverseProxyConfig {
            upstreams: vec![UpstreamConfig {
                url: format!("http://{up_addr}"),
                weight: 1,
            }],
            streaming_flush: StreamingFlushMode::Buffered,
            lb_policy: LoadBalancePolicy::RoundRobin,
            health_check: Some(HealthCheckConfig {
                path: "/health".to_owned(),
                interval: Duration::from_secs(30),
                timeout: Some(Duration::from_secs(2)),
                unhealthy_threshold: 3,
                host: None,
            }),
            upstream_tls: None,
            upstream_connect_timeout: None,
            upstream_response_timeout: None,
            upstream_body_idle_timeout: None,
            preserve_host: false,
            allow_upgrades: true,
            strip_prefix: false,
        },
        Duration::from_secs(2),
        Duration::from_millis(120),
        Duration::from_secs(2),
    )?);

    // Fire 3 concurrent slow `/up/hang` requests -> all 3 return 504 Gateway Timeout!
    let mut handles = Vec::new();
    for _ in 0..3 {
        let p = Arc::clone(&proxy);
        handles.push(tokio::spawn(async move {
            let req = Request::builder().uri("/up/hang").body(empty_body()).ok()?;
            Some(p.forward(req, None, "https").await.status())
        }));
    }
    for h in handles {
        assert_eq!(h.await?, Some(StatusCode::GATEWAY_TIMEOUT));
    }

    // Backend MUST remain in rotation and `/up/ok` MUST return 200 OK (NOT 503)!
    let ok_resp = proxy
        .forward(
            Request::builder().uri("/up/ok").body(empty_body())?,
            None,
            "https",
        )
        .await;
    assert_eq!(
        ok_resp.status(),
        StatusCode::OK,
        "R7-PRX-1: slow URL response-header timeouts must NOT eject a healthy backend"
    );

    up_task.abort();
    Ok(())
}

/// R7-HTTP-2 & R6-HTTP-2: `ReverseProxy` rejects Tomcat/Jetty `;params` dot-segments (`..;`),
/// double-encoded traversal (`%252e%252e`, `%255c`, `%2500`), and RFC 3629 forbidden bytes
/// (`%FC`, `%F5..%FF`) with 400 Bad Request before ever forwarding upstream.
#[tokio::test]
async fn r7_http_2_proxy_blocks_matrix_param_dotdot_and_double_encoded_traversal() -> TestResult {
    let up_listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = up_listener.local_addr()?;
    let up_task = tokio::spawn(async move {
        while let Ok((stream, _)) = up_listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|_req: Request<Incoming>| async move {
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from_static(b"upstream-reached")))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                    )
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let proxy = ReverseProxy::new(&ReverseProxyConfig {
        upstreams: vec![UpstreamConfig {
            url: format!("http://{up_addr}"),
            weight: 1,
        }],
        streaming_flush: StreamingFlushMode::Buffered,
        lb_policy: LoadBalancePolicy::RoundRobin,
        health_check: None,
        upstream_tls: None,
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
        preserve_host: false,
        allow_upgrades: true,
        strip_prefix: false,
    })?;

    for bad in [
        "/public/..;/manager/html",
        "/up/a/..;/x",
        "/up/a/.;/x",
        "/up/%252e%252e/x",
        "/up/%252E%252e/x",
        "/up/%252e%252e%253b/x",
        "/up/%255c/x",
        "/up/%2500/x",
        "/up/f%FCr",
    ] {
        let resp = proxy
            .forward(
                Request::builder().uri(bad).body(empty_body())?,
                None,
                "https",
            )
            .await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "R7-HTTP-2/R6-HTTP-2: proxy must reject '{bad}' with 400"
        );
    }

    up_task.abort();
    Ok(())
}

/// Review 2: `preserve-host` forwards the client's own `Host`; without it the upstream sees its
/// own authority. `X-Real-IP` is set to the client address for ordinary (untrusted) peers and a
/// client-supplied value never passes through.
#[tokio::test]
async fn review2_preserve_host_and_x_real_ip_for_untrusted_peers() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = listener.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let header = |name: &str| {
                        req.headers()
                            .get(name)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("<none>")
                            .to_owned()
                    };
                    let echoed = format!(
                        "host={} x-real-ip={} x-forwarded-for={}",
                        header("host"),
                        header("x-real-ip"),
                        header("x-forwarded-for")
                    );
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from(echoed)))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                    )
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let client_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    let mut bodies = Vec::new();
    for preserve_host in [false, true] {
        let proxy = ReverseProxy::new(&ReverseProxyConfig {
            upstreams: vec![UpstreamConfig {
                url: format!("http://{upstream_addr}"),
                weight: 1,
            }],
            streaming_flush: StreamingFlushMode::Buffered,
            lb_policy: LoadBalancePolicy::RoundRobin,
            health_check: None,
            upstream_tls: None,
            upstream_connect_timeout: None,
            upstream_response_timeout: None,
            upstream_body_idle_timeout: None,
            preserve_host,
            allow_upgrades: true,
            strip_prefix: false,
        })?;
        let resp = proxy
            .forward(
                Request::builder()
                    .uri("/")
                    .header("host", "tenant-a.example.com")
                    .header("x-real-ip", "10.0.0.1")
                    .header("x-forwarded-for", "10.0.0.1")
                    .body(empty_body())?,
                Some(client_ip),
                "https",
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await?.to_bytes();
        bodies.push(String::from_utf8(body.to_vec())?);
    }
    let default_body = bodies.first().ok_or("missing default response")?;
    let preserved_body = bodies.get(1).ok_or("missing preserve-host response")?;

    assert!(
        default_body.contains(&format!("host={upstream_addr} ")),
        "without preserve-host the upstream must see its own authority, got: {default_body}"
    );
    assert!(
        preserved_body.contains("host=tenant-a.example.com "),
        "with preserve-host the upstream must see the client's Host, got: {preserved_body}"
    );
    for body in [default_body, preserved_body] {
        assert!(
            body.contains("x-real-ip=203.0.113.9 "),
            "X-Real-IP must be the client address for an untrusted peer, never absent or client-supplied, got: {body}"
        );
        assert!(
            body.ends_with("x-forwarded-for=203.0.113.9"),
            "X-Forwarded-For must be the client address for an untrusted peer, got: {body}"
        );
    }
    upstream_task.abort();
    Ok(())
}

/// Review 3: against a TLS upstream that offers HTTP/2, the default route negotiates HTTP/2 and
/// the upstream sees its own authority; a `preserve-host` route must reach the same upstream
/// with the CLIENT's host. Over HTTP/2 `:authority` comes from the request URI (the backend), so
/// `preserve-host` requests are sent over HTTP/1.1, where `Host` carries the client's host.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn review3_preserve_host_on_http2_capable_tls_upstream_sends_client_host() -> TestResult {
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let pem = miraserve_tls::generate_dev_cert_pem(&["localhost".to_owned()])?;
    let dir = std::env::temp_dir().join(format!("miraserve-review3-h2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let ca_path = dir.join("ca.pem");
    std::fs::write(&ca_path, pem.cert_pem.as_bytes())?;

    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(pem.cert_pem.as_bytes()).collect::<Result<_, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(pem.key_pem.as_bytes())?;
    let mut server_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(certs, key)?;
    server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let upstream_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let is_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let host = req
                        .headers()
                        .get("host")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("<none>");
                    let authority = req
                        .uri()
                        .authority()
                        .map_or("<none>", http::uri::Authority::as_str);
                    let echoed = format!(
                        "version={:?} host={host} authority={authority}",
                        req.version()
                    );
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from(echoed)))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                    )
                });
                if is_h2 {
                    let _ = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
                } else {
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), svc)
                        .await;
                }
            });
        }
    });

    let mut bodies = Vec::new();
    for preserve_host in [false, true] {
        let proxy = ReverseProxy::new(&ReverseProxyConfig {
            upstreams: vec![UpstreamConfig {
                url: format!("https://localhost:{port}"),
                weight: 1,
            }],
            streaming_flush: StreamingFlushMode::Buffered,
            lb_policy: LoadBalancePolicy::RoundRobin,
            health_check: None,
            upstream_tls: Some(miraserve_config::UpstreamTlsConfig {
                ca_cert: Some(ca_path.to_string_lossy().into_owned()),
                client_cert: None,
                client_key: None,
            }),
            upstream_connect_timeout: None,
            upstream_response_timeout: None,
            upstream_body_idle_timeout: None,
            preserve_host,
            allow_upgrades: true,
            strip_prefix: false,
        })?;
        let resp = proxy
            .forward(
                Request::builder()
                    .uri("/")
                    .header("host", "tenant-a.example.com")
                    .body(empty_body())?,
                Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
                "https",
            )
            .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "upstream request failed (preserve_host={preserve_host})"
        );
        let body = resp.into_body().collect().await?.to_bytes();
        bodies.push(String::from_utf8(body.to_vec())?);
    }
    let default_body = bodies.first().ok_or("missing default response")?;
    let preserved_body = bodies.get(1).ok_or("missing preserve-host response")?;

    // The control proves this upstream really negotiates HTTP/2 with the proxy.
    assert!(
        default_body.starts_with("version=HTTP/2.0 ")
            && default_body.ends_with(&format!("authority=localhost:{port}")),
        "the default route must use HTTP/2 with the backend authority, got: {default_body}"
    );
    assert!(
        preserved_body.contains("host=tenant-a.example.com "),
        "preserve-host must deliver the client's host even to an HTTP/2-capable upstream, got: {preserved_body}"
    );
    assert!(
        !preserved_body.contains(&format!("localhost:{port}")),
        "the backend authority must not be what the upstream sees with preserve-host, got: {preserved_body}"
    );

    upstream_task.abort();
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Review 3: `allow-upgrades #false` never opens a WebSocket tunnel. The upgrade request is
/// forwarded as an ordinary request without `Upgrade`/`Connection: upgrade`.
#[tokio::test]
async fn review3_allow_upgrades_false_never_forwards_a_websocket_upgrade() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = listener.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let echoed = format!(
                        "upgrade={} connection={}",
                        req.headers().contains_key(UPGRADE),
                        req.headers()
                            .get(CONNECTION)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("<none>")
                    );
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from(echoed)))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                    )
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let proxy = ReverseProxy::new(&ReverseProxyConfig {
        upstreams: vec![UpstreamConfig {
            url: format!("http://{upstream_addr}"),
            weight: 1,
        }],
        streaming_flush: StreamingFlushMode::Buffered,
        lb_policy: LoadBalancePolicy::RoundRobin,
        health_check: None,
        upstream_tls: None,
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
        preserve_host: false,
        allow_upgrades: false,
        strip_prefix: false,
    })?;
    let resp = proxy
        .forward(
            Request::builder()
                .method("GET")
                .uri("/ws")
                .header("host", "a.example.com")
                .header(CONNECTION, "Upgrade")
                .header(UPGRADE, "websocket")
                .header("sec-websocket-version", "13")
                .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                .body(empty_body())?,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
            "https",
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await?.to_bytes();
    let text = String::from_utf8(body.to_vec())?;
    assert!(
        text.starts_with("upgrade=false ") && !text.to_ascii_lowercase().contains("upgrade=true"),
        "with allow-upgrades off the upstream must not receive an Upgrade header, got: {text}"
    );
    assert!(
        !text.to_ascii_lowercase().contains("connection=upgrade"),
        "with allow-upgrades off the upstream must not receive `Connection: upgrade`, got: {text}"
    );
    upstream_task.abort();
    Ok(())
}

/// Review 4: on a `preserve-host` route, health probes must reach the upstream the way real
/// requests do: over HTTP/1.1 with the configured host. The upstream here answers `/health`
/// with 200 only for the tenant's host and 503 for its own address, so a probe sent with the
/// backend authority would eject a healthy application.
#[tokio::test]
async fn review4_health_probe_uses_configured_host_on_preserve_host_route() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = listener.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let is_tenant = req
                        .headers()
                        .get("host")
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|h| h == "tenant-a.example.com");
                    let status = if is_tenant {
                        StatusCode::OK
                    } else {
                        StatusCode::SERVICE_UNAVAILABLE
                    };
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(status)
                            .body(Full::new(Bytes::from_static(b"ok")))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                    )
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let proxy = ReverseProxy::new(&ReverseProxyConfig {
        upstreams: vec![UpstreamConfig {
            url: format!("http://{upstream_addr}"),
            weight: 1,
        }],
        streaming_flush: StreamingFlushMode::Buffered,
        lb_policy: LoadBalancePolicy::RoundRobin,
        health_check: Some(HealthCheckConfig {
            path: "/health".to_owned(),
            interval: Duration::from_millis(100),
            timeout: Some(Duration::from_millis(80)),
            unhealthy_threshold: 1,
            host: Some("tenant-a.example.com".to_owned()),
        }),
        upstream_tls: None,
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
        preserve_host: true,
        allow_upgrades: true,
        strip_prefix: false,
    })?;

    // Several probe intervals. With the backend authority as Host the upstream answers 503 and
    // the single backend would be ejected.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(
        proxy.pool().select().is_some(),
        "the backend is healthy for the tenant host and must stay in rotation"
    );
    let resp = proxy
        .forward(
            Request::builder()
                .uri("/")
                .header("host", "tenant-a.example.com")
                .body(empty_body())?,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
            "https",
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    upstream_task.abort();
    Ok(())
}

/// Two upstreams with one down (and no active health-check) must fail over on connect errors
/// (including non-empty POST bodies before any bytes are sent), passively cool down the dead
/// backend, retry after cooldown expires, and never duplicate a POST whose body was already read.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn upstream_failover_retries_on_connect_error_ejects_passively_and_never_duplicates_sent_post()
-> TestResult {
    use http::Method;
    use std::sync::atomic::AtomicUsize;

    // Allocate a guaranteed-closed port for dead backend #1.
    let dead_listener = TcpListener::bind("127.0.0.1:0").await?;
    let dead_addr = dead_listener.local_addr()?;
    drop(dead_listener);

    // Live backend #2 echoes its body back.
    let live_listener = TcpListener::bind("127.0.0.1:0").await?;
    let live_addr = live_listener.local_addr()?;
    let live_hits = Arc::new(AtomicUsize::new(0));
    let live_hits_srv = Arc::clone(&live_hits);
    let live_task = tokio::spawn(async move {
        while let Ok((stream, _)) = live_listener.accept().await {
            let hits = Arc::clone(&live_hits_srv);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let hits = Arc::clone(&hits);
                    async move {
                        hits.fetch_add(1, Ordering::AcqRel);
                        let body = req
                            .into_body()
                            .collect()
                            .await
                            .map_or_else(|_| Bytes::new(), http_body_util::Collected::to_bytes);
                        let resp_body = format!("live-ok:{}", String::from_utf8_lossy(&body));
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::from(resp_body)))
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                        )
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    let proxy = ReverseProxy::new(&ReverseProxyConfig {
        upstreams: vec![
            UpstreamConfig {
                url: format!("http://{dead_addr}"),
                weight: 1,
            },
            UpstreamConfig {
                url: format!("http://{live_addr}"),
                weight: 1,
            },
        ],
        streaming_flush: StreamingFlushMode::Buffered,
        lb_policy: LoadBalancePolicy::RoundRobin,
        health_check: None,
        upstream_tls: None,
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
        preserve_host: false,
        allow_upgrades: true,
        strip_prefix: false,
    })?
    .with_passive_connect_cooldown(Duration::from_millis(200));

    // 1. 10 GET requests in a row must ALL succeed with 200 (zero 502s!), passively cooling down
    //    the dead backend on the very first connect failure.
    for i in 0..10 {
        let resp = proxy
            .forward(
                Request::builder()
                    .uri(format!("/item/{i}"))
                    .header("host", "app.example.test")
                    .body(empty_body())?,
                Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))),
                "https",
            )
            .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "request {i} must fail over cleanly"
        );
    }
    assert!(
        proxy
            .pool()
            .backends()
            .first()
            .is_some_and(|b| b.is_in_passive_cooldown()),
        "dead backend must be in passive cooldown after connect failure"
    );
    assert_eq!(live_hits.load(Ordering::Acquire), 10);

    // 2. Non-empty POST targeting dead backend (after cooldown expires) fails over with its FULL
    //    body intact because TCP connect failed before any body bytes were sent!
    tokio::time::sleep(Duration::from_millis(250)).await;
    let post_body = Full::new(Bytes::from_static(b"payload=hello-failover"))
        .map_err(|never| match never {})
        .boxed();
    let post_resp = proxy
        .forward(
            Request::builder()
                .method(Method::POST)
                .uri("/submit")
                .header("host", "app.example.test")
                .body(post_body)?,
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))),
            "https",
        )
        .await;
    assert_eq!(post_resp.status(), StatusCode::OK);
    let post_bytes = post_resp.into_body().collect().await?.to_bytes();
    assert_eq!(post_bytes.as_ref(), b"live-ok:payload=hello-failover");

    // 3. A backend that ACCEPTS TCP and reads the POST body before dropping the socket MUST NOT
    //    cause a duplicate POST to the sibling backend.
    let drop_listener = TcpListener::bind("127.0.0.1:0").await?;
    let drop_addr = drop_listener.local_addr()?;
    let drop_task = tokio::spawn(async move {
        if let Ok((mut stream, _)) = drop_listener.accept().await {
            use tokio::io::AsyncReadExt as _;
            let mut buf = [0_u8; 512];
            let _ = stream.read(&mut buf).await;
            // Drop socket without sending an HTTP response after reading the request!
        }
    });
    let live_hits_before_drop = live_hits.load(Ordering::Acquire);
    let proxy_post_drop = ReverseProxy::new(&ReverseProxyConfig {
        upstreams: vec![
            UpstreamConfig {
                url: format!("http://{drop_addr}"),
                weight: 1,
            },
            UpstreamConfig {
                url: format!("http://{live_addr}"),
                weight: 1,
            },
        ],
        streaming_flush: StreamingFlushMode::Buffered,
        lb_policy: LoadBalancePolicy::RoundRobin,
        health_check: None,
        upstream_tls: None,
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
        preserve_host: false,
        allow_upgrades: true,
        strip_prefix: false,
    })?;
    let non_idempotent_body = Full::new(Bytes::from_static(b"charge=100"))
        .map_err(|never| match never {})
        .boxed();
    let drop_resp = proxy_post_drop
        .forward(
            Request::builder()
                .method(Method::POST)
                .uri("/charge")
                .header("host", "app.example.test")
                .body(non_idempotent_body)?,
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))),
            "https",
        )
        .await;
    assert_eq!(drop_resp.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        live_hits.load(Ordering::Acquire),
        live_hits_before_drop,
        "POST already sent over an established connection must NEVER be duplicated to backend #2"
    );

    drop_task.abort();
    live_task.abort();
    Ok(())
}

/// Codex G1: A bodyless `POST` that has already reached the upstream application and hits the
/// response-header timeout MUST NOT be replayed on a sibling backend even when another concurrent
/// request is actively handshaking (`connecting_in_flight() > 0`) on the same backend.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn g1_bodyless_post_timeout_with_concurrent_connect_never_replays() -> TestResult {
    use http::Method;
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::sync::atomic::AtomicUsize;

    let pem = miraserve_tls::generate_dev_cert_pem(&["localhost".to_owned()])?;
    let dir = std::env::temp_dir().join(format!("miraserve-g1-post-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let ca_path = dir.join("ca.pem");
    std::fs::write(&ca_path, pem.cert_pem.as_bytes())?;

    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(pem.cert_pem.as_bytes()).collect::<Result<_, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(pem.key_pem.as_bytes())?;
    let mut server_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(certs, key)?;
    server_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

    let post_hits = Arc::new(AtomicUsize::new(0));
    let post_reached = Arc::new(Notify::new());
    let release_stalled_tls = Arc::new(Notify::new());

    // Backend 1 (TLS): connection #1 completes TLS + HTTP/1.1 and stalls the app response to
    // POST /charge beyond `upstream_timeout`; connection #2 accepts TCP and stalls the TLS
    // handshake so `connecting_in_flight() > 0` while Request A times out waiting for the app!
    let b1_listener = TcpListener::bind("127.0.0.1:0").await?;
    let b1_port = b1_listener.local_addr()?.port();
    let b1_hits = Arc::clone(&post_hits);
    let b1_reached = Arc::clone(&post_reached);
    let b1_release = Arc::clone(&release_stalled_tls);
    let b1_task = tokio::spawn(async move {
        let mut conn_num = 0_usize;
        while let Ok((stream, _)) = b1_listener.accept().await {
            conn_num = conn_num.saturating_add(1);
            if conn_num == 1 {
                let acc = acceptor.clone();
                let hits = Arc::clone(&b1_hits);
                let reached = Arc::clone(&b1_reached);
                tokio::spawn(async move {
                    let Ok(tls) = acc.accept(stream).await else {
                        return;
                    };
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let hits = Arc::clone(&hits);
                        let reached = Arc::clone(&reached);
                        async move {
                            if req.method() == Method::POST && req.uri().path() == "/charge" {
                                hits.fetch_add(1, Ordering::AcqRel);
                                reached.notify_one();
                                // Hold response past upstream_timeout (250ms).
                                tokio::time::sleep(Duration::from_millis(700)).await;
                            }
                            Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .body(Full::new(Bytes::from_static(b"b1-ok")))
                                    .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                            )
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), svc)
                        .await;
                });
            } else {
                // Stall TLS handshake without replying so `connecting_in_flight() > 0`.
                let release = Arc::clone(&b1_release);
                tokio::spawn(async move {
                    let _held = stream;
                    release.notified().await;
                });
            }
        }
    });

    // Backend 2 (HTTP): immediately answers 200 OK and counts any POST /charge that reaches it.
    let b2_listener = TcpListener::bind("127.0.0.1:0").await?;
    let b2_addr = b2_listener.local_addr()?;
    let b2_hits = Arc::clone(&post_hits);
    let b2_task = tokio::spawn(async move {
        while let Ok((stream, _)) = b2_listener.accept().await {
            let hits = Arc::clone(&b2_hits);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let hits = Arc::clone(&hits);
                    async move {
                        if req.method() == Method::POST && req.uri().path() == "/charge" {
                            hits.fetch_add(1, Ordering::AcqRel);
                        }
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::from_static(b"b2-ok")))
                                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                        )
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    // Start with a generous 5s setup timeout so initial TLS handshake on conn #1 is decoupled
    // from the short timeout under test even under heavy parallel workspace CPU contention.
    let proxy = ReverseProxy::new_with_timeouts(
        &ReverseProxyConfig {
            upstreams: vec![
                UpstreamConfig {
                    url: format!("https://localhost:{b1_port}"),
                    weight: 1,
                },
                UpstreamConfig {
                    url: format!("http://{b2_addr}"),
                    weight: 1,
                },
            ],
            streaming_flush: StreamingFlushMode::Buffered,
            lb_policy: LoadBalancePolicy::RoundRobin,
            health_check: None,
            upstream_tls: Some(miraserve_config::UpstreamTlsConfig {
                ca_cert: Some(ca_path.to_string_lossy().into_owned()),
                client_cert: None,
                client_key: None,
            }),
            upstream_connect_timeout: None,
            upstream_response_timeout: None,
            upstream_body_idle_timeout: None,
            preserve_host: false,
            allow_upgrades: true,
            strip_prefix: false,
        },
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )?;

    // Warm up conn #1 (Backend 1) and advance RoundRobin past Backend 2 so the TLS keep-alive
    // connection to Backend 1 is already pooled before tightening the deadline to 250ms.
    for uri in ["/warmup-b1", "/warmup-b2"] {
        let resp = proxy
            .forward(
                Request::builder()
                    .uri(uri)
                    .header("host", "app.example.test")
                    .body(empty_body())?,
                Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))),
                "https",
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK, "warmup {uri} failed");
        let _ = resp.into_body().collect().await?;
    }

    let proxy = Arc::new(proxy.with_upstream_timeout(Duration::from_millis(250)));

    // 1. Send Request A: bodyless POST /charge -> RoundRobin picks Backend 1 (warm conn #1).
    let proxy_a = Arc::clone(&proxy);
    let post_handle = tokio::spawn(async move {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/charge")
            .header("host", "app.example.test")
            .body(empty_body());
        match req {
            Ok(r) => proxy_a
                .forward(r, Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))), "https")
                .await
                .status(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    });

    // Wait until Backend 1 has received Request A's POST /charge!
    tokio::time::timeout(Duration::from_secs(2), post_reached.notified()).await?;

    // Advance RoundRobin past Backend 2 with a fast GET so the next request targets Backend 1.
    let rr_resp = proxy
        .forward(
            Request::builder()
                .uri("/ping")
                .header("host", "app.example.test")
                .body(empty_body())?,
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))),
            "https",
        )
        .await;
    assert_eq!(rr_resp.status(), StatusCode::OK);

    // Wait 70ms, then launch Request B against Backend 1 (conn #2, stalled TLS handshake).
    // Now Backend 1 has `connecting_in_flight() > 0` right when Request A hits its 220ms
    // `upstream_timeout`!
    tokio::time::sleep(Duration::from_millis(70)).await;
    let proxy_b = Arc::clone(&proxy);
    let connect_handle = tokio::spawn(async move {
        let req = Request::builder()
            .uri("/concurrent-connect")
            .header("host", "app.example.test")
            .body(empty_body());
        match req {
            Ok(r) => proxy_b
                .forward(r, Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3))), "https")
                .await
                .status(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    });

    // Request A MUST return 504 Gateway Timeout and MUST NOT replay to Backend 2.
    let status_a = post_handle.await?;
    assert_eq!(
        status_a,
        StatusCode::GATEWAY_TIMEOUT,
        "slow bodyless POST must return 504 instead of replaying to Backend 2"
    );
    // Request B's own stalled TLS handshake times out in TimeoutConnector (`is_connect() == true`)
    // and fails over cleanly to Backend 2 -> 200 OK.
    let status_b = connect_handle.await?;
    assert_eq!(
        status_b,
        StatusCode::OK,
        "concurrent request whose own TLS connect timed out must still fail over to Backend 2"
    );
    assert_eq!(
        post_hits.load(Ordering::Acquire),
        1,
        "application across all backends must observe the timed-out bodyless POST exactly once"
    );

    release_stalled_tls.notify_waiters();
    b1_task.abort();
    b2_task.abort();
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Review 23: the access-policy address is established only from a well-formed hop. A bracketed
/// IPv4 address or unbalanced quotes at the decisive position leave the client unknown; a
/// bracketed IPv6 address, a quoted address and an `ip:port` form are accepted.
#[test]
fn established_client_ip_rejects_malformed_decisive_hops() -> Result<(), Box<dyn std::error::Error>>
{
    let trusted = vec![miraserve_config::IpCidr::parse("10.0.0.0/8")?];
    let peer = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let resolve = |xff: &'static str| {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static(xff));
        miraserve_proxy::resolve_established_client_ip(peer, &headers, &trusted)
    };
    assert_eq!(
        resolve("[203.0.113.7]"),
        None,
        "bracketed IPv4 is malformed"
    );
    assert_eq!(resolve("\"203.0.113.7"), None, "unbalanced quote");
    assert_eq!(resolve("203.0.113.7\"\""), None, "stray quotes");
    assert_eq!(
        resolve("203.0.113.7, , 10.0.0.2"),
        None,
        "unnamed hop first"
    );
    assert_eq!(
        resolve("[2001:db8::7%1]:443"),
        None,
        "scoped socket address"
    );
    assert_eq!(resolve("2001:db8::7%eth0"), None, "zone ID");
    assert_eq!(
        resolve("\"203.0.113.7\""),
        Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)))
    );
    assert_eq!(
        resolve("203.0.113.7:4711"),
        Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)))
    );
    assert_eq!(
        resolve("[2001:db8::7]"),
        Some("2001:db8::7".parse::<IpAddr>()?)
    );
    Ok(())
}

/// Vendored `h2` (`COPY_LIMIT = 4096`) also reaches MiraServe's HTTP/2-capable upstream
/// reverse-proxy client (`ReverseProxy` over TLS ALPN `h2`). Verify that:
/// 1. A multi-chunk streaming request upload spanning both copied (`< 4096`) and chained
///    (`>= 4096`) chunks completes byte-for-byte over HTTP/2.
/// 2. Cancelling an in-flight streaming upload cleans up promptly on the upstream HTTP/2
///    stream without poisoning the pooled connection for subsequent uploads.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn h2_upstream_upload_completes_and_cancelled_upload_cleans_up() -> TestResult {
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::sync::mpsc;

    struct ChannelUploadBody {
        rx: mpsc::Receiver<Result<Bytes, miraserve_proxy::ProxyError>>,
    }

    impl http_body::Body for ChannelUploadBody {
        type Data = Bytes;
        type Error = miraserve_proxy::ProxyError;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
            match self.rx.poll_recv(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Some(Ok(b))) => Poll::Ready(Some(Ok(http_body::Frame::data(b)))),
                Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => Poll::Ready(None),
            }
        }
    }

    let pem = miraserve_tls::generate_dev_cert_pem(&["localhost".to_owned()])?;
    let dir = std::env::temp_dir().join(format!(
        "miraserve-h2-up-upload-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir)?;
    let ca_path = dir.join("ca.pem");
    std::fs::write(&ca_path, pem.cert_pem.as_bytes())?;

    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(pem.cert_pem.as_bytes()).collect::<Result<_, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(pem.key_pem.as_bytes())?;
    let mut server_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(certs, key)?;
    server_cfg.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

    let cancel_started = Arc::new(tokio::sync::Notify::new());
    let cancel_started_up = Arc::clone(&cancel_started);
    let cancel_cleaned = Arc::new(tokio::sync::Notify::new());
    let cancel_cleaned_up = Arc::clone(&cancel_cleaned);

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let upstream_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let cancel_started = Arc::clone(&cancel_started_up);
            let cancel_cleaned = Arc::clone(&cancel_cleaned_up);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
                    return;
                }
                let svc = service_fn(move |mut req: Request<Incoming>| {
                    let cancel_started = Arc::clone(&cancel_started);
                    let cancel_cleaned = Arc::clone(&cancel_cleaned);
                    async move {
                        let is_h2 = req.version() == http::Version::HTTP_2;
                        if req.uri().path() == "/upload-cancel" {
                            let mut saw_first = false;
                            while let Some(frame) = req.body_mut().frame().await {
                                if let Ok(f) = frame {
                                    if f.into_data().is_ok() && !saw_first {
                                        saw_first = true;
                                        cancel_started.notify_one();
                                    }
                                } else {
                                    cancel_cleaned.notify_one();
                                    break;
                                }
                            }
                            return Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                                Bytes::from_static(b"cancelled"),
                            )));
                        }

                        let mut received = Vec::new();
                        while let Some(frame) = req.body_mut().frame().await {
                            if let Ok(f) = frame
                                && let Ok(d) = f.into_data()
                            {
                                received.extend_from_slice(&d);
                            }
                        }
                        let resp = Response::builder()
                            .status(StatusCode::OK)
                            .header("x-upstream-h2", if is_h2 { "true" } else { "false" })
                            .header("x-uploaded-len", received.len().to_string())
                            .body(Full::new(Bytes::from(received)))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())));
                        Ok::<_, std::convert::Infallible>(resp)
                    }
                });
                let _ =
                    hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls), svc)
                        .await;
            });
        }
    });

    let proxy = Arc::new(ReverseProxy::new(&ReverseProxyConfig {
        upstreams: vec![UpstreamConfig {
            url: format!("https://localhost:{port}"),
            weight: 1,
        }],
        streaming_flush: StreamingFlushMode::Buffered,
        lb_policy: LoadBalancePolicy::RoundRobin,
        health_check: None,
        upstream_tls: Some(miraserve_config::UpstreamTlsConfig {
            ca_cert: Some(ca_path.to_string_lossy().into_owned()),
            client_cert: None,
            client_key: None,
        }),
        upstream_connect_timeout: None,
        upstream_response_timeout: None,
        upstream_body_idle_timeout: None,
        preserve_host: false,
        allow_upgrades: true,
        strip_prefix: false,
    })?);

    // 1. Upload spanning both copied (< 4096) and chained (>= 4096) DATA chunk sizes over H2,
    //    verifying exact byte-for-byte upload integrity (not just aggregate length).
    let (tx, rx) = mpsc::channel(8);
    let sizes = [255_usize, 256, 1_024, 4_095, 4_096, 8_192];
    let mut expected_chunks = Vec::with_capacity(sizes.len());
    let mut expected_upload = Vec::new();
    for (idx, &sz) in sizes.iter().enumerate() {
        let chunk: Vec<u8> = (0..sz)
            .map(|off| u8::try_from((idx * 37 + off * 13 + 7) & 0xff).unwrap_or(0))
            .collect();
        expected_upload.extend_from_slice(&chunk);
        expected_chunks.push(Bytes::from(chunk));
    }
    let expected_total = expected_upload.len();
    tokio::spawn(async move {
        for chunk in expected_chunks {
            if tx.send(Ok(chunk)).await.is_err() {
                break;
            }
        }
    });
    let upload_req = Request::builder()
        .method(http::Method::POST)
        .uri("/upload")
        .header("host", "upload.example.test")
        .body(ChannelUploadBody { rx }.boxed())?;
    let resp = proxy
        .forward(
            upload_req,
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))),
            "https",
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-upstream-h2")
            .and_then(|v| v.to_str().ok()),
        Some("true")
    );
    assert_eq!(
        resp.headers()
            .get("x-uploaded-len")
            .and_then(|v| v.to_str().ok()),
        Some(expected_total.to_string().as_str())
    );
    let body = resp.into_body().collect().await?.to_bytes();
    assert_eq!(
        body.as_ref(),
        expected_upload.as_slice(),
        "upstream received bytes must match uploaded bytes exactly across copied and chained chunks"
    );

    // 2. Cancelled streaming upload: start uploading, wait for upstream to receive the first
    //    chunk, then abort the proxy forward future and drop the body sender. Upstream must
    //    promptly observe stream cancellation rather than hanging.
    let (cancel_tx, cancel_rx) = mpsc::channel(4);
    cancel_tx
        .send(Ok(Bytes::from(vec![0x77_u8; 1_024])))
        .await?;
    let cancel_req = Request::builder()
        .method(http::Method::POST)
        .uri("/upload-cancel")
        .header("host", "upload.example.test")
        .body(ChannelUploadBody { rx: cancel_rx }.boxed())?;
    let proxy_cancel = Arc::clone(&proxy);
    let forward_handle = tokio::spawn(async move {
        proxy_cancel
            .forward(
                cancel_req,
                Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))),
                "https",
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), cancel_started.notified())
        .await
        .map_err(|_| "upstream never received first chunk of cancelled H2 upload")?;
    forward_handle.abort();
    drop(cancel_tx);
    tokio::time::timeout(Duration::from_secs(5), cancel_cleaned.notified())
        .await
        .map_err(|_| "cancelled H2 upstream upload did not clean up promptly on upstream")?;

    // 3. Follow-up upload on the same pooled H2 ReverseProxy still completes byte-for-byte intact.
    let expected_follow: Vec<u8> = (0_usize..2_048)
        .map(|off| u8::try_from((off * 29 + 0x55) & 0xff).unwrap_or(0))
        .collect();
    let follow_req = Request::builder()
        .method(http::Method::POST)
        .uri("/upload")
        .header("host", "upload.example.test")
        .body(
            Full::new(Bytes::from(expected_follow.clone()))
                .map_err(|never| match never {})
                .boxed(),
        )?;
    let follow_resp = proxy
        .forward(
            follow_req,
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))),
            "https",
        )
        .await;
    assert_eq!(follow_resp.status(), StatusCode::OK);
    assert_eq!(
        follow_resp
            .headers()
            .get("x-upstream-h2")
            .and_then(|v| v.to_str().ok()),
        Some("true")
    );
    let follow_body = follow_resp.into_body().collect().await?.to_bytes();
    assert_eq!(
        follow_body.as_ref(),
        expected_follow.as_slice(),
        "follow-up H2 upload bytes must match byte-for-byte"
    );

    upstream_task.abort();
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

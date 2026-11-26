//! Golden wire-level upstream request-head and downstream response tests for `miraserve-proxy`.
//!
//! Written against unmodified base commit `536486f` and kept unchanged across all proxy-cost
//! optimisations to pin exact byte-for-byte wire parity (request line, every header name/value
//! and order, request body, and downstream response status/headers/body).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::header::{ACCEPT_ENCODING, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, UPGRADE};
use http::{Method, Request, StatusCode, Version};
use http_body_util::BodyExt as _;
use miraserve_config::{
    IpCidr, LoadBalancePolicy, ReverseProxyConfig, StreamingFlushMode, UpstreamConfig,
};
use miraserve_proxy::{ReverseProxy, empty_body, full_body};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct CapturedWireRequest {
    raw_head: String,
    body: Vec<u8>,
}

struct WireCaptureUpstream {
    addr: SocketAddr,
    captured: Arc<Mutex<Vec<CapturedWireRequest>>>,
    task: tokio::task::JoinHandle<()>,
}

impl WireCaptureUpstream {
    async fn start(reply: &'static [u8]) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_c = Arc::clone(&captured);

        let task = tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let captured_inner = Arc::clone(&captured_c);
                tokio::spawn(async move {
                    let mut buf = Vec::with_capacity(4096);
                    let mut tmp = [0_u8; 4096];
                    loop {
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
                        };
                        let Some(end) = head_end else {
                            break;
                        };
                        let head_bytes = buf.get(..end).unwrap_or(&[]).to_vec();
                        let content_len = parse_content_length(&head_bytes);
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
                        let body = buf.get(end..total_needed).unwrap_or(&[]).to_vec();
                        buf.drain(..total_needed);

                        let raw_head = String::from_utf8_lossy(&head_bytes)
                            .replace(&addr.to_string(), "127.0.0.1:<UPSTREAM_PORT>");
                        captured_inner
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push(CapturedWireRequest { raw_head, body });

                        if sock.write_all(reply).await.is_err() {
                            break;
                        }
                        if reply.starts_with(b"HTTP/1.1 101 ") {
                            // Keep upgrade tunnel socket open briefly for handshake completion.
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            break;
                        }
                    }
                });
            }
        });

        Ok(Self {
            addr,
            captured,
            task,
        })
    }

    fn take_last(&self) -> Result<CapturedWireRequest, Box<dyn std::error::Error>> {
        let mut guard = self
            .captured
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .pop()
            .ok_or_else(|| "no upstream request captured".into())
    }
}

impl Drop for WireCaptureUpstream {
    fn drop(&mut self) {
        self.task.abort();
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

fn make_proxy_cfg(urls: Vec<String>, preserve_host: bool) -> ReverseProxyConfig {
    ReverseProxyConfig {
        upstreams: urls
            .into_iter()
            .map(|url| UpstreamConfig { url, weight: 1 })
            .collect(),
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
    }
}

const OK_REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Upstream-Reply: exact\r\nContent-Length: 4\r\nConnection: keep-alive\r\n\r\npong";
const HEAD_REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Upstream-Reply: head\r\nContent-Length: 4\r\nConnection: keep-alive\r\n\r\n";
const UPGRADE_REPLY: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";

fn assert_wire_head_matches(case: &str, actual: &str, expected: &str) {
    assert_eq!(
        actual, expected,
        "upstream wire head mismatch in case `{case}`\n--- ACTUAL ---\n{actual}\n--- EXPECTED ---\n{expected}"
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn golden_upstream_request_heads_and_downstream_responses() -> TestResult {
    let upstream = WireCaptureUpstream::start(OK_REPLY).await?;
    let head_upstream = WireCaptureUpstream::start(HEAD_REPLY).await?;
    let ws_upstream = WireCaptureUpstream::start(UPGRADE_REPLY).await?;

    let default_proxy = ReverseProxy::new(&make_proxy_cfg(
        vec![format!("http://{}", upstream.addr)],
        false,
    ))?;
    let head_proxy = ReverseProxy::new(&make_proxy_cfg(
        vec![format!("http://{}", head_upstream.addr)],
        false,
    ))?;
    let preserve_proxy = ReverseProxy::new(&make_proxy_cfg(
        vec![format!("http://{}", upstream.addr)],
        true,
    ))?;
    let prefix_proxy = ReverseProxy::new(&make_proxy_cfg(
        vec![format!("http://{}/backend/v2/", upstream.addr)],
        false,
    ))?;
    let trusted_proxy = ReverseProxy::new(&make_proxy_cfg(
        vec![format!("http://{}", upstream.addr)],
        false,
    ))?
    .with_trusted_proxy_cidrs(vec![IpCidr::from_ip(IpAddr::V4(Ipv4Addr::new(
        10, 0, 0, 5,
    )))]);
    let ws_proxy = ReverseProxy::new(&make_proxy_cfg(
        vec![format!("http://{}", ws_upstream.addr)],
        false,
    ))?;

    let ipv4_client = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)));
    let ipv6_client = Some(IpAddr::V6(Ipv6Addr::new(
        0x2001, 0x0db8, 0, 0, 0, 0, 0xcafe, 1,
    )));

    // 1. GET default (no preserve-host), hop-by-hop Connection strip + custom header
    {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/items?page=2&sort=asc")
            .header(HOST, "public.example.test")
            .header(ACCEPT_ENCODING, "gzip")
            .header("x-custom", "alpha")
            .header(CONNECTION, "keep-alive, x-hop-secret")
            .header("x-hop-secret", "drop-me")
            .body(empty_body())?;
        let resp = default_proxy.forward(req, ipv4_client, "https").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("x-upstream-reply")
                .and_then(|v| v.to_str().ok()),
            Some("exact")
        );
        assert!(resp.headers().get(CONNECTION).is_none());
        let body = resp.into_body().collect().await?.to_bytes();
        assert_eq!(&body[..], b"pong");

        let cap = upstream.take_last()?;
        assert_eq!(cap.body, b"");
        assert_wire_head_matches(
            "1_get_default",
            &cap.raw_head,
            "GET /api/v1/items?page=2&sort=asc HTTP/1.1\r\n\
             host: 127.0.0.1:<UPSTREAM_PORT>\r\n\
             accept-encoding: gzip\r\n\
             x-custom: alpha\r\n\
             x-real-ip: 198.51.100.7\r\n\
             x-forwarded-for: 198.51.100.7\r\n\
             x-forwarded-proto: https\r\n\
             x-forwarded-host: public.example.test\r\n\r\n",
        );
    }

    // 2. HEAD default
    {
        let req = Request::builder()
            .method(Method::HEAD)
            .uri("/api/v1/items")
            .header(HOST, "public.example.test")
            .body(empty_body())?;
        let resp = head_proxy.forward(req, ipv4_client, "https").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("x-upstream-reply")
                .and_then(|v| v.to_str().ok()),
            Some("head")
        );
        let body = resp.into_body().collect().await?.to_bytes();
        assert!(body.is_empty());

        let cap = head_upstream.take_last()?;
        assert_eq!(cap.body, b"");
        assert_wire_head_matches(
            "2_head_default",
            &cap.raw_head,
            "HEAD /api/v1/items HTTP/1.1\r\n\
             host: 127.0.0.1:<UPSTREAM_PORT>\r\n\
             x-real-ip: 198.51.100.7\r\n\
             x-forwarded-for: 198.51.100.7\r\n\
             x-forwarded-proto: https\r\n\
             x-forwarded-host: public.example.test\r\n\r\n",
        );
    }

    // 3. POST with body
    {
        let payload = br#"{"hello":"world"}"#;
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/submit")
            .header(HOST, "public.example.test")
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_LENGTH, payload.len().to_string())
            .body(full_body(Bytes::from_static(payload)))?;
        let resp = default_proxy.forward(req, ipv4_client, "https").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await?.to_bytes();
        assert_eq!(&body[..], b"pong");

        let cap = upstream.take_last()?;
        assert_eq!(cap.body, payload);
        assert_wire_head_matches(
            "3_post_with_body",
            &cap.raw_head,
            "POST /api/v1/submit HTTP/1.1\r\n\
             host: 127.0.0.1:<UPSTREAM_PORT>\r\n\
             content-type: application/json\r\n\
             content-length: 17\r\n\
             x-real-ip: 198.51.100.7\r\n\
             x-forwarded-for: 198.51.100.7\r\n\
             x-forwarded-proto: https\r\n\
             x-forwarded-host: public.example.test\r\n\r\n",
        );
    }

    // 4. preserve-host = true
    {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/tenant/info")
            .header(HOST, "tenant.example.test:8443")
            .body(empty_body())?;
        let resp = preserve_proxy.forward(req, ipv4_client, "https").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = resp.into_body().collect().await?;

        let cap = upstream.take_last()?;
        assert_wire_head_matches(
            "4_preserve_host_true",
            &cap.raw_head,
            "GET /tenant/info HTTP/1.1\r\n\
             host: tenant.example.test:8443\r\n\
             x-real-ip: 198.51.100.7\r\n\
             x-forwarded-for: 198.51.100.7\r\n\
             x-forwarded-proto: https\r\n\
             x-forwarded-host: tenant.example.test:8443\r\n\r\n",
        );
    }

    // 5. Upstream base path prefix + http scheme
    {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/items/42?q=1")
            .header(HOST, "public.example.test")
            .body(empty_body())?;
        let resp = prefix_proxy.forward(req, ipv4_client, "http").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = resp.into_body().collect().await?;

        let cap = upstream.take_last()?;
        assert_wire_head_matches(
            "5_base_path_prefix",
            &cap.raw_head,
            "GET /backend/v2/items/42?q=1 HTTP/1.1\r\n\
             host: 127.0.0.1:<UPSTREAM_PORT>\r\n\
             x-real-ip: 198.51.100.7\r\n\
             x-forwarded-for: 198.51.100.7\r\n\
             x-forwarded-proto: http\r\n\
             x-forwarded-host: public.example.test\r\n\r\n",
        );
    }

    // 6. Percent-encoded path (encoded slash, space, and legacy Latin-1 byte %E9)
    {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/packages/%40scope%2Fpkg%20name/fichier%E9.pdf?k=a%20b")
            .header(HOST, "public.example.test")
            .body(empty_body())?;
        let resp = default_proxy.forward(req, ipv4_client, "https").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = resp.into_body().collect().await?;

        let cap = upstream.take_last()?;
        assert_wire_head_matches(
            "6_percent_encoded_paths",
            &cap.raw_head,
            "GET /packages/%40scope%2Fpkg%20name/fichier%E9.pdf?k=a%20b HTTP/1.1\r\n\
             host: 127.0.0.1:<UPSTREAM_PORT>\r\n\
             x-real-ip: 198.51.100.7\r\n\
             x-forwarded-for: 198.51.100.7\r\n\
             x-forwarded-proto: https\r\n\
             x-forwarded-host: public.example.test\r\n\r\n",
        );
    }

    // 7. IPv6 client
    {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/v6")
            .header(HOST, "v6.example.test")
            .body(empty_body())?;
        let resp = default_proxy.forward(req, ipv6_client, "https").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = resp.into_body().collect().await?;

        let cap = upstream.take_last()?;
        assert_wire_head_matches(
            "7_ipv6_client",
            &cap.raw_head,
            "GET /v6 HTTP/1.1\r\n\
             host: 127.0.0.1:<UPSTREAM_PORT>\r\n\
             x-real-ip: 2001:db8::cafe:1\r\n\
             x-forwarded-for: 2001:db8::cafe:1\r\n\
             x-forwarded-proto: https\r\n\
             x-forwarded-host: v6.example.test\r\n\r\n",
        );
    }

    // 8. X-Forwarded-* absent (untrusted peer, client_ip = None)
    {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/no-ip")
            .header(HOST, "public.example.test")
            .body(empty_body())?;
        let resp = default_proxy.forward(req, None, "https").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = resp.into_body().collect().await?;

        let cap = upstream.take_last()?;
        assert_wire_head_matches(
            "8_xff_absent_no_ip",
            &cap.raw_head,
            "GET /no-ip HTTP/1.1\r\n\
             host: 127.0.0.1:<UPSTREAM_PORT>\r\n\
             x-forwarded-proto: https\r\n\
             x-forwarded-host: public.example.test\r\n\r\n",
        );
    }

    // 9. X-Forwarded-* present from untrusted peer (spoofed headers stripped & overwritten)
    {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/spoof-xff")
            .header(HOST, "public.example.test")
            .header("x-forwarded-for", "1.2.3.4")
            .header("x-real-ip", "1.2.3.4")
            .header("x-forwarded-proto", "http")
            .header("x-forwarded-host", "evil.test")
            .header("x-forwarded-port", "9999")
            .header("forwarded", "for=1.2.3.4")
            .body(empty_body())?;
        let resp = default_proxy
            .forward(
                req,
                Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 21))),
                "https",
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = resp.into_body().collect().await?;

        let cap = upstream.take_last()?;
        assert_wire_head_matches(
            "9_xff_present_untrusted",
            &cap.raw_head,
            "GET /spoof-xff HTTP/1.1\r\n\
             host: 127.0.0.1:<UPSTREAM_PORT>\r\n\
             x-forwarded-for: 198.51.100.21\r\n\
             x-real-ip: 198.51.100.21\r\n\
             x-forwarded-proto: https\r\n\
             x-forwarded-host: public.example.test\r\n\r\n",
        );
    }

    // 10. X-Forwarded-* present from trusted proxy (chain extended, Forwarded stripped, X-Real-IP resolved)
    {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/trusted-xff")
            .header(HOST, "public.example.test")
            .header("x-forwarded-for", "203.0.113.5")
            .header("x-real-ip", "1.2.3.4")
            .header("forwarded", "for=1.2.3.4")
            .body(empty_body())?;
        let resp = trusted_proxy
            .forward(req, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))), "https")
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = resp.into_body().collect().await?;

        let cap = upstream.take_last()?;
        assert_wire_head_matches(
            "10_xff_present_trusted",
            &cap.raw_head,
            "GET /trusted-xff HTTP/1.1\r\n\
             host: 127.0.0.1:<UPSTREAM_PORT>\r\n\
             x-forwarded-for: 203.0.113.5, 10.0.0.5\r\n\
             x-real-ip: 203.0.113.5\r\n\
             x-forwarded-proto: https\r\n\
             x-forwarded-host: public.example.test\r\n\r\n",
        );
    }

    // 11. Multi-backend retry after failed first attempt (GET and POST)
    {
        let dead_listener = TcpListener::bind("127.0.0.1:0").await?;
        let dead_addr = dead_listener.local_addr()?;
        drop(dead_listener);

        let multi_proxy = ReverseProxy::new(&make_proxy_cfg(
            vec![
                format!("http://{dead_addr}"),
                format!("http://{}", upstream.addr),
            ],
            false,
        ))?
        .with_passive_connect_cooldown(Duration::from_millis(20));

        let get_req = Request::builder()
            .method(Method::GET)
            .uri("/retry-get?x=1")
            .header(HOST, "retry.example.test")
            .header("x-trace", "abc")
            .body(empty_body())?;
        let get_resp = multi_proxy.forward(get_req, ipv4_client, "https").await;
        assert_eq!(get_resp.status(), StatusCode::OK);
        let _ = get_resp.into_body().collect().await?;
        let cap_get = upstream.take_last()?;
        assert_eq!(cap_get.body, b"");
        assert_wire_head_matches(
            "11a_multi_backend_retry_get",
            &cap_get.raw_head,
            "GET /retry-get?x=1 HTTP/1.1\r\n\
             host: 127.0.0.1:<UPSTREAM_PORT>\r\n\
             x-trace: abc\r\n\
             x-real-ip: 198.51.100.7\r\n\
             x-forwarded-for: 198.51.100.7\r\n\
             x-forwarded-proto: https\r\n\
             x-forwarded-host: retry.example.test\r\n\r\n",
        );

        // Wait for dead backend cooldown to expire so POST also hits dead backend first and retries.
        tokio::time::sleep(Duration::from_millis(35)).await;
        // Advance RR cursor back to dead backend if needed by using a fresh proxy with dead first.
        let multi_proxy_post = ReverseProxy::new(&make_proxy_cfg(
            vec![
                format!("http://{dead_addr}"),
                format!("http://{}", upstream.addr),
            ],
            false,
        ))?;
        let post_payload = b"retry-body-42";
        let post_req = Request::builder()
            .method(Method::POST)
            .uri("/retry-post")
            .header(HOST, "retry.example.test")
            .header(CONTENT_TYPE, "text/plain")
            .header(CONTENT_LENGTH, post_payload.len().to_string())
            .body(full_body(Bytes::from_static(post_payload)))?;
        let post_resp = multi_proxy_post
            .forward(post_req, ipv4_client, "https")
            .await;
        assert_eq!(post_resp.status(), StatusCode::OK);
        let _ = post_resp.into_body().collect().await?;
        let cap_post = upstream.take_last()?;
        assert_eq!(cap_post.body, post_payload);
        assert_wire_head_matches(
            "11b_multi_backend_retry_post",
            &cap_post.raw_head,
            "POST /retry-post HTTP/1.1\r\n\
             host: 127.0.0.1:<UPSTREAM_PORT>\r\n\
             content-type: text/plain\r\n\
             content-length: 13\r\n\
             x-real-ip: 198.51.100.7\r\n\
             x-forwarded-for: 198.51.100.7\r\n\
             x-forwarded-proto: https\r\n\
             x-forwarded-host: retry.example.test\r\n\r\n",
        );
    }

    // 12. RFC 6455 WebSocket upgrade request
    {
        let req = Request::builder()
            .version(Version::HTTP_11)
            .method(Method::GET)
            .uri("/ws/chat")
            .header(HOST, "ws.example.test")
            .header(CONNECTION, "Upgrade")
            .header(UPGRADE, "websocket")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("sec-websocket-version", "13")
            .body(empty_body())?;
        let resp = ws_proxy
            .forward(
                req,
                Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 30))),
                "https",
            )
            .await;
        assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(
            resp.headers().get(UPGRADE).and_then(|v| v.to_str().ok()),
            Some("websocket")
        );
        assert_eq!(
            resp.headers().get(CONNECTION).and_then(|v| v.to_str().ok()),
            Some("upgrade")
        );
        assert_eq!(
            resp.headers()
                .get("sec-websocket-accept")
                .and_then(|v| v.to_str().ok()),
            Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
        );

        let cap = ws_upstream.take_last()?;
        assert_eq!(cap.body, b"");
        assert_wire_head_matches(
            "12_websocket_upgrade",
            &cap.raw_head,
            "GET /ws/chat HTTP/1.1\r\n\
             host: 127.0.0.1:<UPSTREAM_PORT>\r\n\
             connection: upgrade\r\n\
             upgrade: websocket\r\n\
             sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             sec-websocket-version: 13\r\n\
             x-real-ip: 198.51.100.30\r\n\
             x-forwarded-for: 198.51.100.30\r\n\
             x-forwarded-proto: https\r\n\
             x-forwarded-host: ws.example.test\r\n\r\n",
        );
    }

    Ok(())
}

/// Round 2 golden cases pinning hop-by-hop removal order (surviving `HeaderMap` iteration order)
/// for both upstream requests and downstream responses when `Connection` nominates a static
/// hop-by-hop field (`keep-alive`) that is also present alongside a custom nominated field
/// (`x-hop`). Verified verbatim against base commit `536486f`.
#[tokio::test]
async fn golden_hop_by_hop_removal_order_request_and_response() -> TestResult {
    const HOP_ORDER_REPLY: &[u8] = b"HTTP/1.1 200 OK\r\n\
        Content-Type: text/plain\r\n\
        Content-Length: 4\r\n\
        Connection: keep-alive, x-hop\r\n\
        Keep-Alive: timeout=5\r\n\
        X-Hop: discard\r\n\
        X-A: a\r\n\
        X-B: b\r\n\r\npong";

    let upstream = WireCaptureUpstream::start(HOP_ORDER_REPLY).await?;
    let proxy = ReverseProxy::new(&make_proxy_cfg(
        vec![format!("http://{}", upstream.addr)],
        false,
    ))?;
    let ipv4_client = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)));

    // 13. Request side (Codex's exact counterexample): `Keep-Alive` is removed in the dynamic pass
    //     before `X-Hop`, leaving `x-a` before `x-b` on the upstream wire head.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/hop-order")
        .header(HOST, "public.example.test")
        .header(CONNECTION, "keep-alive, x-hop")
        .header("keep-alive", "timeout=5")
        .header("x-hop", "discard")
        .header("x-a", "a")
        .header("x-b", "b")
        .body(empty_body())?;
    let resp = proxy.forward(req, ipv4_client, "https").await;
    assert_eq!(resp.status(), StatusCode::OK);

    let cap = upstream.take_last()?;
    assert_eq!(cap.body, b"");
    assert_wire_head_matches(
        "13_request_hop_removal_order",
        &cap.raw_head,
        "GET /hop-order HTTP/1.1\r\n\
         host: 127.0.0.1:<UPSTREAM_PORT>\r\n\
         x-a: a\r\n\
         x-b: b\r\n\
         x-real-ip: 198.51.100.7\r\n\
         x-forwarded-for: 198.51.100.7\r\n\
         x-forwarded-proto: https\r\n\
         x-forwarded-host: public.example.test\r\n\r\n",
    );

    // 14. Response-side twin: downstream response headers preserve the exact 536486f iteration
    //     order (`x-a` before `x-b`) after stripping `Connection: keep-alive, x-hop`,
    //     `Keep-Alive: timeout=5`, and `X-Hop: discard`.
    let resp_headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_owned(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    assert_eq!(
        resp_headers,
        vec![
            ("content-type".to_owned(), "text/plain".to_owned()),
            ("content-length".to_owned(), "4".to_owned()),
            ("x-a".to_owned(), "a".to_owned()),
            ("x-b".to_owned(), "b".to_owned()),
        ],
        "downstream response header order diverged from 536486f"
    );

    let body = resp.into_body().collect().await?.to_bytes();
    assert_eq!(&body[..], b"pong");

    Ok(())
}

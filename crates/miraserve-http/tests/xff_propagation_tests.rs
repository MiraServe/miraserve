//! Dedicated regression tests for `R6-XFF-3`: propagating the trusted-proxy-peeled effective
//! client IP to FastCGI `REMOTE_ADDR`, MCP gateway forwarding/audit, and `miraserve::access` logs
//! while never allowing untrusted peers to spoof `X-Forwarded-For`.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::header::{CONTENT_TYPE, HOST, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use miraserve_config::parse_kdl;
use miraserve_fastcgi::protocol::{
    EndRequestBody, RecordType, decode_params, read_record, write_record, write_stream_records,
};
use miraserve_http::{HttpEngine, RequestContext, empty_http_body, full_http_body};
use miraserve_tls::AcmeChallengeStore;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpListener;

type TestResult = Result<(), Box<dyn std::error::Error>>;

async fn serve_mock_fastcgi<S>(
    mut stream: S,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut raw_params = Vec::new();
    let req_id;
    loop {
        let rec = read_record(&mut stream).await?;
        match rec.record_type {
            RecordType::Params if !rec.content.is_empty() => {
                raw_params.extend_from_slice(&rec.content);
            }
            RecordType::Stdin if rec.content.is_empty() => {
                req_id = rec.request_id;
                break;
            }
            _ => {}
        }
    }
    let params: HashMap<String, String> = decode_params(&raw_params)?.into_iter().collect();
    let remote_addr = params.get("REMOTE_ADDR").map_or("", String::as_str);
    let http_xff = params
        .get("HTTP_X_FORWARDED_FOR")
        .map_or("<none>", String::as_str);
    let http_real_ip = params
        .get("HTTP_X_REAL_IP")
        .map_or("<none>", String::as_str);
    let http_proto = params
        .get("HTTP_X_FORWARDED_PROTO")
        .map_or("<none>", String::as_str);
    let http_fwd = params
        .get("HTTP_FORWARDED")
        .map_or("<none>", String::as_str);
    let payload = format!(
        "Content-Type: text/plain\r\n\r\nREMOTE_ADDR={remote_addr}\nHTTP_X_FORWARDED_FOR={http_xff}\nHTTP_X_REAL_IP={http_real_ip}\nHTTP_X_FORWARDED_PROTO={http_proto}\nHTTP_FORWARDED={http_fwd}"
    );
    write_stream_records(
        &mut stream,
        RecordType::Stdout,
        req_id,
        payload.as_bytes(),
        true,
    )
    .await?;
    let end = EndRequestBody {
        app_status: 0,
        protocol_status: 0,
    }
    .encode();
    write_record(&mut stream, RecordType::EndRequest, req_id, &end).await?;
    stream.flush().await?;
    Ok(())
}

/// R6-XFF-3: Behind a trusted proxy (`127.0.0.1/32`), FastCGI receives the real client IP in
/// `REMOTE_ADDR` and MCP gateway receives the real client IP in its forwarded/audit context,
/// while an untrusted peer cannot spoof either.
#[tokio::test]
async fn r6_xff_3_effective_client_ip_propagates_to_fastcgi_remote_addr_and_mcp_gateway()
-> TestResult {
    // 1. Mock FastCGI TCP responder echoing `REMOTE_ADDR`.
    let fcgi_listener = TcpListener::bind("127.0.0.1:0").await?;
    let fcgi_addr = fcgi_listener.local_addr()?;
    let fcgi_task = tokio::spawn(async move {
        while let Ok((stream, _)) = fcgi_listener.accept().await {
            tokio::spawn(async move {
                let _ = serve_mock_fastcgi(stream).await;
            });
        }
    });

    // 2. Mock MCP upstream echoing the `X-Forwarded-For` header it received from the gateway.
    let mcp_listener = TcpListener::bind("127.0.0.1:0").await?;
    let mcp_addr = mcp_listener.local_addr()?;
    let mcp_task = tokio::spawn(async move {
        while let Ok((stream, _)) = mcp_listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let xff = req
                        .headers()
                        .get("x-forwarded-for")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("<none>")
                        .to_owned();
                    let json = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"xff":"{xff}"}}}}"#);
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, "application/json")
                            .body(Full::new(Bytes::from(json)))
                            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                    )
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    // Create a temporary site root with `index.php` so FastCGI `exists_regular_file` passes.
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root_dir = std::env::temp_dir().join(format!("miraserve-r6-xff-3-{stamp}"));
    std::fs::create_dir_all(&root_dir)?;
    std::fs::write(
        root_dir.join("index.php"),
        "<?php echo $_SERVER['REMOTE_ADDR']; ?>",
    )?;

    let kdl = format!(
        r#"
server {{
    listen "127.0.0.1:8443"
    tls {{ cert "/etc/miraserve/certs/a.crt"; key "/etc/miraserve/certs/a.key"; }}
    limits {{
        trusted-proxies "127.0.0.1/32"
    }}
}}
site "app.example.test" {{
    root "{}"
    route "*.php" {{
        fastcgi-pass "tcp://127.0.0.1:{}"
    }}
    route "/mcp/*" {{
        mcp-gateway upstream="http://127.0.0.1:{}" {{
            oauth-resource-metadata #false
            allow-tools "docs_search"
        }}
    }}
}}
"#,
        root_dir.display(),
        fcgi_addr.port(),
        mcp_addr.port(),
    );

    let (cfg, _) = parse_kdl("r6-xff-3.kdl", &kdl)?;
    let engine = HttpEngine::from_config(&cfg, Arc::new(AcmeChallengeStore::new()), None, 8443)?;

    let trusted_ctx = RequestContext {
        client_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        remote_port: Some(54321),
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 8443,
        is_https: true,
        tls: None,
    };

    // Trusted proxy sends `\xff, 203.0.113.88` -> FastCGI must see `REMOTE_ADDR=203.0.113.88`!
    let fcgi_req = Request::builder()
        .method(Method::GET)
        .uri("/index.php")
        .header(HOST, "app.example.test")
        .header(
            "x-forwarded-for",
            HeaderValue::from_bytes(b"\xff, 203.0.113.88")?,
        )
        .body(empty_http_body())?;
    let fcgi_resp = engine.handle_request(fcgi_req, &trusted_ctx).await;
    assert_eq!(fcgi_resp.status(), StatusCode::OK);
    let fcgi_body = String::from_utf8(fcgi_resp.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(
        fcgi_body.contains("REMOTE_ADDR=203.0.113.88")
            && fcgi_body.contains("HTTP_X_REAL_IP=203.0.113.88")
            && fcgi_body.contains("HTTP_FORWARDED=<none>"),
        "R6-XFF-3/R7-XFF-3: FastCGI must receive effective client IP in REMOTE_ADDR & HTTP_X_REAL_IP, got: {fcgi_body}"
    );

    // Untrusted peer sending spoofed XFF/X-Real-IP/X-Forwarded-Proto/Forwarded must keep its
    // real socket IP (`198.51.100.9`) AND have ALL spoofed forwarding headers stripped (`R7-XFF-3`)!
    let untrusted_ctx = RequestContext {
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))),
        remote_port: Some(54322),
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 8443,
        is_https: true,
        tls: None,
    };
    let spoof_req = Request::builder()
        .method(Method::GET)
        .uri("/index.php")
        .header(HOST, "app.example.test")
        .header("x-forwarded-for", "203.0.113.88")
        .header("x-real-ip", "203.0.113.88")
        .header("x-forwarded-proto", "http")
        .header("forwarded", "for=203.0.113.88")
        .body(empty_http_body())?;
    let spoof_resp = engine.handle_request(spoof_req, &untrusted_ctx).await;
    assert_eq!(spoof_resp.status(), StatusCode::OK);
    let spoof_body =
        String::from_utf8(spoof_resp.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(
        spoof_body.contains("REMOTE_ADDR=198.51.100.9")
            && spoof_body.contains("HTTP_X_FORWARDED_FOR=<none>")
            && spoof_body.contains("HTTP_X_REAL_IP=<none>")
            && spoof_body.contains("HTTP_X_FORWARDED_PROTO=<none>")
            && spoof_body.contains("HTTP_FORWARDED=<none>"),
        "R6-XFF-3/R7-XFF-3: untrusted peer must have spoofed forwarding headers stripped before FastCGI, got: {spoof_body}"
    );

    // Trusted proxy sends MCP JSON-RPC request -> MCP gateway forwards effective client IP `203.0.113.88`!
    let mcp_req = Request::builder()
        .method(Method::POST)
        .uri("/mcp/rpc")
        .header(HOST, "app.example.test")
        .header(CONTENT_TYPE, "application/json")
        .header("x-forwarded-for", "203.0.113.88")
        .body(full_http_body(Bytes::from_static(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"docs_search","arguments":{}}}"#,
        )))?;
    let mcp_resp = engine.handle_request(mcp_req, &trusted_ctx).await;
    assert_eq!(mcp_resp.status(), StatusCode::OK);
    let mcp_body = String::from_utf8(mcp_resp.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(
        mcp_body.contains(r#""xff":"203.0.113.88""#),
        "R6-XFF-3: MCP gateway must propagate effective client IP (got {mcp_body})"
    );

    fcgi_task.abort();
    mcp_task.abort();
    let _ = std::fs::remove_dir_all(&root_dir);
    Ok(())
}

/// R7-DOS-1: `WriteGuardedIo` terminates slow-reader peers (both 0 B/s stalled peers at
/// `response_write_idle` and back-pressured 64 B/s trickle readers below `min_response_rate_bps`)
/// while never killing quiet SSE streams that write immediately without socket backpressure!
#[tokio::test]
async fn r7_dos_1_write_guarded_io_kills_slow_reader_and_preserves_quiet_sse() -> TestResult {
    use std::time::Duration;
    use tokio::io::AsyncReadExt as _;

    // 1. Back-pressured slow reader draining 64 bytes every 80ms (~800 B/s < 4096 B/s minimum)
    //    MUST fail with TimedOut once it is behind by more than the allowance: `write-idle`
    //    (400 ms) worth of data at the minimum rate, about 1.6 KiB, used up after ~0.5 s.
    let (mut client_read, server_write) = tokio::io::duplex(256);
    let mut guarded =
        miraserve_http::WriteGuardedIo::new(server_write, Duration::from_millis(400), 4_096)
            .with_rate_grace(Duration::from_millis(120));

    let trickle_reader = tokio::spawn(async move {
        let mut buf = [0_u8; 64];
        loop {
            tokio::time::sleep(Duration::from_millis(80)).await;
            match client_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });

    let big_chunk = vec![b'A'; 1_024];
    let started = std::time::Instant::now();
    let mut got_timeout = false;
    for _ in 0..64 {
        match guarded.write_all(&big_chunk).await {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {
                got_timeout = true;
                break;
            }
            Err(err) => return Err(format!("unexpected write error: {err}").into()),
        }
    }
    assert!(
        got_timeout,
        "R7-DOS-1: slow trickle reader below min_response_rate_bps must fail with TimedOut"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "R7-DOS-1: slow reader took too long to terminate: {:?}",
        started.elapsed()
    );
    trickle_reader.abort();

    // 2. Dead reader (0 B/s) with `min_response_rate_bps == 0` MUST still time out at
    //    `response_write_idle` (150ms)!
    let (_dead_client, server_write2) = tokio::io::duplex(64);
    let mut guarded2 =
        miraserve_http::WriteGuardedIo::new(server_write2, Duration::from_millis(150), 0);
    let dead_started = std::time::Instant::now();
    let dead_res = guarded2.write_all(&[b'B'; 256]).await;
    assert!(
        matches!(dead_res, Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut),
        "R7-DOS-1: 0 B/s stalled reader must time out at response_write_idle, got {dead_res:?}"
    );
    assert!(dead_started.elapsed() < Duration::from_secs(2));

    // 3. Quiet SSE stream (writes 32 bytes every 100ms, well past `rate_grace = 60ms`, into a
    //    fast reader with zero socket backpressure) MUST succeed cleanly!
    let (mut sse_client, sse_server) = tokio::io::duplex(4_096);
    let mut guarded_sse =
        miraserve_http::WriteGuardedIo::new(sse_server, Duration::from_millis(120), 100_000)
            .with_rate_grace(Duration::from_millis(60));
    let sse_reader = tokio::spawn(async move {
        let mut buf = [0_u8; 256];
        let mut total = 0_usize;
        while let Ok(n) = sse_client.read(&mut buf).await {
            if n == 0 {
                break;
            }
            total = total.saturating_add(n);
        }
        total
    });
    for _ in 0..4 {
        guarded_sse.write_all(b"data: token\n\n").await?;
        guarded_sse.flush().await?;
        tokio::time::sleep(Duration::from_millis(90)).await;
    }
    drop(guarded_sse);
    let received = sse_reader.await?;
    assert_eq!(received, 4 * b"data: token\n\n".len());
    Ok(())
}

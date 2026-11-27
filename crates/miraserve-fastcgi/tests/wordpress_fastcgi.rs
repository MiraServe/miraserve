//! WordPress / PHP-FPM FastCGI v1.0 wire protocol test harness (TCP + Unix domain socket).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};

use http::header::{CONTENT_TYPE, HeaderName, HeaderValue, LOCATION, SET_COOKIE};
use http::{HeaderMap, Method, StatusCode, Version};
use miraserve_config::FastCgiTarget;
use miraserve_fastcgi::protocol::{
    EndRequestBody, RecordType, decode_params, read_record, write_record, write_stream_records,
};
use miraserve_fastcgi::{FastCgiClient, FastCgiError, FastCgiRequest};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpListener;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Minimal pure-Rust mock PHP-FPM responder simulating WordPress request execution.
async fn serve_mock_php_fpm_conn<S>(mut stream: S) -> Result<(), FastCgiError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut raw_params = Vec::new();
    let mut stdin_buf = Vec::new();
    let req_id;

    loop {
        let rec = read_record(&mut stream).await?;
        match rec.record_type {
            RecordType::Params if !rec.content.is_empty() => {
                raw_params.extend_from_slice(&rec.content);
            }
            RecordType::Stdin => {
                if rec.content.is_empty() {
                    req_id = rec.request_id;
                    break;
                }
                stdin_buf.extend_from_slice(&rec.content);
            }
            _ => {}
        }
    }

    let params: HashMap<String, String> = decode_params(&raw_params)?.into_iter().collect();
    let script = params.get("SCRIPT_NAME").map_or("", String::as_str);
    let uri = params.get("REQUEST_URI").map_or("", String::as_str);
    let has_http_proxy = params.contains_key("HTTP_PROXY");

    let stdout_payload = if script == "/redirect.php" {
        b"Status: 301 Moved Permanently\r\nLocation: https://legacy-blog.example.com/new\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n".to_vec()
    } else {
        let body = format!(
            "wp-ok|script={script}|uri={uri}|https={}|httpoxy={has_http_proxy}|stdin={}",
            params.get("HTTPS").map_or("off", String::as_str),
            String::from_utf8_lossy(&stdin_buf)
        );
        format!("Content-Type: text/html; charset=utf-8\r\nX-Powered-By: MockPHP\r\n\r\n{body}")
            .into_bytes()
    };

    write_stream_records(
        &mut stream,
        RecordType::Stderr,
        req_id,
        b"mock php notice",
        true,
    )
    .await?;
    write_stream_records(
        &mut stream,
        RecordType::Stdout,
        req_id,
        &stdout_payload,
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

async fn spawn_tcp_php_fpm() -> Result<(SocketAddr, tokio::task::AbortHandle), std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = serve_mock_php_fpm_conn(stream).await;
            });
        }
    });
    Ok((addr, handle.abort_handle()))
}

#[tokio::test]
async fn tcp_fastcgi_executes_wordpress_post_strips_httpoxy_and_parses_cgi_status() -> TestResult {
    let (addr, abort) = spawn_tcp_php_fpm().await?;
    let client = FastCgiClient::new(
        FastCgiTarget::Tcp {
            host: "127.0.0.1".to_owned(),
            port: addr.port(),
        },
        "/var/www/wordpress",
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    // Attempt HTTPoxy injection (CVE-2016-5385) — must NOT reach PHP-FPM as HTTP_PROXY!
    headers.insert(
        HeaderName::from_static("proxy"),
        HeaderValue::from_static("http://evil.attacker:8080"),
    );

    let req = FastCgiRequest {
        method: &Method::POST,
        version: Version::HTTP_2,
        script_name: "/index.php",
        path_info: "",
        request_uri: "/blog/hello-world/?p=42",
        query_string: "p=42",
        server_name: "legacy-blog.example.com",
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 443,
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
        remote_port: Some(54321),
        is_https: true,
        headers: &headers,
        body: b"comment=hello",
    };

    let resp = client.execute(&req).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(
        resp.body().as_ref(),
        b"wp-ok|script=/index.php|uri=/blog/hello-world/?p=42|https=on|httpoxy=false|stdin=comment=hello"
    );

    // Custom Status: 301 + multiple Set-Cookie headers
    let redir_req = FastCgiRequest {
        script_name: "/redirect.php",
        body: b"",
        ..req
    };
    let redir_resp = client.execute(&redir_req).await?;
    assert_eq!(redir_resp.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        redir_resp
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("https://legacy-blog.example.com/new")
    );
    assert_eq!(redir_resp.headers().get_all(SET_COOKIE).iter().count(), 2);

    // Script traversal rejected before touching PHP-FPM
    let evil_req = FastCgiRequest {
        script_name: "/../../etc/passwd",
        ..req
    };
    assert!(matches!(
        client.execute(&evil_req).await,
        Err(FastCgiError::UnsafeScriptPath(_))
    ));

    abort.abort();
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn unix_socket_fastcgi_executes_wordpress_request() -> TestResult {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let sock_path = std::env::temp_dir().join(format!(
        "miraserve-php-fpm-{}-{nanos}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&sock_path);

    let listener = tokio::net::UnixListener::bind(&sock_path)?;
    let task = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let _ = serve_mock_php_fpm_conn(stream).await;
        }
    });

    let client = FastCgiClient::new(
        FastCgiTarget::Unix {
            path: sock_path.to_string_lossy().into_owned(),
        },
        "/var/www/wordpress",
    );

    let headers = HeaderMap::new();
    let req = FastCgiRequest {
        method: &Method::GET,
        version: Version::HTTP_11,
        script_name: "/index.php",
        path_info: "",
        request_uri: "/",
        query_string: "",
        server_name: "legacy-blog.example.com",
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 443,
        client_ip: None,
        remote_port: Some(41234),
        is_https: true,
        headers: &headers,
        body: b"",
    };

    let resp = client.execute(&req).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.body().as_ref(),
        b"wp-ok|script=/index.php|uri=/|https=on|httpoxy=false|stdin="
    );

    task.abort();
    let _ = std::fs::remove_file(&sock_path);
    Ok(())
}

#[test]
fn cgi_response_parser_rejects_1xx_whitespace_colon_and_strips_framing_headers() -> TestResult {
    // Rejects 101 Switching Protocols from CGI backend
    assert!(
        miraserve_fastcgi::cgi::parse_cgi_response(
            b"Status: 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"
        )
        .is_err()
    );

    // Rejects whitespace before colon
    assert!(
        miraserve_fastcgi::cgi::parse_cgi_response(b"Content-Type : text/plain\r\n\r\nhi").is_err()
    );

    // Strips forged Content-Length / Transfer-Encoding / Alt-Svc and sets authoritative Content-Length
    let resp = miraserve_fastcgi::cgi::parse_cgi_response(
        b"Content-Type: text/plain\r\nContent-Length: 9999\r\nTransfer-Encoding: chunked\r\nAlt-Svc: h3=\":1234\"\r\n\r\nhello",
    )?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()),
        Some("5")
    );
    assert!(
        resp.headers()
            .get(http::header::TRANSFER_ENCODING)
            .is_none()
    );
    assert!(resp.headers().get(http::header::ALT_SVC).is_none());
    Ok(())
}

/// When a backend closes a connection without answering, `replay-safe-methods` retries a safe
/// request once on a fresh connection while never sending a POST twice. Without the setting
/// (the default), nothing that reached the backend is sent again.
#[tokio::test]
async fn connection_dropped_by_backend_is_replayed_only_when_enabled_and_never_for_post()
-> TestResult {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn flaky_backend(
        drop_first: usize,
    ) -> Result<(SocketAddr, Arc<AtomicUsize>, tokio::task::AbortHandle), std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepted);
        let handle = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let n = counter.fetch_add(1, Ordering::SeqCst);
                if n < drop_first {
                    // As a reloading PHP-FPM worker does: close without answering.
                    drop(stream);
                    continue;
                }
                tokio::spawn(async move {
                    let _ = serve_mock_php_fpm_conn(stream).await;
                });
            }
        })
        .abort_handle();
        Ok((addr, accepted, handle))
    }

    let headers = HeaderMap::new();
    let request = |method: &'static Method, body: &'static [u8]| FastCgiRequest {
        method,
        version: Version::HTTP_11,
        script_name: "/index.php",
        path_info: "",
        request_uri: "/",
        query_string: "",
        server_name: "retry.example.com",
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 443,
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
        remote_port: Some(54321),
        is_https: true,
        headers: &headers,
        body,
    };
    let client_for = |addr: SocketAddr| {
        FastCgiClient::new(
            FastCgiTarget::Tcp {
                host: "127.0.0.1".to_owned(),
                port: addr.port(),
            },
            "/var/www/wordpress",
        )
        .with_replay_safe_methods(true)
    };

    // Default (no replay): a GET whose connection is dropped after it was accepted is NOT
    // sent again.
    let (addr, accepted, handle) = flaky_backend(1).await?;
    let default_client = FastCgiClient::new(
        FastCgiTarget::Tcp {
            host: "127.0.0.1".to_owned(),
            port: addr.port(),
        },
        "/var/www/wordpress",
    );
    assert!(
        default_client
            .execute(&request(&Method::GET, b""))
            .await
            .is_err(),
        "without replay-safe-methods a request the backend accepted is not sent twice"
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    handle.abort();

    // GET: first connection dropped, second served -> 200 after exactly two connections.
    let (addr, accepted, handle) = flaky_backend(1).await?;
    let resp = client_for(addr)
        .execute(&request(&Method::GET, b""))
        .await
        .map_err(|err| format!("a GET must survive one dropped backend connection: {err}"))?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
    handle.abort();

    // GET: two drops in a row -> one retry only, then the error is reported.
    let (addr, accepted, handle) = flaky_backend(2).await?;
    assert!(
        client_for(addr)
            .execute(&request(&Method::GET, b""))
            .await
            .is_err()
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 2, "exactly one retry");
    handle.abort();

    // POST: never retried.
    let (addr, accepted, handle) = flaky_backend(1).await?;
    assert!(
        client_for(addr)
            .execute(&request(&Method::POST, b"a=1"))
            .await
            .is_err(),
        "a POST must not be sent a second time"
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    handle.abort();
    Ok(())
}

/// A connection that cannot be made at all never reached the backend, so it is tried once more
/// for every method, also without `replay-safe-methods`: a POST that arrives while PHP-FPM is
/// restarting its listener succeeds instead of failing with 502.
#[tokio::test]
async fn refused_connection_is_retried_for_every_method() -> TestResult {
    // Reserve a port, release it, and start the backend only after the first attempt failed.
    let probe = TcpListener::bind("127.0.0.1:0").await?;
    let addr = probe.local_addr()?;
    drop(probe);

    let backend = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let listener = TcpListener::bind(addr).await?;
        let (stream, _) = listener.accept().await?;
        serve_mock_php_fpm_conn(stream).await
    });

    let headers = HeaderMap::new();
    let request = FastCgiRequest {
        method: &Method::POST,
        version: Version::HTTP_11,
        script_name: "/index.php",
        path_info: "",
        request_uri: "/",
        query_string: "",
        server_name: "retry.example.com",
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 443,
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
        remote_port: Some(54321),
        is_https: true,
        headers: &headers,
        body: b"a=1",
    };
    let client = FastCgiClient::new(
        FastCgiTarget::Tcp {
            host: "127.0.0.1".to_owned(),
            port: addr.port(),
        },
        "/var/www/wordpress",
    );
    let resp = client
        .execute(&request)
        .await
        .map_err(|err| format!("a refused connection must be retried: {err}"))?;
    assert_eq!(resp.status(), StatusCode::OK);
    backend.await??;
    Ok(())
}

//! Unit & adversarial security tests for `miraserve-security`:
//! anti-smuggling, GCRA rate limiting, H2/H3 flood guard, Slowloris body guard,
//! and `wordpress-hardened` / `static-strict` / `api-gateway` presets.

use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, HOST, TRANSFER_ENCODING};
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode, Version};
use http_body::{Body, Frame};
use miraserve_config::{
    ByteSize, LimitsConfig, RateLimitConfig, RateLimitKey, SitePreset, TimeoutsConfig,
};
use miraserve_security::{
    BodyGuardError, BoundedBody, ConnectionFloodGuard, GcraRateLimiter, PresetVerdict,
    SitePresetGuard, validate_request_framing,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn anti_smuggling_rejects_cl_te_duplicate_cl_obfuscated_te_and_host_mismatch() -> TestResult {
    let limits = LimitsConfig::default();

    // Valid HTTP/1.1 request passes
    let ok_req = Request::builder()
        .method(Method::POST)
        .uri("/submit")
        .header(HOST, "example.com")
        .header(CONTENT_LENGTH, "12")
        .body(())?;
    assert!(validate_request_framing(&ok_req, &limits).is_ok());

    // Simultaneous CL + TE rejected
    let cl_te = Request::builder()
        .method(Method::POST)
        .uri("/submit")
        .header(HOST, "example.com")
        .header(CONTENT_LENGTH, "5")
        .header(TRANSFER_ENCODING, "chunked")
        .body(())?;
    let rej = validate_request_framing(&cl_te, &limits)
        .err()
        .ok_or("expected CL+TE rejection")?;
    assert_eq!(rej.rule, "SMUGGLE_CL_TE");
    assert_eq!(rej.status, StatusCode::BAD_REQUEST);

    // Duplicate Content-Length rejected
    let mut dup_cl = Request::builder()
        .method(Method::POST)
        .uri("/submit")
        .header(HOST, "example.com")
        .body(())?;
    dup_cl
        .headers_mut()
        .append(CONTENT_LENGTH, HeaderValue::from_static("5"));
    dup_cl
        .headers_mut()
        .append(CONTENT_LENGTH, HeaderValue::from_static("10"));
    let rej = validate_request_framing(&dup_cl, &limits)
        .err()
        .ok_or("expected duplicate CL rejection")?;
    assert_eq!(rej.rule, "SMUGGLE_DUPLICATE_CL");

    // Obfuscated Transfer-Encoding rejected
    let obf_te = Request::builder()
        .method(Method::POST)
        .uri("/submit")
        .header(HOST, "example.com")
        .header(TRANSFER_ENCODING, "chunked, identity")
        .body(())?;
    let rej = validate_request_framing(&obf_te, &limits)
        .err()
        .ok_or("expected obfuscated TE rejection")?;
    assert_eq!(rej.rule, "SMUGGLE_OBFUSCATED_TE");

    // Transfer-Encoding on HTTP/2 rejected
    let h2_te = Request::builder()
        .version(Version::HTTP_2)
        .uri("https://example.com/api")
        .header(TRANSFER_ENCODING, "chunked")
        .body(())?;
    let rej = validate_request_framing(&h2_te, &limits)
        .err()
        .ok_or("expected H2 TE rejection")?;
    assert_eq!(rej.rule, "SMUGGLE_H2_H3_TE");

    // Host vs :authority mismatch rejected
    let mismatch = Request::builder()
        .version(Version::HTTP_2)
        .uri("https://tenant-a.example.com/admin")
        .header(HOST, "tenant-b.example.com")
        .body(())?;
    let rej = validate_request_framing(&mismatch, &limits)
        .err()
        .ok_or("expected Host/:authority mismatch rejection")?;
    assert_eq!(rej.rule, "HOST_AUTHORITY_MISMATCH");

    // Oversized Content-Length -> 413 Payload Too Large
    let huge = Request::builder()
        .method(Method::POST)
        .uri("/upload")
        .header(HOST, "example.com")
        .header(CONTENT_LENGTH, "999999999999")
        .body(())?;
    let rej = validate_request_framing(&huge, &limits)
        .err()
        .ok_or("expected 413 rejection")?;
    assert_eq!(rej.status, StatusCode::PAYLOAD_TOO_LARGE);

    Ok(())
}

#[test]
fn gcra_rate_limiter_enforces_burst_replenishment_and_key_isolation() {
    let limiter = GcraRateLimiter::from_config(&RateLimitConfig {
        requests: 2,
        per: Duration::from_secs(2), // 1 request/sec steady rate
        burst: 3,                    // initial burst of 3 allowed
        key: RateLimitKey::ClientIp,
        ip_ceiling_multiplier: None,
        max_keys_per_ip: None,
    });

    let t0 = Instant::now();
    // Initial burst of 3 succeeds immediately
    assert!(limiter.check_key_at("ip:1.2.3.4", t0).allowed);
    assert!(limiter.check_key_at("ip:1.2.3.4", t0).allowed);
    assert!(limiter.check_key_at("ip:1.2.3.4", t0).allowed);

    // 4th request at t0 is throttled with retry_after >= 1s
    let denied = limiter.check_key_at("ip:1.2.3.4", t0);
    assert!(!denied.allowed);
    assert!(denied.retry_after_secs >= 1);

    // Different IP is completely unaffected
    assert!(limiter.check_key_at("ip:5.6.7.8", t0).allowed);

    // After 1 second passes, 1 token replenishes
    let t1 = t0 + Duration::from_secs(1);
    assert!(limiter.check_key_at("ip:1.2.3.4", t1).allowed);
}

struct TwoChunks(u8);

impl Body for TwoChunks {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.0 = self.0.saturating_add(1);
        if self.0 <= 2 {
            Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"123456")))))
        } else {
            Poll::Ready(None)
        }
    }
}

#[test]
fn flood_guard_blocks_rapid_reset_and_bounded_body_blocks_oversize() {
    let limits = LimitsConfig {
        max_h2_rst_stream_per_sec: 3,
        max_body_bytes: ByteSize::from_bytes(10),
        ..LimitsConfig::default()
    };
    let guard = ConnectionFloodGuard::from_limits(&limits);
    let t0 = Instant::now();
    assert!(guard.record_stream_reset_at(t0));
    assert!(guard.record_stream_reset_at(t0));
    assert!(guard.record_stream_reset_at(t0));
    assert!(
        !guard.record_stream_reset_at(t0),
        "4th RST_STREAM/sec must trigger flood guard"
    );
    // Next 1-second window resets budget
    assert!(guard.record_stream_reset_at(t0 + Duration::from_secs(1)));

    // BoundedBody rejects payload > 10 bytes
    let mut bounded = BoundedBody::new(TwoChunks(0), &limits, &TimeoutsConfig::default());
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);

    // First 6 bytes OK
    assert!(matches!(
        Pin::new(&mut bounded).poll_frame(&mut cx),
        Poll::Ready(Some(Ok(_)))
    ));
    // Next 6 bytes (total 12 > 10) -> PayloadTooLarge
    assert!(matches!(
        Pin::new(&mut bounded).poll_frame(&mut cx),
        Poll::Ready(Some(Err(BodyGuardError::PayloadTooLarge { max_bytes: 10 })))
    ));
}

#[test]
fn wordpress_hardened_preset_blocks_exploits_and_rate_limits_wp_login() {
    let guard = SitePresetGuard::new(SitePreset::WordpressHardened);
    let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)));
    let headers = HeaderMap::new();

    // Legitimate front-end paths allowed
    assert_eq!(
        guard.evaluate(&Method::GET, "/2026/hello-world/", &headers, ip),
        PresetVerdict::Allow
    );
    assert_eq!(
        guard.evaluate(
            &Method::GET,
            "/wp-content/uploads/2026/photo.jpg",
            &headers,
            ip
        ),
        PresetVerdict::Allow
    );

    // xmlrpc.php blocked
    assert!(matches!(
        guard.evaluate(&Method::POST, "/xmlrpc.php", &headers, ip),
        PresetVerdict::Block {
            status: StatusCode::FORBIDDEN,
            rule: "WP_BLOCK_XMLRPC",
            ..
        }
    ));

    // PHP execution in uploads blocked (including case/URL encoding evasion!)
    for evil_upload in [
        "/wp-content/uploads/2026/shell.php",
        "/wp-content/uploads/2026/shell.PHP",
        "/wp-content/uploads/backdoor.phtml",
        "/wp-includes/evil.php",
    ] {
        assert!(matches!(
            guard.evaluate(&Method::GET, evil_upload, &headers, ip),
            PresetVerdict::Block {
                status: StatusCode::FORBIDDEN,
                rule: "WP_BLOCK_UPLOADS_PHP",
                ..
            }
        ));
    }

    // Dotfiles & wp-config.php blocked
    for secret in [
        "/.env",
        "/.git/HEAD",
        "/wp-config.php",
        "/wp-config.php.bak",
        "/readme.html",
    ] {
        assert!(matches!(
            guard.evaluate(&Method::GET, secret, &headers, ip),
            PresetVerdict::Block {
                status: StatusCode::NOT_FOUND,
                ..
            }
        ));
    }

    // Another path of a request that was evaluated already is checked by the same rules but
    // not counted against the login limit again (Codex 79).
    for _ in 0..20 {
        assert_eq!(
            guard.evaluate_uncounted(&Method::GET, "/docs/wp-login.php/guide.md", &headers, ip),
            PresetVerdict::Allow
        );
    }
    assert!(matches!(
        guard.evaluate_uncounted(&Method::GET, "/wp-config.php", &headers, ip),
        PresetVerdict::Block { .. }
    ));

    // wp-login.php allows burst of 5 then triggers GCRA rate limit!
    for _ in 0..5 {
        assert_eq!(
            guard.evaluate(&Method::POST, "/wp-login.php", &headers, ip),
            PresetVerdict::Allow
        );
    }
    assert!(matches!(
        guard.evaluate(&Method::POST, "/wp-login.php", &headers, ip),
        PresetVerdict::RateLimited {
            rule: "WP_LOGIN_RATE_LIMIT",
            ..
        }
    ));
}

struct PendingForeverBody;

impl Body for PendingForeverBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Pending
    }
}

#[tokio::test]
async fn bounded_body_wakes_and_terminates_completely_stalled_slowloris_peer() -> TestResult {
    let limits = LimitsConfig::default();
    let timeouts = TimeoutsConfig {
        min_body_rate_bps: 1024,
        ..TimeoutsConfig::default()
    };
    let mut body = BoundedBody::new(PendingForeverBody, &limits, &timeouts)
        .with_grace_period(Duration::from_millis(80));

    let res = tokio::time::timeout(
        Duration::from_secs(3),
        std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)),
    )
    .await
    .map_err(|_| "BoundedBody hung indefinitely on stalled peer")?;

    assert!(matches!(
        res,
        Some(Err(BodyGuardError::SlowBodyRate { min_rate_bps: 1024 }))
    ));
    Ok(())
}

#[test]
fn presets_block_slash_and_pathinfo_evasions_and_gcra_hardening() -> TestResult {
    // 1. WordPress preset canonicalization evasions blocked
    let wp = SitePresetGuard::new(SitePreset::WordpressHardened);
    let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99)));
    let headers = HeaderMap::new();
    for evil in [
        "//wp-content/uploads/shell.php",
        "/wp-content/uploads/shell.php/",
        "/wp-content/uploads/shell.php/extra",
        "/xmlrpc.php/",
        "/xmlrpc.php/a.php",
    ] {
        assert!(
            matches!(
                wp.evaluate(&Method::GET, evil, &headers, ip),
                PresetVerdict::Block {
                    status: StatusCode::FORBIDDEN,
                    ..
                }
            ),
            "expected 403 for {evil}"
        );
    }
    for evil_404 in [
        "/wp-config.php/",
        "/wp-config.php/x",
        "/backup.sql/",
        "/.well-known/.env",
    ] {
        assert!(
            matches!(
                wp.evaluate(&Method::GET, evil_404, &headers, ip),
                PresetVerdict::Block {
                    status: StatusCode::NOT_FOUND,
                    ..
                }
            ),
            "expected 404 for {evil_404}"
        );
    }
    // api-gateway blocks `/.well-known/.env` while permitting `/.well-known/oauth-protected-resource`
    let api = SitePresetGuard::new(SitePreset::ApiGateway);
    assert_eq!(
        api.evaluate(
            &Method::GET,
            "/.well-known/oauth-protected-resource",
            &headers,
            ip
        ),
        PresetVerdict::Allow
    );
    assert!(matches!(
        api.evaluate(&Method::GET, "/.well-known/.env", &headers, ip),
        PresetVerdict::Block {
            status: StatusCode::NOT_FOUND,
            ..
        }
    ));

    // 2. GCRA masks IPv6 to /64 (preventing /128 rotation bypass) and hashes raw header bytes
    let v6_limiter = GcraRateLimiter::per_ip(1, Duration::from_secs(60), 1);
    let t0 = Instant::now();
    let v6_a: IpAddr = "2001:db8:abcd:1::1".parse()?;
    let v6_b: IpAddr = "2001:db8:abcd:1::ffff".parse()?;
    assert!(
        v6_limiter
            .check_request_at(Some(v6_a), &headers, None, t0)
            .allowed
    );
    assert!(
        !v6_limiter
            .check_request_at(Some(v6_b), &headers, None, t0)
            .allowed,
        "sibling IPv6 address in same /64 must share GCRA bucket"
    );

    // 3. Smuggling validator blocks H3 Connection/Upgrade headers, Host with `?`, and `..` paths
    let limits = LimitsConfig::default();
    let h3_upg = Request::builder()
        .version(Version::HTTP_3)
        .uri("https://example.com/ws")
        .header(http::header::CONNECTION, "upgrade")
        .header(http::header::UPGRADE, "websocket")
        .body(())?;
    assert!(validate_request_framing(&h3_upg, &limits).is_err());

    let bad_host = Request::builder()
        .uri("/ok")
        .header(HOST, "evil.com?x=1")
        .body(())?;
    assert!(validate_request_framing(&bad_host, &limits).is_err());

    let dotdot = Request::builder()
        .uri("/api/../admin")
        .header(HOST, "example.com")
        .body(())?;
    assert!(validate_request_framing(&dotdot, &limits).is_err());

    Ok(())
}

struct BurstThenStallBody {
    sent_burst: bool,
}

impl Body for BurstThenStallBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.sent_burst {
            Poll::Pending
        } else {
            self.sent_burst = true;
            // Send 1 MiB immediately in first frame, then stall forever!
            Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![b'A'; 1024 * 1024])))))
        }
    }
}

/// R2-HTTP-1, R2-HTTP-2, R2-RL-1 regression tests:
/// - `BoundedBody` starts timing on first poll (delayed poll does not falsely abort ready POST)
/// - `BoundedBody` terminates peer that blasts 1 MiB fast then stalls (idle-gap guard)
/// - `ConnectionFloodGuard::record_bad_request_at` decays strikes across 60s windows
/// - Header-keyed GCRA rate limiter enforces per-IP baseline alongside header keys so rotating
///   random header values cannot bypass rate limits or saturate all shards.
#[tokio::test]
async fn wave3_slowloris_sliding_window_bad_req_decay_and_header_rl_baseline() -> TestResult {
    let limits = LimitsConfig::default();
    let timeouts = TimeoutsConfig {
        min_body_rate_bps: 1024,
        ..TimeoutsConfig::default()
    };

    // 1a. R2-HTTP-1 Scenario A: Construct BoundedBody, sleep longer than grace BEFORE first poll
    //     -> ready body must still succeed cleanly!
    let mut delayed = BoundedBody::new(TwoChunks(0), &limits, &timeouts)
        .with_grace_period(Duration::from_millis(60));
    tokio::time::sleep(Duration::from_millis(120)).await;
    let first_frame = std::future::poll_fn(|cx| Pin::new(&mut delayed).poll_frame(cx)).await;
    assert!(
        matches!(first_frame, Some(Ok(_))),
        "delayed first poll must NOT falsely abort ready POST: {first_frame:?}"
    );

    // 1b. R2-HTTP-1 Scenario B: Peer blasts 1 MiB immediately then stalls -> MUST terminate!
    let mut burst_stall =
        BoundedBody::new(BurstThenStallBody { sent_burst: false }, &limits, &timeouts)
            .with_grace_period(Duration::from_millis(80));
    let burst_frame = std::future::poll_fn(|cx| Pin::new(&mut burst_stall).poll_frame(cx)).await;
    assert!(matches!(burst_frame, Some(Ok(_))));
    let stall_res = tokio::time::timeout(
        Duration::from_secs(2),
        std::future::poll_fn(|cx| Pin::new(&mut burst_stall).poll_frame(cx)),
    )
    .await
    .map_err(|_| "BoundedBody allowed burst-then-stall peer to hang")?;
    assert!(matches!(
        stall_res,
        Some(Err(BodyGuardError::SlowBodyRate { min_rate_bps: 1024 }))
    ));

    // 2. R2-HTTP-2: Bad-request strikes decay across 60-second windows
    let fg = ConnectionFloodGuard::from_limits(&limits);
    let t0 = Instant::now();
    for _ in 0..20 {
        assert!(fg.record_bad_request_at(t0));
    }
    assert!(
        !fg.record_bad_request_at(t0),
        "21st bad request in same 60s window must trip guard"
    );
    assert!(
        fg.record_bad_request_at(t0 + Duration::from_secs(61)),
        "strikes must reset in next 60s window"
    );

    // 3. R2-RL-1: Rotating random `X-API-Key` header values from the same IP CANNOT bypass
    //    header-keyed rate limits, AND sharing the same key across different IPs is still limited!
    let hdr_rl = GcraRateLimiter::from_config(&RateLimitConfig {
        requests: 2,
        per: Duration::from_secs(60),
        burst: 2,
        key: RateLimitKey::Header("x-api-key".to_owned()),
        ip_ceiling_multiplier: None,
        max_keys_per_ip: None,
    });
    let attacker_ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77)));
    for idx in 0..2_u32 {
        let mut h = HeaderMap::new();
        h.insert("x-api-key", HeaderValue::from_str(&format!("rand-{idx}"))?);
        assert!(hdr_rl.check_request_at(attacker_ip, &h, None, t0).allowed);
    }
    let mut h_rot = HeaderMap::new();
    h_rot.insert("x-api-key", HeaderValue::from_static("rand-brand-new"));
    assert!(
        !hdr_rl
            .check_request_at(attacker_ip, &h_rot, None, t0)
            .allowed,
        "rotating random header value from same IP must hit per-IP baseline 429"
    );

    // Distributed reuse of the same stolen header key across distinct IPs is ALSO throttled!
    let mut shared_h = HeaderMap::new();
    shared_h.insert("x-api-key", HeaderValue::from_static("stolen-shared-key"));
    assert!(
        hdr_rl
            .check_request_at(
                Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
                &shared_h,
                None,
                t0
            )
            .allowed
    );
    assert!(
        hdr_rl
            .check_request_at(
                Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2))),
                &shared_h,
                None,
                t0
            )
            .allowed
    );
    assert!(
        !hdr_rl
            .check_request_at(
                Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3))),
                &shared_h,
                None,
                t0
            )
            .allowed,
        "same header key across 3 distinct IPs must hit shared header bucket 429"
    );

    Ok(())
}

struct ChannelBody(tokio::sync::mpsc::Receiver<Bytes>);

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

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

/// R3-HTTP-1, R3-HTTP-2, R3-RL-1 & R2-HTTP-3 regression tests:
/// - `BoundedBody` separates `idle_gap_timeout` from `grace_period` so mobile stalls > grace survive
/// - `BoundedBody` NEVER charges time spent unpolled (upstream back-pressure) to the client
/// - `RateLimitKey::Header` lets multiple active tenants behind one NAT/CDN IP use full quotas
///   without double-charging the per-IP bucket while still blocking random-header rotation
/// - `validate_request_framing` allows `%2F` within segments while still rejecting `..%2F` / `%5C`
#[tokio::test]
async fn round3_bounded_body_idle_gap_backpressure_header_nat_and_encoded_slash() -> TestResult {
    let limits = LimitsConfig::default();
    let timeouts = TimeoutsConfig {
        min_body_rate_bps: 1024,
        ..TimeoutsConfig::default()
    };

    // 1. R3-HTTP-1: Send 64 KiB, pause 150ms (> 60ms rate window, < 500ms idle gap) -> MUST SUCCEED!
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(4);
    tokio::spawn(async move {
        let _ = tx.send(Bytes::from(vec![b'a'; 64 * 1024])).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let _ = tx.send(Bytes::from_static(b"done")).await;
    });
    let mut mobile_body = BoundedBody::new(ChannelBody(rx), &limits, &timeouts)
        .with_grace_period(Duration::from_millis(60))
        .with_idle_gap(Duration::from_millis(500));
    let mut received = 0_usize;
    while let Some(frame_res) =
        std::future::poll_fn(|cx| Pin::new(&mut mobile_body).poll_frame(cx)).await
    {
        let frame = frame_res?;
        if let Some(d) = frame.data_ref() {
            received = received.saturating_add(d.len());
        }
    }
    assert_eq!(received, 64 * 1024 + 4);

    // 2. R3-HTTP-2: Consumer pauses 180ms (3x the 60ms idle gap!) between polling ready chunks
    //    (simulating slow upstream back-pressure) -> MUST NOT blame client with SlowBodyRate!
    let mut backpressured = BoundedBody::new(TwoChunks(0), &limits, &timeouts)
        .with_grace_period(Duration::from_millis(60));
    let f1 = std::future::poll_fn(|cx| Pin::new(&mut backpressured).poll_frame(cx)).await;
    assert!(matches!(f1, Some(Ok(_))));
    tokio::time::sleep(Duration::from_millis(180)).await;
    let f2 = std::future::poll_fn(|cx| Pin::new(&mut backpressured).poll_frame(cx)).await;
    assert!(
        matches!(f2, Some(Ok(_))),
        "upstream consumer back-pressure must NEVER be charged as client SlowBodyRate: {f2:?}"
    );

    // 3. R3-RL-1: Three distinct tenants behind ONE shared corporate NAT IP (burst=3) each get
    //    all 3 of their requests (9 total!) because existing keys never double-charge the IP bucket!
    let nat_rl = GcraRateLimiter::from_config(&RateLimitConfig {
        requests: 3,
        per: Duration::from_secs(60),
        burst: 3,
        key: RateLimitKey::Header("x-api-key".to_owned()),
        ip_ceiling_multiplier: None,
        max_keys_per_ip: None,
    });
    let shared_nat_ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 55)));
    let t0 = Instant::now();
    for tenant in ["tenant-alpha", "tenant-beta", "tenant-gamma"] {
        let mut h = HeaderMap::new();
        h.insert("x-api-key", HeaderValue::from_str(tenant)?);
        for req_idx in 0..3_u32 {
            assert!(
                nat_rl.check_request_at(shared_nat_ip, &h, None, t0).allowed,
                "tenant={tenant} req={req_idx} behind shared NAT must be allowed"
            );
        }
        assert!(
            !nat_rl.check_request_at(shared_nat_ip, &h, None, t0).allowed,
            "tenant={tenant} 4th request must hit header quota"
        );
    }
    let mut h_new = HeaderMap::new();
    h_new.insert(
        "x-api-key",
        HeaderValue::from_static("tenant-brand-new-flood"),
    );
    assert!(
        !nat_rl
            .check_request_at(shared_nat_ip, &h_new, None, t0)
            .allowed,
        "4th brand-new header key from one IP must still hit per-IP admission baseline"
    );

    // 4. R2-HTTP-3: Encoded `%2F` within a segment passes framing; `..%2F` / `%5C` / `%00` still fail!
    let gitlab_req = Request::builder()
        .method(Method::GET)
        .uri("/api/v4/projects/group%2Fproject/issues")
        .header(HOST, "gitlab.example.com")
        .body(())?;
    assert!(
        validate_request_framing(&gitlab_req, &limits).is_ok(),
        "encoded %2F within a non-traversal segment must pass framing for proxy APIs"
    );
    for evil_uri in [
        "/api/..%2Fadmin",
        "/api/%2e%2e%2Fadmin",
        "/api/a%5Cb",
        "/api/a%00b",
    ] {
        let evil_req = Request::builder()
            .method(Method::GET)
            .uri(evil_uri)
            .header(HOST, "gitlab.example.com")
            .body(())?;
        assert!(
            validate_request_framing(&evil_req, &limits).is_err(),
            "traversal/escape {evil_uri} must STILL be rejected globally"
        );
    }

    Ok(())
}

struct StaticErrBody;

impl Body for StaticErrBody {
    type Data = Bytes;
    type Error = &'static str;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(Some(Err("too_big")))
    }
}

/// R4-RL-1 (header rate-limit idle expiry, active-key cap, and unconditional per-IP ceiling),
/// R4-HTTP-1 (`min-body-rate-bps 0` keeps `body-idle-timeout` active),
/// R4-HTTP-2 (`body-idle-timeout` governs pauses for low-rate clients),
/// R4-HTTP-3 (`BoundedBody::with_error_mapper` preserves `PayloadTooLarge`),
/// R4-PRX-1 (rejects `%uXXXX` and overlong/invalid UTF-8 globally), and
/// R2-HTTP-3 (allows `_` in `Host` header).
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn round4_header_rl_ceiling_idle_expiry_bounded_body_and_uri_hardening() -> TestResult {
    // 1a. R4-RL-1 Idle expiry: keys registered in window 0 expire when idle in window 1, so they
    //     MUST re-pass per-IP admission (no free multiplication across windows!).
    let rl = GcraRateLimiter::from_config(&RateLimitConfig {
        requests: 3,
        per: Duration::from_secs(60),
        burst: 3,
        key: RateLimitKey::Header("x-api-key".to_owned()),
        ip_ceiling_multiplier: None,
        max_keys_per_ip: None,
    });
    let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99)));
    let t0 = Instant::now();
    for i in 0..3_u32 {
        let mut h = HeaderMap::new();
        h.insert("x-api-key", HeaderValue::from_str(&format!("win0-{i}"))?);
        assert!(rl.check_request_at(ip, &h, None, t0).allowed);
    }
    // Advance 61s so all 3 entries are idle/drained (`prev_tat <= now_ns`).
    let t1 = t0 + Duration::from_secs(61);
    for i in 0..3_u32 {
        let mut h = HeaderMap::new();
        h.insert("x-api-key", HeaderValue::from_str(&format!("win0-{i}"))?);
        assert!(
            rl.check_request_at(ip, &h, None, t1).allowed,
            "re-admitting expired key win0-{i} consumes per-IP admission"
        );
    }
    // A 4th brand-new key in window 1 MUST now be rejected by per-IP admission!
    let mut h_extra = HeaderMap::new();
    h_extra.insert("x-api-key", HeaderValue::from_static("win1-extra"));
    assert!(
        !rl.check_request_at(ip, &h_extra, None, t1).allowed,
        "expired keys from window 0 must NOT bypass per-IP admission in window 1"
    );

    // 1b. R4-RL-1 Active-key cap + unconditional per-IP 10x ceiling: even if an attacker keeps
    //     keys alive continuously across multiple periods, they can NEVER exceed 10 active keys
    //     or 10x total requests per period from a single IP!
    let rl2 = GcraRateLimiter::from_config(&RateLimitConfig {
        requests: 3,
        per: Duration::from_secs(60),
        burst: 3,
        key: RateLimitKey::Header("x-api-key".to_owned()),
        ip_ceiling_multiplier: None,
        max_keys_per_ip: Some(10),
    });
    let attacker = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 88)));
    let mut cur_t = Instant::now();
    let mut admitted_keys = 0_u32;
    for batch in 0..5_u32 {
        // Keep all previously admitted keys alive (just before their TAT expires).
        for prev in 0..admitted_keys {
            let mut h = HeaderMap::new();
            h.insert("x-api-key", HeaderValue::from_str(&format!("k-{prev}"))?);
            let _ = rl2.check_request_at(attacker, &h, None, cur_t);
        }
        // Try to register 3 brand-new keys in this period.
        for offset in 0..3_u32 {
            let id = batch * 3 + offset;
            let mut h = HeaderMap::new();
            h.insert("x-api-key", HeaderValue::from_str(&format!("k-{id}"))?);
            if rl2.check_request_at(attacker, &h, None, cur_t).allowed {
                admitted_keys = admitted_keys.saturating_add(1);
            }
        }
        // Advance 25s (each key's burst TAT is +20s per req; touching twice keeps TAT alive,
        // while advancing 60s replenishes IP admission).
        cur_t += Duration::from_secs(60);
    }
    assert!(
        rl2.tracked_active_key_count_for_ip(attacker, cur_t) <= 10,
        "per-IP active header keys must remain capped via LRU eviction (got {}, admitted {admitted_keys})",
        rl2.tracked_active_key_count_for_ip(attacker, cur_t)
    );

    // 2. R4-HTTP-1: `min_body_rate_bps == 0` MUST STILL enforce `body_idle_timeout`!
    let limits = LimitsConfig::default();
    let zero_rate_timeouts = TimeoutsConfig {
        min_body_rate_bps: 0,
        body_idle_timeout: Duration::from_millis(80),
        ..TimeoutsConfig::default()
    };
    let mut zero_rate_stall = BoundedBody::new(
        BurstThenStallBody { sent_burst: false },
        &limits,
        &zero_rate_timeouts,
    );
    let first = std::future::poll_fn(|cx| Pin::new(&mut zero_rate_stall).poll_frame(cx)).await;
    assert!(matches!(first, Some(Ok(_))));
    let stalled = tokio::time::timeout(
        Duration::from_secs(2),
        std::future::poll_fn(|cx| Pin::new(&mut zero_rate_stall).poll_frame(cx)),
    )
    .await
    .map_err(|_| "min_body_rate_bps=0 hung indefinitely instead of enforcing body_idle_timeout")?;
    assert!(
        matches!(
            stalled,
            Some(Err(BodyGuardError::SlowBodyRate { min_rate_bps: 0 }))
        ),
        "expected SlowBodyRate {{ min_rate_bps: 0 }}, got {stalled:?}"
    );

    // 3. R4-HTTP-2: Low-rate client sending only 10 bytes, pausing 150ms (> 60ms grace, < 400ms
    //    body_idle_timeout), then sending 10 bytes and EOF MUST SUCCEED!
    let low_rate_timeouts = TimeoutsConfig {
        min_body_rate_bps: 1024,
        ..TimeoutsConfig::default()
    };
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(4);
    tokio::spawn(async move {
        let _ = tx.send(Bytes::from_static(b"0123456789")).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let _ = tx.send(Bytes::from_static(b"abcdefghij")).await;
    });
    let mut low_rate_body = BoundedBody::new(ChannelBody(rx), &limits, &low_rate_timeouts)
        .with_grace_period(Duration::from_millis(60))
        .with_idle_gap(Duration::from_millis(400));
    let mut total = 0_usize;
    while let Some(frame_res) =
        std::future::poll_fn(|cx| Pin::new(&mut low_rate_body).poll_frame(cx)).await
    {
        let frame = frame_res?;
        if let Some(d) = frame.data_ref() {
            total = total.saturating_add(d.len());
        }
    }
    assert_eq!(total, 20);

    // 4. R4-HTTP-3: `BoundedBody::with_error_mapper` preserves `PayloadTooLarge`!
    let mut mapped = BoundedBody::new(StaticErrBody, &limits, &low_rate_timeouts)
        .with_error_mapper(|e| {
            if e == "too_big" {
                BodyGuardError::PayloadTooLarge { max_bytes: 1024 }
            } else {
                BodyGuardError::Inner(e.to_owned())
            }
        });
    let mapped_res = std::future::poll_fn(|cx| Pin::new(&mut mapped).poll_frame(cx)).await;
    assert_eq!(
        mapped_res.and_then(Result::err),
        Some(BodyGuardError::PayloadTooLarge { max_bytes: 1024 })
    );

    // 5. R4-PRX-1: Reject `%uXXXX`/`%UXXXX` IIS Unicode escapes and invalid/overlong UTF-8 globally.
    for evil in [
        "/api/%u002e%u002e/admin",
        "/api/%U002E%U002E/admin",
        "/api/%c0%ae%c0%ae/admin",
        "/api/%e0%80%ae/admin",
    ] {
        let req = Request::builder()
            .method(Method::GET)
            .uri(evil)
            .header(HOST, "api.example.com")
            .body(())?;
        assert!(
            validate_request_framing(&req, &limits).is_err(),
            "R4-PRX-1: {evil} must be rejected globally"
        );
    }

    // 6. R2-HTTP-3: Allow `_` in DNS/internal service `Host` headers.
    let underscore_host = Request::builder()
        .method(Method::GET)
        .uri("/health")
        .header(HOST, "my_service.internal:8443")
        .body(())?;
    assert!(
        validate_request_framing(&underscore_host, &limits).is_ok(),
        "Host with underscore `_` must be accepted"
    );

    Ok(())
}

/// Round 5 Wave 4 security tests (`R5-RL-1`, `R5-RL-2`, `R5-HTTP-1`, `R5-HTTP-2`, `R5-HTTP-3`):
/// - `R5-RL-1`: 50 shared-NAT users (quota 100/min, burst 10, 12 req/min each) with idle keys
///   returning well after `tat` drains (`45s < 60s` idle TTL) get 100% admission without touching
///   per-IP new-key admission; header-less traffic is isolated; rotating attacker is still capped!
/// - `R5-RL-2`: 16 concurrent threads racing against `max_keys_per_ip = 5` never exceed 5 active
///   keys and leave zero ghost keys in `header_shards`.
/// - `R5-HTTP-1`: Client uploading 100ms, pausing 250ms (`< 300ms` idle timeout), and resuming
///   succeeds without false 408; pulse Slowloris attacker repeating 250ms pauses with 1 byte IS cut.
/// - `R5-HTTP-2`: `max_body_duration` terminates slow-drip uploads even when `min_body_rate_bps == 0`.
/// - `R5-HTTP-3`: Legacy ISO-8859-1 `/fichier%E9.pdf` passes framing; overlong UTF-8 & surrogates fail.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn round5_wave4_shared_ip_nat_idle_returning_keys_atomic_cap_paused_uploads_and_legacy_uri()
-> TestResult {
    // 1. R5-RL-1: 50 users behind ONE NAT IP (quota 100/min, burst 10, 12 req/min = 1 req / 5s).
    let nat_rl = GcraRateLimiter::from_config(&RateLimitConfig {
        requests: 100,
        per: Duration::from_secs(60),
        burst: 10,
        key: RateLimitKey::Header("x-api-key".to_owned()),
        ip_ceiling_multiplier: None, // default 10x -> 1000/min
        max_keys_per_ip: None,       // default 64 >= 50
    });
    let nat_ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)));
    let t0 = Instant::now();

    // Admit 50 users smoothly over the first 50 seconds (1 new user/sec <= 100/min admission).
    for u in 0..50_u32 {
        let mut h = HeaderMap::new();
        h.insert(
            "x-api-key",
            HeaderValue::from_str(&format!("nat-user-{u}"))?,
        );
        let t = t0 + Duration::from_secs(u64::from(u));
        assert!(
            nat_rl.check_request_at(nat_ip, &h, None, t).allowed,
            "initial admission for nat-user-{u} must succeed"
        );
    }
    // Now run 2 full minutes of 50 users each sending 12 req/min (every 5s, so every user's
    // `tat` of +0.6s has long since drained on every single request!) -> 1,200 requests, ZERO 429s!
    let steady_start = t0 + Duration::from_secs(55);
    let mut steady_allowed = 0_u32;
    let mut steady_total = 0_u32;
    for tick in 0..24_u64 {
        for u in 0..50_u32 {
            let mut h = HeaderMap::new();
            h.insert(
                "x-api-key",
                HeaderValue::from_str(&format!("nat-user-{u}"))?,
            );
            let t = steady_start + Duration::from_millis(tick * 5_000 + u64::from(u) * 100);
            steady_total += 1;
            if nat_rl.check_request_at(nat_ip, &h, None, t).allowed {
                steady_allowed += 1;
            }
        }
    }
    assert_eq!(
        steady_allowed, steady_total,
        "R5-RL-1: all {steady_total} shared-NAT requests below quota must succeed (got {steady_allowed})"
    );

    // Explicit idle-key comeback test: exhaust header-less bucket AND new-key admission bucket on
    // the SAME NAT IP, let `nat-user-0` sit completely idle for 45s (44.4s after its TAT drained,
    // still < 60s `per` idle TTL), and verify `nat-user-0` returns with 100% admission!
    let comeback_t = steady_start + Duration::from_mins(2) + Duration::from_secs(45);
    let empty_hdrs = HeaderMap::new();
    for _ in 0..20 {
        let _ = nat_rl.check_request_at(nat_ip, &empty_hdrs, None, comeback_t);
    }
    let mut h_comeback = HeaderMap::new();
    h_comeback.insert("x-api-key", HeaderValue::from_static("nat-user-0"));
    assert!(
        nat_rl
            .check_request_at(nat_ip, &h_comeback, None, comeback_t)
            .allowed,
        "R5-RL-1: idle key returning after 45s (< 60s per) must be allowed even when header-less IP bucket is saturated"
    );

    // 2. R5-RL-2: Atomic `try_claim_ip_active_key` cap under 16 concurrent threads (`max_keys_per_ip = 5`).
    let atomic_rl = std::sync::Arc::new(GcraRateLimiter::from_config(&RateLimitConfig {
        requests: 500,
        per: Duration::from_secs(60),
        burst: 500,
        key: RateLimitKey::Header("x-api-key".to_owned()),
        ip_ceiling_multiplier: Some(10),
        max_keys_per_ip: Some(5),
    }));
    let race_ip = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200)));
    let race_t = Instant::now();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
    let mut handles = Vec::new();
    for tid in 0..16_u32 {
        let rl_c = std::sync::Arc::clone(&atomic_rl);
        let b_c = std::sync::Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            b_c.wait();
            let mut admitted = Vec::new();
            for k in 0..4_u32 {
                let key_name = format!("race-t{tid}-k{k}");
                let mut h = HeaderMap::new();
                if let Ok(val) = HeaderValue::from_str(&key_name) {
                    h.insert("x-api-key", val);
                    if rl_c.check_request_at(race_ip, &h, None, race_t).allowed {
                        admitted.push(key_name);
                    }
                }
            }
            admitted
        }));
    }
    let mut all_admitted = Vec::new();
    for h in handles {
        let v = h.join().map_err(|_| "race thread panicked")?;
        all_admitted.extend(v);
    }
    assert!(
        !all_admitted.is_empty(),
        "R5-RL-2/R6-RL-1: concurrent threads must admit keys without panicking or starving"
    );
    let tracked = atomic_rl.tracked_active_key_count_for_ip(race_ip, race_t);
    assert!(
        tracked <= 5,
        "R5-RL-2/R6-RL-1: active tracked keys per IP must stay atomically <= 5 under 16-thread race with LRU eviction (got {tracked})"
    );

    // 3. R5-HTTP-1: Upload for 100ms (healthy rate), pause 250ms (< 350ms idle timeout), resume -> SUCCEEDS!
    let limits = LimitsConfig::default();
    let timeouts = TimeoutsConfig {
        min_body_rate_bps: 1024,
        ..TimeoutsConfig::default()
    };
    let (tx_ok, rx_ok) = tokio::sync::mpsc::channel::<Bytes>(8);
    tokio::spawn(async move {
        // Send 5 chunks of 100 bytes every 20ms (5 KB/s >> 1 KB/s for 100ms).
        for _ in 0..5 {
            let _ = tx_ok.send(Bytes::from(vec![b'x'; 100])).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Legitimate discrete pause shorter than idle_gap_timeout (220ms < 400ms).
        tokio::time::sleep(Duration::from_millis(220)).await;
        // Resume with a modest chunk (100 bytes) + finish!
        let _ = tx_ok.send(Bytes::from(vec![b'y'; 100])).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let _ = tx_ok.send(Bytes::from(vec![b'z'; 100])).await;
    });
    let mut paused_body = BoundedBody::new(ChannelBody(rx_ok), &limits, &timeouts)
        .with_grace_period(Duration::from_millis(80))
        .with_idle_gap(Duration::from_millis(400));
    let mut received = 0_usize;
    while let Some(frame_res) =
        std::future::poll_fn(|cx| Pin::new(&mut paused_body).poll_frame(cx)).await
    {
        let frame = frame_res?;
        if let Some(d) = frame.data_ref() {
            received += d.len();
        }
    }
    assert_eq!(
        received, 700,
        "R5-HTTP-1: paused upload must resume cleanly"
    );

    // Pulse Slowloris attacker sending 1 byte every 120ms repeatedly (never transferring quota
    // between pauses) MUST still be cut with SlowBodyRate!
    let (tx_pulse, rx_pulse) = tokio::sync::mpsc::channel::<Bytes>(8);
    tokio::spawn(async move {
        for _ in 0..8 {
            if tx_pulse.send(Bytes::from_static(b"a")).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(120)).await;
        }
    });
    let mut pulse_body = BoundedBody::new(ChannelBody(rx_pulse), &limits, &timeouts)
        .with_grace_period(Duration::from_millis(80))
        .with_idle_gap(Duration::from_millis(400));
    let mut pulse_err = None;
    while let Some(frame_res) =
        std::future::poll_fn(|cx| Pin::new(&mut pulse_body).poll_frame(cx)).await
    {
        if let Err(err) = frame_res {
            pulse_err = Some(err);
            break;
        }
    }
    assert!(
        matches!(pulse_err, Some(BodyGuardError::SlowBodyRate { .. })),
        "R5-HTTP-1: repeated 1-byte pulse Slowloris must still trip SlowBodyRate, got {pulse_err:?}"
    );

    // 4. R5-HTTP-2: Absolute `max_body_duration` terminates slow-drip even when `min_body_rate_bps == 0`.
    let zero_rate = TimeoutsConfig {
        min_body_rate_bps: 0,
        body_idle_timeout: Duration::from_millis(500),
        max_body_duration: Duration::from_millis(140),
        ..TimeoutsConfig::default()
    };
    let (tx_drip, rx_drip) = tokio::sync::mpsc::channel::<Bytes>(8);
    tokio::spawn(async move {
        for _ in 0..20 {
            if tx_drip.send(Bytes::from_static(b"d")).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    });
    let mut drip_body = BoundedBody::new(ChannelBody(rx_drip), &limits, &zero_rate);
    let mut drip_err = None;
    while let Some(frame_res) =
        std::future::poll_fn(|cx| Pin::new(&mut drip_body).poll_frame(cx)).await
    {
        if let Err(err) = frame_res {
            drip_err = Some(err);
            break;
        }
    }
    assert!(
        matches!(
            drip_err,
            Some(BodyGuardError::SlowBodyRate { min_rate_bps: 0 })
        ),
        "R5-HTTP-2: max_body_duration must terminate slow-drip even with min_body_rate_bps=0, got {drip_err:?}"
    );

    // 5. R5-HTTP-3: Legacy ISO-8859-1 `/fichier%E9.pdf` passes global framing, while overlong UTF-8
    //    and UTF-16 surrogates are still rejected globally with 400!
    for legacy_ok in ["/fichier%E9.pdf", "/legacy/caf%E9/doc.txt"] {
        let req = Request::builder()
            .method(Method::GET)
            .uri(legacy_ok)
            .header(HOST, "legacy.example.com")
            .body(())?;
        assert!(
            validate_request_framing(&req, &limits).is_ok(),
            "R5-HTTP-3: legacy non-UTF-8 path {legacy_ok} must pass global framing"
        );
    }
    for bad_utf8 in [
        "/api/%C0%AE%C0%AE/admin",
        "/api/%E0%80%AE/admin",
        "/api/%F0%80%80%AE/admin",
        "/api/%ED%A0%80/admin",
        "/api/%FC%80%80%80%80%AF/admin",
        "/api/%E9/..%2Fsecret",
    ] {
        let req = Request::builder()
            .method(Method::GET)
            .uri(bad_utf8)
            .header(HOST, "legacy.example.com")
            .body(())?;
        assert!(
            validate_request_framing(&req, &limits).is_err(),
            "R5-HTTP-3: overlong/surrogate/traversal {bad_utf8} must be rejected globally"
        );
    }

    Ok(())
}

/// R6-RL-1: One attacker behind a shared NAT/CDN IP must not starve sibling users via either
/// slot exhaustion (64 keys kept alive) OR aggregate ceiling exhaustion (20 noisy keys blasting
/// > 1000/min), and rejected per-key requests must never drain the shared IP ceiling.
#[test]
#[allow(clippy::too_many_lines)]
fn r6_rl_1_shared_ip_slot_eviction_and_fair_share_ceiling_prevent_single_user_starvation()
-> TestResult {
    // Part A: Slot exhaustion — attacker mints 64 keys in 38s and keeps all 64 alive with 64 req/min;
    // victim sends 300 requests over 5 minutes (1 req/sec) and MUST NOT be starved (0/300 -> 300/300)!
    let slot_rl = GcraRateLimiter::from_config(&RateLimitConfig {
        requests: 100,
        per: Duration::from_secs(60),
        burst: 10,
        key: RateLimitKey::Header("x-api-key".to_owned()),
        ip_ceiling_multiplier: None,
        max_keys_per_ip: None, // default 64
    });
    let shared_ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)));
    let t0 = Instant::now();
    for i in 0..64_u64 {
        let mut h = HeaderMap::new();
        h.insert(
            "x-api-key",
            HeaderValue::from_str(&format!("atk-slot-{i}"))?,
        );
        let t = t0 + Duration::from_millis(i * 600);
        assert!(slot_rl.check_request_at(shared_ip, &h, None, t).allowed);
    }
    let mut victim_allowed = 0_u32;
    let mut victim_hdr = HeaderMap::new();
    victim_hdr.insert("x-api-key", HeaderValue::from_static("victim-key"));
    let start_s = t0 + Duration::from_secs(40);
    for sec in 0..300_u64 {
        let now = start_s + Duration::from_secs(sec);
        // Attacker keeps ~1 of its 64 keys alive every second (~60 req/min).
        let atk_idx = sec % 64;
        let mut h_atk = HeaderMap::new();
        h_atk.insert(
            "x-api-key",
            HeaderValue::from_str(&format!("atk-slot-{atk_idx}"))?,
        );
        let _ = slot_rl.check_request_at(shared_ip, &h_atk, None, now);
        if slot_rl
            .check_request_at(shared_ip, &victim_hdr, None, now)
            .allowed
        {
            victim_allowed += 1;
        }
    }
    assert!(
        victim_allowed >= 290,
        "R6-RL-1 slot exhaustion: victim must not be starved by 64 active attacker keys (got {victim_allowed}/300)"
    );
    assert!(
        slot_rl.tracked_active_key_count_for_ip(shared_ip, start_s + Duration::from_secs(300))
            <= 64,
        "R6-RL-1: LRU eviction must keep tracked active keys <= 64"
    );

    // Part B: Ceiling exhaustion — attacker runs 20 keys blasting 2,000 req/min against 1,000/min
    // IP ceiling while active victim sends 12 req/min (1 every 5s). Victim MUST get 12/12 while
    // attacker's 20 keys combined remain bounded by the IP ceiling!
    let ceil_rl = GcraRateLimiter::from_config(&RateLimitConfig {
        requests: 100,
        per: Duration::from_secs(60),
        burst: 10,
        key: RateLimitKey::Header("x-api-key".to_owned()),
        ip_ceiling_multiplier: None, // 10x -> 1000/min, burst 100
        max_keys_per_ip: None,
    });
    let ip_b = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77)));
    let tb0 = Instant::now();
    // Pre-admit 20 attacker keys + 1 active victim key over 13 seconds.
    for i in 0..20_u64 {
        let mut h = HeaderMap::new();
        h.insert("x-api-key", HeaderValue::from_str(&format!("atk-c-{i}"))?);
        assert!(
            ceil_rl
                .check_request_at(ip_b, &h, None, tb0 + Duration::from_millis(i * 600))
                .allowed
        );
    }
    assert!(
        ceil_rl
            .check_request_at(ip_b, &victim_hdr, None, tb0 + Duration::from_secs(13))
            .allowed
    );
    let flood_start = tb0 + Duration::from_secs(20);
    let mut attacker_allowed = 0_u32;
    let mut victim_c_allowed = 0_u32;
    // 60 seconds at 30ms steps (~2,000 attacker attempts = 100/min per key across 20 keys).
    for step in 0..2_000_u64 {
        let now = flood_start + Duration::from_millis(step * 30);
        let key_idx = step % 20;
        let mut h_atk = HeaderMap::new();
        h_atk.insert(
            "x-api-key",
            HeaderValue::from_str(&format!("atk-c-{key_idx}"))?,
        );
        if ceil_rl.check_request_at(ip_b, &h_atk, None, now).allowed {
            attacker_allowed += 1;
        }
        // Victim sends 1 request every 5 seconds (12 total over 60 seconds).
        if step > 0
            && step % 166 == 0
            && victim_c_allowed < 12
            && ceil_rl
                .check_request_at(ip_b, &victim_hdr, None, now)
                .allowed
        {
            victim_c_allowed += 1;
        }
    }
    assert_eq!(
        victim_c_allowed, 12,
        "R6-RL-1 ceiling exhaustion: active quiet victim must get all 12/12 requests despite 20 noisy keys (got {victim_c_allowed}/12)"
    );
    assert!(
        attacker_allowed <= 1_100,
        "R6-RL-1: 20 attacker keys combined must remain bounded by the IP ceiling (got {attacker_allowed})"
    );

    // Part C: Hammering a single throttled key must NOT drain the shared IP ceiling for a sibling key.
    let mut loud_hdr = HeaderMap::new();
    loud_hdr.insert("x-api-key", HeaderValue::from_static("loud-throttled"));
    let mut quiet_hdr = HeaderMap::new();
    quiet_hdr.insert("x-api-key", HeaderValue::from_static("quiet-sibling"));
    let tc0 = Instant::now();
    let ip_c = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 91)));
    let single_rl = GcraRateLimiter::from_config(&RateLimitConfig {
        requests: 5,
        per: Duration::from_secs(60),
        burst: 2,
        key: RateLimitKey::Header("x-api-key".to_owned()),
        ip_ceiling_multiplier: Some(2), // ceiling burst = 4
        max_keys_per_ip: None,
    });
    assert!(
        single_rl
            .check_request_at(ip_c, &quiet_hdr, None, tc0)
            .allowed
    );
    // 30s later (`quiet_hdr` is still active within 60s idle TTL, ceiling has fully drained):
    // `loud_hdr` hammers 50 times (2 allowed, 48 rejected by per-key GCRA). If the 48 rejected
    // requests charged the ceiling (burst=4), `quiet_hdr` would be blocked; it MUST succeed!
    let tc1 = tc0 + Duration::from_secs(30);
    let mut loud_allowed = 0_u32;
    for _ in 0..50 {
        if single_rl
            .check_request_at(ip_c, &loud_hdr, None, tc1)
            .allowed
        {
            loud_allowed += 1;
        }
    }
    assert_eq!(loud_allowed, 2);
    assert!(
        single_rl
            .check_request_at(ip_c, &quiet_hdr, None, tc1)
            .allowed,
        "R6-RL-1: rejected requests from a throttled key must never consume shared IP ceiling tokens"
    );
    Ok(())
}

/// R6-HTTP-1: Repeated discrete pauses interspersed with minimal healthy windows must exhaust the
/// lifetime free-pause budget (`2 * body_idle_timeout`) and be killed with `408 SlowBodyRate`.
#[tokio::test]
async fn r6_http_1_lifetime_free_pause_budget_stops_repeated_pause_and_trickle_slowloris()
-> TestResult {
    let limits = LimitsConfig::default();
    let timeouts = TimeoutsConfig {
        min_body_rate_bps: 1024,
        ..TimeoutsConfig::default()
    };
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(8);
    tokio::spawn(async move {
        // Initial healthy byte so first poll establishes timing.
        let _ = tx.send(Bytes::from(vec![b'a'; 128])).await;
        // Attacker tries 5 cycles of [pause 130ms (< 180ms idle_gap) -> 80B -> wait 65ms -> 1B]:
        // lifetime free pause budget is `2 * 180ms = 360ms`, so cycle 3 (390ms > 360ms) MUST fail!
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(130)).await;
            if tx.send(Bytes::from(vec![b'b'; 80])).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(65)).await;
            if tx.send(Bytes::from_static(b"c")).await.is_err() {
                break;
            }
        }
    });
    let mut body = BoundedBody::new(ChannelBody(rx), &limits, &timeouts)
        .with_grace_period(Duration::from_millis(60))
        .with_idle_gap(Duration::from_millis(180));
    let mut got_err = None;
    while let Some(frame_res) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await
    {
        if let Err(err) = frame_res {
            got_err = Some(err);
            break;
        }
    }
    assert!(
        matches!(
            got_err,
            Some(BodyGuardError::SlowBodyRate { min_rate_bps: 1024 })
        ),
        "R6-HTTP-1: repeated pause/trickle Slowloris must exhaust lifetime pause budget and fail with SlowBodyRate, got {got_err:?}"
    );
    Ok(())
}

/// R6-HTTP-2: Reject `%C0%2F`, `%C0.`, `%E0%80.`, and truncated overlong/surrogate UTF-8 prefixes
/// globally while keeping legacy ISO-8859-1 `/fichier%E9.pdf` allowed for reverse proxies.
#[test]
fn r6_http_2_rejects_c0_and_truncated_overlong_utf8_while_allowing_legacy_latin1() -> TestResult {
    let limits = LimitsConfig::default();
    for bad in [
        "/api/%C0%2F",
        "/api/%C0.",
        "/api/%C1%2F",
        "/api/%E0%80.",
        "/api/%ED%A0.",
        "/api/%F0%80.",
        "/api/%F4%90.",
        "/api/%FF",
    ] {
        let req = Request::builder()
            .method(Method::GET)
            .uri(bad)
            .header(HOST, "api.example.com")
            .body(())?;
        assert!(
            validate_request_framing(&req, &limits).is_err(),
            "R6-HTTP-2: {bad} must be rejected with 400"
        );
    }

    let ok_req = Request::builder()
        .method(Method::GET)
        .uri("/fichier%E9.pdf")
        .header(HOST, "api.example.com")
        .body(())?;
    assert!(
        validate_request_framing(&ok_req, &limits).is_ok(),
        "R6-HTTP-2: legacy Latin-1 /fichier%E9.pdf must remain allowed for proxy routes"
    );
    Ok(())
}

/// R7-HTTP-1: A legitimate upload that alternates fast active chunks (`~2x min_body_rate_bps`)
/// with repeated stalls `< body_idle_timeout` replenishes pause credit via surplus bytes and
/// completes all 10 cycles cleanly even when total cumulative stalls exceed `4x max_total_free_pause`.
// Runs on tokio's paused clock: the 72 ms stall against an 80 ms idle gap leaves an 8 ms margin
// that real sleeps cannot hold on a loaded or emulated machine (it failed there with the
// minimum-rate error although the guard was right). Virtual time makes the timings exact.
#[tokio::test(start_paused = true)]
async fn r7_http_1_legitimate_repeatedly_stalled_upload_survives_via_surplus_pause_credit()
-> TestResult {
    let limits = LimitsConfig::default();
    let timeouts = TimeoutsConfig {
        min_body_rate_bps: 1024,
        ..TimeoutsConfig::default()
    };
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(32);
    tokio::spawn(async move {
        // Exact 100:1 scaled R7-HTTP-1 reproducer (matching 20s @ 2048 B/s + 7.5s stall on 8s idle / 10s grace):
        // min_body_rate_bps=1024, grace=100ms, idle_gap=80ms (max_total_free_pause=160ms).
        // 8 cycles of [upload at ~2000 B/s for 200ms (21 x 20B every 10ms = 2 full 100ms windows,
        // rolling the window right before the stall!) -> stall 72ms (< 80ms)].
        // Cumulative pause = 576ms (> 3.5x max_total_free_pause), long-run rate ~1540 B/s (150% of min).
        // Without surplus pause-credit replenishment, cycle 3 fails with SlowBodyRate because 72ms
        // stall + 30ms active (~80B) falls below 104B required for 102ms!
        for _ in 0..8 {
            for chunk_idx in 0..21 {
                if tx.send(Bytes::from(vec![b'x'; 20])).await.is_err() {
                    return;
                }
                if chunk_idx < 20 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
            tokio::time::sleep(Duration::from_millis(72)).await;
        }
        let _ = tx.send(Bytes::from(vec![b'z'; 32])).await;
    });

    let mut body = BoundedBody::new(ChannelBody(rx), &limits, &timeouts)
        .with_grace_period(Duration::from_millis(100))
        .with_idle_gap(Duration::from_millis(80));
    let mut total_bytes = 0_usize;
    while let Some(frame_res) = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await
    {
        let frame = frame_res.map_err(|err| {
            format!("R7-HTTP-1: legitimate 150% average stalled upload was killed: {err}")
        })?;
        if let Some(d) = frame.data_ref() {
            total_bytes = total_bytes.saturating_add(d.len());
        }
    }
    assert_eq!(total_bytes, 8 * 21 * 20 + 32);
    Ok(())
}

/// R7-HTTP-2 & R6-HTTP-2: Anti-smuggling rejects `;params` dot-segments (`/public/..;/manager/html`,
/// `/up/a/%2e%2e;/x`, `/up/a/.;/x`) and RFC 3629 invalid UTF-8 lead bytes `0xF5..=0xFF` (`%FC`).
#[test]
fn r7_http_2_blocks_semicolon_dot_segments_and_r6_http_2_f5_to_ff() -> TestResult {
    let limits = LimitsConfig::default();
    for bad in [
        "/public/..;/manager/html",
        "/up/a/..;/x",
        "/up/a/..;jsessionid=1/x",
        "/up/a/.;/x",
        "/up/a/%2e%2e;/x",
        "/up/a/..%3b/x",
        "/up/f%FCr",
        "/up/a/%F5test",
        "/up/a/%FEtest",
    ] {
        let req = Request::builder()
            .method(Method::GET)
            .uri(bad)
            .header(HOST, "app.example.com")
            .body(())?;
        assert!(
            validate_request_framing(&req, &limits).is_err(),
            "R7-HTTP-2/R6-HTTP-2: '{bad}' must be rejected with 400"
        );
    }
    // Normal matrix parameter on a non-dot segment stays allowed.
    let ok_matrix = Request::builder()
        .method(Method::GET)
        .uri("/app/items;v=2/list")
        .header(HOST, "app.example.com")
        .body(())?;
    assert!(validate_request_framing(&ok_matrix, &limits).is_ok());
    Ok(())
}

/// R7-RL-1: 70,000 requests from distinct `/64`s inside a single IPv6 `/48` MUST trigger `/48`
/// pressure aggregation (throttling the attacker's `/48`) and MUST NEVER lock out fresh IPv4 or
/// unrelated IPv6 clients!
#[test]
fn r7_rl_1_ipv6_slash48_flood_70k_does_not_lock_out_fresh_ipv4_or_ipv6_clients() {
    let limiter = GcraRateLimiter::per_ip(1, Duration::from_secs(3_600), 1);
    let headers = HeaderMap::new();
    let t0 = Instant::now();

    let mut attacker_allowed = 0_u32;
    let mut attacker_denied = 0_u32;
    for idx in 0..70_000_u32 {
        let seg3 = u16::try_from(idx & 0xFFFF).unwrap_or(0);
        let seg4 = u16::try_from((idx >> 16) & 0xFFFF).unwrap_or(0);
        let ip = IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0x0db8, 0xcafe, seg3, seg4, 0, 0, 1,
        ));
        let dec = limiter.check_request_at(Some(ip), &headers, None, t0);
        if dec.allowed {
            attacker_allowed = attacker_allowed.saturating_add(1);
        } else {
            attacker_denied = attacker_denied.saturating_add(1);
        }
    }
    // Pressure mode aggregates the attacker's /48 once occupancy crosses 50% (32,768), so the
    // remaining ~37k /64s are denied instead of filling all 65,536 slots!
    assert!(
        attacker_denied > 30_000 && attacker_allowed < 40_000,
        "R7-RL-1: IPv6 /48 pressure aggregation must throttle single-/48 flood (allowed={attacker_allowed}, denied={attacker_denied})"
    );

    // Every fresh IPv4 client MUST still be allowed (200 OK)!
    for host in 1..=100_u8 {
        let v4 = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, host));
        let dec = limiter.check_request_at(Some(v4), &headers, None, t0);
        assert!(
            dec.allowed,
            "R7-RL-1: fresh IPv4 client {v4} must NOT be locked out after IPv6 /48 flood"
        );
    }

    // Every fresh IPv6 client from OTHER /48s MUST still be allowed (200 OK)!
    for net in 1..=100_u16 {
        let v6 = IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0x0db8, net, 0x0001, 0, 0, 0, 1,
        ));
        let dec = limiter.check_request_at(Some(v6), &headers, None, t0);
        assert!(
            dec.allowed,
            "R7-RL-1: fresh IPv6 client {v6} from distinct /48 must NOT be locked out"
        );
    }
}

/// R8-RL-1: IPv6 aggregation is decided per `/48` from that `/48`'s own behaviour. Ordinary
/// traffic volume must never make unrelated `/64`s share a bucket, a rotating `/48` must be
/// collapsed after a small number of `/64`s, and the collapse must end by itself.
#[test]
fn r8_rl_1_ipv6_aggregation_is_per_slash48_and_ends_by_itself() {
    // The `wordpress-hardened` login limit: 10 per minute, burst 5.
    let limiter = GcraRateLimiter::per_ip(10, Duration::from_secs(60), 5);
    let headers = HeaderMap::new();
    let t0 = Instant::now();
    let v6 = |net: u16, sub: u16| {
        IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0x0db8, net, sub, 0, 0, 0, 1,
        ))
    };
    let burst_allowed = |ip: IpAddr, at: Instant| -> u32 {
        (0..10)
            .filter(|_| {
                limiter
                    .check_request_at(Some(ip), &headers, None, at)
                    .allowed
            })
            .count()
            .try_into()
            .unwrap_or(0)
    };

    // 1. A busy day: 40,000 distinct IPv4 visitors (more than half the table), one request each.
    for idx in 0..40_000_u32 {
        let v4 = IpAddr::V4(std::net::Ipv4Addr::from(0x0A00_0000_u32 | idx));
        let _ = limiter.check_request_at(Some(v4), &headers, None, t0);
    }
    // Two neighbours in the same /48 (different /64s) must still each get their own burst.
    let a = v6(0x00aa, 1);
    let b = v6(0x00aa, 2);
    assert_eq!(burst_allowed(a, t0), 5, "A keeps its own burst");
    assert_eq!(
        burst_allowed(b, t0),
        5,
        "R8-RL-1: B is a different /64; table occupancy alone must never merge it with A"
    );

    // 2. One /48 rotating through 5,000 /64s is collapsed to one bucket after a small number.
    let mut rotator_allowed = 0_u32;
    for sub in 0..5_000_u16 {
        if limiter
            .check_request_at(Some(v6(0xbad0, sub)), &headers, None, t0)
            .allowed
        {
            rotator_allowed = rotator_allowed.saturating_add(1);
        }
    }
    assert!(
        rotator_allowed <= 200,
        "R8-RL-1: a /48 rotating /64s must be limited as one client after ~128 /64s, but {rotator_allowed} requests were allowed"
    );
    assert!(
        rotator_allowed >= 100,
        "a /48 with only a few dozen /64s must not be collapsed early (allowed={rotator_allowed})"
    );

    // 3. That collapse is scoped to the rotating /48: a different /48 is untouched.
    let c = v6(0x00cc, 1);
    let d = v6(0x00cc, 2);
    assert_eq!(burst_allowed(c, t0), 5);
    assert_eq!(
        burst_allowed(d, t0),
        5,
        "R8-RL-1: another /48 must keep per-/64 buckets while a rotating /48 is collapsed"
    );

    // 4. It ends by itself: well after the window, two /64s of the once-rotating /48 are
    //    separate clients again.
    let later = t0 + Duration::from_secs(600);
    assert_eq!(burst_allowed(v6(0xbad0, 1), later), 5);
    assert_eq!(
        burst_allowed(v6(0xbad0, 2), later),
        5,
        "R8-RL-1: aggregation must switch off once the /48 stops rotating"
    );

    // 5. A legitimate /48 with a few dozen active /64s is never collapsed.
    for sub in 0..60_u16 {
        assert!(
            limiter
                .check_request_at(Some(v6(0x0ca5, sub)), &headers, None, later)
                .allowed,
            "R8-RL-1: /64 number {sub} of a modest /48 must get its own bucket"
        );
    }
}

/// R7-RL-1 (eviction fallback) / R8-RL-2: a full table must never lock out a fresh client, even
/// when every tracked bucket is currently throttled.
#[test]
fn r8_rl_2_full_table_of_throttled_buckets_still_admits_a_fresh_client() {
    let limiter = GcraRateLimiter::per_ip(1, Duration::from_secs(3_600), 1);
    let headers = HeaderMap::new();
    let t0 = Instant::now();
    // 80,000 distinct IPv4 clients each spend their only request: more than the 65,536 slots.
    for idx in 0..80_000_u32 {
        let v4 = IpAddr::V4(std::net::Ipv4Addr::from(0x0B00_0000_u32 | idx));
        let _ = limiter.check_request_at(Some(v4), &headers, None, t0);
    }
    for host in 1..=50_u8 {
        let fresh = IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, host));
        assert!(
            limiter
                .check_request_at(Some(fresh), &headers, None, t0)
                .allowed,
            "a fresh client must be admitted by evicting an old bucket, not denied ({fresh})"
        );
    }
}

/// The target's authority is validated without a Host header too, as HTTP/2 and HTTP/3 send
/// it (Cloudflare-skills audit of v0.1.0, claim 1): no userinfo, a numeric port, and HTTP/1.1
/// always needs Host.
#[test]
fn the_request_authority_is_validated_without_a_host_header() -> TestResult {
    let limits = miraserve_config::LimitsConfig::default();
    let h2 = |uri: &str| {
        http::Request::builder()
            .version(http::Version::HTTP_2)
            .uri(uri)
            .body(())
            .map(|req| validate_request_framing(&req, &limits).map_err(|rej| rej.rule))
    };
    assert_eq!(h2("https://site.example.test/")?, Ok(()));
    assert_eq!(h2("https://site.example.test:8443/")?, Ok(()));
    assert_eq!(h2("https://[::1]:8443/")?, Ok(()));
    // The longest DNS name the configuration accepts, with a port (Codex 70 finding 14).
    let label = "a".repeat(61);
    let longest = format!("{label}.{label}.{label}.{label}.examp");
    assert_eq!(longest.len(), 253);
    assert_eq!(h2(&format!("https://{longest}:8443/"))?, Ok(()));
    assert_eq!(h2(&format!("https://{longest}:000443/"))?, Ok(()));
    // Also written with its final root dot, alone and with a port (Codex 87).
    assert_eq!(h2(&format!("https://{longest}./"))?, Ok(()));
    assert_eq!(h2(&format!("https://{longest}.:8443/"))?, Ok(()));
    let padded = "0".repeat(300);
    assert_eq!(h2(&format!("https://{longest}:{padded}443/"))?, Ok(()));
    for bad in [
        "https://evil.test:443@site.example.test/",
        "https://user@site.example.test/",
        "https://[::1]:+443/",
    ] {
        // Some of these the URI parser refuses itself, which is as good.
        if let Ok(outcome) = h2(bad) {
            assert_eq!(outcome, Err("INVALID_AUTHORITY"), "{bad}");
        }
    }
    let absolute_form = http::Request::builder()
        .version(http::Version::HTTP_11)
        .uri("http://site.example.test/")
        .body(())?;
    assert_eq!(
        validate_request_framing(&absolute_form, &limits).map_err(|rej| rej.rule),
        Err("MISSING_HOST")
    );
    Ok(())
}

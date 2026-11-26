//! Regression tests for access-log clock sampling parity with v0.1.2 (Codex Diet Audit 2 P1 #3):
//!
//! 1. `latency_us` (and the HTTP request latency telemetry metric) must cover the pre-dispatch
//!    access-log redaction work, rather than sampling `started.elapsed()` before redaction runs.
//! 2. On the direct `ACCESS_LOG_SINK` path, the RFC 3339 wall-clock timestamp must be sampled
//!    BEFORE the `tracing::enabled!` subscriber check, matching v0.1.2.
//!
//! Kept in its own integration-test binary so installing the process-global `ACCESS_LOG_SINK`
//! never affects other test binaries.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use http::{Method, Request};
use http_body_util::BodyExt as _;
use miraserve_config::parse_kdl;
use miraserve_http::{HttpEngine, RequestContext, empty_http_body, set_access_log_sink};
use miraserve_telemetry::redact::redact_uri_query;
use miraserve_tls::AcmeChallengeStore;

type TestResult = Result<(), Box<dyn std::error::Error>>;

static SINK_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static SINK_LINES: OnceLock<Arc<Mutex<Vec<String>>>> = OnceLock::new();

fn install_shared_sink() -> Arc<Mutex<Vec<String>>> {
    let lines = SINK_LINES
        .get_or_init(|| {
            let store = Arc::new(Mutex::new(Vec::new()));
            let store_cb = Arc::clone(&store);
            let installed = set_access_log_sink(Box::new(move |bytes: &[u8]| {
                if let Ok(mut guard) = store_cb.lock() {
                    guard.push(String::from_utf8_lossy(bytes).into_owned());
                }
            }));
            assert!(
                installed,
                "access_log_clock_tests must own the process-global ACCESS_LOG_SINK"
            );
            store
        })
        .clone();
    if let Ok(mut guard) = lines.lock() {
        guard.clear();
    }
    lines
}

fn test_engine() -> Result<HttpEngine, Box<dyn std::error::Error>> {
    let kdl = r#"
server {
    listen ":8443"
    tls { cert "/c.pem"; key "/k.pem" }
    limits {
        max-header-bytes "1MiB"
    }
}
site "clock.example.test" {
    route "/go" { redirect "/dest" }
}
"#;
    let (cfg, _) = parse_kdl("clock.kdl", kdl)?;
    assert!(cfg.server.telemetry.redact_logs);
    Ok(HttpEngine::from_config(
        &cfg,
        Arc::new(AcmeChallengeStore::new()),
        None,
        8443,
    )?)
}

fn test_ctx() -> RequestContext {
    RequestContext {
        client_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77))),
        remote_port: Some(41_234),
        server_addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        server_port: 8443,
        is_https: true,
        tls: None,
    }
}

fn unix_micros(ts: SystemTime) -> Result<u128, Box<dyn std::error::Error>> {
    Ok(ts.duration_since(UNIX_EPOCH)?.as_micros())
}

fn parse_rfc3339_micros(ts: &str) -> Result<u128, Box<dyn std::error::Error>> {
    let ts = ts.strip_suffix('Z').ok_or("missing Z suffix")?;
    let (date, time) = ts.split_once('T').ok_or("missing T separator")?;
    let mut dp = date.split('-');
    let y: i64 = dp.next().ok_or("missing year")?.parse()?;
    let m: u32 = dp.next().ok_or("missing month")?.parse()?;
    let d: u32 = dp.next().ok_or("missing day")?.parse()?;
    let (hms, frac) = time.split_once('.').ok_or("missing fractional seconds")?;
    if frac.len() != 6 {
        return Err(format!("expected 6 microsecond digits, got {frac:?}").into());
    }
    let mut tp = hms.split(':');
    let hh: u64 = tp.next().ok_or("missing hour")?.parse()?;
    let mm: u64 = tp.next().ok_or("missing minute")?.parse()?;
    let ss: u64 = tp.next().ok_or("missing second")?.parse()?;
    let us: u64 = frac.parse()?;

    // Inverse of H. Hinnant's civil-from-days algorithm used in `push_rfc3339_micros`.
    let y_adj = y - i64::from(m <= 2);
    let era = y_adj.div_euclid(400);
    let yoe = u64::try_from(y_adj.rem_euclid(400))?;
    let mp = u64::from(if m > 2 { m - 3 } else { m + 9 });
    let doy = (153 * mp + 2) / 5 + u64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + i64::try_from(doe)? - 719_468;
    let secs = u128::try_from(days)? * 86_400 + u128::from(hh * 3_600 + mm * 60 + ss);
    Ok(secs * 1_000_000 + u128::from(us))
}

#[derive(Clone)]
struct SpinOnEnableSubscriber {
    enabled_calls: Arc<AtomicUsize>,
    enter_us: Arc<Mutex<Option<u128>>>,
    exit_us: Arc<Mutex<Option<u128>>>,
    advance_us: u128,
}

impl tracing::Subscriber for SpinOnEnableSubscriber {
    fn register_callsite(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if metadata.target() == "miraserve::access" {
            tracing::subscriber::Interest::sometimes()
        } else {
            tracing::subscriber::Interest::never()
        }
    }

    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        if metadata.target() != "miraserve::access" {
            return false;
        }
        self.enabled_calls.fetch_add(1, Ordering::AcqRel);
        let Ok(enter) = unix_micros(SystemTime::now()) else {
            return true;
        };
        if let Ok(mut guard) = self.enter_us.lock()
            && guard.is_none()
        {
            *guard = Some(enter);
        }
        // Advance the wall clock strictly without calling `thread::sleep`, with a monotonic guard
        // so a frozen clock cannot spin indefinitely.
        let deadline = Instant::now() + Duration::from_millis(50);
        let mut exit = enter;
        while exit < enter.saturating_add(self.advance_us) && Instant::now() < deadline {
            std::hint::spin_loop();
            if let Ok(now) = unix_micros(SystemTime::now()) {
                exit = now;
            }
        }
        if let Ok(mut guard) = self.exit_us.lock() {
            *guard = Some(exit);
        }
        true
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, _event: &tracing::Event<'_>) {}

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

/// Regression test for Diet Audit 2 P1 #3 (part 1): `latency_us` must cover the redaction work
/// performed on request metadata before dispatch, matching v0.1.2.
///
/// Calibrates a redactable `Referer` query string with pure CPU work (no sleeps) so its true
/// minimum redaction cost is several milliseconds, then verifies the emitted `latency_us`
/// includes that redaction work instead of sampling `started.elapsed()` before redaction.
#[tokio::test(flavor = "current_thread")]
async fn access_log_latency_us_covers_redaction_work() -> TestResult {
    let _serial = SINK_SERIAL.lock().await;
    let lines = install_shared_sink();
    let engine = test_engine()?;
    let ctx = test_ctx();

    // Size a percent-encoded query-bearing Referer until the minimum of 3 direct redactions
    // takes at least 5 ms of real CPU (works identically in debug and release builds, no sleep).
    let mut pairs = 512_usize;
    let (referer, min_redact_us) = loop {
        let mut s = String::from("https://ref.example/p?");
        for _ in 0..pairs {
            s.push_str("k%31=v%31&token=secret123&");
        }
        let mut min_dur = Duration::MAX;
        for _ in 0..3 {
            let start = Instant::now();
            let redacted = std::hint::black_box(redact_uri_query(std::hint::black_box(&s)));
            let dur = start.elapsed();
            assert!(!redacted.contains("secret123"));
            min_dur = min_dur.min(dur);
        }
        let min_us = u64::try_from(min_dur.as_micros()).unwrap_or(u64::MAX);
        if min_us >= 5_000 || s.len() >= 512 * 1024 {
            break (s, min_us);
        }
        pairs = pairs.saturating_mul(2);
    };
    assert!(
        min_redact_us >= 2_000,
        "expected calibrated redaction work >= 2000 us, got {min_redact_us} us"
    );

    let info_sub = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::sink)
        .finish();
    let _guard = tracing::subscriber::set_default(info_sub);

    // Warm up one-time lazy initializers (PRNG / tracing callsite) on a plain request first so
    // the measured request reflects only per-request work.
    let warmup_req = Request::builder()
        .method(Method::GET)
        .uri("/go?q=ok")
        .header(http::header::HOST, "clock.example.test")
        .body(empty_http_body())?;
    let warmup_resp = engine.handle_request(warmup_req, &ctx).await;
    assert_eq!(warmup_resp.status(), http::StatusCode::MOVED_PERMANENTLY);
    let _ = warmup_resp.into_body().collect().await?;
    if let Ok(mut guard) = lines.lock() {
        guard.clear();
    }

    let req = Request::builder()
        .method(Method::GET)
        .uri("/go?q=ok")
        .header(http::header::HOST, "clock.example.test")
        .header(http::header::REFERER, &referer)
        .body(empty_http_body())?;

    let resp = engine.handle_request(req, &ctx).await;
    assert_eq!(
        resp.status(),
        http::StatusCode::MOVED_PERMANENTLY,
        "large Referer must still fit within max-header-bytes and hit the fast 301 route"
    );
    let _ = resp.into_body().collect().await?;

    let captured = lines.lock().map_err(|_| "lines lock poisoned")?.clone();
    assert_eq!(
        captured.len(),
        1,
        "expected exactly one direct-sink access log line, got {}",
        captured.len()
    );
    let line = captured.first().map_or("", String::as_str);
    assert!(
        line.contains("token=[REDACTED]") && !line.contains("secret123"),
        "expected redacted referer in access log line"
    );
    let latency_us: u64 = line
        .split(" latency_us=")
        .nth(1)
        .and_then(|rest| rest.split(' ').next())
        .ok_or("missing latency_us field")?
        .parse()?;

    assert!(
        latency_us.saturating_mul(2) >= min_redact_us,
        "latency_us={latency_us} did not cover redaction work (calibrated min_redact_us={min_redact_us})"
    );
    Ok(())
}

/// Regression test for Diet Audit 2 P1 #3 (part 2): on the direct `ACCESS_LOG_SINK` path,
/// `SystemTime::now()` must be sampled BEFORE `tracing::enabled!` runs, matching v0.1.2.
#[tokio::test(flavor = "current_thread")]
async fn direct_access_log_timestamp_is_sampled_before_enablement_check() -> TestResult {
    let _serial = SINK_SERIAL.lock().await;
    let lines = install_shared_sink();
    let engine = test_engine()?;
    let ctx = test_ctx();

    let enabled_calls = Arc::new(AtomicUsize::new(0));
    let enter_us = Arc::new(Mutex::new(None));
    let exit_us = Arc::new(Mutex::new(None));
    let sub = SpinOnEnableSubscriber {
        enabled_calls: Arc::clone(&enabled_calls),
        enter_us: Arc::clone(&enter_us),
        exit_us: Arc::clone(&exit_us),
        advance_us: 250,
    };

    let req = Request::builder()
        .method(Method::GET)
        .uri("/go?q=ok")
        .header(http::header::HOST, "clock.example.test")
        .body(empty_http_body())?;

    let _guard = tracing::subscriber::set_default(sub);
    let resp = engine.handle_request(req, &ctx).await;
    let _ = resp.into_body().collect().await?;

    let captured = lines.lock().map_err(|_| "lines lock poisoned")?.clone();
    assert_eq!(
        captured.len(),
        1,
        "expected 1 direct-sink access log line, got {captured:?}"
    );
    assert!(
        enabled_calls.load(Ordering::Acquire) >= 1,
        "expected at least one subscriber enabled() check on the direct-sink path"
    );

    let line = captured.first().map_or("", String::as_str);
    let ts_prefix = line
        .split_whitespace()
        .next()
        .ok_or("missing RFC 3339 timestamp prefix")?;
    let logged_us = parse_rfc3339_micros(ts_prefix)?;
    let entered = enter_us
        .lock()
        .map_err(|_| "enter_us lock poisoned")?
        .ok_or("enabled() did not record enter timestamp")?;
    let exited = exit_us
        .lock()
        .map_err(|_| "exit_us lock poisoned")?
        .ok_or("enabled() did not record exit timestamp")?;

    assert!(
        exited >= entered.saturating_add(250),
        "wall clock did not advance during enabled() check: entered={entered}, exited={exited}"
    );
    assert!(
        logged_us <= entered && logged_us < exited,
        "access-log timestamp ({ts_prefix} = {logged_us} us) must be sampled BEFORE tracing::enabled! (entered={entered} us, exited={exited} us)"
    );
    Ok(())
}

//! `R8-HTTP-1`: the slow-reader write guard must cut clients that are below the minimum rate
//! without cutting slow but steady clients that are above it.
//!
//! The kernel wakes a blocked writer only after a large part of its send buffer has drained, so
//! a steady reader shows up as bursts of accepted bytes separated by long gaps. `BurstyKernel`
//! models exactly that, which makes the tests independent of any one OS's socket-buffer policy.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use miraserve_http::WriteGuardedIo;
use tokio::io::{AsyncWrite, AsyncWriteExt};

const MIN_RATE_BPS: u64 = 100_000;
const WRITE_IDLE: Duration = Duration::from_millis(200);
const RATE_GRACE: Duration = Duration::from_millis(100);
const SEND_BUFFER: usize = 64_000;

/// One phase of a simulated reader: every `interval` the kernel accepts up to `burst` bytes.
#[derive(Clone, Copy)]
struct Phase {
    lasts: Duration,
    interval: Duration,
    burst: usize,
}

/// A socket whose kernel buffer frees `burst` bytes every `interval`, then (after all phases)
/// never again.
struct BurstyKernel {
    started: Instant,
    phases: Vec<Phase>,
    next_ready: Instant,
    waker_timer: Option<Pin<Box<tokio::time::Sleep>>>,
    /// Bytes of the current burst the kernel can still accept.
    burst_left: usize,
}

impl BurstyKernel {
    fn new(phases: Vec<Phase>) -> Self {
        let now = Instant::now();
        Self {
            started: now,
            phases,
            next_ready: now,
            waker_timer: None,
            burst_left: 0,
        }
    }

    fn current_phase(&self, now: Instant) -> Option<Phase> {
        let mut elapsed = now.saturating_duration_since(self.started);
        for phase in &self.phases {
            if elapsed < phase.lasts {
                return Some(*phase);
            }
            elapsed = elapsed.saturating_sub(phase.lasts);
        }
        None
    }
}

impl AsyncWrite for BurstyKernel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let now = Instant::now();
        let Some(phase) = this.current_phase(now) else {
            // The reader has stopped for good. Only the guard's own timer can end this.
            return Poll::Pending;
        };
        if now >= this.next_ready {
            // The reader drained the buffer: a new burst of space is available.
            this.next_ready = now + phase.interval;
            this.waker_timer = None;
            this.burst_left = phase.burst;
        }
        if this.burst_left > 0 {
            let n = buf.len().min(this.burst_left);
            this.burst_left = this.burst_left.saturating_sub(n);
            return Poll::Ready(Ok(n));
        }
        let mut timer = Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(
            this.next_ready,
        )));
        let _ = timer.as_mut().poll(cx);
        this.waker_timer = Some(timer);
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn guarded(phases: Vec<Phase>) -> WriteGuardedIo<BurstyKernel> {
    WriteGuardedIo::new(BurstyKernel::new(phases), WRITE_IDLE, MIN_RATE_BPS)
        .with_rate_grace(RATE_GRACE)
        .with_send_buffer_probe(Box::new(|_: &BurstyKernel| Some(SEND_BUFFER)))
}

/// Writes as fast as the guard allows until it errors or `run_for` elapses. Returns how long
/// the connection lived and the error that ended it, if any.
async fn pump(
    mut io: WriteGuardedIo<BurstyKernel>,
    run_for: Duration,
) -> (Duration, Option<io::Error>) {
    let chunk = vec![0_u8; 8 * 1024];
    let started = Instant::now();
    let outcome = tokio::time::timeout(run_for, async {
        loop {
            if let Err(err) = io.write_all(&chunk).await {
                return err;
            }
        }
    })
    .await;
    (started.elapsed(), outcome.ok())
}

const FOREVER: Duration = Duration::from_secs(3600);

macro_rules! dual_runtime_test {
    ($name:ident, $mt_name:ident, $body:path) => {
        #[tokio::test(flavor = "current_thread")]
        async fn $name() {
            $body().await;
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $mt_name() {
            $body().await;
        }
    };
    ($name:ident, $mt_name:ident, $body:path, -> $ret:ty) => {
        #[tokio::test(flavor = "current_thread")]
        async fn $name() -> $ret {
            $body().await
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $mt_name() -> $ret {
            $body().await
        }
    };
}

async fn r8_http_1_steady_reader_above_min_rate_survives_long_gaps_between_kernel_writes_impl() {
    // 60 kB every 400 ms = 150 kB/s, 1.5x the minimum, but each gap is twice `WRITE_IDLE`.
    let io = guarded(vec![Phase {
        lasts: FOREVER,
        interval: Duration::from_millis(400),
        burst: 60_000,
    }]);
    let (lived, err) = pump(io, Duration::from_secs(3)).await;
    assert!(
        err.is_none(),
        "R8-HTTP-1: a reader at 1.5x min-response-rate-bps must not be cut, but was after {lived:?}: {err:?}"
    );
}

dual_runtime_test!(
    r8_http_1_steady_reader_above_min_rate_survives_long_gaps_between_kernel_writes,
    r8_http_1_steady_reader_above_min_rate_survives_long_gaps_between_kernel_writes_multi_thread,
    r8_http_1_steady_reader_above_min_rate_survives_long_gaps_between_kernel_writes_impl
);

/// Review 12, finding 9: a receiver reopens its window in steps, so even a steady reader is
/// silent between lumps, and the lump size is the client's choice. Here the kernel allowance is
/// tiny (1 kB, as with a bounded unsent queue) and the reader takes 16 kB every 150 ms, just
/// above the minimum rate: before each lump it is 15 kB behind, far more than the kernel
/// allowance. Every silence is shorter than `WRITE_IDLE`, so it must not be cut.
/// How late short timer sleeps run on this machine right now (the worst of five 10 ms sleeps).
/// The tests below use real time; on a heavily loaded machine the simulated reader cannot keep
/// the rate it is meant to have, so a "must not be cut" test would measure the machine.
async fn timer_lateness() -> Duration {
    let mut worst = Duration::ZERO;
    for _ in 0..5 {
        let started = Instant::now();
        tokio::time::sleep(Duration::from_millis(10)).await;
        worst = worst.max(started.elapsed().saturating_sub(Duration::from_millis(10)));
    }
    worst
}

async fn review12_steady_reader_at_the_minimum_rate_survives_lumps_larger_than_the_kernel_allowance_impl()
 {
    let lateness = timer_lateness().await;
    if lateness > Duration::from_millis(15) {
        eprintln!(
            "skipped: timers run {lateness:?} late, so the reader cannot hold the minimum rate this test needs"
        );
        return;
    }
    let io = WriteGuardedIo::new(
        BurstyKernel::new(vec![Phase {
            lasts: FOREVER,
            interval: Duration::from_millis(150),
            burst: 16_000,
        }]),
        WRITE_IDLE,
        MIN_RATE_BPS,
    )
    .with_rate_grace(RATE_GRACE)
    .with_send_buffer_probe(Box::new(|_: &BurstyKernel| Some(1_000)));
    let (lived, err) = pump(io, Duration::from_secs(4)).await;
    assert!(
        err.is_none(),
        "a reader at the minimum rate whose silences stay below write-idle must not be cut, but was after {lived:?}: {err:?}"
    );
}

dual_runtime_test!(
    review12_steady_reader_at_the_minimum_rate_survives_lumps_larger_than_the_kernel_allowance,
    review12_steady_reader_at_the_minimum_rate_survives_lumps_larger_than_the_kernel_allowance_multi_thread,
    review12_steady_reader_at_the_minimum_rate_survives_lumps_larger_than_the_kernel_allowance_impl
);

/// The same lumps at half the size (53 kB/s, about half the minimum rate) must still be cut.
async fn review12_reader_below_the_minimum_rate_is_still_cut_with_a_small_kernel_allowance_impl()
-> Result<(), String> {
    let io = WriteGuardedIo::new(
        BurstyKernel::new(vec![Phase {
            lasts: FOREVER,
            interval: Duration::from_millis(150),
            burst: 8_000,
        }]),
        WRITE_IDLE,
        MIN_RATE_BPS,
    )
    .with_rate_grace(RATE_GRACE)
    .with_send_buffer_probe(Box::new(|_: &BurstyKernel| Some(1_000)));
    let (lived, err) = pump(io, Duration::from_secs(8)).await;
    let err = err.ok_or_else(|| "a reader at half the minimum rate must be cut".to_owned())?;
    assert!(
        err.to_string().contains("min-response-rate-bps"),
        "the rate rule must be what cuts it: {err}"
    );
    assert!(
        lived <= Duration::from_secs(3),
        "the allowance (21 kB) is used up after about 0.5 s, got {lived:?}"
    );
    Ok(())
}

dual_runtime_test!(
    review12_reader_below_the_minimum_rate_is_still_cut_with_a_small_kernel_allowance,
    review12_reader_below_the_minimum_rate_is_still_cut_with_a_small_kernel_allowance_multi_thread,
    review12_reader_below_the_minimum_rate_is_still_cut_with_a_small_kernel_allowance_impl,
    -> Result<(), String>
);

async fn r8_http_1_reader_that_stops_is_cut_after_idle_plus_one_send_buffer_impl()
-> Result<(), String> {
    // One burst, then nothing. Expected cut: WRITE_IDLE + SEND_BUFFER / MIN_RATE = 0.84 s.
    let io = guarded(vec![Phase {
        lasts: Duration::from_millis(50),
        interval: Duration::from_millis(400),
        burst: 60_000,
    }]);
    let (lived, err) = pump(io, Duration::from_secs(5)).await;
    let err = err.ok_or_else(|| "R8-HTTP-1: a reader that stops reading must be cut".to_owned())?;
    assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
    assert!(
        lived >= Duration::from_millis(600) && lived <= Duration::from_secs(3),
        "expected the cut near 0.84 s (idle limit + one send buffer), got {lived:?}"
    );
    Ok(())
}

dual_runtime_test!(
    r8_http_1_reader_that_stops_is_cut_after_idle_plus_one_send_buffer,
    r8_http_1_reader_that_stops_is_cut_after_idle_plus_one_send_buffer_multi_thread,
    r8_http_1_reader_that_stops_is_cut_after_idle_plus_one_send_buffer_impl,
    -> Result<(), String>
);

async fn r8_http_1_reader_below_min_rate_is_cut_and_allowance_is_granted_only_once_impl()
-> Result<(), String> {
    // 20 kB every 400 ms = 50 kB/s, half the minimum. Every gap is inside the idle limit, so
    // only the rate rule can end this, and it must: the allowance (one 64 kB buffer plus
    // WRITE_IDLE worth of data, 20 kB) is used up after about 1.7 s of a 50 kB/s shortfall. If
    // the allowance were granted afresh at every check this reader would never be cut.
    let io = guarded(vec![Phase {
        lasts: FOREVER,
        interval: Duration::from_millis(400),
        burst: 20_000,
    }]);
    let (lived, err) = pump(io, Duration::from_secs(8)).await;
    let err =
        err.ok_or_else(|| "R8-HTTP-1: a reader at half the minimum rate must be cut".to_owned())?;
    assert!(
        err.to_string().contains("min-response-rate-bps"),
        "the rate rule must be what cuts it: {err}"
    );
    assert!(
        lived >= Duration::from_millis(700) && lived <= Duration::from_secs(6),
        "expected the cut after the allowance runs out (about 1.3 s to 3 s), got {lived:?}"
    );
    Ok(())
}

dual_runtime_test!(
    r8_http_1_reader_below_min_rate_is_cut_and_allowance_is_granted_only_once,
    r8_http_1_reader_below_min_rate_is_cut_and_allowance_is_granted_only_once_multi_thread,
    r8_http_1_reader_below_min_rate_is_cut_and_allowance_is_granted_only_once_impl,
    -> Result<(), String>
);

/// A fast start buys silence, but only up to the capped lead (1 MiB): at 1 MB/s minimum a
/// client that took 6 MB in 2 s and then trickles one byte at a time is cut about 1 s into the
/// trickle (1 MiB / 1 MB/s), not after the 4 s its full lead would have bought.
async fn r8_http_1_fast_start_buys_at_most_the_capped_lead_impl() -> Result<(), String> {
    let fast = Duration::from_secs(2);
    let io = WriteGuardedIo::new(
        BurstyKernel::new(vec![
            Phase {
                lasts: fast,
                interval: Duration::from_millis(100),
                burst: 300_000,
            },
            Phase {
                lasts: FOREVER,
                interval: Duration::from_millis(150),
                burst: 1,
            },
        ]),
        WRITE_IDLE,
        1_000_000,
    )
    .with_rate_grace(RATE_GRACE)
    .with_send_buffer_probe(Box::new(|_: &BurstyKernel| Some(SEND_BUFFER)));
    let (lived, err) = pump(io, Duration::from_secs(12)).await;
    let err = err.ok_or_else(|| "a trickling reader must be cut".to_owned())?;
    assert!(
        err.to_string().contains("min-response-rate-bps"),
        "the rate rule must be what cuts it: {err}"
    );
    let into_trickle = lived.saturating_sub(fast);
    assert!(
        lived > fast && into_trickle <= Duration::from_millis(2_500),
        "expected the cut about 1 s into the trickle (capped lead), got {into_trickle:?}"
    );
    Ok(())
}

dual_runtime_test!(
    r8_http_1_fast_start_buys_at_most_the_capped_lead,
    r8_http_1_fast_start_buys_at_most_the_capped_lead_multi_thread,
    r8_http_1_fast_start_buys_at_most_the_capped_lead_impl,
    -> Result<(), String>
);

/// Regression test: an HTTP/2 reader that buffers a large lead ahead of what it has drained and
/// then leaves its window closed longer than `response-write-idle` while still reading must not be
/// cut. Scaled parameters: minimum 100 kB/s, a reader at 150 kB/s that first takes 400 kB in one
/// go, then gets 300 kB every 2 s (silences of 2 s, ten times `WRITE_IDLE`). It is never behind
/// the minimum rate and must not be cut.
async fn review_round6_reader_spending_its_lead_through_long_silences_is_not_cut_impl() {
    let io = WriteGuardedIo::new(
        BurstyKernel::new(vec![
            Phase {
                lasts: Duration::from_millis(50),
                interval: Duration::from_millis(400),
                burst: 400_000,
            },
            Phase {
                lasts: FOREVER,
                interval: Duration::from_secs(2),
                burst: 300_000,
            },
        ]),
        WRITE_IDLE,
        MIN_RATE_BPS,
    )
    .with_rate_grace(RATE_GRACE)
    .with_send_buffer_probe(Box::new(|_: &BurstyKernel| Some(32_768)));
    let (lived, err) = pump(io, Duration::from_secs(9)).await;
    assert!(
        err.is_none(),
        "a reader ahead of the minimum rate spends its lead in silence; cut after {lived:?}: {err:?}"
    );
}

dual_runtime_test!(
    review_round6_reader_spending_its_lead_through_long_silences_is_not_cut,
    review_round6_reader_spending_its_lead_through_long_silences_is_not_cut_multi_thread,
    review_round6_reader_spending_its_lead_through_long_silences_is_not_cut_impl
);

async fn r8_http_1_real_tcp_socket_reports_a_send_buffer_allowance_impl() -> io::Result<()> {
    // `for_tcp_stream` is what the listener uses. It must read a live, non-zero SO_SNDBUF, or
    // the guard silently degrades to the no-allowance behaviour that cut legitimate readers.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let client = tokio::net::TcpStream::connect(addr).await?;
    let (server, _) = listener.accept().await?;
    let reported = socket2::SockRef::from(&server).send_buffer_size()?;
    assert!(reported > 0, "SO_SNDBUF must be readable on this platform");

    let mut guarded = WriteGuardedIo::for_tcp_stream(server, Duration::from_secs(30), 1_024);
    guarded.write_all(b"hello").await?;
    guarded.flush().await?;
    drop(client);
    Ok(())
}

dual_runtime_test!(
    r8_http_1_real_tcp_socket_reports_a_send_buffer_allowance,
    r8_http_1_real_tcp_socket_reports_a_send_buffer_allowance_multi_thread,
    r8_http_1_real_tcp_socket_reports_a_send_buffer_allowance_impl,
    -> io::Result<()>
);

/// Regression test: an HTTP/1.1 client that stopped reading a large download remained connected
/// far past `write-idle` when the allowance followed the kernel's autotuned send buffer.
/// On Linux `for_tcp_stream` bounds the unsent queue (`TCP_NOTSENT_LOWAT`, 32 KiB), so the cut
/// comes at `write-idle + 32 KiB / min-rate` whatever the send buffer is: here 1 s + 0.5 s.
#[cfg(target_os = "linux")]
async fn real_socket_reader_that_stops_is_cut_on_a_fixed_schedule_impl() -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    // The client connects and never reads.
    let client = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| e.to_string())?;
    let (server, _) = listener.accept().await.map_err(|e| e.to_string())?;
    // A large send buffer, as the kernel would grow it during a big download.
    let _ = socket2::SockRef::from(&server).set_send_buffer_size(4 * 1024 * 1024);
    let lowat = {
        let guarded = WriteGuardedIo::for_tcp_stream(server, Duration::from_secs(1), 65_536);
        let lowat = socket2::SockRef::from(guarded.get_ref())
            .tcp_notsent_lowat()
            .map_err(|e| e.to_string())?;
        assert_eq!(
            lowat,
            32 * 1024,
            "for_tcp_stream must bound the unsent queue"
        );
        let mut guarded = guarded;
        let chunk = vec![0_u8; 16 * 1024];
        let started = Instant::now();
        let outcome = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Err(err) = guarded.write_all(&chunk).await {
                    return err;
                }
            }
        })
        .await;
        let lived = started.elapsed();
        let err = outcome.map_err(|_| {
            "a reader that never reads must be cut well inside 20 s, whatever the send buffer"
                .to_owned()
        })?;
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
        assert!(
            lived >= Duration::from_millis(900) && lived <= Duration::from_secs(8),
            "expected the cut near 1.5 s (idle limit + 32 KiB at 64 KiB/s), got {lived:?}"
        );
        lowat
    };
    let _ = lowat;
    drop(client);
    Ok(())
}

#[cfg(target_os = "linux")]
dual_runtime_test!(
    real_socket_reader_that_stops_is_cut_on_a_fixed_schedule,
    real_socket_reader_that_stops_is_cut_on_a_fixed_schedule_multi_thread,
    real_socket_reader_that_stops_is_cut_on_a_fixed_schedule_impl,
    -> Result<(), String>
);

/// Review of section 4e: the lead is capped at 1 MiB also when the minimum rate times
/// `response-write-idle` is larger. Minimum 1 MB/s, idle 2 s (2 MB): a client that takes 5 MB in
/// one second and then stops is cut after about 2 s + (64 kB + 1 MiB) / 1 MB/s = 3.1 s of
/// silence, not after the 4 s an uncapped 2 MB lead would buy.
async fn review_4e_silence_credit_is_capped_at_one_mib_impl() -> Result<(), String> {
    let fast = Duration::from_secs(1);
    let io = WriteGuardedIo::new(
        BurstyKernel::new(vec![Phase {
            lasts: fast,
            interval: Duration::from_millis(100),
            burst: 500_000,
        }]),
        Duration::from_secs(2),
        1_000_000,
    )
    .with_rate_grace(RATE_GRACE)
    .with_send_buffer_probe(Box::new(|_: &BurstyKernel| Some(SEND_BUFFER)));
    let (lived, err) = pump(io, Duration::from_secs(10)).await;
    let err = err.ok_or_else(|| "a reader that stops must be cut".to_owned())?;
    assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
    let silence = lived.saturating_sub(fast);
    assert!(
        silence <= Duration::from_millis(3_600),
        "silence credit must stop at 1 MiB: cut after {silence:?} of silence"
    );
    Ok(())
}

dual_runtime_test!(
    review_4e_silence_credit_is_capped_at_one_mib,
    review_4e_silence_credit_is_capped_at_one_mib_multi_thread,
    review_4e_silence_credit_is_capped_at_one_mib_impl,
    -> Result<(), String>
);

/// Review of section 4e: a burst taken before the first blocked write counts. A fresh
/// connection puts 400 kB into the client's buffers at once; the client reads at 150 kB/s, so
/// the window first reopens after 2.5 s, far beyond the base allowance (0.2 s + 64 kB at
/// 100 kB/s = 0.84 s) but within the burst's lead. It must not be cut.
async fn review_4e_burst_before_the_first_blocked_write_counts_as_lead_impl() {
    let io = WriteGuardedIo::new(
        BurstyKernel::new(vec![
            Phase {
                lasts: Duration::from_millis(50),
                interval: Duration::from_millis(2_500),
                burst: 400_000,
            },
            Phase {
                lasts: FOREVER,
                interval: Duration::from_secs(2),
                burst: 300_000,
            },
        ]),
        WRITE_IDLE,
        MIN_RATE_BPS,
    )
    .with_rate_grace(RATE_GRACE)
    .with_send_buffer_probe(Box::new(|_: &BurstyKernel| Some(SEND_BUFFER)));
    let (lived, err) = pump(io, Duration::from_secs(8)).await;
    assert!(
        err.is_none(),
        "the first burst is lead the first wait may spend; cut after {lived:?}: {err:?}"
    );
}
#[tokio::test]
async fn record_write_progress_skips_clock_when_idle_flush_or_zero_min_rate_and_preserves_enforcement()
-> Result<(), String> {
    // 1. min_response_rate_bps == 0: unblocked writes and flushes succeed without backpressure,
    //    and once the kernel blocks, write_idle_timeout still cuts the connection on schedule.
    let mut zero_rate = WriteGuardedIo::new(
        BurstyKernel::new(vec![Phase {
            lasts: Duration::from_millis(50),
            interval: Duration::from_millis(400),
            burst: 32_768,
        }]),
        WRITE_IDLE,
        0,
    );
    zero_rate
        .write_all(&[b'z'; 4096])
        .await
        .map_err(|e| format!("initial unblocked write failed: {e}"))?;
    zero_rate
        .flush()
        .await
        .map_err(|e| format!("initial unblocked flush failed: {e}"))?;
    let (lived, err) = pump(zero_rate, Duration::from_secs(3)).await;
    let err = err.ok_or_else(|| "stopped reader with min_rate=0 must still be cut".to_owned())?;
    assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
    assert!(
        lived >= WRITE_IDLE && lived <= Duration::from_secs(2),
        "expected write-idle cut near {WRITE_IDLE:?}, got {lived:?}"
    );

    // 2. min_response_rate_bps > 0: unblocked flushes between writes do not clear or corrupt
    //    the pre-backpressure burst lead.
    let mut burst_then_flush = WriteGuardedIo::new(
        BurstyKernel::new(vec![
            Phase {
                lasts: Duration::from_millis(50),
                interval: Duration::from_millis(2_500),
                burst: 400_000,
            },
            Phase {
                lasts: FOREVER,
                interval: Duration::from_secs(2),
                burst: 300_000,
            },
        ]),
        WRITE_IDLE,
        MIN_RATE_BPS,
    )
    .with_rate_grace(RATE_GRACE)
    .with_send_buffer_probe(Box::new(|_: &BurstyKernel| Some(SEND_BUFFER)));
    let burst_payload = vec![b'b'; 65_536];
    burst_then_flush
        .write_all(&burst_payload)
        .await
        .map_err(|e| format!("burst write failed: {e}"))?;
    burst_then_flush
        .flush()
        .await
        .map_err(|e| format!("burst flush failed: {e}"))?;
    let (lived, err) = pump(burst_then_flush, Duration::from_secs(5)).await;
    assert!(
        err.is_none(),
        "unblocked flush must not break burst lead; cut after {lived:?}: {err:?}"
    );
    Ok(())
}

dual_runtime_test!(
    review_4e_burst_before_the_first_blocked_write_counts_as_lead,
    review_4e_burst_before_the_first_blocked_write_counts_as_lead_multi_thread,
    review_4e_burst_before_the_first_blocked_write_counts_as_lead_impl
);

/// Recording writer used to assert `WriteGuardedIo` forwards `poll_write_vectored` and
/// `is_write_vectored` without flattening slices into single-buffer `poll_write` calls.
struct RecordingVectoredIo {
    vectored_capable: bool,
    max_per_call: usize,
    scalar_calls: usize,
    vectored_calls: usize,
    max_slices_seen: usize,
    written: Vec<u8>,
    fail_next: std::sync::atomic::AtomicBool,
}

impl RecordingVectoredIo {
    fn new(vectored_capable: bool, max_per_call: usize) -> Self {
        Self {
            vectored_capable,
            max_per_call,
            scalar_calls: 0,
            vectored_calls: 0,
            max_slices_seen: 0,
            written: Vec::new(),
            fail_next: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl AsyncWrite for RecordingVectoredIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this
            .fail_next
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected scalar error",
            )));
        }
        this.scalar_calls += 1;
        let n = buf.len().min(this.max_per_call);
        this.written.extend_from_slice(buf.get(..n).unwrap_or(&[]));
        Poll::Ready(Ok(n))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this
            .fail_next
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected vectored error",
            )));
        }
        this.vectored_calls += 1;
        this.max_slices_seen = this.max_slices_seen.max(bufs.len());
        let mut budget = this.max_per_call;
        let mut total = 0_usize;
        for slice in bufs {
            if budget == 0 {
                break;
            }
            let take = slice.len().min(budget);
            this.written
                .extend_from_slice(slice.get(..take).unwrap_or(&[]));
            total += take;
            budget -= take;
        }
        Poll::Ready(Ok(total))
    }

    fn is_write_vectored(&self) -> bool {
        self.vectored_capable
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Vectored variant of `BurstyKernel` that accepts multiple `IoSlice`s up to `burst_left`.
struct VectoredBurstyKernel {
    inner: BurstyKernel,
    vectored_calls: usize,
}

impl VectoredBurstyKernel {
    fn new(phases: Vec<Phase>) -> Self {
        Self {
            inner: BurstyKernel::new(phases),
            vectored_calls: 0,
        }
    }
}

impl AsyncWrite for VectoredBurstyKernel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.vectored_calls += 1;
        let total_len: usize = bufs.iter().map(|b| b.len()).sum();
        let now = Instant::now();
        let Some(phase) = this.inner.current_phase(now) else {
            return Poll::Pending;
        };
        if now >= this.inner.next_ready {
            this.inner.next_ready = now + phase.interval;
            this.inner.waker_timer = None;
            this.inner.burst_left = phase.burst;
        }
        if this.inner.burst_left > 0 {
            let n = total_len.min(this.inner.burst_left);
            this.inner.burst_left = this.inner.burst_left.saturating_sub(n);
            return Poll::Ready(Ok(n));
        }
        let mut timer = Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(
            this.inner.next_ready,
        )));
        let _ = timer.as_mut().poll(cx);
        this.inner.waker_timer = Some(timer);
        Poll::Pending
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

async fn pump_vectored(
    mut io: WriteGuardedIo<VectoredBurstyKernel>,
    run_for: Duration,
) -> (Duration, Option<io::Error>, usize) {
    let part_a = vec![b'a'; 4 * 1024];
    let part_b = vec![b'b'; 4 * 1024];
    let started = Instant::now();
    let outcome = tokio::time::timeout(run_for, async {
        loop {
            let slices = [io::IoSlice::new(&part_a), io::IoSlice::new(&part_b)];
            match io.write_vectored(&slices).await {
                Ok(0) => {
                    return io::Error::new(io::ErrorKind::WriteZero, "zero vectored write");
                }
                Ok(_) => {}
                Err(err) => return err,
            }
        }
    })
    .await;
    (started.elapsed(), outcome.ok(), io.get_ref().vectored_calls)
}

#[tokio::test]
async fn vectored_writes_forward_all_slices_and_report_is_write_vectored() -> io::Result<()> {
    // 1. Forwarding `is_write_vectored` (true, false, and real TcpStream).
    let mut guarded_vec = WriteGuardedIo::new(
        RecordingVectoredIo::new(true, 1024 * 1024),
        WRITE_IDLE,
        MIN_RATE_BPS,
    );
    assert!(guarded_vec.is_write_vectored());
    let guarded_scalar = WriteGuardedIo::new(
        RecordingVectoredIo::new(false, 1024 * 1024),
        WRITE_IDLE,
        MIN_RATE_BPS,
    );
    assert!(!guarded_scalar.is_write_vectored());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let _client = tokio::net::TcpStream::connect(addr).await?;
    let (server, _) = listener.accept().await?;
    let guarded_tcp = WriteGuardedIo::for_tcp_stream(server, WRITE_IDLE, MIN_RATE_BPS);
    assert!(
        guarded_tcp.is_write_vectored(),
        "WriteGuardedIo<TcpStream> must advertise vectored write support"
    );

    // 2. Single vectored call delivers 4 x 16 KiB slices without falling back to `poll_write`.
    let r0 = vec![b'0'; 16 * 1024];
    let r1 = vec![b'1'; 16 * 1024];
    let r2 = vec![b'2'; 16 * 1024];
    let r3 = vec![b'3'; 16 * 1024];
    let bufs = [
        io::IoSlice::new(&r0),
        io::IoSlice::new(&r1),
        io::IoSlice::new(&r2),
        io::IoSlice::new(&r3),
    ];
    let n = guarded_vec.write_vectored(&bufs).await?;
    assert_eq!(n, 64 * 1024);
    assert_eq!(guarded_vec.get_ref().vectored_calls, 1);
    assert_eq!(guarded_vec.get_ref().scalar_calls, 0);
    assert_eq!(guarded_vec.get_ref().max_slices_seen, 4);
    assert_eq!(guarded_vec.get_ref().written.len(), 64 * 1024);

    // 3. Partial vectored write + injected error cleanup.
    let mut partial = WriteGuardedIo::new(
        RecordingVectoredIo::new(true, 20 * 1024),
        WRITE_IDLE,
        MIN_RATE_BPS,
    );
    let n_partial = partial.write_vectored(&bufs).await?;
    assert_eq!(n_partial, 20 * 1024);
    assert_eq!(partial.get_ref().vectored_calls, 1);
    partial
        .get_ref()
        .fail_next
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let err = partial
        .write_vectored(&bufs)
        .await
        .err()
        .ok_or_else(|| io::Error::other("expected injected error"))?;
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    Ok(())
}

#[tokio::test]
async fn vectored_writes_preserve_stall_detection_min_rate_and_burst_lead() -> Result<(), String> {
    // 1. Reader that stops is cut on write-idle + one send buffer via `poll_write_vectored`.
    let stalled = WriteGuardedIo::new(
        VectoredBurstyKernel::new(vec![Phase {
            lasts: Duration::from_millis(50),
            interval: Duration::from_millis(400),
            burst: 60_000,
        }]),
        WRITE_IDLE,
        MIN_RATE_BPS,
    )
    .with_rate_grace(RATE_GRACE)
    .with_send_buffer_probe(Box::new(|_: &VectoredBurstyKernel| Some(SEND_BUFFER)));
    let (lived, err, calls) = pump_vectored(stalled, Duration::from_secs(5)).await;
    assert!(calls > 0);
    let err = err.ok_or_else(|| "stalled vectored writer must be cut".to_owned())?;
    assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
    assert!(
        lived >= Duration::from_millis(600) && lived <= Duration::from_secs(3),
        "expected vectored stall cut near 0.84 s, got {lived:?}"
    );

    // 2. Reader below min_response_rate_bps is cut by the rate rule.
    let slow = WriteGuardedIo::new(
        VectoredBurstyKernel::new(vec![Phase {
            lasts: FOREVER,
            interval: Duration::from_millis(400),
            burst: 20_000,
        }]),
        WRITE_IDLE,
        MIN_RATE_BPS,
    )
    .with_rate_grace(RATE_GRACE)
    .with_send_buffer_probe(Box::new(|_: &VectoredBurstyKernel| Some(SEND_BUFFER)));
    let (lived, err, calls) = pump_vectored(slow, Duration::from_secs(8)).await;
    assert!(calls > 0);
    let err = err.ok_or_else(|| "slow vectored reader must be cut".to_owned())?;
    assert!(
        err.to_string().contains("min-response-rate-bps"),
        "rate rule must cut slow vectored reader: {err}"
    );
    assert!(
        lived >= Duration::from_millis(700) && lived <= Duration::from_secs(6),
        "expected rate cut between 0.7 s and 6 s, got {lived:?}"
    );

    // 3. Steady vectored reader above min rate (with burst lead) survives long gaps.
    let steady = WriteGuardedIo::new(
        VectoredBurstyKernel::new(vec![
            Phase {
                lasts: Duration::from_millis(50),
                interval: Duration::from_millis(2_500),
                burst: 400_000,
            },
            Phase {
                lasts: FOREVER,
                interval: Duration::from_secs(2),
                burst: 300_000,
            },
        ]),
        WRITE_IDLE,
        MIN_RATE_BPS,
    )
    .with_rate_grace(RATE_GRACE)
    .with_send_buffer_probe(Box::new(|_: &VectoredBurstyKernel| Some(SEND_BUFFER)));
    let (lived, err, calls) = pump_vectored(steady, Duration::from_secs(6)).await;
    assert!(calls > 0);
    assert!(
        err.is_none(),
        "steady vectored reader spending its burst lead must not be cut; cut after {lived:?}: {err:?}"
    );
    Ok(())
}

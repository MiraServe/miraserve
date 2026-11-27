//! Minimum send-rate accounting for one response stream that is paced by flow control
//! (an HTTP/3 stream; the TCP-level equivalent lives in `WriteGuardedIo`).

use std::time::Duration;

/// Judges whether a client is taking a response stream at `min_rate_bps` or better.
///
/// Flow control opens in steps: one send waits for the window and the next few return at once,
/// and the step size is the client's choice. Two consequences shape the rule:
///
/// - The rate is judged over ALL bytes sent and ALL time spent inside sends, not only the
///   sends that happened to wait long.
/// - A steady reader is silent between two steps, and any silence shorter than the write-idle
///   timeout is allowed (the caller's send timeout enforces that limit). So the client is
///   forgiven `allowance` worth of data at the minimum rate: a reader at or above the minimum
///   rate whose silences stay below `allowance` is never behind by more than that.
///
/// A client that is too slow still falls behind without limit and is reported. Credit from a
/// fast phase is capped at one allowance, so it cannot buy an endless trickle.
#[derive(Debug)]
pub(crate) struct StreamRateBudget {
    min_rate_bps: u64,
    allowance: Duration,
    /// Time spent inside sends.
    blocked: Duration,
    /// Bytes sent (capped, see the type documentation).
    bytes: u64,
}

impl StreamRateBudget {
    /// `allowance` is the write-idle timeout: the longest silence the caller tolerates.
    pub(crate) const fn new(min_rate_bps: u64, allowance: Duration) -> Self {
        Self {
            min_rate_bps,
            allowance,
            blocked: Duration::ZERO,
            bytes: 0,
        }
    }

    fn due(&self, time: Duration) -> u64 {
        let bytes = u128::from(self.min_rate_bps).saturating_mul(time.as_millis()) / 1000;
        u64::try_from(bytes).unwrap_or(u64::MAX)
    }

    /// Records one completed send of `n` bytes that took `elapsed`. Returns `true` when the
    /// client has fallen behind the minimum rate by more than the allowance.
    pub(crate) fn record(&mut self, n: u64, elapsed: Duration) -> bool {
        if self.min_rate_bps == 0 {
            return false;
        }
        // Every send's duration counts, however short: many waits below any threshold would
        // otherwise add up to a slow stream with no blocked time at all. The time measured is
        // the time inside the send only, so waiting for the producer is not charged.
        self.blocked = self.blocked.saturating_add(elapsed);
        self.bytes = self.bytes.saturating_add(n);
        let due = self.due(self.blocked);
        let credit = self.due(self.allowance);
        if self.bytes.saturating_add(credit) < due {
            return true;
        }
        self.bytes = self.bytes.min(due.saturating_add(credit));
        false
    }
}

#[cfg(test)]
mod tests {
    use super::StreamRateBudget;
    use std::time::Duration;

    const MIN_RATE: u64 = 16_384;
    const WRITE_IDLE: Duration = Duration::from_secs(30);
    const CHUNK: u64 = 16 * 1024;

    /// Bursty delivery well above `MIN_RATE` (one chunk after 1.1 s followed by seven chunks at
    /// 1 ms each, repeated for 120 bursts) must not trigger a cut.
    #[test]
    fn bursty_delivery_far_above_the_minimum_rate_is_not_cut() {
        let mut budget = StreamRateBudget::new(MIN_RATE, WRITE_IDLE);
        for _second in 0..120 {
            assert!(!budget.record(CHUNK, Duration::from_millis(1_100)));
            for _ in 0..7 {
                assert!(
                    !budget.record(CHUNK, Duration::from_millis(1)),
                    "a client receiving 8 x 16 KiB per 1.1 s is far above 16 KiB/s"
                );
            }
        }
    }

    /// A reader at exactly the minimum rate whose window opens in large steps: 20 s of silence,
    /// then 20 s worth of data at once. Every silence is shorter than the write-idle timeout.
    #[test]
    fn steady_reader_at_the_minimum_rate_with_large_window_steps_is_not_cut() {
        let mut budget = StreamRateBudget::new(MIN_RATE, WRITE_IDLE);
        for _step in 0..200 {
            assert!(
                !budget.record(CHUNK, Duration::from_secs(20)),
                "20 s of silence is allowed and the lump that follows makes up for it"
            );
            for _ in 0..19 {
                assert!(!budget.record(CHUNK, Duration::from_millis(1)));
            }
        }
    }

    #[test]
    fn reader_below_the_minimum_rate_is_cut_once_the_allowance_is_used_up() {
        // 4 KiB every second: a quarter of the minimum rate, 12 KiB/s behind. The allowance is
        // 30 s x 16 KiB = 480 KiB, so the client is cut in second 41.
        let mut budget = StreamRateBudget::new(MIN_RATE, WRITE_IDLE);
        let mut cut_after = None;
        for second in 1..=120_u32 {
            if budget.record(4 * 1024, Duration::from_secs(1)) {
                cut_after = Some(second);
                break;
            }
        }
        assert_eq!(cut_after, Some(41));
    }

    #[test]
    fn fast_bytes_before_a_trickle_buy_at_most_one_allowance() {
        // 100 MiB sent with almost no waiting, then a trickle of 1 KiB/s (15 KiB/s behind):
        // the surplus is capped at one allowance, so the cut comes after about two allowances
        // (65 s), not after the hours the surplus would otherwise have bought.
        let mut budget = StreamRateBudget::new(MIN_RATE, WRITE_IDLE);
        for _ in 0..6_400 {
            assert!(!budget.record(CHUNK, Duration::from_millis(1)));
        }
        let mut cut_after = None;
        for second in 1..=600_u32 {
            if budget.record(1_024, Duration::from_secs(1)) {
                cut_after = Some(second);
                break;
            }
        }
        assert!(
            matches!(cut_after, Some(60..=70)),
            "cut after about 65 s, got {cut_after:?}"
        );
    }

    /// Review 13: many waits that are each short must still count. 256 bytes every 8 ms is
    /// 32 KiB/s, above the minimum; 64 bytes every 8 ms is 8 KiB/s, half of it.
    #[test]
    fn short_waits_add_up() {
        let mut ok = StreamRateBudget::new(MIN_RATE, WRITE_IDLE);
        for _ in 0..40_000 {
            assert!(!ok.record(256, Duration::from_millis(8)));
        }
        let mut slow = StreamRateBudget::new(MIN_RATE, WRITE_IDLE);
        let mut cut_at_ms = None;
        for i in 1..=40_000_u64 {
            if slow.record(64, Duration::from_millis(8)) {
                cut_at_ms = Some(i * 8);
                break;
            }
        }
        assert!(
            matches!(cut_at_ms, Some(55_000..=65_000)),
            "half the minimum rate uses up a 30 s allowance in about 60 s, got {cut_at_ms:?}"
        );
    }

    #[test]
    fn credit_from_a_fast_phase_under_backpressure_is_capped() {
        // Far above the minimum rate for a minute (always with a short wait), then nothing
        // useful: the trickle is cut after about two allowances, not after the minutes the
        // surplus would otherwise have bought.
        let mut budget = StreamRateBudget::new(MIN_RATE, WRITE_IDLE);
        for _ in 0..600 {
            assert!(!budget.record(64 * CHUNK, Duration::from_millis(100)));
        }
        let mut cut_after = None;
        for second in 1..=600_u32 {
            if budget.record(1, Duration::from_secs(1)) {
                cut_after = Some(second);
                break;
            }
        }
        assert!(
            matches!(cut_after, Some(55..=65)),
            "cut after about 60 s, got {cut_after:?}"
        );
    }

    #[test]
    fn rate_zero_disables_the_check() {
        let mut budget = StreamRateBudget::new(0, WRITE_IDLE);
        assert!(!budget.record(1, Duration::from_secs(3_600)));
    }
}

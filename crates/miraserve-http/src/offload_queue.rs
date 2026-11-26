//! Bounded, single-drainer off-thread log queue shared by interrupted HTTP/2 access records
//! and runtime tracing diagnostics emitted from non-blocking contexts (in-task HTTP/2 streams
//! and dedicated worker event loops).
//!
//! # Invariants
//! - **Single active drainer:** at most one blocking-pool drainer task owns the queue at a time
//!   (`state.draining == true`). Ownership is released **exactly once**, under the queue mutex,
//!   before the retiring drainer returns, and the unwind guard ([`DrainerToken`]) is disarmed on
//!   the normal exit path so a retiring drainer can never clear a successor's ownership.
//! - **Panic recovery without stranding:** if a sink panics inside [`OffloadLogItem::emit_now`],
//!   [`DrainerToken::drop`] runs during stack unwind, locks the queue mutex, restores any
//!   un-emitted items remaining in the local batch back to the front of the queue in FIFO order,
//!   clears in-flight accounting, and either releases ownership (if the queue is now empty) or
//!   transfers ownership directly to a freshly scheduled replacement drainer so queued records are
//!   never stranded. If a scheduled closure is dropped unexecuted (e.g. runtime shutdown), the
//!   unstarted token releases `draining = false` and notifies waiters without attempting to
//!   respawn.
//! - **Bounded memory with drop-oldest overflow:** queued items are bounded by both record count
//!   and approximate byte size (excluding allocator overhead and the drainer's single local batch
//!   of up to 64 items). Overflow evicts oldest queued items, increments the queue's monotonic
//!   drop counter, and emits a rate-limited drop summary from the drainer thread (obeying the
//!   configured interval uniformly, including when the queue empties).
//! - **Caller-measured shutdown drain:** [`OffloadLogQueue::flush_until_blocking`] and
//!   [`OffloadLogQueue::flush_until_async`] measure one deadline from the caller, skip spawning
//!   a blocking-pool waiter when already drained, count both queued items and items currently held
//!   in an active drainer's local batch as outstanding, and never report drained while a batch is
//!   still inside the sink.

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Process-wide approximate cap on bytes buffered per off-thread log queue (1 MiB, excluding
/// allocator overhead and the drainer's single local batch of up to 64 records).
pub(crate) const MAX_OFFLOADED_LOG_BYTES: usize = 1024 * 1024;

/// Process-wide cap on queued records per off-thread log queue.
pub(crate) const MAX_OFFLOADED_LOG_RECORDS: usize = 4_096;

/// Minimum interval between stderr drop-report summaries from a drainer thread.
pub(crate) const OFFLOAD_DROP_REPORT_INTERVAL: Duration = Duration::from_secs(30);

/// Maximum number of queued records popped per drainer lock acquisition.
const DRAIN_BATCH_SIZE: usize = 64;

/// One item stored in an [`OffloadLogQueue`].
pub(crate) trait OffloadLogItem: Send + 'static {
    /// Approximate byte charge of this item while queued.
    fn approx_bytes(&self) -> usize;

    /// Delivers this item to its underlying sink on the drainer thread.
    fn emit_now(self);
}

/// Outcome of draining one off-thread log queue until a caller-supplied deadline.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OffloadDrainOutcome {
    /// `true` iff the queue is empty and no drainer is active.
    pub drained: bool,
    /// Number of records still queued or held in an active drainer's local batch.
    pub remaining: usize,
}

impl OffloadDrainOutcome {
    /// Cleanly drained outcome (zero remaining records, no active drainer).
    #[must_use]
    pub const fn clean() -> Self {
        Self {
            drained: true,
            remaining: 0,
        }
    }
}

/// Combined outcome of draining both process-wide offloaded log queues (interrupted access records
/// and runtime diagnostics) under a single shutdown deadline.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "four independent shutdown status flags (two queue drain flags, connection deadline, worker join timeout)"
)]
pub struct OffloadLogDrainReport {
    /// Interrupted HTTP/2 access-log records still queued or held in a drainer batch when the
    /// shutdown deadline elapsed.
    pub access_remaining: usize,
    /// `true` iff the interrupted access-log queue was empty with no active drainer at the
    /// shutdown snapshot.
    pub access_drained: bool,
    /// Runtime diagnostic log records still queued or held in a drainer batch when the shutdown
    /// deadline elapsed.
    pub diagnostic_remaining: usize,
    /// `true` iff the runtime diagnostic queue was empty with no active drainer at the shutdown
    /// snapshot.
    pub diagnostic_drained: bool,
    /// `true` iff the server's graceful connection-drain deadline expired with connections still
    /// open, so late force-closed connection teardown may enqueue records after this snapshot and
    /// miss the final flush.
    pub connections_forced_closed: bool,
    /// `true` iff one or more dedicated worker-loop threads did not join before the shutdown
    /// worker-join grace period expired, so a clean shutdown could not be certified.
    pub workers_join_timed_out: bool,
}

impl OffloadLogDrainReport {
    /// Cleanly drained report (all connections and worker threads finished, and both offloaded
    /// queues empty with no active drainer).
    #[must_use]
    pub const fn clean() -> Self {
        Self {
            access_remaining: 0,
            access_drained: true,
            diagnostic_remaining: 0,
            diagnostic_drained: true,
            connections_forced_closed: false,
            workers_join_timed_out: false,
        }
    }

    /// Returns `true` only when all connections drained before the graceful deadline, all
    /// dedicated worker threads joined (if any), and both offloaded queues drained cleanly before
    /// the log-drain deadline.
    #[must_use]
    pub const fn is_clean(self) -> bool {
        !self.connections_forced_closed
            && !self.workers_join_timed_out
            && self.access_drained
            && self.access_remaining == 0
            && self.diagnostic_drained
            && self.diagnostic_remaining == 0
    }

    /// Total records still queued or held in a drainer batch across both queues.
    #[must_use]
    pub const fn total_remaining(self) -> usize {
        self.access_remaining
            .saturating_add(self.diagnostic_remaining)
    }
}

struct QueueState<T> {
    queue: VecDeque<T>,
    queued_bytes: usize,
    draining: bool,
    dropped_unreported: u64,
    last_drop_report: Option<Instant>,
}

impl<T> QueueState<T> {
    const fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            queued_bytes: 0,
            draining: false,
            dropped_unreported: 0,
            last_drop_report: None,
        }
    }
}

/// Generic bounded single-drainer off-thread queue.
pub(crate) struct OffloadLogQueue<T: OffloadLogItem> {
    state: Mutex<QueueState<T>>,
    drained: Condvar,
    /// Exact count of records currently popped into the active drainer's local batch and not yet
    /// finished by [`OffloadLogItem::emit_now`]. Incremented under `state` when popping a batch,
    /// decremented after each item completes, and zeroed under `state` on unwind.
    inflight_records: AtomicUsize,
    dropped_total: AtomicU64,
    max_bytes: usize,
    max_records: usize,
    drop_report_interval: Duration,
    report_drops: fn(u64),
    #[cfg(test)]
    after_release_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    #[cfg(test)]
    after_empty_exit_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    #[cfg(test)]
    drop_reports_emitted: AtomicU64,
}

impl<T: OffloadLogItem> OffloadLogQueue<T> {
    pub(crate) fn new(
        max_bytes: usize,
        max_records: usize,
        drop_report_interval: Duration,
        report_drops: fn(u64),
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(QueueState::new()),
            drained: Condvar::new(),
            inflight_records: AtomicUsize::new(0),
            dropped_total: AtomicU64::new(0),
            max_bytes,
            max_records,
            drop_report_interval,
            report_drops,
            #[cfg(test)]
            after_release_hook: Mutex::new(None),
            #[cfg(test)]
            after_empty_exit_hook: Mutex::new(None),
            #[cfg(test)]
            drop_reports_emitted: AtomicU64::new(0),
        })
    }

    #[must_use]
    pub(crate) fn dropped_total(&self) -> u64 {
        self.dropped_total.load(Ordering::Acquire)
    }

    /// Returns a snapshot of whether the queue is currently drained and how many records are
    /// outstanding (queued + held in an active drainer's local batch).
    #[must_use]
    pub(crate) fn snapshot_outcome(&self) -> OffloadDrainOutcome {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let remaining = state
            .queue
            .len()
            .saturating_add(self.inflight_records.load(Ordering::Acquire));
        OffloadDrainOutcome {
            drained: state.queue.is_empty() && !state.draining,
            remaining,
        }
    }

    /// Enqueues `item` (dropping oldest queued items if the byte or record bound would be
    /// exceeded) and schedules a single blocking-pool drainer if none is active.
    pub(crate) fn enqueue(self: &Arc<Self>, item: T) {
        let token = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            let pushed = self.push_bounded_locked(&mut state, item);
            if state.draining
                || (!pushed && state.queue.is_empty() && state.dropped_unreported == 0)
            {
                None
            } else {
                state.draining = true;
                Some(DrainerToken::new(Arc::clone(self), false))
            }
        };
        if let Some(token) = token {
            self.schedule_drainer(token, true);
        }
    }

    fn push_bounded_locked(&self, state: &mut QueueState<T>, item: T) -> bool {
        let item_bytes = item.approx_bytes();
        if item_bytes > self.max_bytes && self.max_bytes > 0 {
            state.dropped_unreported = state.dropped_unreported.saturating_add(1);
            self.dropped_total.fetch_add(1, Ordering::AcqRel);
            return false;
        }
        while !state.queue.is_empty()
            && (state.queue.len() >= self.max_records
                || state.queued_bytes.saturating_add(item_bytes) > self.max_bytes)
        {
            if let Some(evicted) = state.queue.pop_front() {
                state.queued_bytes = state.queued_bytes.saturating_sub(evicted.approx_bytes());
                state.dropped_unreported = state.dropped_unreported.saturating_add(1);
                self.dropped_total.fetch_add(1, Ordering::AcqRel);
            }
        }
        state.queued_bytes = state.queued_bytes.saturating_add(item_bytes);
        state.queue.push_back(item);
        true
    }

    fn schedule_drainer(self: &Arc<Self>, mut token: DrainerToken<T>, allow_inline_fallback: bool) {
        let queue = Arc::clone(self);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            // Tokio `spawn_blocking` tasks are non-mandatory: if `handle`'s runtime is shutting
            // down (e.g. a worker runtime or embedded runtime dropping), Tokio drops the closure
            // unexecuted. Enable a single detached-thread fallback in `DrainerToken::drop` so
            // queued records are never stranded on runtime teardown.
            token.fallback_to_thread = true;
            drop(handle.spawn_blocking(move || queue.drain_loop(token)));
        } else if allow_inline_fallback {
            token.fallback_to_thread = false;
            queue.drain_loop(token);
        } else {
            self.spawn_detached_drainer(token);
        }
    }

    fn spawn_detached_drainer(self: &Arc<Self>, mut token: DrainerToken<T>) {
        let queue = Arc::clone(self);
        // Never recurse if OS thread creation fails; `DrainerToken::drop` releases
        // `draining = false` and notifies waiters when `fallback_to_thread == false`.
        token.fallback_to_thread = false;
        let _ = std::thread::Builder::new()
            .name("miraserve-log-drain".to_owned())
            .spawn(move || queue.drain_loop(token));
    }

    fn drain_loop(self: &Arc<Self>, mut token: DrainerToken<T>) {
        token.mark_started();
        loop {
            let report_drops = {
                let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                token.batch.clear();
                for _ in 0..DRAIN_BATCH_SIZE {
                    let Some(item) = state.queue.pop_front() else {
                        break;
                    };
                    state.queued_bytes = state.queued_bytes.saturating_sub(item.approx_bytes());
                    token.batch.push_back(item);
                }
                // Obey `drop_report_interval` uniformly (including when the queue empties) so
                // bursty stalls cannot spam stderr more often than once per interval.
                let report = if state.dropped_unreported > 0
                    && state
                        .last_drop_report
                        .is_none_or(|t| t.elapsed() >= self.drop_report_interval)
                {
                    state.last_drop_report = Some(Instant::now());
                    let n = state.dropped_unreported;
                    state.dropped_unreported = 0;
                    n
                } else {
                    0
                };
                if token.batch.is_empty() {
                    self.inflight_records.store(0, Ordering::Release);
                    state.draining = false;
                    self.drained.notify_all();
                    // Disarm the unwind guard BEFORE dropping the lock so returning from this
                    // function never locks or writes `draining = false` a second time.
                    token.disarm();
                    drop(state);
                    #[cfg(test)]
                    self.invoke_after_release_hook();
                    if report > 0 {
                        self.emit_drop_report(report);
                    }
                    #[cfg(test)]
                    self.invoke_after_empty_exit_hook();
                    return;
                }
                self.inflight_records
                    .store(token.batch.len(), Ordering::Release);
                report
            };
            if report_drops > 0 {
                self.emit_drop_report(report_drops);
            }
            while let Some(item) = token.batch.pop_front() {
                item.emit_now();
                self.inflight_records.fetch_sub(1, Ordering::AcqRel);
            }
        }
    }

    fn emit_drop_report(&self, dropped: u64) {
        #[cfg(test)]
        self.drop_reports_emitted.fetch_add(1, Ordering::AcqRel);
        (self.report_drops)(dropped);
    }

    #[cfg(test)]
    fn invoke_after_release_hook(&self) {
        let hook = self
            .after_release_hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(hook) = hook {
            hook();
        }
    }

    #[cfg(test)]
    fn invoke_after_empty_exit_hook(&self) {
        let hook = self
            .after_empty_exit_hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(hook) = hook {
            hook();
        }
    }

    /// Blocks until this queue is empty and no drainer is active, or until `deadline` is reached.
    #[must_use]
    pub(crate) fn flush_until_blocking(self: &Arc<Self>, deadline: Instant) -> OffloadDrainOutcome {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let mut rescued = false;
        while !state.queue.is_empty() || state.draining {
            if !state.queue.is_empty() && !state.draining && !rescued {
                // Orphaned items with no active drainer (e.g. an earlier OS thread spawn failed):
                // start a detached drainer once rather than sleeping until the deadline.
                rescued = true;
                state.draining = true;
                let token = DrainerToken::new(Arc::clone(self), false);
                drop(state);
                self.spawn_detached_drainer(token);
                state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                continue;
            }
            let Some(remaining_time) = deadline.checked_duration_since(Instant::now()) else {
                let remaining = state
                    .queue
                    .len()
                    .saturating_add(self.inflight_records.load(Ordering::Acquire));
                return OffloadDrainOutcome {
                    drained: false,
                    remaining,
                };
            };
            if remaining_time.is_zero() {
                let remaining = state
                    .queue
                    .len()
                    .saturating_add(self.inflight_records.load(Ordering::Acquire));
                return OffloadDrainOutcome {
                    drained: false,
                    remaining,
                };
            }
            let (guard, wait_res) = self
                .drained
                .wait_timeout(state, remaining_time)
                .unwrap_or_else(PoisonError::into_inner);
            state = guard;
            if wait_res.timed_out() && (!state.queue.is_empty() || state.draining) {
                let remaining = state
                    .queue
                    .len()
                    .saturating_add(self.inflight_records.load(Ordering::Acquire));
                return OffloadDrainOutcome {
                    drained: false,
                    remaining,
                };
            }
        }
        OffloadDrainOutcome::clean()
    }

    /// Awaits until this queue is drained or `deadline` (measured by the caller BEFORE scheduling
    /// any blocking-pool waiter) is reached. Returns immediately without spawning a blocking-pool
    /// job when the queue is already drained.
    #[must_use]
    pub(crate) async fn flush_until_async(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> OffloadDrainOutcome {
        let fast = self.snapshot_outcome();
        if fast.drained {
            return fast;
        }
        let Some(remaining_time) = deadline.checked_duration_since(Instant::now()) else {
            return fast;
        };
        if remaining_time.is_zero() {
            return fast;
        }
        let queue = Arc::clone(self);
        let wait_task = tokio::task::spawn_blocking(move || queue.flush_until_blocking(deadline));
        match tokio::time::timeout(remaining_time, wait_task).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) | Err(_) => self.snapshot_outcome(),
        }
    }

    #[cfg(test)]
    pub(crate) fn set_after_release_hook(&self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
        *self
            .after_release_hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = hook;
    }

    #[cfg(test)]
    pub(crate) fn set_after_empty_exit_hook(&self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
        *self
            .after_empty_exit_hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = hook;
    }

    #[cfg(test)]
    pub(crate) fn push_bounded_for_test(&self, item: T) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = self.push_bounded_locked(&mut state, item);
    }

    #[cfg(test)]
    pub(crate) fn inspect_queue_for_test<R>(&self, f: impl FnOnce(&VecDeque<T>, usize) -> R) -> R {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        f(&state.queue, state.queued_bytes)
    }

    #[cfg(test)]
    pub(crate) fn drop_reports_emitted(&self) -> u64 {
        self.drop_reports_emitted.load(Ordering::Acquire)
    }
}

/// Ownership token held by the single active drainer task.
///
/// - On normal exit (`drain_loop` sees an empty queue), ownership is released under the queue
///   mutex and [`Self::disarm`] is called before returning, so `Drop` is a no-op.
/// - If a Tokio `spawn_blocking` closure is dropped unexecuted during Tokio runtime shutdown
///   (`started == false && fallback_to_thread == true`) while items remain queued, `Drop` keeps
///   `draining = true` and hands ownership atomically to a single detached OS thread
///   (`fallback_to_thread = false`) so records enqueued during runtime teardown are never
///   stranded. If OS thread creation itself fails (`fallback_to_thread == false`), `Drop` simply
///   sets `draining = false` and notifies `drained` without attempting to respawn.
/// - If a sink panics inside `emit_now` (`started == true`), `Drop` runs during unwind, restores
///   any un-emitted items still in `self.batch` back to the front of the queue in FIFO order,
///   clears `inflight_records`, and either clears `draining` (if empty) or hands ownership
///   atomically to a replacement drainer so queued records are never stranded.
struct DrainerToken<T: OffloadLogItem> {
    queue: Arc<OffloadLogQueue<T>>,
    batch: VecDeque<T>,
    armed: bool,
    started: bool,
    fallback_to_thread: bool,
}

impl<T: OffloadLogItem> DrainerToken<T> {
    fn new(queue: Arc<OffloadLogQueue<T>>, fallback_to_thread: bool) -> Self {
        Self {
            queue,
            batch: VecDeque::with_capacity(DRAIN_BATCH_SIZE),
            armed: true,
            started: false,
            fallback_to_thread,
        }
    }

    fn mark_started(&mut self) {
        self.started = true;
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<T: OffloadLogItem> Drop for DrainerToken<T> {
    fn drop(&mut self) {
        enum Replacement<T: OffloadLogItem> {
            None,
            Schedule(DrainerToken<T>),
            DetachedThread(DrainerToken<T>),
        }
        if !self.armed {
            return;
        }
        let replacement = {
            let mut state = self
                .queue
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            self.queue.inflight_records.store(0, Ordering::Release);
            // Restore any un-emitted items that were popped into this batch (after the item that
            // panicked) to the front of `state.queue` in original FIFO order.
            while let Some(item) = self.batch.pop_back() {
                state.queued_bytes = state.queued_bytes.saturating_add(item.approx_bytes());
                state.queue.push_front(item);
            }
            let has_work = !state.queue.is_empty() || state.dropped_unreported > 0;
            if self.started && has_work {
                // Sink panic inside `emit_now`: keep `state.draining = true` and transfer
                // ownership atomically to a replacement drainer.
                Replacement::Schedule(DrainerToken::new(Arc::clone(&self.queue), false))
            } else if !self.started && self.fallback_to_thread && has_work {
                // Tokio rejected/dropped an unstarted `spawn_blocking` drainer during runtime
                // shutdown: hand ownership to one detached OS thread (`fallback_to_thread = false`)
                // so records enqueued during runtime teardown are never stranded.
                Replacement::DetachedThread(DrainerToken::new(Arc::clone(&self.queue), false))
            } else {
                state.draining = false;
                self.queue.drained.notify_all();
                Replacement::None
            }
        };
        match replacement {
            Replacement::None => {}
            Replacement::Schedule(next_token) => {
                self.queue.schedule_drainer(next_token, false);
            }
            Replacement::DetachedThread(next_token) => {
                self.queue.spawn_detached_drainer(next_token);
            }
        }
    }
}

/// Sink callback writing one formatted runtime diagnostic log line to its underlying destination
/// (rotating log file, stderr, or stdout) off the connection/worker task.
pub type DiagnosticLogSink = Arc<dyn Fn(&[u8]) + Send + Sync>;

struct OffloadDiagnosticItem {
    bytes: Vec<u8>,
    sink: DiagnosticLogSink,
}

impl OffloadLogItem for OffloadDiagnosticItem {
    fn approx_bytes(&self) -> usize {
        self.bytes.len()
    }

    fn emit_now(self) {
        (self.sink)(&self.bytes);
    }
}

static OFFLOAD_DIAGNOSTIC_LOG_QUEUE: LazyLock<Arc<OffloadLogQueue<OffloadDiagnosticItem>>> =
    LazyLock::new(|| {
        OffloadLogQueue::new(
            MAX_OFFLOADED_LOG_BYTES,
            MAX_OFFLOADED_LOG_RECORDS,
            OFFLOAD_DROP_REPORT_INTERVAL,
            report_offloaded_diagnostic_log_drops,
        )
    });

fn report_offloaded_diagnostic_log_drops(dropped: u64) {
    use std::io::Write as _;
    let mut stderr = io::stderr().lock();
    let _ = writeln!(
        stderr,
        "miraserve: dropped {dropped} runtime diagnostic log record(s) while the log sink was stalled"
    );
}

/// Enqueues one already-formatted runtime diagnostic log line onto the bounded off-thread
/// diagnostic queue so handlers running in a non-blocking context (in-task HTTP/2 streams or
/// dedicated worker event loops) never block on log file locks, rotation, or slow stderr/stdout
/// pipes.
pub fn enqueue_offloaded_diagnostic_log(bytes: Vec<u8>, sink: DiagnosticLogSink) {
    if bytes.is_empty() {
        return;
    }
    OFFLOAD_DIAGNOSTIC_LOG_QUEUE.enqueue(OffloadDiagnosticItem { bytes, sink });
}

/// Writes `bytes` synchronously via `sink` when outside a non-blocking context, or enqueues a
/// copy onto the bounded off-thread diagnostic queue when
/// [`miraserve_static::inline_work_must_not_block`] is active.
pub fn write_or_offload_diagnostic_line(bytes: &[u8], sink: &DiagnosticLogSink) {
    if bytes.is_empty() {
        return;
    }
    if miraserve_static::inline_work_must_not_block() {
        enqueue_offloaded_diagnostic_log(bytes.to_vec(), Arc::clone(sink));
    } else {
        sink(bytes);
    }
}

/// Returns how many runtime diagnostic log lines were dropped because the bounded off-thread
/// diagnostic queue (1 MiB / 4,096 records) overflowed while the diagnostic sink was stalled.
#[must_use]
pub fn offloaded_diagnostic_log_dropped() -> u64 {
    OFFLOAD_DIAGNOSTIC_LOG_QUEUE.dropped_total()
}

/// Blocks up to `deadline` until all offloaded runtime diagnostic log records have been handed
/// to their sink.
#[must_use]
pub fn flush_offloaded_diagnostic_logs_until_blocking(deadline: Instant) -> OffloadDrainOutcome {
    OFFLOAD_DIAGNOSTIC_LOG_QUEUE.flush_until_blocking(deadline)
}

/// Blocks up to `timeout` (measured from the caller) until all offloaded runtime diagnostic log
/// records have been handed to their sink.
#[must_use]
pub fn flush_offloaded_diagnostic_logs_blocking(timeout: Duration) -> OffloadDrainOutcome {
    flush_offloaded_diagnostic_logs_until_blocking(Instant::now() + timeout)
}

/// Awaits up to `deadline` (measured from the caller) until all offloaded runtime diagnostic log
/// records have been handed to their sink.
#[must_use]
pub async fn flush_offloaded_diagnostic_logs_until(deadline: Instant) -> OffloadDrainOutcome {
    OFFLOAD_DIAGNOSTIC_LOG_QUEUE
        .flush_until_async(deadline)
        .await
}

/// Awaits up to `timeout` (measured from the caller) until all offloaded runtime diagnostic log
/// records have been handed to their sink.
#[must_use]
pub async fn flush_offloaded_diagnostic_logs(timeout: Duration) -> OffloadDrainOutcome {
    flush_offloaded_diagnostic_logs_until(Instant::now() + timeout).await
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::{Duration, Instant};

    use super::{OffloadDrainOutcome, OffloadLogItem, OffloadLogQueue};

    struct TestItem {
        size: usize,
        run: Box<dyn FnOnce() + Send>,
    }

    impl OffloadLogItem for TestItem {
        fn approx_bytes(&self) -> usize {
            self.size
        }

        fn emit_now(self) {
            (self.run)();
        }
    }

    fn noop_report(_: u64) {}

    /// P1-2: Deterministic retiring-drainer race test.
    ///
    /// Parks Drainer A via `after_release_hook` AFTER it releases `draining = false` and disarms
    /// its guard, BEFORE it returns (and runs `DrainerToken::drop`). While A is parked there,
    /// enqueues a batch `[2, 3, 4]` that starts Drainer B and blocks B inside item 2's sink,
    /// then lets A return and run `Drop`. Verifies:
    /// 1. Drainer A's return does NOT clear B's ownership (`drained` remains `false` with `3`
    ///    records outstanding while B's batch is inside the sink).
    /// 2. Enqueuing item 5 while B is blocked does NOT start a second concurrent drainer
    ///    (`max_concurrent == 1`), and `remaining` reflects `3 (batch) + 1 (queue) = 4`.
    /// 3. Once B unblocks, all records emit in exact FIFO order `[1, 2, 3, 4, 5]` and drain
    ///    reports clean.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn retiring_drainer_does_not_clear_successor_ownership()
    -> Result<(), Box<dyn std::error::Error>> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;

        let q = OffloadLogQueue::<TestItem>::new(
            1024 * 1024,
            1024,
            Duration::from_secs(30),
            noop_report,
        );
        let emitted: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let active_drainers = Arc::new(AtomicUsize::new(0));
        let max_concurrent = Arc::new(AtomicUsize::new(0));

        let (a_paused_tx, a_paused_rx) = std::sync::mpsc::channel::<()>();
        let (a_resume_tx, a_resume_rx) = std::sync::mpsc::channel::<()>();
        let a_resume_rx = Arc::new(Mutex::new(Some(a_resume_rx)));
        let a_hook_once = Arc::new(AtomicBool::new(false));
        let a_hook_once_c = Arc::clone(&a_hook_once);
        q.set_after_release_hook(Some(Arc::new(move || {
            if !a_hook_once_c.swap(true, Ordering::AcqRel) {
                let _ = a_paused_tx.send(());
                if let Some(rx) = a_resume_rx
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take()
                {
                    let _ = rx.recv_timeout(Duration::from_secs(10));
                }
            }
        })));

        let (b_entered_tx, b_entered_rx) = std::sync::mpsc::channel::<()>();
        let (b_release_tx, b_release_rx) = std::sync::mpsc::channel::<()>();
        let b_release_rx = Arc::new(Mutex::new(Some(b_release_rx)));

        let make_item = |id: u32, block_on_b: bool| {
            let emitted = Arc::clone(&emitted);
            let active = Arc::clone(&active_drainers);
            let max_c = Arc::clone(&max_concurrent);
            let b_entered = b_entered_tx.clone();
            let b_release = Arc::clone(&b_release_rx);
            TestItem {
                size: 16,
                run: Box::new(move || {
                    let cur = active.fetch_add(1, Ordering::AcqRel) + 1;
                    max_c.fetch_max(cur, Ordering::AcqRel);
                    if block_on_b {
                        let _ = b_entered.send(());
                        if let Some(rx) = b_release
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .take()
                        {
                            let _ = rx.recv_timeout(Duration::from_secs(10));
                        }
                    }
                    emitted
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(id);
                    active.fetch_sub(1, Ordering::AcqRel);
                }),
            }
        };

        rt.block_on(async {
            // 1. Enqueue item 1 -> Drainer A processes it, releases ownership, and pauses in hook.
            q.enqueue(make_item(1, false));
            a_paused_rx
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| "Drainer A never reached after_release_hook")?;

            // 2. While A is parked between release and return, enqueue [2, 3, 4].
            //    Item 2 starts Drainer B and parks B inside the sink with [2, 3, 4] in its batch.
            q.enqueue(make_item(2, true));
            b_entered_rx
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| "Drainer B never entered blocked sink for item 2")?;
            q.enqueue(make_item(3, false));
            q.enqueue(make_item(4, false));

            // 3. Let Drainer A return and run `DrainerToken::drop` while B is still inside item 2.
            let _ = a_resume_tx.send(());
            tokio::time::sleep(Duration::from_millis(30)).await;

            // 4. Shutdown's drained predicate MUST remain false (B holds item 2 in its local batch,
            //    and items 3, 4 are queued -> 3 outstanding total).
            let mid = q.flush_until_blocking(Instant::now() + Duration::from_millis(25));
            assert!(
                !mid.drained,
                "shutdown drained predicate must be false while Drainer B is inside sink"
            );
            assert_eq!(
                mid.remaining, 3,
                "outstanding count must include item 2 in B's local batch plus queued items 3 and 4"
            );

            // 5. Enqueue item 5 while B is STILL inside item 2 -> MUST NOT start a 2nd drainer!
            q.enqueue(make_item(5, false));
            tokio::time::sleep(Duration::from_millis(30)).await;
            assert_eq!(
                max_concurrent.load(Ordering::Acquire),
                1,
                "at most one concurrent drainer may ever run"
            );
            let mid2 = q.snapshot_outcome();
            assert!(!mid2.drained);
            assert_eq!(mid2.remaining, 4);

            // 6. Release Drainer B and verify clean drain + exact FIFO order.
            let _ = b_release_tx.send(());
            let done = q
                .flush_until_async(Instant::now() + Duration::from_secs(5))
                .await;
            assert_eq!(done, OffloadDrainOutcome::clean());
            assert_eq!(
                max_concurrent.load(Ordering::Acquire),
                1,
                "no second concurrent drainer may run across the whole test"
            );
            let got = emitted
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            assert_eq!(got, vec![1, 2, 3, 4, 5]);
            Ok::<_, Box<dyn std::error::Error>>(())
        })
    }

    /// P1-2: A panic inside a sink must release ownership cleanly under the lock, preserve
    /// un-emitted batch and queued records, and restart draining so nothing is stranded.
    #[test]
    fn sink_panic_releases_ownership_and_restarts_draining_for_remaining_records()
    -> Result<(), Box<dyn std::error::Error>> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;

        let q = OffloadLogQueue::<TestItem>::new(
            1024 * 1024,
            1024,
            Duration::from_secs(30),
            noop_report,
        );
        let emitted: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let (hold_entered_tx, hold_entered_rx) = std::sync::mpsc::channel::<()>();
        let (hold_release_tx, hold_release_rx) = std::sync::mpsc::channel::<()>();
        let hold_release_rx = Arc::new(Mutex::new(Some(hold_release_rx)));

        rt.block_on(async {
            // Item 1 pauses so items 2 (panics), 3, and 4 are all queued together into one batch.
            let e1 = Arc::clone(&emitted);
            let rx1 = Arc::clone(&hold_release_rx);
            q.enqueue(TestItem {
                size: 16,
                run: Box::new(move || {
                    let _ = hold_entered_tx.send(());
                    if let Some(rx) = rx1.lock().unwrap_or_else(PoisonError::into_inner).take() {
                        let _ = rx.recv_timeout(Duration::from_secs(10));
                    }
                    e1.lock().unwrap_or_else(PoisonError::into_inner).push(1);
                }),
            });
            hold_entered_rx
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| "item 1 did not enter sink")?;

            // Item 2 triggers a sink panic via unwinding (`resume_unwind` avoids the clippy
            // `panic = "deny"` lint while performing a genuine Rust stack unwind).
            q.enqueue(TestItem {
                size: 16,
                run: Box::new(|| {
                    std::panic::resume_unwind(Box::new("simulated sink panic"));
                }),
            });
            for id in [3_u32, 4] {
                let e = Arc::clone(&emitted);
                q.enqueue(TestItem {
                    size: 16,
                    run: Box::new(move || {
                        e.lock().unwrap_or_else(PoisonError::into_inner).push(id);
                    }),
                });
            }

            let _ = hold_release_tx.send(());
            let done = q
                .flush_until_async(Instant::now() + Duration::from_secs(5))
                .await;
            assert_eq!(done, OffloadDrainOutcome::clean());
            assert_eq!(
                *emitted.lock().unwrap_or_else(PoisonError::into_inner),
                vec![1, 3, 4],
                "items 3 and 4 after panicking item 2 must be drained in FIFO order"
            );

            // Also verify a panic on the sole remaining item leaves the queue usable afterward.
            q.enqueue(TestItem {
                size: 16,
                run: Box::new(|| {
                    std::panic::resume_unwind(Box::new("sole-item sink panic"));
                }),
            });
            let done_after_sole = q
                .flush_until_async(Instant::now() + Duration::from_secs(5))
                .await;
            assert_eq!(done_after_sole, OffloadDrainOutcome::clean());

            let e5 = Arc::clone(&emitted);
            q.enqueue(TestItem {
                size: 16,
                run: Box::new(move || {
                    e5.lock().unwrap_or_else(PoisonError::into_inner).push(5);
                }),
            });
            let done5 = q
                .flush_until_async(Instant::now() + Duration::from_secs(5))
                .await;
            assert_eq!(done5, OffloadDrainOutcome::clean());
            assert_eq!(
                *emitted.lock().unwrap_or_else(PoisonError::into_inner),
                vec![1, 3, 4, 5]
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        })
    }

    /// P2-3: Drop-report rate-limiting interval MUST be obeyed uniformly — including in the
    /// empty-batch exit branch of the drainer.
    #[test]
    fn empty_batch_branch_obeys_drop_report_interval() -> Result<(), Box<dyn std::error::Error>> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;

        let q = OffloadLogQueue::<TestItem>::new(32, 2, Duration::from_secs(60), noop_report);

        rt.block_on(async {
            let (exit_tx, exit_rx) = std::sync::mpsc::channel::<()>();
            q.set_after_empty_exit_hook(Some(Arc::new(move || {
                let _ = exit_tx.send(());
            })));

            // Burst 1: enqueue an oversized item (size 64 > max_bytes 32) -> dropped, triggers
            // 1st drop report immediately when the drainer inspects the empty queue.
            q.enqueue(TestItem {
                size: 64,
                run: Box::new(|| {}),
            });
            let d1 = q
                .flush_until_async(Instant::now() + Duration::from_secs(5))
                .await;
            assert_eq!(d1, OffloadDrainOutcome::clean());
            assert_eq!(q.dropped_total(), 1);
            // Wait until Burst 1's retiring drainer passes the post-emission exit hook so any
            // `emit_drop_report` call has deterministically completed before inspecting the count.
            exit_rx
                .recv_timeout(Duration::from_secs(2))
                .map_err(|_| "Burst 1 drainer did not reach post-emission exit hook")?;
            assert_eq!(q.drop_reports_emitted(), 1);

            // Burst 2 immediately afterward (well within the 60 s interval): MUST increment
            // `dropped_total` but MUST NOT bypass the interval on the empty-batch exit branch!
            q.enqueue(TestItem {
                size: 64,
                run: Box::new(|| {}),
            });
            let d2 = q
                .flush_until_async(Instant::now() + Duration::from_secs(5))
                .await;
            assert_eq!(d2, OffloadDrainOutcome::clean());
            assert_eq!(q.dropped_total(), 2);
            // Wait until Burst 2's retiring drainer passes the post-emission exit hook (strictly
            // AFTER any optional `emit_drop_report` call), closing any scheduling race window.
            exit_rx
                .recv_timeout(Duration::from_secs(2))
                .map_err(|_| "Burst 2 drainer did not reach post-emission exit hook")?;
            assert_eq!(
                q.drop_reports_emitted(),
                1,
                "empty-batch branch must obey the 30s/60s drop-report interval"
            );
            q.set_after_empty_exit_hook(None);
            Ok::<_, Box<dyn std::error::Error>>(())
        })
    }

    /// P2-1: `flush_until_async` fast-paths cleanly when already drained (no blocking-pool wait)
    /// and enforces a caller-measured deadline without starting a fresh timeout inside the pool.
    #[test]
    fn caller_measured_deadline_and_fast_path_when_drained()
    -> Result<(), Box<dyn std::error::Error>> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let q = OffloadLogQueue::<TestItem>::new(1024, 64, Duration::from_secs(30), noop_report);

        rt.block_on(async {
            // Already drained with an already-expired deadline still fast-paths to clean.
            let expired = Instant::now()
                .checked_sub(Duration::from_secs(1))
                .unwrap_or_else(Instant::now);
            assert_eq!(
                q.flush_until_async(expired).await,
                OffloadDrainOutcome::clean()
            );

            // With one blocked item in the drainer's local batch, an already-expired deadline
            // returns immediately with `drained: false, remaining: 1`.
            let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let release_rx = Arc::new(Mutex::new(Some(release_rx)));
            q.enqueue(TestItem {
                size: 16,
                run: Box::new(move || {
                    let _ = entered_tx.send(());
                    if let Some(rx) = release_rx
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .take()
                    {
                        let _ = rx.recv_timeout(Duration::from_secs(10));
                    }
                }),
            });
            entered_rx
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| "blocked item never entered sink")?;

            let t0 = Instant::now();
            let timed_out = q.flush_until_async(t0 + Duration::from_millis(30)).await;
            assert!(!timed_out.drained);
            assert_eq!(timed_out.remaining, 1);
            assert!(
                t0.elapsed() < Duration::from_secs(1),
                "drain must honor the caller's short deadline promptly"
            );

            let _ = release_tx.send(());
            assert_eq!(
                q.flush_until_async(Instant::now() + Duration::from_secs(5))
                    .await,
                OffloadDrainOutcome::clean()
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        })
    }

    /// Reproduces the runtime-teardown enqueue sequence: an async task dropped during
    /// `tokio::runtime::Runtime::drop` enqueues a record while `Handle::try_current()` still
    /// returns the shutting-down runtime whose blocking pool rejects `spawn_blocking`
    /// (`SpawnError::ShuttingDown`). Because `flush_until_blocking` is called immediately after
    /// `drop(rt)` before observing delivery, this test proves eventual clean delivery (never
    /// stranding) through either recovery path (`DrainerToken::drop`'s detached-thread hand-off or
    /// `flush_until_blocking`'s orphan rescue).
    #[test]
    fn enqueue_during_tokio_runtime_shutdown_does_not_strand_records()
    -> Result<(), Box<dyn std::error::Error>> {
        struct EnqueueOnDrop {
            q: Arc<OffloadLogQueue<TestItem>>,
            emitted: Arc<AtomicUsize>,
        }

        impl Drop for EnqueueOnDrop {
            fn drop(&mut self) {
                let emitted = Arc::clone(&self.emitted);
                self.q.enqueue(TestItem {
                    size: 16,
                    run: Box::new(move || {
                        emitted.fetch_add(1, Ordering::AcqRel);
                    }),
                });
            }
        }

        let q = OffloadLogQueue::<TestItem>::new(1024, 64, Duration::from_secs(30), noop_report);
        let emitted = Arc::new(AtomicUsize::new(0));

        for _ in 0..8 {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?;
            let entered = Arc::new(tokio::sync::Notify::new());
            let entered_c = Arc::clone(&entered);
            let guard_obj = EnqueueOnDrop {
                q: Arc::clone(&q),
                emitted: Arc::clone(&emitted),
            };
            rt.block_on(async {
                tokio::spawn(async move {
                    let _guard = guard_obj;
                    entered_c.notify_one();
                    std::future::pending::<()>().await;
                });
                entered.notified().await;
            });
            // Dropping `rt` cancels the parked task during runtime shutdown, triggering
            // `EnqueueOnDrop::drop` -> `q.enqueue(...)` while the blocking pool is shutting down.
            drop(rt);
            let outcome = q.flush_until_blocking(Instant::now() + Duration::from_secs(5));
            assert_eq!(
                outcome,
                OffloadDrainOutcome::clean(),
                "record enqueued during Tokio runtime shutdown must drain cleanly, never strand"
            );
        }

        assert_eq!(emitted.load(Ordering::Acquire), 8);
        Ok(())
    }

    #[test]
    fn drain_report_flags_are_independent() {
        use super::OffloadLogDrainReport;

        let clean = OffloadLogDrainReport::clean();
        assert!(clean.is_clean());
        assert!(!clean.connections_forced_closed);
        assert!(!clean.workers_join_timed_out);

        let forced = OffloadLogDrainReport {
            connections_forced_closed: true,
            ..clean
        };
        assert!(!forced.is_clean());
        assert!(!forced.workers_join_timed_out);

        let unjoined = OffloadLogDrainReport {
            workers_join_timed_out: true,
            ..clean
        };
        assert!(!unjoined.is_clean());
        assert!(!unjoined.connections_forced_closed);
    }
}

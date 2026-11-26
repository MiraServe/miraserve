//! Runs selected streams of an HTTP/2 connection inside the connection's own task while spawning
//! waiting streams as independent Tokio tasks (v0.1.4's model).
//!
//! `hyper` hands every HTTP/2 stream's future (and any HTTP/2 `CONNECT` upgraded send-stream task)
//! to its configured executor. With `TokioExecutor` each stream becomes an independent task on the
//! runtime: a heap allocation and scheduler round trip per request, and on a multi-thread runtime
//! the stream often runs on another worker thread than its connection (a cross-thread wake-up, and
//! responses travel back through shared mutex state).
//!
//! In-task execution speeds up requests that finish in one poll (static files, redirects, fixed
//! responses, immediate errors, ACME answers) and slows down requests that wait on another task
//! (reverse proxy, FastCGI/PHP, WASM, MCP/publish). Therefore [`InTaskExec`] dispatches **per
//! request** using a per-connection [`StreamHandoff`] cell (`AtomicU8` inside the connection's
//! single shared `Arc<InTaskInner>`, never a thread-local):
//!
//! - In pinned `hyper 1.12.0` (`proto/h2/server.rs:308–316`), `Serving::poll_server` calls
//!   `service.call(req)` (`L309`), clones `exec` for `H2Stream` (`L313`), and immediately calls
//!   `exec.execute_h2stream(fut)` (`L316`) synchronously inside `Driven::poll` -> `conn.poll`.
//! - The connection's service closure classifies the request synchronously from the compiled
//!   router and stores [`StreamExec::InTask`] or [`StreamExec::Spawn`] into its [`StreamHandoff`].
//! - `InTaskExec::execute` takes the decision:
//!   - [`StreamExec::InTask`]: wraps the stream in [`IsolatedStream`] and queues it for [`Driven`]
//!     to poll in its `FuturesUnordered` inside the connection's task.
//!   - [`StreamExec::Spawn`]: hands `fut` directly to `tokio::spawn(fut)` — not in `Driven`'s set,
//!     no [`IsolatedStream`], no poll budget, no non-blocking inline context (exact v0.1.4 model).
//!   - Missing decision or double `service.call` without an intervening `execute`: counts the
//!     mismatch ([`test_h2_handoff_mismatch_count`]), falls back to the safe side (`tokio::spawn`),
//!     and trips `debug_assert!`.
//! - Non-stream executor uses in pinned `hyper 1.12.0` / `hyper-util 0.1.21`:
//!   - `hyper-util 0.1.21` (`server/conn/auto/mod.rs:95–97, 686–694`): passes the executor ONLY to
//!     `http2::Builder`; HTTP/1.x connections and HTTP/1.1 upgrades never touch `InTaskExec`, and
//!     the service closure only writes [`StreamHandoff`] on `Version::HTTP_2` requests.
//!   - `hyper 1.12.0` (`proto/h2/server.rs:313, 509`): `H2Stream` holds `exec.clone()` solely to
//!     run `self.exec.execute_upgrade(up_task)` (`UpgradedSendStreamTask`) when an HTTP/2 `CONNECT`
//!     returns `2xx`. Cloning [`InTaskExec`] while a stream decision is pending yields
//!     `InTaskExec::UpgradeOnly`, which spawns `up_task` directly onto `tokio::spawn` without
//!     touching the hand-off cell or cloning the connection's `Arc`.
//!
//! For in-task streams, [`Driven`] enforces:
//! - **Panic isolation ([`IsolatedStream`]):** every stream poll and drop runs inside
//!   [`std::panic::catch_unwind`]. A panicking handler drops only its own `hyper` stream future
//!   (causing `h2` to emit `RST_STREAM(CANCEL)` for that stream and drop in-flight guards), while
//!   sibling streams and the connection continue unaffected.
//! - **Bounded work per poll:** each [`Driven::poll`] caps both the number of stream polls
//!   ([`MAX_STREAM_POLLS_PER_POLL`]) and outer accept/poll iterations ([`MAX_OUTER_ITERATIONS`]),
//!   and respects Tokio's cooperative task budget, then yields back to the runtime (waking itself
//!   and returning `Poll::Pending`) so one busy connection cannot starve sibling connections on a
//!   worker thread.
//! - **Race-free wake-ups:** while `Driven` is parked, any asynchronous [`InTaskExec::execute`]
//!   wakes the stored connection waker outside the queue lock; while [`Driven::poll`] is active,
//!   synchronous `execute` calls skip waking to avoid spurious reschedules.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};

use futures_util::stream::{FuturesUnordered, StreamExt as _};
use hyper_util::rt::TokioExecutor;

/// Counts any hand-off protocol mismatch (missing decision on `execute`, double `service.call`
/// without an intervening `execute`, or an unconsumed decision left after `conn.poll`).
static HANDOFF_MISMATCHES: AtomicUsize = AtomicUsize::new(0);

#[cfg(any(test, feature = "test-h2-hooks"))]
static TEST_H2_EXEC_OVERRIDE: AtomicU8 = AtomicU8::new(0);

#[cfg(any(test, feature = "test-h2-hooks"))]
static TEST_INTASK_STREAMS_EXECUTED: AtomicUsize = AtomicUsize::new(0);

#[cfg(any(test, feature = "test-h2-hooks"))]
static TEST_SPAWNED_STREAMS_EXECUTED: AtomicUsize = AtomicUsize::new(0);

#[cfg(any(test, feature = "test-h2-hooks"))]
static TEST_UPGRADE_TASKS_SPAWNED: AtomicUsize = AtomicUsize::new(0);

/// Integration-test RAII guard forcing HTTP/2 connections onto `InTaskExec` (`Some(true)`),
/// `TokioExecutor` (`Some(false)`), or restoring automatic capability dispatch (`None`).
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
pub struct TestH2ExecOverrideGuard {
    prev: u8,
}

#[cfg(any(test, feature = "test-h2-hooks"))]
impl Drop for TestH2ExecOverrideGuard {
    fn drop(&mut self) {
        TEST_H2_EXEC_OVERRIDE.store(self.prev, Ordering::Relaxed);
    }
}

/// Integration-test helper overriding per-connection HTTP/2 executor selection until drop.
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
#[must_use]
pub fn test_h2_exec_override_guard(force_in_task: Option<bool>) -> TestH2ExecOverrideGuard {
    let val = match force_in_task {
        Some(true) => 1,
        Some(false) => 2,
        None => 0,
    };
    let prev = TEST_H2_EXEC_OVERRIDE.swap(val, Ordering::Relaxed);
    TestH2ExecOverrideGuard { prev }
}

/// Returns `(in_task_streams, spawned_streams)` executed through [`H2Exec`] since process start.
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
#[must_use]
pub fn test_h2_exec_stream_counts() -> (usize, usize) {
    (
        TEST_INTASK_STREAMS_EXECUTED.load(Ordering::Acquire),
        TEST_SPAWNED_STREAMS_EXECUTED.load(Ordering::Acquire),
    )
}

/// Returns how many HTTP/2 stream hand-off mismatches have been observed since process start.
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
#[must_use]
pub fn test_h2_handoff_mismatch_count() -> usize {
    HANDOFF_MISMATCHES.load(Ordering::Acquire)
}

#[cfg(test)]
pub(crate) fn h2_exec_test_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Returns how many HTTP/2 `CONNECT` upgrade send-stream tasks were spawned directly via
/// `InTaskExec::UpgradeOnly` since process start.
#[cfg(any(test, feature = "test-h2-hooks"))]
#[doc(hidden)]
#[must_use]
pub fn test_h2_upgrade_tasks_spawned() -> usize {
    TEST_UPGRADE_TASKS_SPAWNED.load(Ordering::Acquire)
}

/// Per-request HTTP/2 stream execution decision stored in [`StreamHandoff`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StreamExec {
    /// Run this stream inside the connection's own task (`Driven` + `IsolatedStream`).
    InTask,
    /// Spawn this stream as its own Tokio task (`tokio::spawn`, v0.1.4 model).
    Spawn,
}

const HANDOFF_EMPTY: u8 = 0;
const HANDOFF_IN_TASK: u8 = 1;
const HANDOFF_SPAWN: u8 = 2;

impl StreamExec {
    const fn encode(self) -> u8 {
        match self {
            Self::InTask => HANDOFF_IN_TASK,
            Self::Spawn => HANDOFF_SPAWN,
        }
    }
}

/// Selected HTTP/2 stream execution mode for a server configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum H2ExecMode {
    /// Run static/local HTTP/2 stream futures inside the connection's own task (`InTaskExec` +
    /// `Driven`) while spawning waiting handlers (reverse-proxy, FastCGI, WASM, MCP) as separate
    /// Tokio tasks.
    InTask,
    /// Spawn one Tokio task per HTTP/2 stream (`TokioExecutor`, v0.1.4 model).
    Spawned,
}

impl H2ExecMode {
    /// Stable label used in startup and reload logs (`"in-task"` or `"spawned"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InTask => "in-task",
            Self::Spawned => "spawned",
        }
    }

    pub(crate) const fn encode(self) -> u8 {
        match self {
            Self::InTask => 1,
            Self::Spawned => 2,
        }
    }
}

/// Result of evaluating the HTTP/2 stream execution mode for a configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct H2ExecSelection {
    /// Selected HTTP/2 stream execution mode.
    pub mode: H2ExecMode,
    /// Stable operator-facing reason string for startup and reload logs.
    pub reason: &'static str,
}

/// Evaluates whether new HTTP/2 connections should use per-request in-task execution
/// ([`H2ExecMode::InTask`]: static/local streams in-task, waiting handlers spawned) or plain
/// [`H2ExecMode::Spawned`] (`TokioExecutor`, zero overhead, exact v0.1.4 model), avoiding any
/// `openat2(2)` probe unless HTTP/2, static file work, and Linux 5.12–6.11 are ALL active:
///
/// 1. No HTTP/2 listener configured -> `Spawned` (no `openat2` syscall).
/// 2. No static file work configured -> `Spawned` (no `openat2` syscall; nothing would run
///    in-task, so plain `TokioExecutor` avoids the per-connection driver completely).
/// 3. Non-Linux or host kernel outside Linux 5.12–6.11 -> `Spawned` (no `openat2` syscall).
/// 4. Otherwise -> checks (and when `active_probe` is `true`, actively probes) `openat2` +
///    `RESOLVE_CACHED`; selects `InTask` iff `NonblockingStaticSupport::Available`.
#[must_use]
pub fn select_h2_exec_mode(
    has_h2_listener: bool,
    has_static_work: bool,
    active_probe: bool,
) -> H2ExecSelection {
    if !has_h2_listener {
        return H2ExecSelection {
            mode: H2ExecMode::Spawned,
            reason: "no HTTP/2 listener is configured",
        };
    }
    if !has_static_work {
        return H2ExecSelection {
            mode: H2ExecMode::Spawned,
            reason: "no static file work is configured (waiting handlers run as separate tasks)",
        };
    }
    if !miraserve_static::kernel_supports_h2_intask_static() {
        let reason = if cfg!(target_os = "linux") {
            miraserve_static::NonblockingStaticSupport::KernelOutsideNowaitRange.reason()
        } else {
            miraserve_static::NonblockingStaticSupport::UnsupportedPlatform.reason()
        };
        return H2ExecSelection {
            mode: H2ExecMode::Spawned,
            reason,
        };
    }
    let support = if active_probe {
        miraserve_static::probe_nonblocking_static_support()
    } else {
        miraserve_static::nonblocking_static_support()
    };
    if support == miraserve_static::NonblockingStaticSupport::Available {
        H2ExecSelection {
            mode: H2ExecMode::InTask,
            reason: "static/local HTTP/2 streams run in-task (openat2 + RESOLVE_CACHED available on Linux 5.12-6.11); waiting handlers (reverse-proxy, FastCGI, WASM, MCP) run as separate tasks",
        }
    } else {
        H2ExecSelection {
            mode: H2ExecMode::Spawned,
            reason: support.reason(),
        }
    }
}

pub(crate) fn should_use_in_task_h2(has_h2_listener: bool, has_static_work: bool) -> bool {
    #[cfg(any(test, feature = "test-h2-hooks"))]
    match TEST_H2_EXEC_OVERRIDE.load(Ordering::Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    select_h2_exec_mode(has_h2_listener, has_static_work, false).mode == H2ExecMode::InTask
}

/// Maximum number of stream-future polls performed in a single [`Driven::poll`] turn before
/// flushing the connection once and yielding back to the scheduler.
///
/// Chosen to complete common multiplexed bursts (e.g. 10–64 streams) in one turn while staying
/// strictly below Tokio's 128-unit cooperative budget and preventing a saturated HTTP/2 connection
/// from monopolizing a worker thread.
pub(crate) const MAX_STREAM_POLLS_PER_POLL: usize = 64;

/// Maximum number of outer `(poll streams -> poll conn -> drain new streams)` iterations per
/// [`Driven::poll`] turn before yielding back to the scheduler.
///
/// A normal burst completes in two iterations (accept batch, then execute + flush); capping at 4
/// absorbs a quick follow-up batch while guaranteeing a tight single-stream pipelining loop yields
/// promptly to sibling connections.
pub(crate) const MAX_OUTER_ITERATIONS: usize = 4;

type StreamFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Per-connection remaining stream-poll budget for the current [`Driven::poll`] call.
///
/// Only mutated by the connection task while [`Driven::poll`] runs; atomics are used solely so
/// [`IsolatedStream`] satisfies `Send` inside `FuturesUnordered`.
#[derive(Default)]
struct PollBudget {
    remaining: AtomicUsize,
    exhausted: AtomicBool,
}

#[derive(Default)]
struct QueueState {
    queued: Vec<IsolatedStream>,
    waker: Option<Waker>,
    polling: bool,
}

/// Single shared per-connection allocation backing [`InTaskExec`], [`StreamHandoff`], [`Driven`],
/// and [`IsolatedStream`].
///
/// `handoff` is a 1-byte `AtomicU8` (`HANDOFF_EMPTY` / `HANDOFF_IN_TASK` / `HANDOFF_SPAWN`):
/// `AtomicU8` is the cheapest `Send + Sync` interior-mutable cell without `unsafe` (`Cell` is
/// `!Sync`, so `Arc<Cell<_>>` is `!Send` and cannot live inside a `tokio::spawn` connection task).
/// Because only the single connection task touches `handoff` (synchronously between
/// `service.call(req)` and `exec.execute_h2stream(fut)` in `hyper 1.12.0`
/// `proto/h2/server.rs:308–316`), `Ordering::Relaxed` suffices with zero fences or locks.
#[derive(Default)]
struct InTaskInner {
    state: Mutex<QueueState>,
    budget: PollBudget,
    handoff: AtomicU8,
}

/// Wrapper around one queued HTTP/2 stream future that isolates panics (in both `poll` and `drop`)
/// and enforces the per-turn stream-poll budget.
struct IsolatedStream {
    fut: Option<StreamFuture>,
    inner: Arc<InTaskInner>,
}

impl IsolatedStream {
    fn new(fut: StreamFuture, inner: Arc<InTaskInner>) -> Self {
        Self {
            fut: Some(fut),
            inner,
        }
    }
}

impl Future for IsolatedStream {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(mut fut) = self.fut.take() else {
            return Poll::Ready(());
        };
        let rem = self.inner.budget.remaining.load(Ordering::Relaxed);
        if rem == 0 || !tokio::task::coop::has_budget_remaining() {
            self.fut = Some(fut);
            self.inner.budget.exhausted.store(true, Ordering::Relaxed);
            // Re-enqueue in `FuturesUnordered` and mark this stream as having yielded so
            // `FuturesUnordered::poll_next` stops polling further ready streams promptly.
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.inner
            .budget
            .remaining
            .store(rem - 1, Ordering::Relaxed);

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // Mark the thread non-blocking for the duration of this stream poll (including
            // handler execution, hyper's `PipeToSendStream` response-body polls inside
            // `H2Stream::poll2`, and synchronous drops of finished stream futures). Using the
            // closure-scoped API guarantees restoration on normal return OR unwind.
            miraserve_static::with_nonblocking_inline_context(|| match fut.as_mut().poll(cx) {
                Poll::Pending => Some(fut),
                Poll::Ready(()) => {
                    drop(fut);
                    None
                }
            })
        }));

        match outcome {
            Ok(Some(fut)) => {
                self.fut = Some(fut);
                Poll::Pending
            }
            Ok(None) => Poll::Ready(()),
            Err(payload) => {
                // `fut` was already dropped during stack unwinding inside `catch_unwind`, which
                // dropped hyper's `SendResponse`/`SendStream` (scheduling `RST_STREAM(CANCEL)`)
                // and released all RAII request guards.
                log_stream_panic(&*payload);
                // Guard against a custom panic payload whose own `Drop` panics.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    drop(payload);
                }));
                Poll::Ready(())
            }
        }
    }
}

impl Drop for IsolatedStream {
    fn drop(&mut self) {
        if let Some(fut) = self.fut.take() {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                // Keep the non-blocking context active during drop as well so an incomplete
                // `AccessLogBody::drop` offloads access-log emission off the connection task.
                miraserve_static::with_nonblocking_inline_context(move || {
                    drop(fut);
                });
            }));
            if let Err(payload) = outcome {
                log_stream_panic(&*payload);
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    drop(payload);
                }));
            }
        }
    }
}

fn log_stream_panic(payload: &(dyn std::any::Any + Send)) {
    let msg = if let Some(s) = payload.downcast_ref::<&str>() {
        *s
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.as_str()
    } else {
        "<non-string panic payload>"
    };
    // Emit inside the non-blocking inline context so panic recovery queues its diagnostic line
    // onto the off-thread writer instead of writing synchronously on the connection task.
    miraserve_static::with_nonblocking_inline_context(|| {
        tracing::error!(panic = %msg, "HTTP/2 stream future panicked; stream reset");
    });
}

/// Service-side handle to one HTTP/2 connection's per-request execution hand-off cell.
///
/// Written synchronously inside `service.call(req)` (only for `Version::HTTP_2` requests) and
/// consumed immediately by [`InTaskExec::execute`] in `hyper 1.12.0`
/// (`proto/h2/server.rs:308–316`).
///
/// **UPGRADE INVARIANT (`hyper` / `hyper-util`):** This hand-off relies on `hyper 1.12.0`'s exact
/// synchronous order inside `Serving::poll_server` — `service.call(req)` (`L309`), then per-stream
/// `exec.clone()` into `H2Stream` (`L313`), then `exec.execute_h2stream(fut)` on the original
/// executor (`L316`), with no `.await` or fallible exit between them — and on `hyper-util 0.1.21`'s
/// `auto::Builder` passing the executor only to HTTP/2. Re-review this module on ANY `hyper` or
/// `hyper-util` upgrade; `tests::per_request_handoff_detects_missing_decision_and_double_service_call`
/// acts as a live-`hyper` tripwire that fails on any change to that call/clone/execute order.
pub(crate) struct StreamHandoff {
    inner: Arc<InTaskInner>,
}

impl StreamHandoff {
    /// Records the execution decision for the HTTP/2 request currently inside `service.call(req)`.
    ///
    /// If a previous decision was still unconsumed (service called twice without an intervening
    /// `execute`), increments [`HANDOFF_MISMATCHES`], overwrites the cell with the safe fallback
    /// ([`StreamExec::Spawn`]), and triggers `debug_assert_eq!`.
    pub(crate) fn set(&self, decision: StreamExec) {
        let prev = self.inner.handoff.load(Ordering::Relaxed);
        if prev != HANDOFF_EMPTY {
            HANDOFF_MISMATCHES.fetch_add(1, Ordering::AcqRel);
            // Fall back to the safe side (spawn, v0.1.4 model) before asserting.
            self.inner.handoff.store(HANDOFF_SPAWN, Ordering::Relaxed);
            debug_assert_eq!(
                prev, HANDOFF_EMPTY,
                "HTTP/2 stream hand-off mismatch: service called twice without an intervening execute"
            );
            return;
        }
        self.inner
            .handoff
            .store(decision.encode(), Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn take_for_test(&self) -> u8 {
        self.inner.handoff.swap(HANDOFF_EMPTY, Ordering::Relaxed)
    }
}

/// The executor given to `hyper` for ONE connection.
pub(crate) struct InTaskExec(InTaskExecKind);

enum InTaskExecKind {
    /// Production per-connection executor reading each stream's [`StreamExec`] decision from the
    /// connection's [`StreamHandoff`] cell.
    PerRequest(Arc<InTaskInner>),
    /// Lightweight upgrade-only clone handed into each `H2Stream` at
    /// `hyper 1.12.0` `proto/h2/server.rs:313` (used solely by `H2Stream::poll2` ->
    /// `self.exec.execute_upgrade(up_task)` at line 509). Never touches the connection's hand-off
    /// cell or `Driven` queue; spawns `up_task` directly on Tokio.
    UpgradeOnly,
    /// Unit-test-only unconditional in-task executor for low-level [`Driven`] mechanics tests
    /// (panic isolation, poll budgets, external async wake-up) that do not attach a
    /// [`StreamHandoff`].
    #[cfg(test)]
    AlwaysInTask(Arc<InTaskInner>),
}

impl InTaskExec {
    /// Creates a paired `(InTaskExec, StreamHandoff)` sharing one per-connection `InTaskInner`.
    pub(crate) fn with_handoff() -> (Self, StreamHandoff) {
        let inner = Arc::new(InTaskInner::default());
        let handoff = StreamHandoff {
            inner: Arc::clone(&inner),
        };
        (Self(InTaskExecKind::PerRequest(inner)), handoff)
    }

    fn enqueue_in_task<F>(inner: &Arc<InTaskInner>, fut: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let wrapped = IsolatedStream::new(Box::pin(fut), Arc::clone(inner));
        let waker = {
            let mut state = inner.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.queued.push(wrapped);
            // If `Driven::poll` is currently executing, it will inspect `queued` before parking;
            // waking now would only schedule a redundant turn. When `Driven` is parked, take and
            // wake its stored waker outside the lock.
            if state.polling {
                None
            } else {
                state.waker.take()
            }
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn into_inner_or_default(self) -> Arc<InTaskInner> {
        match self.0 {
            InTaskExecKind::PerRequest(inner) => inner,
            #[cfg(test)]
            InTaskExecKind::AlwaysInTask(inner) => inner,
            InTaskExecKind::UpgradeOnly => Arc::new(InTaskInner::default()),
        }
    }
}

#[cfg(test)]
impl Default for InTaskExec {
    fn default() -> Self {
        Self(InTaskExecKind::AlwaysInTask(Arc::new(
            InTaskInner::default(),
        )))
    }
}

impl Clone for InTaskExec {
    fn clone(&self) -> Self {
        match &self.0 {
            InTaskExecKind::PerRequest(inner) => {
                // UPGRADE INVARIANT (`hyper` / `hyper-util`):
                // In pinned `hyper 1.12.0` (`proto/h2/server.rs:308–316`), `Serving::poll_server`
                // calls `service.call(req)` (`L309`, populating `handoff`), then `exec.clone()`
                // (`L313`) to construct `H2Stream` (which only uses `self.exec` for
                // `execute_upgrade` at `L509`), and finally `exec.execute_h2stream(fut)` (`L316`)
                // on `Server`'s own `exec`. Re-review on ANY `hyper` upgrade; if an upgrade moves
                // `exec.clone()` before `service.call(req)` or after `execute_h2stream(fut)`, or
                // invokes `execute_h2stream` on the per-stream clone, the live-`hyper` tripwire in
                // `tests::per_request_handoff_detects_missing_decision_and_double_service_call`
                // fails via `HANDOFF_MISMATCHES` / `TEST_UPGRADE_TASKS_SPAWNED`.
                //
                // Every connection-setup clone (`AutoConnBuilder::new` and `http2::Builder` at
                // `server/conn/http2.rs:319`) runs while `handoff == HANDOFF_EMPTY`, keeping
                // `InTaskExecKind::PerRequest`. The per-stream clone at `L313` sees a pending
                // decision and returns `InTaskExecKind::UpgradeOnly`, which avoids an `Arc`
                // refcount round-trip on every request AND guarantees a concurrently running
                // spawned `CONNECT` stream's `execute_upgrade` can never race with or steal from
                // `inner.handoff`.
                if inner.handoff.load(Ordering::Relaxed) == HANDOFF_EMPTY {
                    Self(InTaskExecKind::PerRequest(Arc::clone(inner)))
                } else {
                    Self(InTaskExecKind::UpgradeOnly)
                }
            }
            InTaskExecKind::UpgradeOnly => Self(InTaskExecKind::UpgradeOnly),
            #[cfg(test)]
            InTaskExecKind::AlwaysInTask(inner) => {
                Self(InTaskExecKind::AlwaysInTask(Arc::clone(inner)))
            }
        }
    }
}

impl<F> hyper::rt::Executor<F> for InTaskExec
where
    F: Future<Output = ()> + Send + 'static,
{
    fn execute(&self, fut: F) {
        match &self.0 {
            InTaskExecKind::PerRequest(inner) => {
                let decision = inner.handoff.swap(HANDOFF_EMPTY, Ordering::Relaxed);
                match decision {
                    HANDOFF_IN_TASK => {
                        #[cfg(any(test, feature = "test-h2-hooks"))]
                        TEST_INTASK_STREAMS_EXECUTED.fetch_add(1, Ordering::AcqRel);
                        Self::enqueue_in_task(inner, fut);
                    }
                    HANDOFF_SPAWN => {
                        #[cfg(any(test, feature = "test-h2-hooks"))]
                        TEST_SPAWNED_STREAMS_EXECUTED.fetch_add(1, Ordering::AcqRel);
                        drop(tokio::spawn(fut));
                    }
                    _ => {
                        // Missing hand-off decision: count the mismatch, fall back to the safe
                        // side (spawn, v0.1.4 model), and fail loudly in debug builds.
                        HANDOFF_MISMATCHES.fetch_add(1, Ordering::AcqRel);
                        #[cfg(any(test, feature = "test-h2-hooks"))]
                        TEST_SPAWNED_STREAMS_EXECUTED.fetch_add(1, Ordering::AcqRel);
                        drop(tokio::spawn(fut));
                        debug_assert_ne!(
                            decision, HANDOFF_EMPTY,
                            "HTTP/2 stream hand-off mismatch: execute called with no pending service decision"
                        );
                    }
                }
            }
            InTaskExecKind::UpgradeOnly => {
                #[cfg(any(test, feature = "test-h2-hooks"))]
                TEST_UPGRADE_TASKS_SPAWNED.fetch_add(1, Ordering::AcqRel);
                drop(tokio::spawn(fut));
            }
            #[cfg(test)]
            InTaskExecKind::AlwaysInTask(inner) => Self::enqueue_in_task(inner, fut),
        }
    }
}

/// Per-connection HTTP/2 executor that dispatches between [`InTaskExec`] (per-request in-task vs.
/// spawned when non-blocking static serving is available and static work is configured) and
/// [`TokioExecutor`] (exact v0.1.4 one-task-per-stream fallback).
#[derive(Clone)]
pub(crate) enum H2Exec {
    InTask(InTaskExec),
    Spawned(TokioExecutor),
}

impl H2Exec {
    pub(crate) fn for_connection(
        has_h2_listener: bool,
        has_static_work: bool,
    ) -> (Self, Option<StreamHandoff>) {
        if should_use_in_task_h2(has_h2_listener, has_static_work) {
            let (in_task, handoff) = InTaskExec::with_handoff();
            (Self::InTask(in_task), Some(handoff))
        } else {
            (Self::Spawned(TokioExecutor::new()), None)
        }
    }
}

impl<F> hyper::rt::Executor<F> for H2Exec
where
    F: Future<Output = ()> + Send + 'static,
{
    fn execute(&self, fut: F) {
        match self {
            Self::InTask(exec) => exec.execute(fut),
            Self::Spawned(exec) => {
                #[cfg(any(test, feature = "test-h2-hooks"))]
                TEST_SPAWNED_STREAMS_EXECUTED.fetch_add(1, Ordering::AcqRel);
                exec.execute(fut);
            }
        }
    }
}

/// Connection driver matching [`H2Exec`]: polls queued HTTP/2 stream futures alongside `conn` when
/// [`H2Exec::InTask`] was selected, or polls `conn` directly with zero extra overhead when
/// [`H2Exec::Spawned`] was selected.
pub(crate) enum ConnDriver<'a, C> {
    InTask(Driven<'a, C>),
    PassThrough {
        conn: Pin<&'a mut C>,
        graceful: fn(Pin<&mut C>),
    },
}

impl<'a, C> ConnDriver<'a, C> {
    pub(crate) fn new(conn: Pin<&'a mut C>, exec: H2Exec, graceful: fn(Pin<&mut C>)) -> Self {
        match exec {
            H2Exec::InTask(in_task) => Self::InTask(Driven::new(conn, in_task, graceful)),
            H2Exec::Spawned(_) => Self::PassThrough { conn, graceful },
        }
    }

    pub(crate) fn graceful_shutdown(self: Pin<&mut Self>) {
        match self.get_mut() {
            Self::InTask(driven) => Pin::new(driven).graceful_shutdown(),
            Self::PassThrough { conn, graceful } => graceful(conn.as_mut()),
        }
    }
}

impl<C: Future> Future for ConnDriver<'_, C> {
    type Output = C::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            Self::InTask(driven) => Pin::new(driven).poll(cx),
            Self::PassThrough { conn, .. } => conn.as_mut().poll(cx),
        }
    }
}

/// Ensures `QueueState::polling` is cleared even if the inner connection future unwinds.
struct PollingGuard<'a> {
    state: &'a Mutex<QueueState>,
    active: bool,
}

impl Drop for PollingGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.polling = false;
        }
    }
}

/// `hyper`'s connection future together with the stream futures queued by [`InTaskExec`].
pub(crate) struct Driven<'a, C> {
    conn: Pin<&'a mut C>,
    streams: FuturesUnordered<IsolatedStream>,
    scratch: Vec<IsolatedStream>,
    inner: Arc<InTaskInner>,
    graceful: fn(Pin<&mut C>),
    max_stream_polls: usize,
    max_outer_iters: usize,
}

impl<'a, C> Driven<'a, C> {
    pub(crate) fn new(conn: Pin<&'a mut C>, exec: InTaskExec, graceful: fn(Pin<&mut C>)) -> Self {
        Self {
            conn,
            streams: FuturesUnordered::new(),
            scratch: Vec::new(),
            inner: exec.into_inner_or_default(),
            graceful,
            max_stream_polls: MAX_STREAM_POLLS_PER_POLL,
            max_outer_iters: MAX_OUTER_ITERATIONS,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_limits(
        conn: Pin<&'a mut C>,
        exec: InTaskExec,
        graceful: fn(Pin<&mut C>),
        max_stream_polls: usize,
        max_outer_iters: usize,
    ) -> Self {
        Self {
            conn,
            streams: FuturesUnordered::new(),
            scratch: Vec::new(),
            inner: exec.into_inner_or_default(),
            graceful,
            max_stream_polls: max_stream_polls.max(1),
            max_outer_iters: max_outer_iters.max(1),
        }
    }

    pub(crate) fn graceful_shutdown(mut self: Pin<&mut Self>) {
        let this = &mut *self;
        (this.graceful)(this.conn.as_mut());
    }

    fn begin_poll_and_take_queued(
        state_lock: &Mutex<QueueState>,
        scratch: &mut Vec<IsolatedStream>,
        streams: &mut FuturesUnordered<IsolatedStream>,
    ) {
        {
            let mut state = state_lock.lock().unwrap_or_else(PoisonError::into_inner);
            state.polling = true;
            if !state.queued.is_empty() {
                std::mem::swap(&mut state.queued, scratch);
            }
        }
        for fut in scratch.drain(..) {
            streams.push(fut);
        }
    }

    fn finish_poll_ready(state_lock: &Mutex<QueueState>, guard: &mut PollingGuard<'_>) {
        let mut state = state_lock.lock().unwrap_or_else(PoisonError::into_inner);
        state.polling = false;
        state.waker = None;
        guard.active = false;
    }

    /// Polls ready stream futures up to the per-turn budget. Returns `true` if polling stopped
    /// early due to the stream-poll or Tokio cooperative budget while streams may still be ready.
    fn poll_streams(
        streams: &mut FuturesUnordered<IsolatedStream>,
        budget: &PollBudget,
        cx: &mut Context<'_>,
    ) -> bool {
        while budget.remaining.load(Ordering::Relaxed) > 0 {
            if !tokio::task::coop::has_budget_remaining() {
                if !streams.is_empty() {
                    budget.exhausted.store(true, Ordering::Relaxed);
                    return true;
                }
                break;
            }
            match streams.poll_next_unpin(cx) {
                Poll::Ready(Some(())) => {}
                Poll::Ready(None) | Poll::Pending => break,
            }
        }
        if budget.remaining.load(Ordering::Relaxed) == 0 && !streams.is_empty() {
            budget.exhausted.store(true, Ordering::Relaxed);
            return true;
        }
        budget.exhausted.load(Ordering::Relaxed)
    }
}

impl<C> Drop for Driven<'_, C> {
    fn drop(&mut self) {
        // Drop active stream futures first (each `IsolatedStream::drop` catches panics), then
        // release any remaining queued futures outside the queue lock.
        self.streams.clear();
        self.scratch.clear();
        let leftover = {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            state.polling = false;
            state.waker = None;
            std::mem::take(&mut state.queued)
        };
        drop(leftover);
    }
}

impl<C: Future> Future for Driven<'_, C> {
    type Output = C::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        let state_lock = &this.inner.state;
        let budget = &this.inner.budget;
        budget
            .remaining
            .store(this.max_stream_polls, Ordering::Relaxed);
        budget.exhausted.store(false, Ordering::Relaxed);

        let mut guard = PollingGuard {
            state: state_lock,
            active: true,
        };
        Self::begin_poll_and_take_queued(state_lock, &mut this.scratch, &mut this.streams);

        let mut outer_iters: usize = 0;
        loop {
            // Streams first: responses (and any `RST_STREAM` from a panicked stream) are written
            // by the connection poll that follows.
            let hit_stream_budget = Self::poll_streams(&mut this.streams, budget, cx);

            let res = this.conn.as_mut().poll(cx);
            if this.inner.handoff.load(Ordering::Relaxed) != HANDOFF_EMPTY {
                let leftover = this.inner.handoff.swap(HANDOFF_EMPTY, Ordering::Relaxed);
                HANDOFF_MISMATCHES.fetch_add(1, Ordering::AcqRel);
                debug_assert_eq!(
                    leftover, HANDOFF_EMPTY,
                    "HTTP/2 stream hand-off mismatch: service stored a decision that conn.poll did not consume"
                );
            }
            if res.is_ready() {
                Self::finish_poll_ready(state_lock, &mut guard);
                return res;
            }

            outer_iters += 1;
            let hit_budget = hit_stream_budget
                || outer_iters >= this.max_outer_iters
                || budget.remaining.load(Ordering::Relaxed) == 0
                || !tokio::task::coop::has_budget_remaining();

            let mut state = state_lock.lock().unwrap_or_else(PoisonError::into_inner);
            let has_queued = !state.queued.is_empty();
            if has_queued && !hit_budget {
                std::mem::swap(&mut state.queued, &mut this.scratch);
                drop(state);
                for fut in this.scratch.drain(..) {
                    this.streams.push(fut);
                }
                continue;
            }

            state.polling = false;
            guard.active = false;
            let need_yield_wake = hit_stream_budget || has_queued;
            if !need_yield_wake
                && !state
                    .waker
                    .as_ref()
                    .is_some_and(|w| w.will_wake(cx.waker()))
            {
                state.waker = Some(cx.waker().clone());
            }
            drop(state);

            if need_yield_wake {
                cx.waker().wake_by_ref();
            }
            return Poll::Pending;
        }
    }
}

#[cfg(test)]
#[allow(clippy::too_many_lines)]
mod tests {
    use std::convert::Infallible;
    use std::future::Future;
    use std::pin::{Pin, pin};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::Duration;

    use bytes::Bytes;
    use http::{Method, Request, Response, StatusCode};
    use http_body::Frame;
    use http_body_util::{BodyExt as _, Empty, Full, combinators::BoxBody};
    use hyper::body::Incoming;
    use hyper::client::conn::http2 as h2_client;
    use hyper::rt::Executor as _;
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
    use hyper_util::server::conn::auto::Builder as AutoConnBuilder;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::Notify;

    use super::{Driven, InTaskExec};

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    type TestBody = BoxBody<Bytes, Infallible>;

    fn full_body(data: &'static [u8]) -> TestBody {
        Full::new(Bytes::from_static(data)).boxed()
    }

    fn error_chain_text(err: &(dyn std::error::Error + 'static)) -> String {
        let mut out = err.to_string();
        let mut cur = err.source();
        while let Some(src) = cur {
            out.push_str(": ");
            out.push_str(&src.to_string());
            cur = src.source();
        }
        out
    }

    struct FlagWaker(AtomicBool);

    impl Wake for FlagWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// Runs a panicking HTTP/2 service on real TCP loopback under either `TokioExecutor` or
    /// `InTaskExec` + `Driven`, returning the client error message seen on `/panic` after proving
    /// that a concurrent sibling stream and a follow-up request on the same connection both
    /// succeed.
    async fn run_panic_before_headers_case(
        use_in_task: bool,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let release_slow = Arc::new(Notify::new());
        let slow_entered = Arc::new(Notify::new());
        let release_srv = Arc::clone(&release_slow);
        let entered_srv = Arc::clone(&slow_entered);

        let srv_task = tokio::spawn(async move {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let _ = tcp.set_nodelay(true);
            let svc = service_fn(move |req: Request<Incoming>| {
                let release = Arc::clone(&release_srv);
                let entered = Arc::clone(&entered_srv);
                async move {
                    match req.uri().path() {
                        "/panic" => {
                            #[allow(clippy::panic)]
                            {
                                panic!("boom before headers");
                            }
                        }
                        "/slow" => {
                            entered.notify_one();
                            release.notified().await;
                            Ok::<_, Infallible>(Response::new(full_body(b"slow-ok")))
                        }
                        _ => Ok::<_, Infallible>(Response::new(full_body(b"after-ok"))),
                    }
                }
            });

            if use_in_task {
                let exec = InTaskExec::default();
                let mut builder = AutoConnBuilder::new(exec.clone());
                builder.http2().timer(TokioTimer::new());
                let conn = builder.serve_connection_with_upgrades(TokioIo::new(tcp), svc);
                let conn = pin!(conn);
                let driven = Driven::new(
                    conn,
                    exec,
                    hyper_util::server::conn::auto::UpgradeableConnection::graceful_shutdown,
                );
                let _ = driven.await;
            } else {
                let mut builder = AutoConnBuilder::new(TokioExecutor::new());
                builder.http2().timer(TokioTimer::new());
                let _ = builder
                    .serve_connection_with_upgrades(TokioIo::new(tcp), svc)
                    .await;
            }
        });

        let client_tcp = TcpStream::connect(addr).await?;
        let _ = client_tcp.set_nodelay(true);
        let (mut sender, conn) = h2_client::handshake::<_, _, Empty<Bytes>>(
            TokioExecutor::new(),
            TokioIo::new(client_tcp),
        )
        .await?;
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });

        // 1. Start a slow sibling stream on the same connection.
        sender.ready().await?;
        let slow_fut = sender.send_request(
            Request::builder()
                .uri("https://example.test/slow")
                .body(Empty::new())?,
        );
        tokio::time::timeout(Duration::from_secs(5), slow_entered.notified()).await?;

        // 2. Send the panicking stream concurrently while `/slow` is pending.
        sender.ready().await?;
        let panic_res = sender
            .send_request(
                Request::builder()
                    .uri("https://example.test/panic")
                    .body(Empty::new())?,
            )
            .await;
        let Err(panic_err) = panic_res else {
            return Err("panicking stream must fail with RST_STREAM".into());
        };
        let panic_text = error_chain_text(&panic_err);

        // 3. Release `/slow`: it MUST finish cleanly on the same connection.
        release_slow.notify_one();
        let slow_resp = tokio::time::timeout(Duration::from_secs(5), slow_fut).await??;
        assert_eq!(slow_resp.status(), StatusCode::OK);
        let slow_body = slow_resp.into_body().collect().await?.to_bytes();
        assert_eq!(slow_body.as_ref(), b"slow-ok");

        // 4. Send a follow-up request on the SAME connection: connection must stay alive.
        assert!(
            !conn_task.is_finished(),
            "connection must stay open after a single stream panics"
        );
        sender.ready().await?;
        let after_resp = sender
            .send_request(
                Request::builder()
                    .uri("https://example.test/after")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(after_resp.status(), StatusCode::OK);
        let after_body = after_resp.into_body().collect().await?.to_bytes();
        assert_eq!(after_body.as_ref(), b"after-ok");

        drop(sender);
        let _ = tokio::time::timeout(Duration::from_secs(5), conn_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), srv_task).await;
        Ok(panic_text)
    }

    #[tokio::test]
    async fn panic_before_headers_matches_tokio_executor_rst_stream_cancel() -> TestResult {
        let _tracing_serial = crate::test_tracing_lock().lock().await;
        let baseline = run_panic_before_headers_case(false).await?;
        let in_task = run_panic_before_headers_case(true).await?;
        assert_eq!(
            in_task, baseline,
            "in-task panic isolation must present the exact same client-visible reset as TokioExecutor"
        );
        // `h2::Reason::CANCEL` formats as "stream no longer needed".
        assert!(
            in_task.contains("stream no longer needed"),
            "expected RST_STREAM(CANCEL), got: {in_task}"
        );
        Ok(())
    }

    /// Response body that yields one DATA chunk and panics on the second poll.
    struct PanicAfterFirstChunk {
        sent_first: bool,
    }

    impl http_body::Body for PanicAfterFirstChunk {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            if !self.sent_first {
                self.sent_first = true;
                return Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"chunk1-")))));
            }
            #[allow(clippy::panic)]
            {
                panic!("boom mid-body");
            }
        }
    }

    #[tokio::test]
    async fn panic_mid_body_resets_only_that_stream_and_keeps_connection() -> TestResult {
        let _tracing_serial = crate::test_tracing_lock().lock().await;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let srv_task = tokio::spawn(async move {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let _ = tcp.set_nodelay(true);
            let svc = service_fn(|req: Request<Incoming>| async move {
                if req.uri().path() == "/panic-body" {
                    let body: TestBody = PanicAfterFirstChunk { sent_first: false }.boxed();
                    Ok::<_, Infallible>(Response::new(body))
                } else {
                    Ok::<_, Infallible>(Response::new(full_body(b"healthy")))
                }
            });
            let exec = InTaskExec::default();
            let mut builder = AutoConnBuilder::new(exec.clone());
            builder.http2().timer(TokioTimer::new());
            let conn = builder.serve_connection_with_upgrades(TokioIo::new(tcp), svc);
            let conn = pin!(conn);
            let _ = Driven::new(
                conn,
                exec,
                hyper_util::server::conn::auto::UpgradeableConnection::graceful_shutdown,
            )
            .await;
        });

        let client_tcp = TcpStream::connect(addr).await?;
        let _ = client_tcp.set_nodelay(true);
        let (mut sender, conn) = h2_client::handshake::<_, _, Empty<Bytes>>(
            TokioExecutor::new(),
            TokioIo::new(client_tcp),
        )
        .await?;
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });

        sender.ready().await?;
        let resp = sender
            .send_request(
                Request::builder()
                    .uri("https://example.test/panic-body")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(resp.status(), StatusCode::OK);
        let body_err = resp
            .into_body()
            .collect()
            .await
            .err()
            .ok_or("mid-body panic must reset stream before EOF")?;
        let err_text = error_chain_text(&body_err);
        assert!(
            err_text.contains("stream no longer needed"),
            "expected RST_STREAM(CANCEL) mid-body, got: {err_text}"
        );

        assert!(!conn_task.is_finished());
        sender.ready().await?;
        let ok_resp = sender
            .send_request(
                Request::builder()
                    .uri("https://example.test/ok")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(ok_resp.status(), StatusCode::OK);
        assert_eq!(
            ok_resp.into_body().collect().await?.to_bytes().as_ref(),
            b"healthy"
        );

        drop(sender);
        let _ = tokio::time::timeout(Duration::from_secs(5), conn_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), srv_task).await;
        Ok(())
    }

    /// Verifies wire-level `RST_STREAM` frame carries exact error code `0x8` (`CANCEL`) for the
    /// panicking stream and does NOT emit `GOAWAY`.
    #[tokio::test]
    async fn panic_emits_wire_rst_stream_cancel_without_goaway() -> TestResult {
        const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        let _tracing_serial = crate::test_tracing_lock().lock().await;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let srv_task = tokio::spawn(async move {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let _ = tcp.set_nodelay(true);
            let svc = service_fn(|_req: Request<Incoming>| async move {
                #[allow(clippy::panic)]
                {
                    panic!("wire-level panic test");
                }
                #[allow(unreachable_code)]
                Ok::<_, Infallible>(Response::new(full_body(b"unreachable")))
            });
            let exec = InTaskExec::default();
            let mut builder = AutoConnBuilder::new(exec.clone());
            builder.http2().timer(TokioTimer::new());
            let conn = builder.serve_connection_with_upgrades(TokioIo::new(tcp), svc);
            let conn = pin!(conn);
            let _ = Driven::new(
                conn,
                exec,
                hyper_util::server::conn::auto::UpgradeableConnection::graceful_shutdown,
            )
            .await;
        });

        let mut sock = TcpStream::connect(addr).await?;
        let _ = sock.set_nodelay(true);
        // Client preface + empty SETTINGS + HEADERS(stream 1, END_STREAM|END_HEADERS):
        // static HPACK indexed: :method GET (0x82), :scheme https (0x87), :path / (0x84),
        // :authority literal without indexing (0x01, len 4, "test").
        let hpack = [0x82_u8, 0x87, 0x84, 0x01, 0x04, b't', b'e', b's', b't'];
        let mut wire = Vec::new();
        wire.extend_from_slice(PREFACE);
        // Empty SETTINGS frame (len=0, type=4, flags=0, sid=0)
        wire.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
        // SETTINGS ACK (len=0, type=4, flags=1, sid=0)
        wire.extend_from_slice(&[0, 0, 0, 4, 1, 0, 0, 0, 0]);
        // HEADERS frame on stream 1 with END_STREAM (0x1) | END_HEADERS (0x4)
        let hlen = u32::try_from(hpack.len())?;
        wire.extend_from_slice(&[
            u8::try_from((hlen >> 16) & 0xff)?,
            u8::try_from((hlen >> 8) & 0xff)?,
            u8::try_from(hlen & 0xff)?,
            0x01,
            0x05,
            0,
            0,
            0,
            1,
        ]);
        wire.extend_from_slice(&hpack);
        sock.write_all(&wire).await?;

        let mut saw_rst_cancel = false;
        let mut saw_goaway = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !saw_rst_cancel && tokio::time::Instant::now() < deadline {
            let mut hdr = [0_u8; 9];
            tokio::time::timeout(Duration::from_secs(2), sock.read_exact(&mut hdr)).await??;
            let len =
                (usize::from(hdr[0]) << 16) | (usize::from(hdr[1]) << 8) | usize::from(hdr[2]);
            let ftype = hdr[3];
            let sid = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) & 0x7fff_ffff;
            let mut payload = vec![0_u8; len];
            if len > 0 {
                tokio::time::timeout(Duration::from_secs(2), sock.read_exact(&mut payload))
                    .await??;
            }
            if ftype == 0x03 {
                // RST_STREAM
                assert_eq!(sid, 1, "RST_STREAM must target stream 1");
                let raw: [u8; 4] = payload
                    .as_slice()
                    .try_into()
                    .map_err(|_| "RST_STREAM payload must be 4 bytes")?;
                let code = u32::from_be_bytes(raw);
                assert_eq!(code, 0x08, "RST_STREAM error code must be CANCEL (0x8)");
                saw_rst_cancel = true;
            } else if ftype == 0x07 {
                saw_goaway = true;
            }
        }
        assert!(
            saw_rst_cancel,
            "must receive RST_STREAM(CANCEL) for stream 1"
        );
        assert!(!saw_goaway, "panicking stream must NOT emit GOAWAY");

        drop(sock);
        let _ = tokio::time::timeout(Duration::from_secs(5), srv_task).await;
        Ok(())
    }

    #[tokio::test]
    async fn panic_on_stream_drop_is_isolated() {
        struct PanicOnDrop(bool);
        impl Drop for PanicOnDrop {
            fn drop(&mut self) {
                assert!(!self.0, "drop panic");
            }
        }

        let _tracing_serial = crate::test_tracing_lock().lock().await;

        // Case 1: panic in Drop during normal stream completion.
        let exec = InTaskExec::default();
        let done = Arc::new(AtomicBool::new(false));
        let done_c = Arc::clone(&done);
        exec.execute(async move {
            let _bomb = PanicOnDrop(true);
            done_c.store(true, Ordering::SeqCst);
        });
        let exec_c = exec.clone();
        let conn = pin!(std::future::poll_fn(|_cx| {
            if done.load(Ordering::SeqCst) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }));
        Driven::new(conn, exec_c, |_| {}).await;
        assert!(done.load(Ordering::SeqCst));

        // Case 2: panic in Drop when `Driven` itself is dropped with pending streams.
        let exec2 = InTaskExec::default();
        exec2.execute(async move {
            let _bomb = PanicOnDrop(true);
            std::future::pending::<()>().await;
        });
        let conn2 = pin!(std::future::pending::<()>());
        let mut driven2 = pin!(Driven::new(conn2, exec2, |_| {}));
        let flag = Arc::new(FlagWaker(AtomicBool::new(false)));
        let waker = Waker::from(flag);
        let mut cx = Context::from_waker(&waker);
        assert!(driven2.as_mut().poll(&mut cx).is_pending());
        // Dropping `driven2` must catch the drop panic instead of unwinding.
    }

    #[tokio::test]
    async fn external_execute_while_parked_wakes_driven() -> TestResult {
        let exec = InTaskExec::default();
        let exec_external = exec.clone();
        let finished = Arc::new(Notify::new());
        let finished_stream = Arc::clone(&finished);
        let stop_conn = Arc::new(Notify::new());
        let stop_conn_c = Arc::clone(&stop_conn);

        let driven_task = tokio::spawn(async move {
            let conn = pin!(async move {
                stop_conn_c.notified().await;
            });
            Driven::new(conn, exec, |_| {}).await;
        });

        // Give `Driven` time to poll once and park with `Poll::Pending`.
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Enqueue asynchronously from outside `Driven::poll`.
        exec_external.execute(async move {
            finished_stream.notify_one();
        });

        tokio::time::timeout(Duration::from_secs(5), finished.notified()).await?;
        stop_conn.notify_one();
        tokio::time::timeout(Duration::from_secs(5), driven_task).await??;
        Ok(())
    }

    #[tokio::test]
    async fn h2_connect_upgrade_executes_upgrade_task_in_task() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let srv_task = tokio::spawn(async move {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let _ = tcp.set_nodelay(true);
            let svc = service_fn(|mut req: Request<Incoming>| async move {
                if req.method() == Method::CONNECT {
                    let on_upgrade = hyper::upgrade::on(&mut req);
                    tokio::spawn(async move {
                        if let Ok(upgraded) = on_upgrade.await {
                            let mut io = TokioIo::new(upgraded);
                            let mut buf = [0_u8; 64];
                            if let Ok(n) = io.read(&mut buf).await
                                && let Some(slice) = buf.get(..n)
                            {
                                let _ = io.write_all(slice).await;
                                let _ = io.shutdown().await;
                            }
                        }
                    });
                    return Ok::<_, Infallible>(Response::new(Empty::new().boxed()));
                }
                Ok::<_, Infallible>(Response::new(full_body(b"sibling-get")))
            });
            let exec = InTaskExec::default();
            let mut builder = AutoConnBuilder::new(exec.clone());
            builder.http2().timer(TokioTimer::new());
            let conn = builder.serve_connection_with_upgrades(TokioIo::new(tcp), svc);
            let conn = pin!(conn);
            let _ = Driven::new(
                conn,
                exec,
                hyper_util::server::conn::auto::UpgradeableConnection::graceful_shutdown,
            )
            .await;
        });

        let client_tcp = TcpStream::connect(addr).await?;
        let _ = client_tcp.set_nodelay(true);
        let (mut sender, conn) = h2_client::handshake::<_, _, Empty<Bytes>>(
            TokioExecutor::new(),
            TokioIo::new(client_tcp),
        )
        .await?;
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });

        sender.ready().await?;
        let connect_req = Request::builder()
            .method(Method::CONNECT)
            .uri("tunnel.example.test:443")
            .body(Empty::new())?;
        let connect_resp = sender.send_request(connect_req).await?;
        assert_eq!(connect_resp.status(), StatusCode::OK);
        let client_upgrade = hyper::upgrade::on(connect_resp);

        // Drive upgraded H2 tunnel (server side runs hyper's `UpgradedSendStreamTask` inside
        // `Driven::streams`, queued via `H2Stream::poll2 -> self.exec.execute_upgrade`).
        let upgraded = tokio::time::timeout(Duration::from_secs(5), client_upgrade).await??;
        let mut io = TokioIo::new(upgraded);
        io.write_all(b"ping-h2-connect").await?;
        let mut echoed = [0_u8; 15];
        tokio::time::timeout(Duration::from_secs(5), io.read_exact(&mut echoed)).await??;
        assert_eq!(&echoed, b"ping-h2-connect");

        // Sibling ordinary GET on the same HTTP/2 connection still succeeds.
        sender.ready().await?;
        let get_resp = sender
            .send_request(
                Request::builder()
                    .uri("https://example.test/ok")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(get_resp.status(), StatusCode::OK);
        assert_eq!(
            get_resp.into_body().collect().await?.to_bytes().as_ref(),
            b"sibling-get"
        );

        drop(io);
        drop(sender);
        let _ = tokio::time::timeout(Duration::from_secs(5), conn_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), srv_task).await;
        Ok(())
    }

    #[test]
    fn pending_streams_respect_per_poll_budget_without_losing_wakeups() {
        const TOTAL: usize = 50;
        const CAP: usize = 16;

        struct ChildState {
            ready: AtomicBool,
            waker: Mutex<Option<Waker>>,
        }

        let exec = InTaskExec::default();
        let inner_polls = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let mut states = Vec::with_capacity(TOTAL);

        for _ in 0..TOTAL {
            let state = Arc::new(ChildState {
                ready: AtomicBool::new(false),
                waker: Mutex::new(None),
            });
            states.push(Arc::clone(&state));
            let polls = Arc::clone(&inner_polls);
            let done = Arc::clone(&completed);
            exec.execute(std::future::poll_fn(move |cx| {
                polls.fetch_add(1, Ordering::Relaxed);
                if state.ready.load(Ordering::Acquire) {
                    done.fetch_add(1, Ordering::Relaxed);
                    Poll::Ready(())
                } else {
                    // Park on an externally controlled waker WITHOUT self-waking, so
                    // `FuturesUnordered` does not trip its `yielded >= 2` shortcut and the
                    // per-turn `PollBudget` is genuinely exercised on ordinary `Poll::Pending`
                    // polls.
                    *state
                        .waker
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                        Some(cx.waker().clone());
                    Poll::Pending
                }
            }));
        }

        let conn = pin!(std::future::pending::<()>());
        let mut driven = pin!(Driven::with_limits(conn, exec, |_| {}, CAP, 4));
        let woken = Arc::new(FlagWaker(AtomicBool::new(false)));
        let waker = Waker::from(Arc::clone(&woken));
        let mut cx = Context::from_waker(&waker);

        // Phase 1: All 50 children are initially ready and return `Poll::Pending` without
        // self-waking. Expect exact batches of [16, 16, 16, 2] polls, self-waking after each
        // capped turn and parking cleanly on the final partial turn.
        let mut phase1_batches = Vec::new();
        while inner_polls.load(Ordering::Relaxed) < TOTAL {
            let before = inner_polls.load(Ordering::Relaxed);
            woken.0.store(false, Ordering::SeqCst);
            assert!(driven.as_mut().poll(&mut cx).is_pending());
            let polled_this_turn = inner_polls.load(Ordering::Relaxed) - before;
            assert!(
                polled_this_turn <= CAP,
                "single Driven::poll polled {polled_this_turn} pending children, exceeding cap {CAP}"
            );
            phase1_batches.push(polled_this_turn);
            if inner_polls.load(Ordering::Relaxed) < TOTAL {
                assert!(
                    woken.0.load(Ordering::SeqCst),
                    "Driven must wake itself when PollBudget stops mid-pending-batch"
                );
            }
            assert!(phase1_batches.len() < 100, "stuck in phase 1");
        }
        assert_eq!(phase1_batches, vec![16, 16, 16, 2]);
        assert!(
            !woken.0.load(Ordering::SeqCst),
            "Driven must park without self-waking once all externally parked children have been polled"
        );
        assert_eq!(completed.load(Ordering::Relaxed), 0);

        // Phase 2: Wake every child via its stored external waker and verify `PollBudget` also
        // caps completing (`Poll::Ready`) children in batches of [16, 16, 16, 2] with zero lost
        // wakeups.
        for state in &states {
            state.ready.store(true, Ordering::Release);
            if let Some(w) = state
                .waker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                w.wake();
            }
        }
        let mut phase2_batches = Vec::new();
        while completed.load(Ordering::Relaxed) < TOTAL {
            let before = inner_polls.load(Ordering::Relaxed);
            woken.0.store(false, Ordering::SeqCst);
            assert!(driven.as_mut().poll(&mut cx).is_pending());
            let polled_this_turn = inner_polls.load(Ordering::Relaxed) - before;
            assert!(
                polled_this_turn <= CAP,
                "single Driven::poll polled {polled_this_turn} ready children, exceeding cap {CAP}"
            );
            phase2_batches.push(polled_this_turn);
            if completed.load(Ordering::Relaxed) < TOTAL {
                assert!(
                    woken.0.load(Ordering::SeqCst),
                    "Driven must wake itself while ready children remain"
                );
            }
            assert!(phase2_batches.len() < 100, "stuck in phase 2");
        }
        assert_eq!(phase2_batches, vec![16, 16, 16, 2]);
        assert_eq!(completed.load(Ordering::Relaxed), TOTAL);
        assert_eq!(inner_polls.load(Ordering::Relaxed), TOTAL * 2);
    }

    #[test]
    fn nonblocking_context_guard_active_during_stream_poll_and_restored_after_panic() {
        let _tracing_serial = crate::test_tracing_lock().blocking_lock();
        assert!(!miraserve_static::inline_work_must_not_block());
        assert!(!miraserve_static::in_nonblocking_inline_context());
        assert!(!miraserve_static::is_worker_loop_thread());

        let exec = InTaskExec::default();
        let saw_in_stream = Arc::new(AtomicBool::new(false));
        let saw_worker_flag_in_stream = Arc::new(AtomicBool::new(false));
        let saw_in_conn = Arc::new(AtomicBool::new(false));
        let saw_in_stream_c = Arc::clone(&saw_in_stream);
        let saw_worker_c = Arc::clone(&saw_worker_flag_in_stream);
        let saw_in_conn_c = Arc::clone(&saw_in_conn);

        // Stream 1: observes the non-blocking inline context (without claiming to be a worker
        // loop) and then panics.
        exec.execute(std::future::poll_fn(move |_cx| -> Poll<()> {
            saw_in_stream_c.store(
                miraserve_static::inline_work_must_not_block()
                    && miraserve_static::in_nonblocking_inline_context(),
                Ordering::SeqCst,
            );
            saw_worker_c.store(miraserve_static::is_worker_loop_thread(), Ordering::SeqCst);
            #[allow(clippy::panic)]
            {
                panic!("stream context panic");
            }
        }));

        // Connection future (`conn.poll`, which also serves HTTP/1.1 connections): must NOT have
        // `NONBLOCKING_INLINE_CONTEXT` set.
        let conn = pin!(std::future::poll_fn(move |_cx| {
            saw_in_conn_c.store(
                miraserve_static::inline_work_must_not_block(),
                Ordering::SeqCst,
            );
            Poll::<()>::Pending
        }));
        let mut driven = pin!(Driven::new(conn, exec, |_| {}));
        let waker = Waker::from(Arc::new(FlagWaker(AtomicBool::new(false))));
        let mut cx = Context::from_waker(&waker);
        assert!(driven.as_mut().poll(&mut cx).is_pending());

        assert!(
            saw_in_stream.load(Ordering::SeqCst),
            "in-task stream poll must see inline_work_must_not_block() == true"
        );
        assert!(
            !saw_worker_flag_in_stream.load(Ordering::SeqCst),
            "in-task stream poll on shared runtime must NOT set is_worker_loop_thread()"
        );
        assert!(
            !saw_in_conn.load(Ordering::SeqCst),
            "conn.poll (including HTTP/1.1) must NOT see inline_work_must_not_block() == true"
        );
        assert!(
            !miraserve_static::inline_work_must_not_block(),
            "non-blocking context guard must be restored after a stream panics"
        );
        assert!(!miraserve_static::in_nonblocking_inline_context());

        // Inside a real worker loop thread, the outer worker-loop state is preserved across a
        // stream panic while `in_nonblocking_inline_context()` still returns to `false`.
        let _worker = miraserve_static::enter_worker_loop_thread();
        let exec2 = InTaskExec::default();
        exec2.execute(std::future::poll_fn(|_cx| -> Poll<()> {
            assert!(miraserve_static::inline_work_must_not_block());
            assert!(miraserve_static::in_nonblocking_inline_context());
            assert!(miraserve_static::is_worker_loop_thread());
            #[allow(clippy::panic)]
            {
                panic!("worker stream panic");
            }
        }));
        let conn2 = pin!(std::future::pending::<()>());
        let mut driven2 = pin!(Driven::new(conn2, exec2, |_| {}));
        assert!(driven2.as_mut().poll(&mut cx).is_pending());
        assert!(miraserve_static::is_worker_loop_thread());
        assert!(miraserve_static::inline_work_must_not_block());
        assert!(!miraserve_static::in_nonblocking_inline_context());
    }

    #[test]
    fn log_stream_panic_emits_inside_nonblocking_context() {
        struct ContextRecorder {
            saw_events: Arc<AtomicUsize>,
            all_in_nonblocking_ctx: Arc<AtomicBool>,
        }

        impl tracing::Subscriber for ContextRecorder {
            fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
                true
            }

            fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }

            fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

            fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {
            }

            fn event(&self, _event: &tracing::Event<'_>) {
                self.saw_events.fetch_add(1, Ordering::SeqCst);
                if !miraserve_static::in_nonblocking_inline_context() {
                    self.all_in_nonblocking_ctx.store(false, Ordering::SeqCst);
                }
            }

            fn enter(&self, _span: &tracing::span::Id) {}
            fn exit(&self, _span: &tracing::span::Id) {}
        }

        struct PanicOnDrop;
        impl Drop for PanicOnDrop {
            fn drop(&mut self) {
                #[allow(clippy::panic)]
                {
                    panic!("drop panic for log_stream_panic context check");
                }
            }
        }

        let _tracing_serial = crate::test_tracing_lock().blocking_lock();
        let saw_events = Arc::new(AtomicUsize::new(0));
        let all_in_nonblocking_ctx = Arc::new(AtomicBool::new(true));
        let subscriber = ContextRecorder {
            saw_events: Arc::clone(&saw_events),
            all_in_nonblocking_ctx: Arc::clone(&all_in_nonblocking_ctx),
        };

        tracing::subscriber::with_default(subscriber, || {
            let exec = InTaskExec::default();
            // Stream 1 panics during poll; Stream 2 parks holding `PanicOnDrop` and panics on drop.
            exec.execute(std::future::poll_fn(|_cx| -> Poll<()> {
                #[allow(clippy::panic)]
                {
                    panic!("poll panic for log_stream_panic context check");
                }
            }));
            exec.execute(async {
                let _guard = PanicOnDrop;
                std::future::pending::<()>().await;
            });

            let conn = pin!(std::future::pending::<()>());
            let mut driven = pin!(Driven::new(conn, exec, |_| {}));
            let waker = Waker::from(Arc::new(FlagWaker(AtomicBool::new(false))));
            let mut cx = Context::from_waker(&waker);
            assert!(driven.as_mut().poll(&mut cx).is_pending());
            // Leaving this block drops `driven` and the parked Stream 2 (`IsolatedStream::drop`).
        });

        assert_eq!(
            saw_events.load(Ordering::SeqCst),
            2,
            "expected panic error events from both poll unwind and drop unwind"
        );
        assert!(
            all_in_nonblocking_ctx.load(Ordering::SeqCst),
            "log_stream_panic must emit inside the non-blocking inline context"
        );
        assert!(
            !miraserve_static::in_nonblocking_inline_context(),
            "non-blocking inline context must be restored after log_stream_panic"
        );
    }

    #[test]
    fn outer_loop_iteration_cap_yields_when_conn_keeps_queuing() {
        const MAX_ITERS: usize = 3;
        let exec = InTaskExec::default();
        let exec_conn = exec.clone();
        let conn_polls = Arc::new(AtomicUsize::new(0));
        let conn_polls_c = Arc::clone(&conn_polls);
        let completed = Arc::new(AtomicUsize::new(0));
        let completed_c = Arc::clone(&completed);

        let conn = pin!(std::future::poll_fn(move |_cx| {
            conn_polls_c.fetch_add(1, Ordering::Relaxed);
            let done = Arc::clone(&completed_c);
            exec_conn.execute(async move {
                done.fetch_add(1, Ordering::Relaxed);
            });
            Poll::<()>::Pending
        }));
        let mut driven = pin!(Driven::with_limits(conn, exec, |_| {}, 64, MAX_ITERS));
        let woken = Arc::new(FlagWaker(AtomicBool::new(false)));
        let waker = Waker::from(Arc::clone(&woken));
        let mut cx = Context::from_waker(&waker);

        assert!(driven.as_mut().poll(&mut cx).is_pending());
        assert_eq!(
            conn_polls.load(Ordering::Relaxed),
            MAX_ITERS,
            "outer loop must stop after MAX_ITERS"
        );
        assert!(
            woken.0.load(Ordering::SeqCst),
            "Driven must wake itself when outer loop cap stops with queued work"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fairness_two_connections_on_single_thread_runtime() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let stop = Arc::new(AtomicBool::new(false));
        let b_completions_while_a_active = Arc::new(AtomicUsize::new(0));
        let a_total = Arc::new(AtomicUsize::new(0));
        let conn_served = Arc::new(Mutex::new(Vec::<usize>::new()));

        let stop_accept = Arc::clone(&stop);
        let accept_task = tokio::spawn(async move {
            for idx in 0..2_usize {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                let _ = tcp.set_nodelay(true);
                let svc = service_fn(move |_req: Request<Incoming>| async move {
                    // Synchronous completion: no awaits inside the handler, exercising worst-case
                    // ready-stream bursts that do NOT consume Tokio coop budget on their own.
                    let payload = if idx == 0 {
                        b"conn-a-ok".as_slice()
                    } else {
                        b"conn-b-ok".as_slice()
                    };
                    Ok::<_, Infallible>(Response::new(full_body(payload)))
                });
                tokio::spawn(async move {
                    let exec = InTaskExec::default();
                    let mut builder = AutoConnBuilder::new(exec.clone());
                    builder
                        .http2()
                        .timer(TokioTimer::new())
                        .max_concurrent_streams(256);
                    let conn = builder.serve_connection_with_upgrades(TokioIo::new(tcp), svc);
                    let conn = pin!(conn);
                    let _ = Driven::new(
                        conn,
                        exec,
                        hyper_util::server::conn::auto::UpgradeableConnection::graceful_shutdown,
                    )
                    .await;
                });
                if stop_accept.load(Ordering::Relaxed) {
                    break;
                }
            }
        });

        // Connect Connection A (flooder) and Connection B (victim) on the single-thread runtime.
        let tcp_flood = TcpStream::connect(addr).await?;
        let _ = tcp_flood.set_nodelay(true);
        let (flood_sender, flood_conn) = h2_client::handshake::<_, _, Empty<Bytes>>(
            TokioExecutor::new(),
            TokioIo::new(tcp_flood),
        )
        .await?;
        let flood_conn_task = tokio::spawn(async move {
            let _ = flood_conn.await;
        });

        let tcp_victim = TcpStream::connect(addr).await?;
        let _ = tcp_victim.set_nodelay(true);
        let (mut victim_sender, victim_conn) = h2_client::handshake::<_, _, Empty<Bytes>>(
            TokioExecutor::new(),
            TokioIo::new(tcp_victim),
        )
        .await?;
        let victim_conn_task = tokio::spawn(async move {
            let _ = victim_conn.await;
        });

        // Connection A continuously pipelines 96 concurrent streams (above `MAX_STREAM_POLLS_PER_POLL`).
        let stop_a = Arc::clone(&stop);
        let a_total_c = Arc::clone(&a_total);
        let a_flood = tokio::spawn(async move {
            let mut sender = flood_sender;
            while !stop_a.load(Ordering::Relaxed) {
                let mut futs = Vec::with_capacity(96);
                for _ in 0..96 {
                    if sender.ready().await.is_err() {
                        return;
                    }
                    let Ok(req) = Request::builder()
                        .uri("https://example.test/a")
                        .body(Empty::new())
                    else {
                        return;
                    };
                    futs.push(sender.send_request(req));
                }
                for fut in futs {
                    if let Ok(resp) = fut.await
                        && resp.into_body().collect().await.is_ok()
                    {
                        a_total_c.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });

        // Let A reach full burst saturation first, failing promptly if the producer exits early or
        // times out instead of spinning indefinitely.
        let warmup_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while a_total.load(Ordering::Relaxed) < 96 {
            if a_flood.is_finished() {
                return Err(format!(
                    "connection A flood producer exited early after {} completions",
                    a_total.load(Ordering::Relaxed)
                )
                .into());
            }
            if tokio::time::Instant::now() >= warmup_deadline {
                return Err(format!(
                    "connection A warmup timed out at {} completions",
                    a_total.load(Ordering::Relaxed)
                )
                .into());
            }
            tokio::task::yield_now().await;
        }

        // Connection B sends 20 sequential requests while A is actively flooding.
        let a_at_b_start = a_total.load(Ordering::Relaxed);
        for _ in 0..20 {
            let a_before = a_total.load(Ordering::Relaxed);
            victim_sender.ready().await?;
            let resp = tokio::time::timeout(
                Duration::from_secs(10),
                victim_sender.send_request(
                    Request::builder()
                        .uri("https://example.test/b")
                        .body(Empty::new())?,
                ),
            )
            .await??;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.into_body().collect().await?.to_bytes();
            assert_eq!(body.as_ref(), b"conn-b-ok");
            b_completions_while_a_active.fetch_add(1, Ordering::Relaxed);
            conn_served
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(a_total.load(Ordering::Relaxed).saturating_sub(a_before));
        }
        assert!(
            !a_flood.is_finished(),
            "connection A flooder must still be active throughout connection B's requests"
        );
        let a_at_b_end = a_total.load(Ordering::Relaxed);
        stop.store(true, Ordering::Relaxed);

        assert_eq!(b_completions_while_a_active.load(Ordering::Relaxed), 20);
        assert!(
            a_at_b_end > a_at_b_start,
            "connection A should also have continued making interleaved progress (before={a_at_b_start}, after={a_at_b_end})"
        );

        drop(victim_sender);
        let _ = tokio::time::timeout(Duration::from_secs(5), a_flood).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), flood_conn_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), victim_conn_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), accept_task).await;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::too_many_lines)]
    async fn per_request_handoff_routes_in_task_and_spawned_streams_on_one_connection() -> TestResult
    {
        use super::{StreamExec, test_h2_exec_stream_counts, test_h2_handoff_mismatch_count};

        struct DropSignal(Arc<Notify>);
        impl Drop for DropSignal {
            fn drop(&mut self) {
                self.0.notify_one();
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let spawned_entered = Arc::new(Notify::new());
        let spawned_release = Arc::new(Notify::new());
        let intask_entered = Arc::new(Notify::new());
        let intask_release = Arc::new(Notify::new());
        let drop_spawned_entered = Arc::new(Notify::new());
        let drop_spawned_dropped = Arc::new(Notify::new());
        let drop_intask_entered = Arc::new(Notify::new());
        let drop_intask_dropped = Arc::new(Notify::new());

        let sp_in_ctx = Arc::new(AtomicBool::new(true));
        let it_in_ctx = Arc::new(AtomicBool::new(false));

        let se = Arc::clone(&spawned_entered);
        let sr = Arc::clone(&spawned_release);
        let ie = Arc::clone(&intask_entered);
        let ir = Arc::clone(&intask_release);
        let dse = Arc::clone(&drop_spawned_entered);
        let dsd = Arc::clone(&drop_spawned_dropped);
        let die = Arc::clone(&drop_intask_entered);
        let did = Arc::clone(&drop_intask_dropped);
        let sp_ctx_c = Arc::clone(&sp_in_ctx);
        let it_ctx_c = Arc::clone(&it_in_ctx);

        let _tracing_serial = crate::test_tracing_lock().lock().await;
        let _serial = super::h2_exec_test_lock().lock().await;
        let (in_before, sp_before) = test_h2_exec_stream_counts();
        let mm_before = test_h2_handoff_mismatch_count();

        let srv_task = tokio::spawn(async move {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let _ = tcp.set_nodelay(true);
            let (exec, handoff) = InTaskExec::with_handoff();
            let svc = service_fn(move |req: Request<Incoming>| {
                let path = req.uri().path().to_owned();
                let decision = if path.starts_with("/spawned") {
                    StreamExec::Spawn
                } else {
                    StreamExec::InTask
                };
                handoff.set(decision);

                let se = Arc::clone(&se);
                let sr = Arc::clone(&sr);
                let ie = Arc::clone(&ie);
                let ir = Arc::clone(&ir);
                let dse = Arc::clone(&dse);
                let dsd = Arc::clone(&dsd);
                let die = Arc::clone(&die);
                let did = Arc::clone(&did);
                let sp_ctx = Arc::clone(&sp_ctx_c);
                let it_ctx = Arc::clone(&it_ctx_c);

                async move {
                    match path.as_str() {
                        "/in-task" => {
                            it_ctx.store(
                                miraserve_static::in_nonblocking_inline_context()
                                    && miraserve_static::inline_work_must_not_block(),
                                Ordering::SeqCst,
                            );
                            Ok::<_, Infallible>(Response::new(full_body(b"in-task-ok")))
                        }
                        "/spawned" => {
                            sp_ctx.store(
                                miraserve_static::in_nonblocking_inline_context()
                                    || miraserve_static::inline_work_must_not_block(),
                                Ordering::SeqCst,
                            );
                            Ok::<_, Infallible>(Response::new(full_body(b"spawned-ok")))
                        }
                        "/spawned-block" => {
                            se.notify_one();
                            sr.notified().await;
                            Ok::<_, Infallible>(Response::new(full_body(b"spawned-unblocked")))
                        }
                        "/in-task-block" => {
                            ie.notify_one();
                            ir.notified().await;
                            Ok::<_, Infallible>(Response::new(full_body(b"in-task-unblocked")))
                        }
                        "/panic-in-task" => {
                            #[allow(clippy::panic)]
                            {
                                panic!("in-task panic");
                            }
                        }
                        "/spawned-panic" => {
                            #[allow(clippy::panic)]
                            {
                                panic!("spawned panic");
                            }
                        }
                        "/spawned-drop" => {
                            let _sig = DropSignal(dsd);
                            dse.notify_one();
                            std::future::pending::<()>().await;
                            Ok::<_, Infallible>(Response::new(full_body(b"never")))
                        }
                        "/in-task-drop" => {
                            let _sig = DropSignal(did);
                            die.notify_one();
                            std::future::pending::<()>().await;
                            Ok::<_, Infallible>(Response::new(full_body(b"never")))
                        }
                        _ => Ok::<_, Infallible>(Response::new(full_body(b"other"))),
                    }
                }
            });

            let mut builder = AutoConnBuilder::new(exec.clone());
            builder.http2().timer(TokioTimer::new());
            let conn = builder.serve_connection_with_upgrades(TokioIo::new(tcp), svc);
            let conn = pin!(conn);
            let _ = Driven::new(
                conn,
                exec,
                hyper_util::server::conn::auto::UpgradeableConnection::graceful_shutdown,
            )
            .await;
        });

        let client_tcp = TcpStream::connect(addr).await?;
        let _ = client_tcp.set_nodelay(true);
        let (mut sender, conn) = h2_client::handshake::<_, _, Empty<Bytes>>(
            TokioExecutor::new(),
            TokioIo::new(client_tcp),
        )
        .await?;
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });

        // 1. Both paths execute on ONE connection with exact non-blocking context semantics.
        sender.ready().await?;
        let r_it = sender
            .send_request(
                Request::builder()
                    .uri("https://example.test/in-task")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(
            r_it.into_body().collect().await?.to_bytes().as_ref(),
            b"in-task-ok"
        );
        assert!(
            it_in_ctx.load(Ordering::SeqCst),
            "in-task stream must run inside non-blocking inline context"
        );

        sender.ready().await?;
        let r_sp = sender
            .send_request(
                Request::builder()
                    .uri("https://example.test/spawned")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(
            r_sp.into_body().collect().await?.to_bytes().as_ref(),
            b"spawned-ok"
        );
        assert!(
            !sp_in_ctx.load(Ordering::SeqCst),
            "spawned stream must NOT inherit non-blocking inline context"
        );

        // 2. Blocking spawned stream does not delay in-task stream, and blocking in-task stream
        //    does not delay spawned stream.
        sender.ready().await?;
        let block_sp = sender.send_request(
            Request::builder()
                .uri("https://example.test/spawned-block")
                .body(Empty::new())?,
        );
        tokio::time::timeout(Duration::from_secs(5), spawned_entered.notified()).await?;

        sender.ready().await?;
        let fast_it = tokio::time::timeout(
            Duration::from_secs(3),
            sender.send_request(
                Request::builder()
                    .uri("https://example.test/in-task")
                    .body(Empty::new())?,
            ),
        )
        .await??;
        assert_eq!(
            fast_it.into_body().collect().await?.to_bytes().as_ref(),
            b"in-task-ok"
        );
        spawned_release.notify_one();
        let block_sp_resp = tokio::time::timeout(Duration::from_secs(5), block_sp).await??;
        assert_eq!(
            block_sp_resp
                .into_body()
                .collect()
                .await?
                .to_bytes()
                .as_ref(),
            b"spawned-unblocked"
        );

        sender.ready().await?;
        let block_it = sender.send_request(
            Request::builder()
                .uri("https://example.test/in-task-block")
                .body(Empty::new())?,
        );
        tokio::time::timeout(Duration::from_secs(5), intask_entered.notified()).await?;

        sender.ready().await?;
        let fast_sp = tokio::time::timeout(
            Duration::from_secs(3),
            sender.send_request(
                Request::builder()
                    .uri("https://example.test/spawned")
                    .body(Empty::new())?,
            ),
        )
        .await??;
        assert_eq!(
            fast_sp.into_body().collect().await?.to_bytes().as_ref(),
            b"spawned-ok"
        );
        intask_release.notify_one();
        let block_it_resp = tokio::time::timeout(Duration::from_secs(5), block_it).await??;
        assert_eq!(
            block_it_resp
                .into_body()
                .collect()
                .await?
                .to_bytes()
                .as_ref(),
            b"in-task-unblocked"
        );

        // 3. Panic in BOTH an in-task stream and a spawned stream on the same connection resets
        //    only the panicking stream with RST_STREAM(CANCEL) and keeps the connection alive.
        for panic_uri in [
            "https://example.test/panic-in-task",
            "https://example.test/spawned-panic",
        ] {
            sender.ready().await?;
            let err = sender
                .send_request(Request::builder().uri(panic_uri).body(Empty::new())?)
                .await
                .err()
                .ok_or("panicking stream must return RST_STREAM")?;
            let text = error_chain_text(&err);
            assert!(
                text.contains("stream no longer needed"),
                "{panic_uri} must emit RST_STREAM(CANCEL), got: {text}"
            );
        }

        // 4. Connection drop with ONE in-task stream AND ONE spawned stream simultaneously in
        //    flight drops both futures cleanly.
        sender.ready().await?;
        let drop_sp_fut = sender.send_request(
            Request::builder()
                .uri("https://example.test/spawned-drop")
                .body(Empty::new())?,
        );
        sender.ready().await?;
        let drop_it_fut = sender.send_request(
            Request::builder()
                .uri("https://example.test/in-task-drop")
                .body(Empty::new())?,
        );
        let _drop_sp_h = tokio::spawn(async move {
            let _ = drop_sp_fut.await;
        });
        let _drop_it_h = tokio::spawn(async move {
            let _ = drop_it_fut.await;
        });
        tokio::time::timeout(Duration::from_secs(5), drop_spawned_entered.notified()).await?;
        tokio::time::timeout(Duration::from_secs(5), drop_intask_entered.notified()).await?;

        let (in_after, sp_after) = test_h2_exec_stream_counts();
        assert!(
            in_after >= in_before + 5 && sp_after >= sp_before + 5,
            "expected >=5 in-task and >=5 spawned streams (in: {in_before} -> {in_after}, sp: {sp_before} -> {sp_after})"
        );
        assert_eq!(
            test_h2_handoff_mismatch_count(),
            mm_before,
            "normal per-request execution must record zero hand-off mismatches"
        );

        // Abruptly abort server connection task: Driven drops the in-task stream immediately, and
        // h2 closes the connection waking the spawned stream to drop just as under TokioExecutor.
        srv_task.abort();
        let _ = srv_task.await;
        tokio::time::timeout(Duration::from_secs(5), drop_intask_dropped.notified())
            .await
            .map_err(|_| "in-task stream future was not dropped on connection drop")?;
        tokio::time::timeout(Duration::from_secs(5), drop_spawned_dropped.notified())
            .await
            .map_err(|_| "spawned stream future was not dropped on connection drop")?;

        drop(sender);
        conn_task.abort();
        Ok(())
    }

    /// Verifies all hand-off mismatch guards AND serves as a live-`hyper` upgrade tripwire for
    /// `hyper 1.12.0`'s `Serving::poll_server` ordering (`service.call` -> per-stream `exec.clone`
    /// -> `exec.execute_h2stream`). Any future `hyper` upgrade that reorders those three steps
    /// (moving `clone` before `service.call` or after `execute`, calling `execute` before
    /// `service.call`, or executing streams through the per-stream clone) fails Part 4 via
    /// `HANDOFF_MISMATCHES`, `TEST_UPGRADE_TASKS_SPAWNED`, or `TEST_INTASK_STREAMS_EXECUTED`.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn per_request_handoff_detects_missing_decision_and_double_service_call() -> TestResult {
        use super::{
            StreamExec, test_h2_exec_stream_counts, test_h2_handoff_mismatch_count,
            test_h2_upgrade_tasks_spawned,
        };

        let _tracing_serial = crate::test_tracing_lock().lock().await;
        let _serial = super::h2_exec_test_lock().lock().await;

        // 1. Missing decision: `execute` called without a prior `handoff.set`.
        {
            let (exec, _handoff) = InTaskExec::with_handoff();
            let ran_spawned = Arc::new(Notify::new());
            let ran_c = Arc::clone(&ran_spawned);
            let saw_nonblocking = Arc::new(AtomicBool::new(true));
            let saw_c = Arc::clone(&saw_nonblocking);
            let mm_before = test_h2_handoff_mismatch_count();

            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                exec.execute(async move {
                    saw_c.store(
                        miraserve_static::in_nonblocking_inline_context(),
                        Ordering::SeqCst,
                    );
                    ran_c.notify_one();
                });
            }));
            #[cfg(debug_assertions)]
            assert!(
                res.is_err(),
                "missing hand-off decision must trip debug_assert in debug builds"
            );
            #[cfg(not(debug_assertions))]
            assert!(
                res.is_ok(),
                "release build must fall back without panicking"
            );

            assert!(
                test_h2_handoff_mismatch_count() > mm_before,
                "missing decision must increment mismatch counter"
            );
            tokio::time::timeout(Duration::from_secs(5), ran_spawned.notified())
                .await
                .map_err(|_| "missing decision fallback did not spawn future on Tokio")?;
            assert!(
                !saw_nonblocking.load(Ordering::SeqCst),
                "safe spawn fallback must run without non-blocking inline context"
            );
        }

        // 2. Double service call without intervening `execute`: overwrites with safe Spawn.
        {
            let (exec, handoff) = InTaskExec::with_handoff();
            let mm_before = test_h2_handoff_mismatch_count();
            handoff.set(StreamExec::InTask);
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handoff.set(StreamExec::InTask);
            }));
            #[cfg(debug_assertions)]
            assert!(
                res.is_err(),
                "double service.call without execute must trip debug_assert in debug builds"
            );
            #[cfg(not(debug_assertions))]
            assert!(
                res.is_ok(),
                "release build must fall back without panicking"
            );
            assert!(
                test_h2_handoff_mismatch_count() > mm_before,
                "double service.call must increment mismatch counter"
            );

            // Subsequent `execute` MUST take the safe Spawn fallback (NOT InTask) without tripping
            // another mismatch.
            let mm_mid = test_h2_handoff_mismatch_count();
            let ran_spawned = Arc::new(Notify::new());
            let ran_c = Arc::clone(&ran_spawned);
            let saw_nonblocking = Arc::new(AtomicBool::new(true));
            let saw_c = Arc::clone(&saw_nonblocking);
            exec.execute(async move {
                saw_c.store(
                    miraserve_static::in_nonblocking_inline_context(),
                    Ordering::SeqCst,
                );
                ran_c.notify_one();
            });
            assert_eq!(test_h2_handoff_mismatch_count(), mm_mid);
            tokio::time::timeout(Duration::from_secs(5), ran_spawned.notified())
                .await
                .map_err(|_| "double-call safe fallback did not spawn future on Tokio")?;
            assert!(!saw_nonblocking.load(Ordering::SeqCst));
        }

        // 3. `conn.poll` returning with an unconsumed hand-off decision clears it and counts it.
        {
            let (exec, handoff) = InTaskExec::with_handoff();
            let mm_before = test_h2_handoff_mismatch_count();
            let conn = pin!(std::future::poll_fn(move |_cx| {
                handoff.set(StreamExec::InTask);
                Poll::<()>::Pending
            }));
            let mut driven = pin!(Driven::new(conn, exec, |_| {}));
            let waker = Waker::from(Arc::new(FlagWaker(AtomicBool::new(false))));
            let mut cx = Context::from_waker(&waker);
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = driven.as_mut().poll(&mut cx);
            }));
            #[cfg(debug_assertions)]
            assert!(
                res.is_err(),
                "unconsumed decision after conn.poll must trip debug_assert in debug builds"
            );
            #[cfg(not(debug_assertions))]
            assert!(res.is_ok());
            assert!(test_h2_handoff_mismatch_count() > mm_before);
        }

        // 4. Live-`hyper` upgrade tripwire: drive a real `AutoConnBuilder` HTTP/2 connection with
        //    one in-task GET, one spawned GET, and one `CONNECT` upgrade. Every alternative order
        //    of `(service.call, exec.clone, exec.execute)` fails here:
        //    - `clone` before `service.call` or after `execute` => `H2Stream` keeps `PerRequest`
        //      instead of `UpgradeOnly`, so `CONNECT`'s `execute_upgrade` hits `HANDOFF_EMPTY`
        //      (mismatch > 0, `up_after == up_before`);
        //    - `execute` before `service.call` => `execute` hits `HANDOFF_EMPTY` AND `Driven::poll`
        //      catches unconsumed `handoff` (mismatch > 0);
        //    - `execute_h2stream` on the per-stream `UpgradeOnly` clone => `handoff` stays
        //      unconsumed (mismatch > 0, `in_after == in_before`).
        {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let (in_before, sp_before) = test_h2_exec_stream_counts();
            let up_before = test_h2_upgrade_tasks_spawned();
            let mm_before = test_h2_handoff_mismatch_count();
            let in_saw_nb = Arc::new(AtomicBool::new(false));
            let sp_saw_nb = Arc::new(AtomicBool::new(true));
            let in_nb_c = Arc::clone(&in_saw_nb);
            let sp_nb_c = Arc::clone(&sp_saw_nb);

            let srv_task = tokio::spawn(async move {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let _ = tcp.set_nodelay(true);
                let (exec, handoff) = InTaskExec::with_handoff();
                let svc = service_fn(move |mut req: Request<Incoming>| {
                    let is_in_task =
                        req.method() == Method::GET && req.uri().path() == "/tripwire-in-task";
                    handoff.set(if is_in_task {
                        StreamExec::InTask
                    } else {
                        StreamExec::Spawn
                    });
                    let in_nb = Arc::clone(&in_nb_c);
                    let sp_nb = Arc::clone(&sp_nb_c);
                    async move {
                        if req.method() == Method::CONNECT {
                            let on_upgrade = hyper::upgrade::on(&mut req);
                            tokio::spawn(async move {
                                if let Ok(upgraded) = on_upgrade.await {
                                    let mut io = TokioIo::new(upgraded);
                                    let mut buf = [0_u8; 16];
                                    if let Ok(n) = io.read(&mut buf).await
                                        && let Some(slice) = buf.get(..n)
                                    {
                                        let _ = io.write_all(slice).await;
                                        let _ = io.shutdown().await;
                                    }
                                }
                            });
                            return Ok::<_, Infallible>(Response::new(Empty::new().boxed()));
                        }
                        let nb = miraserve_static::in_nonblocking_inline_context();
                        if is_in_task {
                            in_nb.store(nb, Ordering::SeqCst);
                        } else {
                            sp_nb.store(nb, Ordering::SeqCst);
                        }
                        Ok::<_, Infallible>(Response::new(full_body(b"ok")))
                    }
                });
                let mut builder = AutoConnBuilder::new(exec.clone());
                builder.http2().timer(TokioTimer::new());
                let conn = builder.serve_connection_with_upgrades(TokioIo::new(tcp), svc);
                let conn = pin!(conn);
                let _ = Driven::new(
                    conn,
                    exec,
                    hyper_util::server::conn::auto::UpgradeableConnection::graceful_shutdown,
                )
                .await;
            });

            let client_tcp = TcpStream::connect(addr).await?;
            let _ = client_tcp.set_nodelay(true);
            let (mut sender, conn) = h2_client::handshake::<_, _, Empty<Bytes>>(
                TokioExecutor::new(),
                TokioIo::new(client_tcp),
            )
            .await?;
            let conn_task = tokio::spawn(async move {
                let _ = conn.await;
            });

            sender.ready().await?;
            let r_in = sender
                .send_request(
                    Request::builder()
                        .uri("https://example.test/tripwire-in-task")
                        .body(Empty::new())?,
                )
                .await?;
            assert_eq!(r_in.status(), StatusCode::OK);
            let _ = r_in.into_body().collect().await?;

            sender.ready().await?;
            let r_sp = sender
                .send_request(
                    Request::builder()
                        .uri("https://example.test/tripwire-spawned")
                        .body(Empty::new())?,
                )
                .await?;
            assert_eq!(r_sp.status(), StatusCode::OK);
            let _ = r_sp.into_body().collect().await?;

            sender.ready().await?;
            let r_conn = sender
                .send_request(
                    Request::builder()
                        .method(Method::CONNECT)
                        .uri("tripwire.example.test:443")
                        .body(Empty::new())?,
                )
                .await?;
            assert_eq!(r_conn.status(), StatusCode::OK);
            let upgraded =
                tokio::time::timeout(Duration::from_secs(5), hyper::upgrade::on(r_conn)).await??;
            let mut io = TokioIo::new(upgraded);
            io.write_all(b"ping").await?;
            let mut echoed = [0_u8; 4];
            tokio::time::timeout(Duration::from_secs(5), io.read_exact(&mut echoed)).await??;
            assert_eq!(&echoed, b"ping");

            let (in_after, sp_after) = test_h2_exec_stream_counts();
            assert_eq!(
                (in_after - in_before, sp_after - sp_before),
                (1, 2),
                "hyper order tripwire: expected 1 in-task stream and 2 spawned streams (GET + CONNECT)"
            );
            assert_eq!(
                test_h2_upgrade_tasks_spawned() - up_before,
                1,
                "hyper order tripwire: CONNECT upgrade task must use UpgradeOnly clone (exec.clone after service.call)"
            );
            assert_eq!(
                test_h2_handoff_mismatch_count(),
                mm_before,
                "hyper order tripwire: zero hand-off mismatches expected"
            );
            assert!(in_saw_nb.load(Ordering::SeqCst));
            assert!(!sp_saw_nb.load(Ordering::SeqCst));

            drop(io);
            drop(sender);
            let _ = tokio::time::timeout(Duration::from_secs(5), conn_task).await;
            let _ = tokio::time::timeout(Duration::from_secs(5), srv_task).await;
        }

        Ok(())
    }

    #[tokio::test]
    async fn per_request_handoff_h2_connect_upgrade_spawns_both_stream_and_upgrade_task_with_zero_mismatches()
    -> TestResult {
        use super::{
            StreamExec, test_h2_exec_stream_counts, test_h2_handoff_mismatch_count,
            test_h2_upgrade_tasks_spawned,
        };

        let _tracing_serial = crate::test_tracing_lock().lock().await;
        let _serial = super::h2_exec_test_lock().lock().await;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (in_before, sp_before) = test_h2_exec_stream_counts();
        let up_before = test_h2_upgrade_tasks_spawned();
        let mm_before = test_h2_handoff_mismatch_count();

        let srv_task = tokio::spawn(async move {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let _ = tcp.set_nodelay(true);
            let (exec, handoff) = InTaskExec::with_handoff();
            let svc = service_fn(move |mut req: Request<Incoming>| {
                let decision = if req.method() == Method::CONNECT {
                    StreamExec::Spawn
                } else {
                    StreamExec::InTask
                };
                handoff.set(decision);
                async move {
                    if req.method() == Method::CONNECT {
                        let on_upgrade = hyper::upgrade::on(&mut req);
                        tokio::spawn(async move {
                            if let Ok(upgraded) = on_upgrade.await {
                                let mut io = TokioIo::new(upgraded);
                                let mut buf = [0_u8; 64];
                                if let Ok(n) = io.read(&mut buf).await
                                    && let Some(slice) = buf.get(..n)
                                {
                                    let _ = io.write_all(slice).await;
                                    let _ = io.shutdown().await;
                                }
                            }
                        });
                        return Ok::<_, Infallible>(Response::new(Empty::new().boxed()));
                    }
                    Ok::<_, Infallible>(Response::new(full_body(b"sibling-in-task")))
                }
            });
            let mut builder = AutoConnBuilder::new(exec.clone());
            builder.http2().timer(TokioTimer::new());
            let conn = builder.serve_connection_with_upgrades(TokioIo::new(tcp), svc);
            let conn = pin!(conn);
            let _ = Driven::new(
                conn,
                exec,
                hyper_util::server::conn::auto::UpgradeableConnection::graceful_shutdown,
            )
            .await;
        });

        let client_tcp = TcpStream::connect(addr).await?;
        let _ = client_tcp.set_nodelay(true);
        let (mut sender, conn) = h2_client::handshake::<_, _, Empty<Bytes>>(
            TokioExecutor::new(),
            TokioIo::new(client_tcp),
        )
        .await?;
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });

        sender.ready().await?;
        let connect_resp = sender
            .send_request(
                Request::builder()
                    .method(Method::CONNECT)
                    .uri("tunnel.example.test:443")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(connect_resp.status(), StatusCode::OK);
        let upgraded =
            tokio::time::timeout(Duration::from_secs(5), hyper::upgrade::on(connect_resp))
                .await??;

        let mut io = TokioIo::new(upgraded);
        io.write_all(b"connect-spawned").await?;
        let mut echoed = [0_u8; 15];
        tokio::time::timeout(Duration::from_secs(5), io.read_exact(&mut echoed)).await??;
        assert_eq!(&echoed, b"connect-spawned");

        // Concurrent in-task sibling on the same connection while upgrade was active.
        sender.ready().await?;
        let sib = sender
            .send_request(
                Request::builder()
                    .uri("https://example.test/ok")
                    .body(Empty::new())?,
            )
            .await?;
        assert_eq!(sib.status(), StatusCode::OK);
        assert_eq!(
            sib.into_body().collect().await?.to_bytes().as_ref(),
            b"sibling-in-task"
        );

        let (in_after, sp_after) = test_h2_exec_stream_counts();
        assert!(in_after > in_before);
        assert!(sp_after > sp_before);
        assert!(
            test_h2_upgrade_tasks_spawned() > up_before,
            "CONNECT upgrade send-stream task must spawn via InTaskExec::UpgradeOnly"
        );
        assert_eq!(
            test_h2_handoff_mismatch_count(),
            mm_before,
            "CONNECT execute_upgrade must never disturb per-connection handoff"
        );

        drop(io);
        drop(sender);
        let _ = tokio::time::timeout(Duration::from_secs(5), conn_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), srv_task).await;
        Ok(())
    }

    #[tokio::test]
    async fn per_request_handoff_spawned_streams_do_not_consume_in_task_poll_budget() -> TestResult
    {
        use super::{StreamExec, test_h2_handoff_mismatch_count};

        const IN_TASK_TOTAL: usize = 50;
        const SPAWNED_TOTAL: usize = 20;
        const CAP: usize = 16;

        struct ChildState {
            ready: AtomicBool,
            waker: Mutex<Option<Waker>>,
        }

        let _tracing_serial = crate::test_tracing_lock().lock().await;
        let _serial = super::h2_exec_test_lock().lock().await;
        let (exec, handoff) = InTaskExec::with_handoff();
        let mm_before = test_h2_handoff_mismatch_count();
        let inner_polls = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let spawned_done = Arc::new(AtomicUsize::new(0));
        let spawned_all = Arc::new(Notify::new());
        let mut states = Vec::with_capacity(IN_TASK_TOTAL);

        // Mix spawned streams and in-task streams interleaved through the same executor.
        for i in 0..IN_TASK_TOTAL {
            if i < SPAWNED_TOTAL {
                let sd = Arc::clone(&spawned_done);
                let sa = Arc::clone(&spawned_all);
                handoff.set(StreamExec::Spawn);
                exec.execute(async move {
                    if sd.fetch_add(1, Ordering::AcqRel) + 1 == SPAWNED_TOTAL {
                        sa.notify_one();
                    }
                });
            }

            let state = Arc::new(ChildState {
                ready: AtomicBool::new(false),
                waker: Mutex::new(None),
            });
            states.push(Arc::clone(&state));
            let polls = Arc::clone(&inner_polls);
            let done = Arc::clone(&completed);
            handoff.set(StreamExec::InTask);
            exec.execute(std::future::poll_fn(move |cx| {
                polls.fetch_add(1, Ordering::Relaxed);
                if state.ready.load(Ordering::Acquire) {
                    done.fetch_add(1, Ordering::Relaxed);
                    Poll::Ready(())
                } else {
                    *state
                        .waker
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                        Some(cx.waker().clone());
                    Poll::Pending
                }
            }));
        }

        // Wait for all 20 spawned streams to finish on Tokio without polling `Driven` at all:
        // proves they are NOT in `Driven`'s set.
        if spawned_done.load(Ordering::Acquire) < SPAWNED_TOTAL {
            tokio::time::timeout(Duration::from_secs(5), spawned_all.notified()).await?;
        }
        assert_eq!(spawned_done.load(Ordering::Acquire), SPAWNED_TOTAL);
        assert_eq!(inner_polls.load(Ordering::Relaxed), 0);

        let conn = pin!(std::future::pending::<()>());
        let mut driven = pin!(Driven::with_limits(conn, exec, |_| {}, CAP, 4));
        let woken = Arc::new(FlagWaker(AtomicBool::new(false)));
        let waker = Waker::from(Arc::clone(&woken));
        let mut cx = Context::from_waker(&waker);

        let mut phase1_batches = Vec::new();
        while inner_polls.load(Ordering::Relaxed) < IN_TASK_TOTAL {
            let before = inner_polls.load(Ordering::Relaxed);
            woken.0.store(false, Ordering::SeqCst);
            assert!(driven.as_mut().poll(&mut cx).is_pending());
            phase1_batches.push(inner_polls.load(Ordering::Relaxed) - before);
        }
        assert_eq!(phase1_batches, vec![16, 16, 16, 2]);

        for state in &states {
            state.ready.store(true, Ordering::Release);
            if let Some(w) = state
                .waker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                w.wake();
            }
        }
        let mut phase2_batches = Vec::new();
        while completed.load(Ordering::Relaxed) < IN_TASK_TOTAL {
            let before = inner_polls.load(Ordering::Relaxed);
            assert!(driven.as_mut().poll(&mut cx).is_pending());
            phase2_batches.push(inner_polls.load(Ordering::Relaxed) - before);
        }
        assert_eq!(phase2_batches, vec![16, 16, 16, 2]);
        assert_eq!(completed.load(Ordering::Relaxed), IN_TASK_TOTAL);
        assert_eq!(test_h2_handoff_mismatch_count(), mm_before);
        Ok(())
    }
}

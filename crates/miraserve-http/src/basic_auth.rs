//! HTTP Basic authentication against an htpasswd file with bcrypt hashes
//! (`basic-auth "/path/htpasswd" realm="..."` on a site or a route).
//!
//! The file is read when the configuration is loaded, through the same no-symlink reader as
//! custom error pages. A file that is missing, unreadable, malformed or inside a served
//! document root does not stop the server or a reload: that one area answers every request
//! with 503 (fail closed) and the problem is logged; `miraserve check --fs` reports it first.

use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use base64::Engine as _;
use http::header::AUTHORIZATION;
use http::{HeaderMap, HeaderValue};
use miraserve_config::{BasicAuthConfig, MAX_HTPASSWD_BYTES, parse_htpasswd};
use tokio::sync::Semaphore;
use tracing::warn;

/// bcrypt checks running at the same time, for the whole process.
const MAX_CONCURRENT_CHECKS: usize = 4;

/// bcrypt checks running at the same time for one site, shared by all its protected areas.
pub(crate) const MAX_CONCURRENT_CHECKS_PER_SITE: usize = 2;

/// Longest a request waits for a free bcrypt slot plus the check itself before it is answered
/// with 503.
const MAX_CHECK_WAIT: Duration = Duration::from_secs(5);

/// How long a successful check is remembered after its last use (each use renews it, so a
/// login in use never expires in the middle of a page's parallel requests).
const VERIFIED_TTL: Duration = Duration::from_secs(600);

/// Most remembered successful checks per protected area.
const MAX_REMEMBERED: usize = 4_096;

/// Failed attempts per visitor address and area (counted for one to two [`FAILURE_WINDOW`]s)
/// before further attempts are refused without a bcrypt check.
const MAX_FAILURES_PER_MINUTE: u32 = 10;

/// Length of one minute of an area's failure counts (two are kept).
const FAILURE_WINDOW: Duration = Duration::from_secs(60);

/// Rows of an area's failure sketch: an address's count is the smallest of its counters, one
/// per row.
const SKETCH_ROWS: usize = 4;

/// Counters per row of an area's failure sketch.
const SKETCH_WIDTH: usize = 32_768;

/// Counters a minute of an area keeps in a small map before switching to the full array (so a
/// scanner touching many areas once each does not make each allocate the array).
const SKETCH_SPARSE_LIMIT: usize = 4_096;

/// Checks of one area queued or running at once (each waits for a bcrypt slot); a request that
/// would start one more gets 503 at once instead of piling up. (No process-wide limit: one
/// site could fill it and lock out the others; the process-wide bcrypt slots are handed out
/// first come, first served.)
const MAX_WAITING_PER_AREA: usize = 16;

/// Requests of one area allowed to wait for a check of their credentials that is already
/// running (a page's parallel requests, an HTTP/2 connection's streams); more are answered 503
/// at once. They do no work and hold no bcrypt slot.
const MAX_FOLLOWERS_PER_AREA: usize = 512;

/// Failures an IPv6 /48 may make per minute across its /64s.
const MAX_FAILURES_PER_MINUTE_48: u32 = 50;

/// The counters an address's failed attempts are charged to, with their limits: an IPv4
/// address itself; an IPv6 address by its /64 (one subscriber's network, so rotating
/// addresses inside it gives no new attempts) and by its /48 with a higher limit (so rotating
/// through /64s inside one allocation does not either); unknown addresses together. A /48 key
/// has its low 64 bits set, which no /64 key has.
fn attempt_keys(client_ip: Option<IpAddr>) -> Vec<(Option<IpAddr>, u32)> {
    match client_ip.map(|ip| ip.to_canonical()) {
        Some(IpAddr::V6(v6)) => {
            let s = v6.segments();
            let net64 = std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0);
            let net48 =
                std::net::Ipv6Addr::new(s[0], s[1], s[2], 0, 0xffff, 0xffff, 0xffff, 0xffff);
            vec![
                (Some(IpAddr::V6(net64)), MAX_FAILURES_PER_MINUTE),
                (Some(IpAddr::V6(net48)), MAX_FAILURES_PER_MINUTE_48),
            ]
        }
        other => vec![(other, MAX_FAILURES_PER_MINUTE)],
    }
}

/// The counters of one minute of an area: a small map until it holds
/// [`SKETCH_SPARSE_LIMIT`] counters, then the full array.
#[derive(Debug)]
enum Counts {
    Sparse(HashMap<usize, u16>),
    Dense(Box<[u16]>),
}

impl Counts {
    fn get(&self, slot: usize) -> u32 {
        u32::from(match self {
            Self::Sparse(map) => map.get(&slot).copied().unwrap_or(0),
            Self::Dense(array) => array.get(slot).copied().unwrap_or(0),
        })
    }

    fn add(&mut self, slot: usize) {
        if let Self::Sparse(map) = self
            && map.len() >= SKETCH_SPARSE_LIMIT
            && !map.contains_key(&slot)
        {
            let mut array = vec![0_u16; SKETCH_ROWS * SKETCH_WIDTH].into_boxed_slice();
            for (&at, &count) in map.iter() {
                if let Some(cell) = array.get_mut(at) {
                    *cell = count;
                }
            }
            *self = Self::Dense(array);
        }
        match self {
            Self::Sparse(map) => {
                let cell = map.entry(slot).or_insert(0);
                *cell = cell.saturating_add(1);
            }
            Self::Dense(array) => {
                if let Some(cell) = array.get_mut(slot) {
                    *cell = cell.saturating_add(1);
                }
            }
        }
    }

    fn sub(&mut self, slot: usize) {
        match self {
            // A saturated counter no longer knows what it holds: it stays at its maximum until
            // its minute is dropped (never lowered below what it counts).
            Self::Sparse(map) => {
                if let Some(cell) = map.get_mut(&slot)
                    && *cell < u16::MAX
                {
                    *cell = cell.saturating_sub(1);
                    if *cell == 0 {
                        map.remove(&slot);
                    }
                }
            }
            Self::Dense(array) => {
                if let Some(cell) = array.get_mut(slot)
                    && *cell < u16::MAX
                {
                    *cell = cell.saturating_sub(1);
                }
            }
        }
    }
}

/// One minute of an area's failures.
#[derive(Debug)]
struct Generation {
    /// When this minute started (minutes follow each other on a fixed grid).
    start: Instant,
    counts: Counts,
}

impl Generation {
    fn starting(start: Instant) -> Self {
        Self {
            start,
            counts: Counts::Sparse(HashMap::new()),
        }
    }
}

/// Failed attempts of one protected area within the last one to two minutes, kept in a
/// fixed-size count-min sketch. Each counter key (an IPv4 address, an IPv6 /64 or /48, or the
/// bucket of unknown addresses) maps to one counter per row through a hash keyed at random per
/// table (nobody can choose which counters an address shares); a failure adds one to each, and
/// the key's count is the smallest of them. So a count is never too low, only sometimes too
/// high (when every one of its counters is shared with failing addresses: rare until tens of
/// thousands of addresses fail within two minutes). Nothing is ever evicted or moved: a
/// failure is counted until its minute is over and the next one too (one to two minutes), and
/// memory is bounded by two minutes of [`SKETCH_ROWS`] x [`SKETCH_WIDTH`] counters.
#[derive(Debug)]
pub(crate) struct FailureTable {
    hasher: std::collections::hash_map::RandomState,
    current: Generation,
    previous: Option<Generation>,
    /// Charges whose bcrypt check is still running, per counter key: a block made only of
    /// them lifts within seconds (most are given back), so its 429 says so.
    pending: HashMap<(Instant, usize), u32>,
}

impl FailureTable {
    fn new() -> Self {
        Self {
            hasher: std::collections::hash_map::RandomState::new(),
            current: Generation::starting(Instant::now()),
            previous: None,
            pending: HashMap::new(),
        }
    }

    /// Moves on to the minute `now` falls in: the current minute becomes the previous one, or
    /// both are dropped after two quiet minutes.
    fn roll(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.current.start);
        if elapsed < FAILURE_WINDOW {
            return;
        }
        if elapsed < FAILURE_WINDOW.saturating_mul(2) {
            let next = self
                .current
                .start
                .checked_add(FAILURE_WINDOW)
                .unwrap_or(now);
            self.previous = Some(std::mem::replace(
                &mut self.current,
                Generation::starting(next),
            ));
        } else {
            self.previous = None;
            self.current = Generation::starting(now);
        }
    }

    /// The counter of `key` in each row.
    fn slots(&self, key: Option<IpAddr>) -> [usize; SKETCH_ROWS] {
        std::array::from_fn(|row| {
            // The remainder is below SKETCH_WIDTH, so it fits in usize.
            let column = usize::try_from(self.hasher.hash_one((row, key)) % SKETCH_WIDTH as u64)
                .unwrap_or(0);
            row * SKETCH_WIDTH + column
        })
    }

    /// The failures counted for `key` at `now` (never fewer than it made in the last minute).
    fn failures_of(&mut self, key: Option<IpAddr>, now: Instant) -> u32 {
        self.roll(now);
        let slots = self.slots(key);
        slots
            .iter()
            .map(|&slot| {
                self.current.counts.get(slot)
                    + self
                        .previous
                        .as_ref()
                        .map_or(0, |previous| previous.counts.get(slot))
            })
            .min()
            .unwrap_or(0)
    }

    /// The count of `key` without charges whose check is still running (counter by counter, as
    /// counters are shared): a block only they hold lifts within seconds.
    fn settled_failures_of(&self, key: Option<IpAddr>) -> u32 {
        self.slots(key)
            .iter()
            .map(|&slot| {
                let in_minute = |minute: Option<&Generation>| {
                    minute.map_or(0, |minute| {
                        minute.counts.get(slot).saturating_sub(
                            self.pending
                                .get(&(minute.start, slot))
                                .copied()
                                .unwrap_or(0),
                        )
                    })
                };
                in_minute(Some(&self.current)) + in_minute(self.previous.as_ref())
            })
            .min()
            .unwrap_or(0)
    }

    /// How long until none of `keys` is at its limit any more, if nothing else is counted: when
    /// the previous minute is dropped, or, if the current minute alone holds a key at its
    /// limit, when the current one is.
    fn retry_after(&mut self, keys: &[(Option<IpAddr>, u32)], now: Instant) -> Duration {
        let mut until = now;
        for &(key, limit) in keys {
            let counted = self.failures_of(key, now);
            if counted < limit {
                continue;
            }
            let settled = self.settled_failures_of(key);
            if settled < limit {
                until = until.max(now.checked_add(Duration::from_secs(1)).unwrap_or(now));
                continue;
            }
            // Does the current minute alone (without charges still being checked) hold it?
            let current_alone = self
                .slots(key)
                .iter()
                .map(|&slot| {
                    self.current.counts.get(slot).saturating_sub(
                        self.pending
                            .get(&(self.current.start, slot))
                            .copied()
                            .unwrap_or(0),
                    )
                })
                .min()
                .unwrap_or(0);
            let windows = if current_alone >= limit { 2 } else { 1 };
            let end = self
                .current
                .start
                .checked_add(FAILURE_WINDOW.saturating_mul(windows))
                .unwrap_or(now);
            until = until.max(end);
        }
        until.saturating_duration_since(now)
    }

    /// Removes the pending marks of `ticket`.
    fn settle_pending(&mut self, ticket: &AttemptTicket) {
        for &(key, start) in ticket {
            for slot in self.slots(key) {
                if let Some(count) = self.pending.get_mut(&(start, slot)) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        self.pending.remove(&(start, slot));
                    }
                }
            }
        }
    }

    /// Counts one failure of `key` in the minute of `now`; returns that minute's start (to give
    /// it back on success).
    fn charge(&mut self, key: Option<IpAddr>, now: Instant) -> Instant {
        self.roll(now);
        let slots = self.slots(key);
        for slot in slots {
            self.current.counts.add(slot);
        }
        self.current.start
    }

    /// Gives back one failure of `key` counted in the minute that started at `start`, if that
    /// minute is still kept (only counters this failure added to are lowered).
    fn refund(&mut self, key: Option<IpAddr>, start: Instant) {
        let slots = self.slots(key);
        let generation = if self.current.start == start {
            Some(&mut self.current)
        } else {
            self.previous
                .as_mut()
                .filter(|previous| previous.start == start)
        };
        if let Some(generation) = generation {
            for slot in slots {
                generation.counts.sub(slot);
            }
        }
    }
}

/// The counter keys one attempt was charged to and the start of the minute it was charged in.
type AttemptTicket = Vec<(Option<IpAddr>, Instant)>;

/// When a check ended, and how.
type Outcome = (AuthDecision, Instant);

/// What a running check is for: the credentials' digest and the address's own counter key.
/// Every address has its own checks, so none can learn anything from another's.
type FlightKey = ([u8; 32], Option<IpAddr>);

/// A check that is running now; the requests of its address with the same credentials wait for
/// its outcome.
struct Flight {
    id: u64,
    client_ip: Option<IpAddr>,
    /// The attempt it is charged as.
    ticket: AttemptTicket,
    /// Its credentials were compared with the remembered logins.
    compared: bool,
    /// The check gives up (without a verdict) when bcrypt has not started by then.
    deadline: Instant,
    /// The deadlines of the other requests waiting for it: after these and its own, nobody
    /// gets the verdict.
    waiting: Vec<Instant>,
    /// A worker runs its bcrypt check: it ends with a verdict.
    started: bool,
    outcome: tokio::sync::watch::Sender<Option<Outcome>>,
}

/// Everything an area's decisions read and change, under one lock: admission, the remembered
/// logins, the running checks, a new charge and the settling of a finished check are each one
/// atomic step. Shared across reloads with the area.
///
/// The rule: no address learns whether a guess is right without paying for it first. A guess
/// is charged to `table` before it is checked, and given back when it was right or nobody got a
/// verdict (full queue, no bcrypt slot in time); so only wrong passwords ever add up to a 429,
/// and a request blocked only by checks still running waits for one to end.
/// Comparing a guess with the remembered logins also answers it (a match is let in), so a
/// comparison whose check then gets no verdict moves to `unanswered`; an address that has used
/// up its attempts between the two is no longer compared with the remembered logins (its
/// requests go through bcrypt instead), but not refused.
pub(crate) struct AreaState {
    table: FailureTable,
    /// Comparisons with the remembered logins that got no verdict.
    unanswered: FailureTable,
    /// The last use of recently verified credentials, by their digest. The digest includes the
    /// stored hash: a changed or removed user's old login never matches.
    verified: HashMap<[u8; 32], Instant>,
    flights: HashMap<FlightKey, Flight>,
    /// Checks queued or running ([`MAX_WAITING_PER_AREA`]), the `leaving` ones included.
    running: usize,
    /// Answered checks ([`AreaState::answer`]) whose jobs have not ended yet.
    leaving: HashSet<u64>,
    /// Requests waiting for a running check ([`MAX_FOLLOWERS_PER_AREA`]).
    followers: usize,
    next_flight: u64,
    /// Changes whenever a check ends.
    ended: tokio::sync::watch::Sender<u64>,
}

impl std::fmt::Debug for AreaState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AreaState")
            .field("running", &self.running)
            .field("followers", &self.followers)
            .field("flights", &self.flights.len())
            .finish_non_exhaustive()
    }
}

impl std::ops::Deref for AreaState {
    type Target = FailureTable;
    fn deref(&self) -> &FailureTable {
        &self.table
    }
}

impl std::ops::DerefMut for AreaState {
    fn deref_mut(&mut self) -> &mut FailureTable {
        &mut self.table
    }
}

impl AreaState {
    fn new() -> Self {
        Self {
            table: FailureTable::new(),
            unanswered: FailureTable::new(),
            verified: HashMap::new(),
            flights: HashMap::new(),
            running: 0,
            leaving: HashSet::new(),
            followers: 0,
            next_flight: 0,
            ended: tokio::sync::watch::Sender::new(0),
        }
    }

    /// Whether every counter of `client_ip` is below its limit.
    fn admits(&mut self, client_ip: Option<IpAddr>, now: Instant) -> bool {
        attempt_keys(client_ip)
            .iter()
            .all(|&(key, limit)| self.table.failures_of(key, now) < limit)
    }

    /// Whether `client_ip` may still have a guess compared with the remembered logins: its
    /// failures, running checks and unanswered comparisons together are below its limits.
    fn may_compare(&mut self, client_ip: Option<IpAddr>, now: Instant) -> bool {
        attempt_keys(client_ip).iter().all(|&(key, limit)| {
            self.table.failures_of(key, now) + self.unanswered.failures_of(key, now) < limit
        })
    }

    /// Counts a comparison with the remembered logins that got no verdict.
    fn count_unanswered(&mut self, client_ip: Option<IpAddr>, now: Instant) {
        for (key, _) in attempt_keys(client_ip) {
            self.unanswered.charge(key, now);
        }
    }

    /// Charges one attempt of `client_ip`, marked pending until it is settled.
    fn charge_attempt(&mut self, client_ip: Option<IpAddr>, now: Instant) -> AttemptTicket {
        let ticket: AttemptTicket = attempt_keys(client_ip)
            .into_iter()
            .map(|(key, _)| (key, self.table.charge(key, now)))
            .collect();
        for &(key, start) in &ticket {
            for slot in self.table.slots(key) {
                *self.table.pending.entry((start, slot)).or_insert(0) += 1;
            }
        }
        ticket
    }

    /// Settles an attempt that was right or got no verdict: given back.
    fn refund_ticket(&mut self, ticket: &AttemptTicket) {
        for &(key, start) in ticket {
            self.table.refund(key, start);
        }
        self.table.settle_pending(ticket);
    }

    /// Settles a wrong attempt: it stays counted.
    fn keep_ticket(&mut self, ticket: &AttemptTicket) {
        self.table.settle_pending(ticket);
    }

    /// Whether `key` was verified and last used less than [`VERIFIED_TTL`] before `now`; a use
    /// renews it (never moving it backwards).
    fn remembered(&mut self, key: &[u8; 32], now: Instant) -> bool {
        match self.verified.get_mut(key) {
            Some(at) if now.saturating_duration_since(*at) < VERIFIED_TTL => {
                *at = (*at).max(now);
                true
            }
            _ => false,
        }
    }

    /// Remembers a successful check of `key`.
    fn remember(&mut self, key: [u8; 32], now: Instant) {
        if self.verified.len() >= MAX_REMEMBERED && !self.verified.contains_key(&key) {
            self.verified
                .retain(|_, at| now.saturating_duration_since(*at) < VERIFIED_TTL);
            // Still full: the login unused for longest makes room.
            if self.verified.len() >= MAX_REMEMBERED
                && let Some(oldest) = self
                    .verified
                    .iter()
                    .min_by_key(|&(_, at)| *at)
                    .map(|(oldest, _)| *oldest)
            {
                self.verified.remove(&oldest);
            }
        }
        self.verified.insert(key, now);
    }

    /// Whether only checks still running keep `client_ip` from being admitted.
    fn blocked_by_running(&self, client_ip: Option<IpAddr>) -> bool {
        attempt_keys(client_ip)
            .iter()
            .all(|&(key, limit)| self.table.settled_failures_of(key) < limit)
    }

    /// Settles the checks that ran out of time before they started, so their charges count for
    /// no later decision (their tasks may not have run yet).
    fn expire(&mut self, now: Instant) {
        let expired: Vec<(FlightKey, u64)> = self
            .flights
            .iter()
            .filter(|(_, flight)| !flight.started && flight.deadline <= now)
            .map(|(key, flight)| (*key, flight.id))
            .collect();
        for (key, id) in expired {
            self.settle(&key, id, AuthDecision::Unavailable, now);
        }
    }

    /// Starts the check `id` of `key` in a worker. `None`: it has ended or is out of time.
    /// `Some(true)`: its credentials, which its address may have compared, are a remembered
    /// login by now, so there is nothing to check.
    fn start(&mut self, key: &FlightKey, id: u64, now: Instant) -> Option<bool> {
        let flight = self
            .flights
            .get_mut(key)
            .filter(|flight| flight.id == id && now < flight.deadline)?;
        flight.started = true;
        let compared = flight.compared;
        Some(compared && self.remembered(&key.0, now))
    }

    /// Ends the check `id` of `key` (unless it has ended): settles its attempt, removes it and
    /// tells the requests waiting for it, all in this one step.
    fn settle(&mut self, key: &FlightKey, id: u64, decision: AuthDecision, now: Instant) {
        if self.leaving.remove(&id) {
            self.running = self.running.saturating_sub(1);
            return;
        }
        if self.flights.get(key).is_none_or(|flight| flight.id != id) {
            return;
        }
        if decision == AuthDecision::Allowed {
            self.remember(key.0, now);
        }
        self.end(key, decision, now);
    }

    /// Answers the check of `key`, whose address has just been let in with the same login: its
    /// attempt is given back and its requests are let in; later requests do not join it. Its
    /// place in the queue stays taken until its job has ended.
    fn answer(&mut self, key: &FlightKey, now: Instant) {
        let Some(flight) = self.flights.remove(key) else {
            return;
        };
        self.leaving.insert(flight.id);
        self.refund_ticket(&flight.ticket);
        flight
            .outcome
            .send_replace(Some((AuthDecision::Allowed, now)));
        self.ended
            .send_modify(|ended| *ended = ended.wrapping_add(1));
    }

    fn end(&mut self, key: &FlightKey, decision: AuthDecision, now: Instant) {
        let Some(flight) = self.flights.remove(key) else {
            return;
        };
        self.running = self.running.saturating_sub(1);
        // A denial that comes too late for every request waiting for it is no verdict.
        let wanted = std::iter::once(&flight.deadline)
            .chain(&flight.waiting)
            .any(|deadline| now <= *deadline);
        if decision == AuthDecision::Denied && wanted {
            self.keep_ticket(&flight.ticket);
        } else {
            self.refund_ticket(&flight.ticket);
            if decision != AuthDecision::Allowed && flight.compared {
                self.count_unanswered(flight.client_ip, now);
            }
        }
        flight.outcome.send_replace(Some((decision, now)));
        self.ended
            .send_modify(|ended| *ended = ended.wrapping_add(1));
    }
}

/// A request's place among the requests waiting for running checks, and the check it waits for
/// with its deadline (which counts no more once the request is gone).
struct FollowerPlace {
    area: Arc<FailureMap>,
    check: Option<(FlightKey, u64, Instant)>,
}

impl Drop for FollowerPlace {
    fn drop(&mut self) {
        let mut state = self.area.lock().unwrap_or_else(PoisonError::into_inner);
        state.followers = state.followers.saturating_sub(1);
        if let Some((key, id, deadline)) = self.check
            && let Some(flight) = state.flights.get_mut(&key)
            && flight.id == id
            && let Some(at) = flight.waiting.iter().position(|at| *at == deadline)
        {
            flight.waiting.swap_remove(at);
        }
    }
}

/// Waits (holding a follower place) until a check ends or counted failures may have expired.
struct Blocked {
    ended: tokio::sync::watch::Receiver<u64>,
    rolls: Instant,
    _place: FollowerPlace,
}

impl Blocked {
    /// `false` when `deadline` came first.
    async fn wait(mut self, deadline: tokio::time::Instant) -> bool {
        let until = deadline.min(self.rolls.into());
        let _ = tokio::time::timeout_at(until, self.ended.changed()).await;
        tokio::time::Instant::now() < deadline
    }
}

/// What a request does next, decided in one locked step.
enum Step {
    /// Answered.
    Decided(AuthDecision),
    /// Its deadline has come: nothing is charged or started.
    OutOfTime,
    /// Waits for a running check (holding a follower place) that gives up at this time.
    Follow(
        tokio::sync::watch::Receiver<Option<Outcome>>,
        FollowerPlace,
        Instant,
    ),
    /// Only checks still running keep its address from being admitted: waits for any check to
    /// end (holding a follower place).
    Blocked(Blocked),
    /// Starts a new check, already charged.
    Start(
        FlightKey,
        u64,
        tokio::sync::watch::Receiver<Option<Outcome>>,
    ),
}

/// A running check. Whoever holds it last (the check's task, or the bcrypt worker once it has
/// started) settles it by dropping it, whatever happens to the requests waiting for it.
struct CheckJob {
    area: Arc<FailureMap>,
    id: u64,
    key: FlightKey,
    /// The user exists (a match of the dummy hash is never a login).
    known: bool,
    /// `Some(correct)` once bcrypt has answered; `None`: no verdict.
    verdict: Option<bool>,
}

impl Drop for CheckJob {
    fn drop(&mut self) {
        let decision = match self.verdict {
            Some(true) if self.known => AuthDecision::Allowed,
            Some(_) => AuthDecision::Denied,
            None => AuthDecision::Unavailable,
        };
        let mut state = self.area.lock().unwrap_or_else(PoisonError::into_inner);
        state.settle(&self.key, self.id, decision, Instant::now());
    }
}

/// bcrypt jobs submitted to the blocking pool and not yet started, process-wide (the pool also
/// serves file work and can stall): beyond this, a check gets no verdict instead of queueing.
const MAX_QUEUED_BCRYPT: usize = 4 * MAX_CONCURRENT_CHECKS;

static QUEUED_BCRYPT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A place among the queued bcrypt jobs, given back when the job starts or is dropped.
struct QueuedJob(&'static std::sync::atomic::AtomicUsize);

impl QueuedJob {
    fn take(jobs: &'static std::sync::atomic::AtomicUsize) -> Option<Self> {
        use std::sync::atomic::Ordering;
        let mut queued = jobs.load(Ordering::Acquire);
        loop {
            if queued >= MAX_QUEUED_BCRYPT {
                return None;
            }
            match jobs.compare_exchange_weak(
                queued,
                queued + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(Self(jobs)),
                Err(now) => queued = now,
            }
        }
    }
}

impl Drop for QueuedJob {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// What a queued bcrypt job needs, claimed when it starts. An unclaimed one is taken back at
/// the deadline, which settles the check, frees its slots and drops the credentials at once.
struct Claim {
    job: CheckJob,
    password: String,
    hash: String,
    _permits: [tokio::sync::OwnedSemaphorePermit; 2],
}

/// Takes an unclaimed [`Claim`] back when dropped (at the deadline, or with the check's task).
struct TakeBack(Arc<Mutex<Option<Claim>>>);

impl Drop for TakeBack {
    fn drop(&mut self) {
        let unclaimed = self.0.lock().unwrap_or_else(PoisonError::into_inner).take();
        drop(unclaimed);
    }
}

/// A worker's part of a check: claims it and, unless it is out of time, runs bcrypt and settles
/// it with the verdict.
fn work(claim: &Mutex<Option<Claim>>) {
    let claimed = claim.lock().unwrap_or_else(PoisonError::into_inner).take();
    let Some(mut claim) = claimed else {
        return;
    };
    let started = claim
        .job
        .area
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .start(&claim.job.key, claim.job.id, Instant::now());
    claim.job.verdict = started.map(|remembered| {
        remembered || bcrypt::verify(claim.password.as_bytes(), &claim.hash).unwrap_or(false)
    });
}

/// Runs one check: waits for the bcrypt slots and hands the job to the blocking pool, until
/// `deadline` or until it has been answered. Once a worker has claimed the job, the worker
/// settles it with its real verdict.
async fn run_check(
    job: CheckJob,
    password: String,
    hash: String,
    deadline: tokio::time::Instant,
    mut outcome: tokio::sync::watch::Receiver<Option<Outcome>>,
) {
    let answered = async move {
        let _ = outcome.wait_for(Option::is_some).await;
    };
    tokio::pin!(answered);
    let slots = Arc::clone(&job.area.slots);
    let permits = tokio::time::timeout_at(deadline, async move {
        let site = slots.acquire_owned().await.ok()?;
        let global = Arc::clone(global_slots()).acquire_owned().await.ok()?;
        Some([site, global])
    });
    let permits = tokio::select! {
        permits = permits => permits,
        () = &mut answered => return,
    };
    let Ok(Some(permits)) = permits else {
        return;
    };
    if tokio::time::Instant::now() >= deadline {
        return;
    }
    let Some(queued) = QueuedJob::take(&QUEUED_BCRYPT) else {
        return;
    };
    let claim = Arc::new(Mutex::new(Some(Claim {
        job,
        password,
        hash,
        _permits: permits,
    })));
    let worker_claim = Arc::clone(&claim);
    let _take_back = TakeBack(claim);
    let worker = tokio::task::spawn_blocking(move || {
        drop(queued);
        work(&worker_claim);
    });
    tokio::select! {
        _ = worker => {}
        () = tokio::time::sleep_until(deadline) => {}
        () = &mut answered => {}
    }
}

/// One dummy hash per bcrypt cost for the whole process: computing it costs as much as a login
/// check, so it is done once, not for every protected site on every reload.
fn dummy_hash_for(cost: u32) -> Result<String, String> {
    static DUMMIES: OnceLock<Mutex<HashMap<u32, String>>> = OnceLock::new();
    let dummies = DUMMIES.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(hash) = dummies
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&cost)
    {
        return Ok(hash.clone());
    }
    let hash = bcrypt::hash("miraserve-dummy-password", cost)
        .map_err(|err| format!("cannot prepare the area: {err}"))?;
    dummies
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(cost, hash.clone());
    Ok(hash)
}

fn global_slots() -> &'static Arc<Semaphore> {
    static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SLOTS.get_or_init(|| Arc::new(Semaphore::new(MAX_CONCURRENT_CHECKS)))
}

/// What one protected area shares across configuration reloads (and between the router
/// generations that overlap during one): its state under one lock, and its bcrypt slots.
#[derive(Debug)]
pub(crate) struct FailureMap {
    state: Mutex<AreaState>,
    /// The area's bcrypt slots ([`MAX_CONCURRENT_CHECKS_PER_SITE`]).
    slots: Arc<Semaphore>,
}

impl FailureMap {
    fn new() -> Self {
        Self {
            state: Mutex::new(AreaState::new()),
            slots: Arc::new(Semaphore::new(MAX_CONCURRENT_CHECKS_PER_SITE)),
        }
    }

    /// Whether attempts counted here may still matter: an area no configuration uses is kept
    /// until then (a site can be taken offline and come back).
    fn holds_failures(&self, now: Instant) -> bool {
        let state = self.lock().unwrap_or_else(PoisonError::into_inner);
        [&state.table, &state.unanswered].into_iter().any(|table| {
            now.saturating_duration_since(table.current.start) < FAILURE_WINDOW.saturating_mul(2)
        })
    }

    fn lock(&self) -> std::sync::LockResult<std::sync::MutexGuard<'_, AreaState>> {
        self.state.lock()
    }
}

fn failure_registry() -> &'static Mutex<HashMap<String, Arc<FailureMap>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, Arc<FailureMap>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The users-file path as a registry key: the same file spelled with `.` segments or repeated
/// separators is the same area (the file itself is read through the no-symlink reader).
fn users_file_key(users_file: &str) -> String {
    let path: PathBuf = Path::new(users_file)
        .components()
        .filter(|part| !matches!(part, std::path::Component::CurDir))
        .collect();
    path.display().to_string()
}

/// How often a configuration load reads the users files again when one is replaced meanwhile.
const MAX_LOAD_ATTEMPTS: usize = 5;

/// Why a users file that is the same file as the one configured as `first` is not loaded.
#[must_use]
pub fn users_file_alias_problem(first: &Path) -> String {
    format!(
        "it is the same file as '{}' under another name; use one name for it in every site",
        first.display()
    )
}

/// The users of a loaded users file (or why there are none) and its area.
type LoadedArea = (Result<Arc<Users>, String>, Arc<FailureMap>);

/// The areas of one configuration load, by the path of their users files (the only thing that
/// makes an area: host-name edits and replacing the file keep its state). Every file is read
/// once, so all sites naming it have the same users; another name of a file that is already
/// loaded (a hard link, another case on a case-insensitive volume) is refused, as its attempts
/// would be counted apart.
#[derive(Debug)]
pub(crate) struct LoadedAreas(HashMap<String, LoadedArea>);

/// What one path held: the content of its users file and the identity and handle it was read
/// from, or why it cannot be used.
struct ReadUsers {
    content: Result<Vec<u8>, String>,
    opened: Option<(std::fs::File, (u64, u64))>,
}

impl ReadUsers {
    /// Whether both are the same file with the same content, or fail the same way.
    fn is_same_as(&self, other: &Self) -> bool {
        let identity = |read: &Self| read.opened.as_ref().map(|(_, identity)| *identity);
        self.content == other.content && identity(self) == identity(other)
    }
}

impl LoadedAreas {
    /// Reads the users files of `configs` and finds or creates their areas; also returns the
    /// handles of the files read.
    pub(crate) fn load<'a>(
        configs: impl IntoIterator<Item = &'a BasicAuthConfig>,
        served_roots: &[PathBuf],
    ) -> (Self, Vec<std::fs::File>) {
        let mut keys: Vec<String> = Vec::new();
        let mut seen = HashSet::new();
        for cfg in configs {
            let key = users_file_key(&cfg.users_file);
            if seen.insert(key.clone()) {
                keys.push(key);
            }
        }
        let read = read_stable(&keys, served_roots);
        let mut first_names: HashMap<(u64, u64), &String> = HashMap::new();
        let mut files = Vec::new();
        let mut map = failure_registry()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        map.retain(|_, area| Arc::strong_count(area) > 1 || area.holds_failures(now));
        let mut areas = HashMap::with_capacity(keys.len());
        for (key, (read, stable)) in keys.iter().zip(read) {
            let mut users = read.content.and_then(users_of).map(Arc::new);
            if let Some((file, identity)) = read.opened {
                files.push(file);
                if stable {
                    let first = *first_names.entry(identity).or_insert(key);
                    if first != key {
                        users = Err(users_file_alias_problem(Path::new(first)));
                    }
                }
            }
            let area = map
                .entry(key.clone())
                .or_insert_with(|| Arc::new(FailureMap::new()));
            areas.insert(key.clone(), (users, Arc::clone(area)));
        }
        drop(map);
        (Self(areas), files)
    }
}

/// Reads the users files at `paths` until two readings in a row agree: the result is what all of
/// them held between the two. One that keeps changing is not used.
fn read_stable(paths: &[String], served_roots: &[PathBuf]) -> Vec<(ReadUsers, bool)> {
    let read_all = || -> Vec<ReadUsers> {
        paths
            .iter()
            .map(|path| read_users_file(Path::new(path), served_roots))
            .collect()
    };
    let mut read = read_all();
    let mut stable = Vec::new();
    for _ in 0..MAX_LOAD_ATTEMPTS {
        let again = read_all();
        stable = again
            .iter()
            .zip(&read)
            .map(|(again, read)| again.is_same_as(read))
            .collect();
        read = again;
        if stable.iter().all(|stable| *stable) {
            break;
        }
    }
    read.into_iter()
        .zip(stable)
        .map(|(mut read, stable)| {
            if !stable && read.content.is_ok() {
                read.content = Err(
                    "it kept changing while the configuration was loaded; reload again".to_owned(),
                );
            }
            (read, stable)
        })
        .collect()
}

fn read_users_file(path: &Path, served_roots: &[PathBuf]) -> ReadUsers {
    let failed = |problem| ReadUsers {
        content: Err(problem),
        opened: None,
    };
    if let Some(problem) = users_file_problem(path, served_roots)
        .or_else(|| miraserve_static::credential_file_problem(path))
    {
        return failed(problem);
    }
    let (raw, file) =
        match miraserve_static::read_no_symlink_file_opened(path, MAX_HTPASSWD_BYTES, &[]) {
            Ok(opened) => opened,
            Err(problem) => return failed(problem),
        };
    let identities = miraserve_static::handle_identities(std::slice::from_ref(&file));
    let Some(identity) = identities.first().copied() else {
        return failed("its identity cannot be read".to_owned());
    };
    // The file that was opened, and its place once more: the path may have led to another file
    // when it was checked by name.
    let problem = miraserve_static::opened_credential_problem(&file)
        .or_else(|| miraserve_static::credential_file_problem(path));
    ReadUsers {
        content: problem.map_or(Ok(raw), Err),
        opened: Some((file, identity)),
    }
}

fn users_of(raw: Vec<u8>) -> Result<Users, String> {
    let text = String::from_utf8(raw).map_err(|_| "not UTF-8 text".to_owned())?;
    let users = parse_htpasswd(&text)?;
    let cost = users
        .first()
        .and_then(|(_, hash)| hash.get(4..6))
        .and_then(|c| c.parse::<u32>().ok())
        .unwrap_or(10);
    let dummy_hash = dummy_hash_for(cost)?;
    Ok(Users {
        by_name: users.into_iter().collect(),
        dummy_hash,
    })
}

/// The outcome of checking a request against an area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthDecision {
    /// Valid credentials.
    Allowed,
    /// Missing or wrong credentials: 401 with the challenge.
    Denied,
    /// Too many failed attempts from this address: 429.
    Throttled,
    /// The area cannot check credentials (bad users file, no free bcrypt slot): 503.
    Unavailable,
}

#[derive(Debug)]
struct Users {
    by_name: HashMap<String, String>,
    /// A valid hash at the cost the area's users have, checked for unknown user names so that
    /// they take as long as wrong passwords.
    dummy_hash: String,
}

/// A loaded `basic-auth` area.
#[derive(Debug)]
pub(crate) struct CompiledBasicAuth {
    /// Why the users file could not be loaded (the area answers 503 to everything).
    load_error: Option<String>,
    /// `Basic realm="...", charset="UTF-8"`.
    challenge: HeaderValue,
    /// `None`: the users file could not be used; every request gets 503.
    users: Option<Arc<Users>>,
    /// The area's counts, remembered logins and running checks (see [`AreaState`]). Shared
    /// across reloads for the same users file, so a reload does not clear an active throttle.
    failures: Arc<FailureMap>,
}

/// Why a users file cannot be used, or `None` when it can. `served_roots` are the document roots
/// of every site and route: a users file inside one of them could be downloaded.
pub(crate) fn users_file_problem(path: &Path, served_roots: &[PathBuf]) -> Option<String> {
    // Compared as configured (no link is followed): only the configuration decides, so a file
    // a tenant replaces with a link cannot make this fail for everyone.
    let inside = served_roots.iter().any(|root| lexically_within(path, root));
    inside.then(|| "it is inside a served document root and could be downloaded".to_owned())
}

/// Whether `path` is `root` or below it, comparing normalised components without touching the
/// filesystem.
pub(crate) fn lexically_within(path: &Path, root: &Path) -> bool {
    fn normal(p: &Path) -> Vec<std::path::Component<'_>> {
        let mut out = Vec::new();
        for c in p.components() {
            match c {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    out.pop();
                }
                other => out.push(other),
            }
        }
        out
    }
    let (path, root) = (normal(path), normal(root));
    path.get(..root.len()) == Some(root.as_slice())
}

impl CompiledBasicAuth {
    /// The area of `cfg` (one of those `areas` was loaded for). Never fails: a problem with the
    /// users file makes it answer 503 and is logged with the file and line (never a hash).
    pub(crate) fn load(cfg: &BasicAuthConfig, areas: &LoadedAreas) -> Arc<Self> {
        let challenge =
            HeaderValue::from_str(&format!("Basic realm=\"{}\", charset=\"UTF-8\"", cfg.realm))
                .unwrap_or_else(|_| {
                    HeaderValue::from_static("Basic realm=\"Restricted\", charset=\"UTF-8\"")
                });
        let mut load_error = None;
        let (users, failures) = match areas.0.get(&users_file_key(&cfg.users_file)) {
            Some((users, area)) => (users.clone(), Arc::clone(area)),
            None => (
                Err("it was not loaded with the configuration".to_owned()),
                Arc::new(FailureMap::new()),
            ),
        };
        let users = match users {
            Ok(users) => Some(users),
            Err(reason) => {
                warn!(
                    users_file = %cfg.users_file,
                    reason = %reason,
                    "basic-auth area unavailable: every request to it gets 503; fix the users file and reload (or restart if the reason says the file is outside the startup sandbox)"
                );
                load_error = Some(format!("users file '{}': {reason}", cfg.users_file));
                None
            }
        };
        Arc::new(Self {
            load_error,
            challenge,
            users,
            failures,
        })
    }

    /// Why this area answers 503 to everything, when its users file could not be loaded.
    pub(crate) fn load_error(&self) -> Option<&str> {
        self.load_error.as_deref()
    }

    /// The `WWW-Authenticate` value for a 401.
    pub(crate) fn challenge(&self) -> HeaderValue {
        self.challenge.clone()
    }

    /// Checks the request's credentials (`credentials`: every `Authorization` value it sent).
    pub(crate) async fn check(
        &self,
        credentials: &[HeaderValue],
        client_ip: Option<IpAddr>,
    ) -> AuthDecision {
        let Some(users) = &self.users else {
            return AuthDecision::Unavailable;
        };
        if credentials.is_empty() {
            return AuthDecision::Denied;
        }
        let Some((user, password)) = basic_credentials(credentials) else {
            let deadline = tokio::time::Instant::now() + MAX_CHECK_WAIT;
            return self.malformed(client_ip, deadline).await;
        };
        let hash = users.by_name.get(&user).cloned();
        let key = credential_key(&user, &password, hash.as_deref().unwrap_or(""));
        // Each request has its own deadline, kept while it waits for a check.
        let deadline = tokio::time::Instant::now() + MAX_CHECK_WAIT;
        let mut out_of_time = AuthDecision::Unavailable;
        loop {
            let (outcome, gives_up) = match self.step(key, client_ip, deadline) {
                Step::OutOfTime => return out_of_time,
                Step::Decided(decision) => return decision,
                Step::Follow(outcome, place, gives_up) => {
                    // Not held back any more: what it waits for now is bcrypt.
                    out_of_time = AuthDecision::Unavailable;
                    let outcome = self.wait(outcome, deadline).await;
                    drop(place);
                    (outcome, gives_up)
                }
                Step::Blocked(blocked) => {
                    if blocked.wait(deadline).await {
                        out_of_time = AuthDecision::Throttled;
                        continue;
                    }
                    return AuthDecision::Throttled;
                }
                Step::Start(flight, id, outcome) => {
                    let job = CheckJob {
                        area: Arc::clone(&self.failures),
                        id,
                        key: flight,
                        known: hash.is_some(),
                        verdict: None,
                    };
                    let checked_hash = hash.clone().unwrap_or_else(|| users.dummy_hash.clone());
                    // The check runs on its own: cancelling this request (a closed browser
                    // tab, a reset HTTP/2 stream) neither stops nor unsettles it.
                    tokio::spawn(run_check(
                        job,
                        password.clone(),
                        checked_hash,
                        deadline,
                        outcome.clone(),
                    ));
                    (self.wait(outcome, deadline).await, deadline.into_std())
                }
            };
            match outcome {
                // The check ran out of its own time; this request has some left: start over
                // (it may run the check itself).
                Some((AuthDecision::Unavailable, ended))
                    if ended >= gives_up && tokio::time::Instant::now() < deadline => {}
                Some((decision, _)) => return decision,
                None => return AuthDecision::Unavailable,
            }
        }
    }

    /// Takes the next step for a request, in one locked step (see [`AreaState`]).
    fn step(
        &self,
        key: [u8; 32],
        client_ip: Option<IpAddr>,
        deadline: tokio::time::Instant,
    ) -> Step {
        let mut state = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        // Out of time: nothing is charged or started (checked under the lock).
        if now >= deadline.into_std() {
            return Step::OutOfTime;
        }
        state.expire(now);
        // The address's own counter key (the address, or its /64).
        let address = attempt_keys(client_ip).first().and_then(|&(key, _)| key);
        let flight_key = (key, address);
        let running = state.flights.contains_key(&flight_key);
        let admitted = state.admits(client_ip, now);
        if !admitted && !state.blocked_by_running(client_ip) {
            return Step::Decided(AuthDecision::Throttled);
        }
        let compared = admitted && state.may_compare(client_ip, now);
        if compared && state.remembered(&key, now) {
            state.answer(&flight_key, now);
            return Step::Decided(AuthDecision::Allowed);
        }
        // The address has paid for this running check: its requests share the verdict.
        if state.followers < MAX_FOLLOWERS_PER_AREA
            && let Some(flight) = state.flights.get_mut(&flight_key)
        {
            flight.compared |= compared;
            flight.waiting.push(deadline.into_std());
            let (outcome, gives_up) = (flight.outcome.subscribe(), flight.deadline);
            let place = FollowerPlace {
                area: Arc::clone(&self.failures),
                check: Some((flight_key, flight.id, deadline.into_std())),
            };
            state.followers += 1;
            return Step::Follow(outcome, place, gives_up);
        }
        if !admitted {
            return match self.blocked(&mut state) {
                Some(blocked) => Step::Blocked(blocked),
                // Not throttled, only no room to wait.
                None => Step::Decided(AuthDecision::Unavailable),
            };
        }
        let full = state.running >= MAX_WAITING_PER_AREA;
        if full || running {
            if compared {
                state.count_unanswered(client_ip, now);
            }
            return Step::Decided(AuthDecision::Unavailable);
        }
        // Charged in this same step, before any verdict can be learned.
        let ticket = state.charge_attempt(client_ip, now);
        state.running += 1;
        let id = state.next_flight;
        state.next_flight = state.next_flight.wrapping_add(1);
        let (outcome, receiver) = tokio::sync::watch::channel(None);
        state.flights.insert(
            flight_key,
            Flight {
                id,
                client_ip,
                ticket,
                compared,
                deadline: deadline.into_std(),
                waiting: Vec::new(),
                started: false,
                outcome,
            },
        );
        Step::Start(flight_key, id, receiver)
    }

    /// A way to wait for a request that only checks still running hold back; `None`: no room.
    fn blocked(&self, state: &mut AreaState) -> Option<Blocked> {
        if state.followers >= MAX_FOLLOWERS_PER_AREA {
            return None;
        }
        state.followers += 1;
        Some(Blocked {
            ended: state.ended.subscribe(),
            rolls: state.table.current.start + FAILURE_WINDOW,
            _place: FollowerPlace {
                area: Arc::clone(&self.failures),
                check: None,
            },
        })
    }

    /// Waits for a check's outcome; `None` when there is none by `deadline` (one that came
    /// later does not count for this request).
    async fn wait(
        &self,
        mut outcome: tokio::sync::watch::Receiver<Option<Outcome>>,
        deadline: tokio::time::Instant,
    ) -> Option<Outcome> {
        let _ = tokio::time::timeout_at(deadline, outcome.wait_for(Option::is_some)).await;
        // Checks end under the area's lock: holding it, an outcome from before the deadline is
        // there, or there will be none.
        let state = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        let ended = *outcome.borrow();
        drop(state);
        // An unstarted check ends without a verdict at (just after) its deadline.
        ended.filter(|(decision, at)| {
            *at <= deadline.into_std() || *decision == AuthDecision::Unavailable
        })
    }

    #[cfg(test)]
    fn recently_verified_at(&self, key: &[u8; 32], now: Instant) -> bool {
        self.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remembered(key, now)
    }

    #[cfg(test)]
    fn remember(&self, key: [u8; 32]) {
        self.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remember(key, Instant::now());
    }

    /// Malformed or non-Basic credentials count as a failed attempt, and a throttled address is
    /// refused with 429 instead of 401 (held back only by running checks, it waits).
    async fn malformed(
        &self,
        client_ip: Option<IpAddr>,
        deadline: tokio::time::Instant,
    ) -> AuthDecision {
        let mut waited = false;
        loop {
            let blocked = {
                let mut state = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
                let now = Instant::now();
                if now >= deadline.into_std() {
                    // Out of time (checked under the lock): nothing is charged.
                    return if waited {
                        AuthDecision::Throttled
                    } else {
                        AuthDecision::Unavailable
                    };
                }
                state.expire(now);
                if state.admits(client_ip, now) {
                    for (key, _) in attempt_keys(client_ip) {
                        state.table.charge(key, now);
                    }
                    return AuthDecision::Denied;
                }
                if !state.blocked_by_running(client_ip) {
                    return AuthDecision::Throttled;
                }
                self.blocked(&mut state)
            };
            match blocked {
                Some(blocked) => {
                    if !blocked.wait(deadline).await {
                        return AuthDecision::Throttled;
                    }
                    waited = true;
                }
                None => return AuthDecision::Unavailable,
            }
        }
    }

    #[cfg(test)]
    fn reserve_attempt(&self, client_ip: Option<IpAddr>, charge: bool) -> Option<AttemptTicket> {
        let mut state = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        if !state.admits(client_ip, now) {
            return None;
        }
        let keys = attempt_keys(client_ip).into_iter().filter(|_| charge);
        Some(
            keys.map(|(key, _)| (key, state.table.charge(key, now)))
                .collect(),
        )
    }

    /// Whole seconds until `client_ip` may try again if nothing else is counted (for the
    /// `Retry-After` of a 429; at least one).
    pub(crate) fn retry_after_secs(&self, client_ip: Option<IpAddr>) -> u64 {
        let mut table = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        let wait = table.retry_after(&attempt_keys(client_ip), Instant::now());
        let whole = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
        whole.max(1)
    }

    #[cfg(test)]
    /// Gives back the attempt of a successful login (each counter it was charged to, in the
    /// minute it was charged in).
    fn refund_attempt(&self, ticket: &AttemptTicket) {
        let mut table = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        for &(key, start) in ticket {
            table.refund(key, start);
        }
    }
}

/// `user`, `password` from exactly one `Authorization: Basic <base64(user:password)>`. Returns
/// `None` for several `Authorization` values, another scheme, invalid base64, non-UTF-8 text,
/// control characters, or a missing colon.
fn basic_credentials(values: &[HeaderValue]) -> Option<(String, String)> {
    let [value] = values else {
        return None;
    };
    let value = value.to_str().ok()?;
    let (scheme, encoded) = value.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    if text.chars().any(char::is_control) {
        return None;
    }
    let (user, password) = text.split_once(':')?;
    Some((user.to_owned(), password.to_owned()))
}

/// Every `Authorization` value of a request.
pub(crate) fn authorization_values(headers: &HeaderMap) -> Vec<HeaderValue> {
    headers.get_all(AUTHORIZATION).iter().cloned().collect()
}

fn credential_key(user: &str, password: &str, hash: &str) -> [u8; 32] {
    let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    ctx.update(user.as_bytes());
    ctx.update(&[0]);
    ctx.update(password.as_bytes());
    ctx.update(&[0]);
    ctx.update(hash.as_bytes());
    let digest = ctx.finish();
    let mut key = [0_u8; 32];
    key.copy_from_slice(digest.as_ref());
    key
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::sync::{Arc, PoisonError};

    use base64::Engine as _;
    use http::HeaderValue;
    use miraserve_config::BasicAuthConfig;

    use super::{
        AuthDecision, CompiledBasicAuth, LoadedAreas, MAX_CONCURRENT_CHECKS_PER_SITE,
        MAX_FAILURES_PER_MINUTE, MAX_WAITING_PER_AREA, basic_credentials, failure_registry,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn basic(text: &str) -> HeaderValue {
        let encoded = base64::engine::general_purpose::STANDARD.encode(text);
        HeaderValue::from_str(&format!("Basic {encoded}"))
            .unwrap_or_else(|_| HeaderValue::from_static(""))
    }

    struct TempUsersFile {
        dir: PathBuf,
        path: PathBuf,
    }

    impl TempUsersFile {
        fn new(tag: &str) -> Result<Self, Box<dyn std::error::Error>> {
            let dir = std::env::temp_dir().join(format!(
                "miraserve-basic-auth-unit-{tag}-{}",
                std::process::id()
            ));
            let inner = dir.join(".htpasswds");
            std::fs::create_dir_all(&inner)?;
            let path = inner.join("users");
            std::fs::write(&path, format!("ann:{}\n", bcrypt::hash("s3cret", 4)?))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o700))?;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            }
            Ok(Self { dir, path })
        }

        fn config(&self) -> BasicAuthConfig {
            BasicAuthConfig {
                users_file: self.path.display().to_string(),
                realm: "Test".to_owned(),
            }
        }
    }

    impl Drop for TempUsersFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn load_area(cfg: &BasicAuthConfig) -> Arc<CompiledBasicAuth> {
        CompiledBasicAuth::load(cfg, &LoadedAreas::load([cfg], &[]).0)
    }

    #[test]
    fn credentials_are_read_from_exactly_one_basic_value() {
        assert_eq!(
            basic_credentials(&[basic("ann:pa:ss")]),
            Some(("ann".to_owned(), "pa:ss".to_owned()))
        );
        assert_eq!(
            basic_credentials(&[HeaderValue::from_static("Bearer abc")]),
            None
        );
        assert_eq!(
            basic_credentials(&[basic("ann:one"), basic("ann:two")]),
            None,
            "two Authorization values are ambiguous"
        );
        assert_eq!(basic_credentials(&[basic("ann:pa\nss")]), None);
        assert_eq!(basic_credentials(&[]), None);
    }

    #[tokio::test]
    async fn malformed_credentials_count_towards_throttle_while_missing_do_not() -> TestResult {
        let users = TempUsersFile::new("malformed")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)));

        // Missing credentials are just a challenge, never a failed attempt.
        for _ in 0..(MAX_FAILURES_PER_MINUTE + 5) {
            assert_eq!(auth.check(&[], ip).await, AuthDecision::Denied);
        }
        assert_eq!(
            count_of(&auth, ip),
            0,
            "requests without Authorization must not be counted"
        );

        let malformed_attempts: [Vec<HeaderValue>; 10] = [
            vec![HeaderValue::from_static("Basic !!!not-base64!!!")],
            vec![basic("no-colon-here")],
            vec![HeaderValue::from_static("Basic /+8=")], // invalid UTF-8 bytes
            vec![HeaderValue::from_static("Bearer some-token")],
            vec![basic("ann:pa\nss")],
            vec![basic("ann:one"), basic("ann:two")],
            vec![HeaderValue::from_static("Basic")],
            vec![HeaderValue::from_static("")],
            vec![basic("unknown-user:wrong")],
            vec![basic("ann:wrong")],
        ];
        assert_eq!(
            u32::try_from(malformed_attempts.len())?,
            MAX_FAILURES_PER_MINUTE
        );
        for attempt in &malformed_attempts {
            assert_eq!(auth.check(attempt, ip).await, AuthDecision::Denied);
        }

        // Once throttled, malformed, unknown-user, wrong-password and uncached valid attempts
        // are all refused with 429; a request with no credentials still gets the 401 challenge.
        assert_eq!(
            auth.check(&[HeaderValue::from_static("Basic !!!")], ip)
                .await,
            AuthDecision::Throttled
        );
        assert_eq!(
            auth.check(&[basic("unknown-user:wrong")], ip).await,
            AuthDecision::Throttled
        );
        assert_eq!(
            auth.check(&[basic("ann:wrong")], ip).await,
            AuthDecision::Throttled
        );
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], ip).await,
            AuthDecision::Throttled
        );
        assert_eq!(auth.check(&[], ip).await, AuthDecision::Denied);
        Ok(())
    }

    #[tokio::test]
    async fn full_waiting_queue_throttles_blocked_address_and_counts_nothing_else() -> TestResult {
        let users = TempUsersFile::new("queue")?;
        let auth = load_area(&users.config());
        let blocked_ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)));
        let clean_ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 21)));

        for _ in 0..MAX_FAILURES_PER_MINUTE {
            assert_eq!(
                auth.check(&[HeaderValue::from_static("Basic !!!")], blocked_ip)
                    .await,
                AuthDecision::Denied
            );
        }

        // Saturate the area's queue of checks.
        auth.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .running = MAX_WAITING_PER_AREA;

        // Already-throttled address must still receive 429 even when the queue is full.
        assert_eq!(
            auth.check(&[basic("ann:wrong")], blocked_ip).await,
            AuthDecision::Throttled
        );
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], blocked_ip).await,
            AuthDecision::Throttled
        );

        // Another address gets 503 while the queue is full; attempts without a verdict never
        // count towards its 429.
        for _ in 0..(MAX_FAILURES_PER_MINUTE * 2) {
            assert_eq!(
                auth.check(&[basic("ann:wrong")], clean_ip).await,
                AuthDecision::Unavailable
            );
        }
        assert_eq!(count_of(&auth, clean_ip), 0);

        // Once the queue drains, that address can still sign in (it has attempts left).
        auth.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .running = 0;
        assert_eq!(
            auth.check(&[basic("ann:wrong")], clean_ip).await,
            AuthDecision::Denied
        );
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], clean_ip).await,
            AuthDecision::Allowed
        );
        Ok(())
    }

    #[tokio::test]
    async fn reload_preserves_active_throttle_and_prunes_dead_registry_entries() -> TestResult {
        let users = TempUsersFile::new("reload-a")?;
        let other_users = TempUsersFile::new("reload-b")?;
        let pruner_users = TempUsersFile::new("reload-c")?;
        let cfg = users.config();
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 30)));

        let first = load_area(&cfg);
        for _ in 0..MAX_FAILURES_PER_MINUTE {
            assert_eq!(
                first
                    .check(&[HeaderValue::from_static("Basic !!!")], ip)
                    .await,
                AuthDecision::Denied
            );
        }
        assert_eq!(
            first.check(&[basic("ann:wrong")], ip).await,
            AuthDecision::Throttled
        );

        // Reload builds the next CompiledBasicAuth while the previous one is still alive.
        let reloaded = load_area(&cfg);
        assert!(Arc::ptr_eq(&first.failures, &reloaded.failures));
        drop(first);

        assert_eq!(
            reloaded.check(&[basic("ann:wrong")], ip).await,
            AuthDecision::Throttled
        );
        assert_eq!(
            reloaded.check(&[basic("ann:s3cret")], ip).await,
            AuthDecision::Throttled
        );

        // A different users file has its own independent failure table.
        let other = load_area(&other_users.config());
        assert!(!Arc::ptr_eq(&reloaded.failures, &other.failures));
        assert_eq!(
            other.check(&[basic("ann:s3cret")], ip).await,
            AuthDecision::Allowed
        );

        // The same users file on another site is the same accounts: one shared throttle.
        let other_site = load_area(&cfg);
        assert!(Arc::ptr_eq(&reloaded.failures, &other_site.failures));
        assert_eq!(
            other_site.check(&[basic("ann:s3cret")], ip).await,
            AuthDecision::Throttled
        );
        drop(other_site);

        // A retired area is kept while its failures count (a site taken offline and back)...
        drop(reloaded);
        let key = super::users_file_key(&cfg.users_file);
        let _pruner = load_area(&pruner_users.config());
        let registered = || {
            failure_registry()
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&key)
                .cloned()
        };
        {
            let area = registered().ok_or("a blocked area is kept")?;
            let mut state = area.lock().unwrap_or_else(PoisonError::into_inner);
            let long_ago = std::time::Instant::now()
                .checked_sub(super::FAILURE_WINDOW.saturating_mul(2))
                .ok_or("clock")?;
            state.table.current.start = long_ago;
            state.unanswered.current.start = long_ago;
        }
        // ... and dropped at the first configuration load after that.
        let _pruner = load_area(&pruner_users.config());
        assert!(registered().is_none());

        // Loading `cfg` again after the old area was completely dropped starts fresh.
        let fresh = load_area(&cfg);
        assert_eq!(
            fresh.check(&[basic("ann:s3cret")], ip).await,
            AuthDecision::Allowed
        );
        Ok(())
    }

    /// Antigravity review P1: a throttled address is refused before the remembered logins, so
    /// it cannot guess at full speed and be let in when a guess matches a recently used
    /// password.
    #[tokio::test]
    async fn throttled_address_cannot_use_a_remembered_login() -> TestResult {
        let users = TempUsersFile::new("throttle-cache")?;
        let auth = load_area(&users.config());
        let user_ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 40)));
        let attacker = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 41)));
        // A real user signs in: the login is remembered.
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], user_ip).await,
            AuthDecision::Allowed
        );
        // The attacker uses up its attempts, then tries the right password.
        for _ in 0..MAX_FAILURES_PER_MINUTE {
            assert_eq!(
                auth.check(&[HeaderValue::from_static("Basic !!!")], attacker)
                    .await,
                AuthDecision::Denied
            );
        }
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], attacker).await,
            AuthDecision::Throttled
        );
        // The real user is unaffected.
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], user_ip).await,
            AuthDecision::Allowed
        );
        Ok(())
    }

    /// Antigravity review P1: IPv6 addresses are counted by their /64, so rotating addresses
    /// inside one network gives no new attempts.
    #[tokio::test]
    async fn ipv6_addresses_in_one_network_share_their_attempts() -> TestResult {
        let users = TempUsersFile::new("ipv6-bucket")?;
        let auth = load_area(&users.config());
        for i in 0..MAX_FAILURES_PER_MINUTE {
            let ip: IpAddr = format!("2001:db8:abcd:1::{:x}", i + 1).parse()?;
            assert_eq!(
                auth.check(&[HeaderValue::from_static("Basic !!!")], Some(ip))
                    .await,
                AuthDecision::Denied
            );
        }
        let fresh_in_same_net: IpAddr = "2001:db8:abcd:1::ffff".parse()?;
        assert_eq!(
            auth.check(&[basic("ann:wrong")], Some(fresh_in_same_net))
                .await,
            AuthDecision::Throttled
        );
        let other_net: IpAddr = "2001:db8:abcd:2::1".parse()?;
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], Some(other_net)).await,
            AuthDecision::Allowed
        );
        Ok(())
    }

    /// Codex review 36: rotating through /64s inside one /48 hits the /48 limit too.
    #[tokio::test]
    async fn ipv6_rotation_across_networks_of_one_allocation_is_throttled() -> TestResult {
        let users = TempUsersFile::new("ipv6-48")?;
        let auth = load_area(&users.config());
        let per_net = MAX_FAILURES_PER_MINUTE;
        let nets = super::MAX_FAILURES_PER_MINUTE_48 / per_net;
        for net in 0..nets {
            for host in 0..per_net {
                let ip: IpAddr = format!("2001:db8:77:{:x}::{:x}", net + 1, host + 1).parse()?;
                assert_eq!(
                    auth.check(&[HeaderValue::from_static("Basic !!!")], Some(ip))
                        .await,
                    AuthDecision::Denied
                );
            }
        }
        let fresh_net: IpAddr = "2001:db8:77:ffff::1".parse()?;
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], Some(fresh_net)).await,
            AuthDecision::Throttled
        );
        let other_allocation: IpAddr = "2001:db8:78::1".parse()?;
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], Some(other_allocation))
                .await,
            AuthDecision::Allowed
        );
        Ok(())
    }

    /// A deadline well ahead, for direct calls to `step`.
    fn far() -> tokio::time::Instant {
        tokio::time::Instant::now() + std::time::Duration::from_secs(3600)
    }

    /// The test-only view of an address's count.
    fn count_of(auth: &CompiledBasicAuth, key: Option<IpAddr>) -> u32 {
        auth.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .failures_of(key, std::time::Instant::now())
    }

    /// Moves an area's minutes `by` into the past (as if that much time had passed).
    fn age(auth: &CompiledBasicAuth, by: std::time::Duration) -> TestResult {
        let mut table = auth.failures.lock().unwrap_or_else(PoisonError::into_inner);
        table.current.start = table.current.start.checked_sub(by).ok_or("clock")?;
        if let Some(previous) = table.previous.as_mut() {
            previous.start = previous.start.checked_sub(by).ok_or("clock")?;
        }
        Ok(())
    }

    /// A failure counts until its minute and the next one are over: a block holds for one to
    /// two minutes, then the address may try again.
    #[tokio::test]
    async fn failures_count_for_one_to_two_minutes() -> TestResult {
        let users = TempUsersFile::new("minutes")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 80)));
        for _ in 0..MAX_FAILURES_PER_MINUTE {
            assert_eq!(
                auth.check(&[basic("ann:wrong")], ip).await,
                AuthDecision::Denied
            );
        }
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], ip).await,
            AuthDecision::Throttled
        );
        age(&auth, std::time::Duration::from_secs(61))?;
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], ip).await,
            AuthDecision::Throttled,
            "still counted in the next minute"
        );
        age(&auth, std::time::Duration::from_secs(60))?;
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], ip).await,
            AuthDecision::Allowed
        );
        Ok(())
    }

    /// A successful login gives back exactly its own charge.
    #[tokio::test]
    async fn success_gives_back_its_own_charge() -> TestResult {
        let users = TempUsersFile::new("refund")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 81)));
        for _ in 0..(MAX_FAILURES_PER_MINUTE - 1) {
            assert_eq!(
                auth.check(&[basic("ann:wrong")], ip).await,
                AuthDecision::Denied
            );
        }
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], ip).await,
            AuthDecision::Allowed
        );
        assert_eq!(count_of(&auth, ip), MAX_FAILURES_PER_MINUTE - 1);
        assert_eq!(
            auth.check(&[basic("ann:wrong")], ip).await,
            AuthDecision::Denied
        );
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], ip).await,
            AuthDecision::Throttled
        );
        Ok(())
    }

    /// A browser's parallel requests with a remembered login are never counted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn parallel_remembered_logins_are_not_counted() -> TestResult {
        let users = TempUsersFile::new("parallel")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 60)));
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], ip).await,
            AuthDecision::Allowed
        );
        let mut tasks = Vec::new();
        for _ in 0..30 {
            let auth = Arc::clone(&auth);
            tasks.push(tokio::spawn(async move {
                auth.check(&[basic("ann:s3cret")], ip).await
            }));
        }
        for task in tasks {
            assert_eq!(task.await?, AuthDecision::Allowed);
        }
        assert_eq!(count_of(&auth, ip), 0, "remembered logins are not counted");
        Ok(())
    }

    /// Thousands of failing addresses neither lift anyone's block (nothing is evicted) nor
    /// throttle an unrelated address; the counters switch to the full array on the way.
    #[tokio::test]
    async fn many_failing_addresses_neither_unblock_nor_throttle_others() -> TestResult {
        let users = TempUsersFile::new("many")?;
        let auth = load_area(&users.config());
        let first = Some(IpAddr::V4(Ipv4Addr::from(0x0a00_0000_u32)));
        for i in 0..3_000_u32 {
            let ip = Some(IpAddr::V4(Ipv4Addr::from(0x0a00_0000_u32 + i)));
            for _ in 0..MAX_FAILURES_PER_MINUTE {
                // Denied, or throttled early when its counters are shared (the accepted cost).
                assert_ne!(
                    auth.check(&[HeaderValue::from_static("Basic !!!")], ip)
                        .await,
                    AuthDecision::Allowed
                );
            }
        }
        assert!(matches!(
            auth.failures
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .current
                .counts,
            super::Counts::Dense(_)
        ));
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], first).await,
            AuthDecision::Throttled
        );
        // An address whose counters are not all shared with blocked ones (almost any) logs in.
        let mut unrelated = None;
        for i in 0..1_000_u32 {
            let candidate = Some(IpAddr::V4(Ipv4Addr::from(0xcb00_7100_u32 + i)));
            if count_of(&auth, candidate) < MAX_FAILURES_PER_MINUTE {
                unrelated = Some(candidate);
                break;
            }
        }
        let unrelated = unrelated.ok_or("every candidate collided")?;
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], unrelated).await,
            AuthDecision::Allowed
        );
        Ok(())
    }

    /// The accepted cost, made deterministic: an address all of whose counters are shared with
    /// blocked addresses is refused although it never failed.
    #[tokio::test]
    async fn an_address_whose_counters_are_all_shared_is_refused() -> TestResult {
        let users = TempUsersFile::new("collision")?;
        let auth = load_area(&users.config());
        let victim = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77)));
        {
            let mut table = auth.failures.lock().unwrap_or_else(PoisonError::into_inner);
            for slot in table.slots(victim) {
                for _ in 0..MAX_FAILURES_PER_MINUTE {
                    table.current.counts.add(slot);
                }
            }
        }
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], victim).await,
            AuthDecision::Throttled
        );
        Ok(())
    }

    /// Retry-After matches the block: one minute when the previous minute's drop lifts it,
    /// two when the current minute alone holds it; a saturated counter is not lowered.
    #[tokio::test]
    async fn retry_after_matches_the_block_and_saturation_holds() -> TestResult {
        let users = TempUsersFile::new("retry")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 90)));
        for _ in 0..MAX_FAILURES_PER_MINUTE {
            assert_eq!(
                auth.check(&[basic("ann:wrong")], ip).await,
                AuthDecision::Denied
            );
        }
        assert!(auth.retry_after_secs(ip) >= 1);
        // Exact waits at chosen instants (no real clock): all failures in the current minute
        // block until the next minute is over too; a minute later they sit in the previous
        // minute and block until it is dropped; then nothing blocks.
        let secs = std::time::Duration::from_secs;
        let keys = super::attempt_keys(ip);
        let mut table = auth.failures.lock().unwrap_or_else(PoisonError::into_inner);
        let start = table.current.start;
        let at = |offset: u64| start.checked_add(secs(offset)).ok_or("clock");
        assert_eq!(table.retry_after(&keys, at(1)?), secs(119));
        assert_eq!(table.retry_after(&keys, at(61)?), secs(59));
        assert_eq!(table.retry_after(&keys, at(121)?), secs(0));
        drop(table);
        // Saturation: a counter at its maximum stays there.
        let mut counts = super::Counts::Sparse(std::collections::HashMap::new());
        for _ in 0..u32::from(u16::MAX) + 5 {
            counts.add(7);
        }
        counts.sub(7);
        assert_eq!(counts.get(7), u32::from(u16::MAX));
        Ok(())
    }

    /// One IPv6 /64 using up its own attempts leaves the rest of its /48 able to log in; the
    /// /48 limit still bounds its /64s together.
    #[tokio::test]
    async fn one_64_does_not_lock_out_its_48() -> TestResult {
        let users = TempUsersFile::new("one-64")?;
        let auth = load_area(&users.config());
        let noisy: IpAddr = "2001:db8:90:1::1".parse()?;
        for _ in 0..MAX_FAILURES_PER_MINUTE {
            assert_eq!(
                auth.check(&[basic("ann:wrong")], Some(noisy)).await,
                AuthDecision::Denied
            );
        }
        assert_eq!(
            auth.check(&[basic("ann:wrong")], Some(noisy)).await,
            AuthDecision::Throttled
        );
        let neighbour: IpAddr = "2001:db8:90:2::1".parse()?;
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], Some(neighbour)).await,
            AuthDecision::Allowed
        );
        Ok(())
    }

    /// Refund edges (Antigravity review of db2a946): a refund after its minute became the
    /// previous one, one older than two minutes, an IPv6 refund (its /64 and /48), one after
    /// the switch to the full array, and the unknown-address bucket.
    #[tokio::test]
    async fn refunds_reach_exactly_their_own_counters_in_every_case() -> TestResult {
        let users = TempUsersFile::new("refund-edges")?;
        let auth = load_area(&users.config());
        let secs = std::time::Duration::from_secs;
        let v4 = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 95)));
        let v6: IpAddr = "2001:db8:91:1::1".parse()?;
        let mut v6_keys = super::attempt_keys(Some(v6))
            .into_iter()
            .map(|(key, _)| key);
        let (v6_64, v6_48) = (v6_keys.next().ok_or("64")?, v6_keys.next().ok_or("48")?);

        // Moves the table on to `offset` after its current minute started, as time does (the
        // minutes keep their starts, which tickets refer to).
        let roll_to = |offset: u64| -> TestResult {
            let mut table = auth.failures.lock().unwrap_or_else(PoisonError::into_inner);
            let at = table
                .current
                .start
                .checked_add(secs(offset))
                .ok_or("clock")?;
            table.roll(at);
            Ok(())
        };
        let count_at = |key: Option<IpAddr>, offset: u64| -> Result<u32, &'static str> {
            let mut table = auth.failures.lock().unwrap_or_else(PoisonError::into_inner);
            let at = table
                .current
                .start
                .checked_add(secs(offset))
                .ok_or("clock")?;
            Ok(table.failures_of(key, at))
        };

        // Charged in one minute, refunded after it became the previous minute.
        let ticket = auth.reserve_attempt(v4, true).ok_or("refused")?;
        roll_to(61)?;
        assert!(
            auth.failures
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .previous
                .is_some()
        );
        assert_eq!(count_at(v4, 0)?, 1);
        auth.refund_attempt(&ticket);
        assert_eq!(count_at(v4, 0)?, 0);

        // A refund of a minute no longer kept leaves the new minutes alone.
        let stale = auth.reserve_attempt(v4, true).ok_or("refused")?;
        roll_to(130)?;
        auth.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .charge(v4, std::time::Instant::now());
        auth.refund_attempt(&stale);
        assert_eq!(count_at(v4, 0)?, 1);

        // IPv6: one refund gives back the /64 and the /48 charge.
        let ticket = auth.reserve_attempt(Some(v6), true).ok_or("refused")?;
        assert_eq!((count_of(&auth, v6_64), count_of(&auth, v6_48)), (1, 1));
        auth.refund_attempt(&ticket);
        assert_eq!((count_of(&auth, v6_64), count_of(&auth, v6_48)), (0, 0));

        // The unknown-address bucket.
        let ticket = auth.reserve_attempt(None, true).ok_or("refused")?;
        assert_eq!(count_of(&auth, None), 1);
        auth.refund_attempt(&ticket);
        assert_eq!(count_of(&auth, None), 0);

        // After the switch to the full array, a charge made before it is still given back.
        let early = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 96)));
        let ticket = auth.reserve_attempt(early, true).ok_or("refused")?;
        for i in 0..2_000_u32 {
            let ip = Some(IpAddr::V4(Ipv4Addr::from(0x0b00_0000_u32 + i)));
            let _ = auth.reserve_attempt(ip, true);
        }
        assert!(matches!(
            auth.failures
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .current
                .counts,
            super::Counts::Dense(_)
        ));
        let before = count_of(&auth, early);
        auth.refund_attempt(&ticket);
        assert_eq!(count_of(&auth, early), before - 1);
        Ok(())
    }

    /// Spawns 20 concurrent login tasks for one address with nothing cached yet: all are allowed,
    /// no failures are recorded, and no in-flight entries remain afterward.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn parallel_first_logins_share_one_check() -> TestResult {
        let users = TempUsersFile::new("first-burst")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 120)));
        let mut tasks = Vec::new();
        for _ in 0..20 {
            let auth = Arc::clone(&auth);
            tasks.push(tokio::spawn(async move {
                auth.check(&[basic("ann:s3cret")], ip).await
            }));
        }
        for task in tasks {
            assert_eq!(task.await?, AuthDecision::Allowed);
        }
        assert_eq!(count_of(&auth, ip), 0);
        assert!(
            auth.failures
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .flights
                .is_empty(),
            "no check left behind"
        );
        Ok(())
    }

    /// Twenty copies of one wrong password in flight at once are one guess: all refused, none
    /// throttled, exactly one charge. The site's bcrypt slots are held until every copy has
    /// joined the one check, so they really overlap.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn parallel_copies_of_one_guess_are_counted_once() -> TestResult {
        let users = TempUsersFile::new("same-guess")?;
        let auth = load_area(&users.config());
        let held = Arc::clone(&auth.failures.slots)
            .acquire_many_owned(u32::try_from(MAX_CONCURRENT_CHECKS_PER_SITE)?)
            .await?;
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 121)));
        let mut tasks = Vec::new();
        for _ in 0..20 {
            let auth = Arc::clone(&auth);
            tasks.push(tokio::spawn(async move {
                auth.check(&[basic("ann:wrong")], ip).await
            }));
        }
        let joined = async {
            while auth
                .failures
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .followers
                < 19
            {
                tokio::task::yield_now().await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(4), joined).await?;
        drop(held);
        for task in tasks {
            assert_eq!(task.await?, AuthDecision::Denied);
        }
        assert_eq!(count_of(&auth, ip), 1);
        assert!(
            auth.failures
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .flights
                .is_empty()
        );
        Ok(())
    }

    /// A remembered login is renewed by each use, so it does not expire while in use (times
    /// move forward from now, which works on a machine that has just booted).
    #[tokio::test]
    async fn a_remembered_login_in_use_does_not_expire() -> TestResult {
        let users = TempUsersFile::new("renew")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 122)));
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], ip).await,
            AuthDecision::Allowed
        );
        let key = key_of(&auth, "ann", "s3cret");
        let start = std::time::Instant::now();
        let at = |secs: u64| {
            start
                .checked_add(std::time::Duration::from_secs(secs))
                .ok_or("clock")
        };
        // Used every nine minutes: still remembered after 27 minutes.
        for minute in [9, 18, 27] {
            assert!(auth.recently_verified_at(&key, at(minute * 60)?));
        }
        // Then unused for longer than the limit: forgotten.
        let later = 27 * 60 + super::VERIFIED_TTL.as_secs() + 1;
        assert!(!auth.recently_verified_at(&key, at(later)?));
        Ok(())
    }

    /// A block made only of checks still running says to retry in a second, not in minutes.
    #[tokio::test]
    async fn a_block_of_running_checks_says_retry_soon() -> TestResult {
        let users = TempUsersFile::new("pending")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 123)));
        let mut running = Vec::new();
        for _ in 0..MAX_FAILURES_PER_MINUTE {
            running.push(
                auth.failures
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .charge_attempt(ip, std::time::Instant::now()),
            );
        }
        assert!(auth.reserve_attempt(ip, false).is_none());
        assert_eq!(auth.retry_after_secs(ip), 1);
        // Once they have ended as failures, the block is a real one.
        for ticket in &running {
            auth.failures
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .keep_ticket(ticket);
        }
        assert!(auth.retry_after_secs(ip) > 100);
        Ok(())
    }

    /// The digest of `user:password` in an area.
    fn key_of(auth: &CompiledBasicAuth, user: &str, password: &str) -> [u8; 32] {
        let hash = auth
            .users
            .as_ref()
            .and_then(|users| users.by_name.get(user).cloned())
            .unwrap_or_default();
        super::credential_key(user, password, &hash)
    }

    /// Codex review 55 P1 3: a block held only by another address's running check on a shared
    /// counter says to retry soon.
    #[tokio::test]
    async fn a_shared_counter_held_by_a_running_check_says_retry_soon() -> TestResult {
        let users = TempUsersFile::new("shared-pending")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 140)));
        {
            let mut table = auth.failures.lock().unwrap_or_else(PoisonError::into_inner);
            let slots = table.slots(ip);
            let start = table.current.start;
            for (row, slot) in slots.into_iter().enumerate() {
                let fill = if row == 3 {
                    MAX_FAILURES_PER_MINUTE - 1
                } else {
                    MAX_FAILURES_PER_MINUTE
                };
                for _ in 0..fill {
                    table.current.counts.add(slot);
                }
            }
            // Another address's charge, still being checked, on the last counter.
            let last = slots.last().copied().ok_or("slot")?;
            table.current.counts.add(last);
            table.pending.insert((start, last), 1);
        }
        assert!(auth.reserve_attempt(ip, false).is_none());
        assert_eq!(auth.retry_after_secs(ip), 1);
        Ok(())
    }

    /// Codex reviews 55-57: an area (its throttle, waiting limits and bcrypt slots) is its
    /// users file however spelled, so no host-name edit (alias added, moved, reordered, first
    /// name renamed) resets it.
    #[tokio::test]
    async fn an_area_is_its_users_file_however_spelled() -> TestResult {
        let users = TempUsersFile::new("identity")?;
        let first = load_area(&users.config());
        let mut respelled = users.config();
        respelled.users_file = users.config().users_file.replace('/', "/./");
        let reloaded = load_area(&respelled);
        assert!(Arc::ptr_eq(&first.failures, &reloaded.failures));
        assert!(Arc::ptr_eq(&first.failures.slots, &reloaded.failures.slots));
        Ok(())
    }

    /// Codex review 56 P1 4: the one-or-two-minute choice uses the current minute without
    /// charges still being checked (the block lifts with the previous minute when the pending
    /// one is given back).
    #[tokio::test]
    async fn retry_after_ignores_pending_charges_when_choosing_the_minute() -> TestResult {
        let users = TempUsersFile::new("retry-pending")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 150)));
        let mut table = auth.failures.lock().unwrap_or_else(PoisonError::into_inner);
        let start = table.current.start;
        let secs = std::time::Duration::from_secs;
        // Minute one: one failure on every counter of `ip`.
        table.charge(ip, std::time::Instant::now());
        // Minute two: nine settled failures plus one pending charge on the last counter.
        table.roll(start.checked_add(secs(60)).ok_or("clock")?);
        let second = table.current.start;
        let slots = table.slots(ip);
        for slot in slots {
            for _ in 0..(MAX_FAILURES_PER_MINUTE - 1) {
                table.current.counts.add(slot);
            }
        }
        for slot in slots.iter().take(3) {
            table.current.counts.add(*slot);
        }
        let last = slots.last().copied().ok_or("slot")?;
        table.current.counts.add(last);
        table.pending.insert((second, last), 1);
        // At second 119: blocked by ten settled failures that include minute one's, so the
        // block lifts when minute one is dropped, one second later.
        let keys = super::attempt_keys(ip);
        let wait = table.retry_after(&keys, second.checked_add(secs(59)).ok_or("clock")?);
        assert_eq!(wait, secs(1));
        Ok(())
    }

    /// Codex review 58 P1 2 and 3: cancelling the request that started a check (a reset
    /// HTTP/2 stream) neither stops nor unsettles it; its page's identical request gets in
    /// and nothing stays counted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_cancelled_first_request_does_not_stop_its_check() -> TestResult {
        let users = TempUsersFile::new("cancel")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 172)));
        let held = Arc::clone(&auth.failures.slots)
            .acquire_many_owned(u32::try_from(MAX_CONCURRENT_CHECKS_PER_SITE)?)
            .await?;
        let first = {
            let auth = Arc::clone(&auth);
            tokio::spawn(async move { auth.check(&[basic("ann:s3cret")], ip).await })
        };
        let started = async {
            while auth
                .failures
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .flights
                .is_empty()
            {
                tokio::task::yield_now().await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(4), started).await?;
        first.abort();
        let second = {
            let auth = Arc::clone(&auth);
            tokio::spawn(async move { auth.check(&[basic("ann:s3cret")], ip).await })
        };
        drop(held);
        assert_eq!(second.await?, AuthDecision::Allowed);
        assert_eq!(count_of(&auth, ip), 0);
        Ok(())
    }

    /// Holds all of an area's bcrypt slots (its checks get no verdict until released).
    async fn hold_slots(
        auth: &CompiledBasicAuth,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, Box<dyn std::error::Error>> {
        Ok(Arc::clone(&auth.failures.slots)
            .acquire_many_owned(u32::try_from(MAX_CONCURRENT_CHECKS_PER_SITE)?)
            .await?)
    }

    /// Codex review 59 P1 2: a request that joined late and still has time takes over when the
    /// check it waited for got no verdict.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_late_follower_takes_over_a_check_without_a_verdict() -> TestResult {
        let users = TempUsersFile::new("take-over")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 181)));
        let held = hold_slots(&auth).await?;
        let first = {
            let auth = Arc::clone(&auth);
            tokio::spawn(async move { auth.check(&[basic("ann:s3cret")], ip).await })
        };
        tokio::time::sleep(std::time::Duration::from_secs(4)).await;
        let late = {
            let auth = Arc::clone(&auth);
            tokio::spawn(async move { auth.check(&[basic("ann:s3cret")], ip).await })
        };
        assert_eq!(first.await?, AuthDecision::Unavailable);
        drop(held);
        assert_eq!(late.await?, AuthDecision::Allowed);
        Ok(())
    }

    fn set_running(auth: &CompiledBasicAuth, running: usize) {
        auth.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .running = running;
    }

    fn charge_failures(auth: &CompiledBasicAuth, ip: Option<IpAddr>, count: u32) {
        let mut state = auth.failures.lock().unwrap_or_else(PoisonError::into_inner);
        for _ in 0..count {
            state.charge(ip, std::time::Instant::now());
        }
    }

    /// Waits until `ready` holds for the area's state.
    async fn until(
        auth: &CompiledBasicAuth,
        ready: impl Fn(&super::AreaState) -> bool,
    ) -> TestResult {
        let waiting = async {
            while !ready(&auth.failures.lock().unwrap_or_else(PoisonError::into_inner)) {
                tokio::task::yield_now().await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(4), waiting).await?;
        Ok(())
    }

    /// A full queue answers 503 without counting towards a 429, but it compares at most ten
    /// guesses per address with the remembered logins: after that, not even the right
    /// password is let in by the comparison (it needs a check), while other addresses still
    /// use their remembered logins.
    #[tokio::test]
    async fn a_full_queue_is_no_oracle_for_remembered_logins() -> TestResult {
        let users = TempUsersFile::new("no-oracle")?;
        let auth = load_area(&users.config());
        let friend = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 160)));
        let guesser = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 161)));
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], friend).await,
            AuthDecision::Allowed
        );
        set_running(&auth, MAX_WAITING_PER_AREA);
        for i in 0..MAX_FAILURES_PER_MINUTE {
            assert_eq!(
                auth.check(&[basic(&format!("ann:guess{i}"))], guesser)
                    .await,
                AuthDecision::Unavailable
            );
        }
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], guesser).await,
            AuthDecision::Unavailable
        );
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], friend).await,
            AuthDecision::Allowed
        );
        // Nothing counts towards a 429; with room again, the right password gets in.
        assert_eq!(count_of(&auth, guesser), 0);
        set_running(&auth, 0);
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], guesser).await,
            AuthDecision::Allowed
        );
        Ok(())
    }

    /// Failures, running checks and unanswered comparisons share the comparison limit.
    #[tokio::test]
    async fn comparisons_share_the_attempt_limit() -> TestResult {
        let users = TempUsersFile::new("compare-limit")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 162)));
        charge_failures(&auth, ip, MAX_FAILURES_PER_MINUTE - 1);
        set_running(&auth, MAX_WAITING_PER_AREA);
        assert_eq!(
            auth.check(&[basic("ann:guess")], ip).await,
            AuthDecision::Unavailable
        );
        auth.remember(key_of(&auth, "ann", "s3cret"));
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], ip).await,
            AuthDecision::Unavailable
        );
        Ok(())
    }

    /// A reload that changes or removes the user's hash ends its remembered login at once,
    /// although the area keeps its state.
    #[tokio::test]
    async fn a_changed_or_removed_user_is_forgotten_by_a_reload() -> TestResult {
        let users = TempUsersFile::new("revoked")?;
        let old = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 186)));
        let login = [basic("ann:s3cret")];
        assert_eq!(old.check(&login, ip).await, AuthDecision::Allowed);
        for line in ["ann:", "eve:"] {
            let hash = bcrypt::hash("changed", 4)?;
            std::fs::write(&users.path, format!("{line}{hash}\n"))?;
            let reloaded = load_area(&users.config());
            assert!(Arc::ptr_eq(&old.failures, &reloaded.failures));
            assert_eq!(reloaded.check(&login, ip).await, AuthDecision::Denied);
        }
        Ok(())
    }

    /// Codex review 60 P1 4-5, Antigravity P1 1-2: a check without a verdict is given back
    /// completely, as often as it happens; a wrong password with a verdict always counts.
    #[tokio::test]
    async fn no_verdict_is_given_back_and_every_denial_counts() -> TestResult {
        let users = TempUsersFile::new("given-back")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 187)));
        let held = hold_slots(&auth).await?;
        assert_eq!(
            auth.check(&[basic("ann:wrong")], ip).await,
            AuthDecision::Unavailable
        );
        until(&auth, |state| state.flights.is_empty()).await?;
        assert_eq!(count_of(&auth, ip), 0);
        drop(held);
        for count in 1..=3 {
            assert_eq!(
                auth.check(&[basic("ann:wrong")], ip).await,
                AuthDecision::Denied
            );
            assert_eq!(count_of(&auth, ip), count);
        }
        let state = auth.failures.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!((state.running, state.followers), (0, 0));
        assert!(state.pending.is_empty());
        Ok(())
    }

    /// A verdict that came after a request's own deadline does not let that request in; one
    /// from before it does, however late the request looks (Codex 60 P1 8, 63 P1 3).
    #[tokio::test]
    async fn a_late_verdict_does_not_count_for_an_expired_request() -> TestResult {
        let users = TempUsersFile::new("late-verdict")?;
        let auth = load_area(&users.config());
        let deadline = tokio::time::Instant::now();
        let late = deadline.into_std() + std::time::Duration::from_millis(1);
        for (ended, accepted) in [(late, false), (deadline.into_std(), true)] {
            let outcome = Some((AuthDecision::Allowed, ended));
            let (_sender, receiver) = tokio::sync::watch::channel(outcome);
            assert_eq!(auth.wait(receiver, deadline).await.is_some(), accepted);
        }
        let (sender, receiver) = tokio::sync::watch::channel(None);
        let state = auth.failures.lock().unwrap_or_else(PoisonError::into_inner);
        let waiting = {
            let auth = Arc::clone(&auth);
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()?;
                Ok::<_, std::io::Error>(runtime.block_on(auth.wait(receiver, deadline)))
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(100));
        sender.send_replace(Some((AuthDecision::Denied, deadline.into_std())));
        drop(state);
        let outcome = waiting.join().map_err(|_| "panicked")??;
        assert_eq!(
            outcome.map(|(decision, _)| decision),
            Some(AuthDecision::Denied)
        );
        Ok(())
    }

    /// A remembered login's last use never moves backwards.
    #[tokio::test]
    async fn an_older_use_never_moves_a_login_back() -> TestResult {
        let users = TempUsersFile::new("renew-order")?;
        let auth = load_area(&users.config());
        let key = key_of(&auth, "ann", "s3cret");
        auth.remember(key);
        let now = std::time::Instant::now();
        let later = now + std::time::Duration::from_secs(300);
        assert!(auth.recently_verified_at(&key, later));
        assert!(auth.recently_verified_at(&key, now));
        let state = auth.failures.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(state.verified.get(&key), Some(&later));
        Ok(())
    }

    /// Codex review 61 P1 5: a full list of remembered logins loses at most the one unused for
    /// longest, and none when the login is already in it.
    #[test]
    fn a_full_list_of_remembered_logins_loses_only_the_oldest() -> TestResult {
        let mut state = super::AreaState::new();
        let start = std::time::Instant::now();
        let key = |n: usize| {
            let mut key = [0_u8; 32];
            for (slot, byte) in key.iter_mut().zip(n.to_le_bytes()) {
                *slot = byte;
            }
            key
        };
        for n in 0..super::MAX_REMEMBERED {
            let at = start + std::time::Duration::from_millis(u64::try_from(n)?);
            state.remember(key(n), at);
        }
        let later = start + std::time::Duration::from_secs(30);
        state.remember(key(7), later);
        assert_eq!(state.verified.len(), super::MAX_REMEMBERED);
        state.remember(key(super::MAX_REMEMBERED), later);
        assert_eq!(state.verified.len(), super::MAX_REMEMBERED);
        assert!(!state.verified.contains_key(&key(0)));
        assert!(state.verified.contains_key(&key(1)));
        Ok(())
    }

    fn address_of(ip: Option<IpAddr>) -> Option<IpAddr> {
        super::attempt_keys(ip).first().and_then(|&(key, _)| key)
    }

    fn unavailable(step: &super::Step) -> bool {
        matches!(
            step,
            super::Step::Decided(AuthDecision::Unavailable) | super::Step::OutOfTime
        )
    }

    /// With one attempt left, the first guess takes it in the step that admits it; while it is
    /// checked, the address's other requests wait instead of getting 429, and are answered once it has
    /// ended.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_last_attempt_is_taken_in_one_step_and_others_wait() -> TestResult {
        let users = TempUsersFile::new("last-attempt")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 170)));
        charge_failures(&auth, ip, MAX_FAILURES_PER_MINUTE - 1);
        let held = hold_slots(&auth).await?;
        let mut tasks = Vec::new();
        for password in ["s3cret", "s3cret", "s3cret"] {
            let shared = Arc::clone(&auth);
            let header = basic(&format!("ann:{password}"));
            tasks.push(tokio::spawn(
                async move { shared.check(&[header], ip).await },
            ));
            let waiting = tasks.len() - 1;
            until(&auth, |state| {
                state.flights.len() == 1 && state.followers == waiting
            })
            .await?;
        }
        assert_eq!(auth.retry_after_secs(ip), 1);
        drop(held);
        for task in tasks {
            assert_eq!(task.await?, AuthDecision::Allowed);
        }
        assert_eq!(count_of(&auth, ip), MAX_FAILURES_PER_MINUTE - 1);
        assert_eq!(
            auth.check(&[basic("ann:wrong")], ip).await,
            AuthDecision::Denied
        );
        assert_eq!(count_of(&auth, ip), MAX_FAILURES_PER_MINUTE);
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], ip).await,
            AuthDecision::Throttled
        );
        Ok(())
    }

    /// More first logins in flight from one address than it has attempts (an office): all get
    /// in, the ones beyond the limit after waiting.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn more_right_logins_at_once_than_attempts_all_get_in() -> TestResult {
        let users = TempUsersFile::new("office")?;
        let mut lines = String::new();
        for i in 0..14 {
            use std::fmt::Write as _;
            writeln!(lines, "u{i}:{}", bcrypt::hash(format!("p{i}"), 4)?)?;
        }
        std::fs::write(&users.path, lines)?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 171)));
        let held = hold_slots(&auth).await?;
        let mut tasks = Vec::new();
        for i in 0..14 {
            let shared = Arc::clone(&auth);
            tasks.push(tokio::spawn(async move {
                shared.check(&[basic(&format!("u{i}:p{i}"))], ip).await
            }));
        }
        until(&auth, |state| state.running + state.followers == 14).await?;
        drop(held);
        for task in tasks {
            assert_eq!(task.await?, AuthDecision::Allowed);
        }
        assert_eq!(count_of(&auth, ip), 0);
        Ok(())
    }

    /// Each address pays for its own check of the same password, once for all its requests;
    /// when it is right, every address's check of it ends with the first, in every
    /// configuration generation.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_same_password_from_several_addresses() -> TestResult {
        let users = TempUsersFile::new("several")?;
        let old = load_area(&users.config());
        let new = load_area(&users.config());
        let a = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 182)));
        let b = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 183)));
        for (password, expected, counted) in [
            ("wrong", AuthDecision::Denied, 1),
            ("s3cret", AuthDecision::Allowed, 1),
        ] {
            let held = hold_slots(&old).await?;
            let mut tasks = Vec::new();
            for (auth, ip) in [(&old, a), (&new, b), (&new, b), (&new, b)] {
                let shared = Arc::clone(auth);
                let header = basic(&format!("ann:{password}"));
                tasks.push(tokio::spawn(
                    async move { shared.check(&[header], ip).await },
                ));
            }
            until(&old, |state| state.running == 2 && state.followers == 2).await?;
            drop(held);
            for task in tasks {
                assert_eq!(task.await?, expected);
            }
            assert_eq!((count_of(&old, a), count_of(&new, b)), (counted, counted));
        }
        set_running(&new, MAX_WAITING_PER_AREA);
        assert_eq!(
            new.check(&[basic("ann:s3cret")], b).await,
            AuthDecision::Allowed
        );
        Ok(())
    }

    /// No room to wait, or no time left: 503, nothing charged or started.
    #[tokio::test]
    async fn no_room_to_wait_or_no_time_left_charges_nothing() -> TestResult {
        let users = TempUsersFile::new("no-room")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 188)));
        let key = key_of(&auth, "ann", "guess");
        assert!(unavailable(&auth.step(
            key,
            ip,
            tokio::time::Instant::now()
        )));
        assert_eq!(count_of(&auth, ip), 0);
        let first = auth.step(key, ip, far());
        assert!(matches!(first, super::Step::Start(..)));
        auth.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .followers = super::MAX_FOLLOWERS_PER_AREA;
        assert!(unavailable(&auth.step(key, ip, far())));
        assert_eq!(count_of(&auth, ip), 1);
        Ok(())
    }

    /// With a full queue and no comparisons left, an address gets the same 503 for every
    /// password but the ones it is being checked for (Codex 61 P1 1).
    #[tokio::test]
    async fn a_full_queue_hides_the_running_checks() -> TestResult {
        let users = TempUsersFile::new("hidden-flights")?;
        let auth = load_area(&users.config());
        let user = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 191)));
        let guesser = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 192)));
        for ip in [user, guesser] {
            let key = key_of(&auth, "ann", if ip == user { "s3cret" } else { "mine" });
            assert!(matches!(auth.step(key, ip, far()), super::Step::Start(..)));
        }
        set_running(&auth, MAX_WAITING_PER_AREA);
        for i in 0..MAX_FAILURES_PER_MINUTE {
            let key = key_of(&auth, "ann", &format!("g{i}"));
            assert!(unavailable(&auth.step(key, guesser, far())));
        }
        for password in ["other", "s3cret"] {
            let key = key_of(&auth, "ann", password);
            assert!(unavailable(&auth.step(key, guesser, far())));
        }
        // Its own running check it has paid for.
        assert!(matches!(
            auth.step(key_of(&auth, "ann", "mine"), guesser, far()),
            super::Step::Follow(..)
        ));
        Ok(())
    }

    /// A check out of time before it started holds no charge for the next decision and tells
    /// its waiters at once, although its task has not run (Codex 61 P1 2, 62 P1 4); ending it
    /// again changes nothing.
    #[tokio::test]
    async fn an_expired_unstarted_check_is_ended_by_the_next_decision() -> TestResult {
        let users = TempUsersFile::new("expired-unstarted")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 193)));
        charge_failures(&auth, ip, MAX_FAILURES_PER_MINUTE - 1);
        let soon = tokio::time::Instant::now() + std::time::Duration::from_millis(20);
        let key = key_of(&auth, "ann", "guess");
        let super::Step::Start(flight, id, outcome) = auth.step(key, ip, soon) else {
            return Err("expected a new check".into());
        };
        tokio::time::sleep_until(soon).await;
        let next = auth.step(key_of(&auth, "ann", "s3cret"), ip, far());
        assert!(matches!(next, super::Step::Start(..)));
        let ended = *outcome.borrow();
        assert_eq!(
            ended.map(|(decision, _)| decision),
            Some(AuthDecision::Unavailable)
        );
        let mut state = auth.failures.lock().unwrap_or_else(PoisonError::into_inner);
        let now = std::time::Instant::now();
        state.settle(&flight, id, AuthDecision::Denied, now);
        assert!(state.start(&flight, id, now).is_none());
        assert_eq!((state.running, state.flights.len()), (1, 1));
        Ok(())
    }

    /// A check whose login another address proved right meanwhile needs no bcrypt, if its own
    /// address may compare; otherwise it has to be checked (Codex 63 P1 2).
    #[tokio::test]
    async fn a_login_remembered_meanwhile_needs_no_bcrypt_if_compared() -> TestResult {
        let users = TempUsersFile::new("remembered-meanwhile")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 194)));
        for compared in [true, false] {
            let digest = key_of(&auth, "ann", if compared { "x" } else { "y" });
            let super::Step::Start(flight, id, outcome) = auth.step(digest, ip, far()) else {
                return Err("expected a new check".into());
            };
            {
                let mut state = auth.failures.lock().unwrap_or_else(PoisonError::into_inner);
                state.flights.get_mut(&flight).ok_or("flight")?.compared = compared;
            }
            auth.remember(digest);
            super::work(&claim_of(&auth, flight, id).await?);
            let ended = *outcome.borrow();
            let expected = if compared {
                AuthDecision::Allowed
            } else {
                AuthDecision::Denied
            };
            assert_eq!(ended.map(|(decision, _)| decision), Some(expected));
        }
        Ok(())
    }

    /// A request held back by a running check is answered when the failures expire, without
    /// waiting for that check (Codex 63 P1 4); malformed credentials wait too (P1 7).
    #[tokio::test]
    async fn held_back_requests_wake_when_failures_expire() -> TestResult {
        let users = TempUsersFile::new("rolls")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 198)));
        charge_failures(&auth, ip, MAX_FAILURES_PER_MINUTE - 1);
        auth.remember(key_of(&auth, "ann", "s3cret"));
        {
            // The failures' minute is the previous one and ends in 200 ms.
            let mut state = auth.failures.lock().unwrap_or_else(PoisonError::into_inner);
            let left = std::time::Duration::from_millis(200);
            let by = super::FAILURE_WINDOW.saturating_sub(left);
            let start = state.table.current.start.checked_sub(by).ok_or("clock")?;
            let before = start.checked_sub(super::FAILURE_WINDOW).ok_or("clock")?;
            let mut previous =
                std::mem::replace(&mut state.table.current, super::Generation::starting(start));
            previous.start = before;
            state.table.previous = Some(previous);
            // One more attempt, still being checked.
            let _ticket = state.charge_attempt(ip, std::time::Instant::now());
        }
        let started = std::time::Instant::now();
        let (login, malformed) = tokio::join!(
            async {
                let header = [basic("ann:s3cret")];
                auth.check(&header, ip).await
            },
            async {
                let header = [HeaderValue::from_static("Basic !!!")];
                auth.check(&header, ip).await
            }
        );
        assert_eq!(
            (login, malformed),
            (AuthDecision::Allowed, AuthDecision::Denied)
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
        Ok(())
    }

    /// A comparison made while the address already waits for its check is counted when that
    /// check gets no verdict (Codex 62 P1 2).
    #[tokio::test]
    async fn a_later_comparison_counts_with_its_check() -> TestResult {
        let users = TempUsersFile::new("later-comparison")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 196)));
        let key = key_of(&auth, "ann", "guess");
        let super::Step::Start(flight, id, _) = auth.step(key, ip, far()) else {
            return Err("expected a new check".into());
        };
        {
            let mut state = auth.failures.lock().unwrap_or_else(PoisonError::into_inner);
            state.flights.get_mut(&flight).ok_or("flight")?.compared = false;
        }
        assert!(matches!(auth.step(key, ip, far()), super::Step::Follow(..)));
        let mut state = auth.failures.lock().unwrap_or_else(PoisonError::into_inner);
        let now = std::time::Instant::now();
        state.settle(&flight, id, AuthDecision::Unavailable, now);
        assert_eq!(state.unanswered.failures_of(address_of(ip), now), 1);
        Ok(())
    }

    /// A denial that comes too late for every request waiting for it does not count; one in
    /// time for any of them does (Codex 62 P1 5).
    #[tokio::test]
    async fn a_denial_nobody_got_does_not_count() -> TestResult {
        let users = TempUsersFile::new("late-denial")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 197)));
        let key = key_of(&auth, "ann", "guess");
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
        let later = deadline + std::time::Duration::from_secs(2);
        let ended = deadline.into_std() + std::time::Duration::from_secs(1);
        for (joins, counted) in [(false, 0), (true, 1)] {
            let super::Step::Start(flight, id, _) = auth.step(key, ip, deadline) else {
                return Err("expected a new check".into());
            };
            // Kept waiting until the check has ended.
            let follower = joins.then(|| auth.step(key, ip, later));
            assert_eq!(matches!(follower, Some(super::Step::Follow(..))), joins);
            let mut state = auth.failures.lock().unwrap_or_else(PoisonError::into_inner);
            assert!(
                state
                    .start(&flight, id, std::time::Instant::now())
                    .is_some()
            );
            state.settle(&flight, id, AuthDecision::Denied, ended);
            drop(state);
            drop(follower);
            assert_eq!(count_of(&auth, ip), counted);
        }
        Ok(())
    }

    /// The claim of a check of `key`, holding all the area's slots.
    async fn claim_of(
        auth: &CompiledBasicAuth,
        key: super::FlightKey,
        id: u64,
    ) -> Result<std::sync::Mutex<Option<super::Claim>>, Box<dyn std::error::Error>> {
        let slots = &auth.failures.slots;
        Ok(std::sync::Mutex::new(Some(super::Claim {
            job: super::CheckJob {
                area: Arc::clone(&auth.failures),
                id,
                key,
                known: true,
                verdict: None,
            },
            password: "guess".to_owned(),
            hash: bcrypt::hash("s3cret", 4)?,
            _permits: [
                Arc::clone(slots).acquire_owned().await?,
                Arc::clone(slots).acquire_owned().await?,
            ],
        })))
    }

    /// Dropping an unclaimed check settles it and frees its slots; a job dequeued after its
    /// deadline runs no bcrypt (no verdict, rather than a denial); at most
    /// [`super::MAX_QUEUED_BCRYPT`] jobs are queued.
    #[tokio::test]
    async fn unclaimed_late_and_queued_jobs() -> TestResult {
        static JOBS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let mut jobs: Vec<_> = (0..super::MAX_QUEUED_BCRYPT)
            .map_while(|_| super::QueuedJob::take(&JOBS))
            .collect();
        assert_eq!(jobs.len(), super::MAX_QUEUED_BCRYPT);
        assert!(super::QueuedJob::take(&JOBS).is_none());
        jobs.pop();
        assert!(super::QueuedJob::take(&JOBS).is_some());

        let users = TempUsersFile::new("jobs")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 195)));
        let key = key_of(&auth, "ann", "guess");
        for case in ["taken back", "late", "in time"] {
            let deadline = if case == "late" {
                tokio::time::Instant::now() + std::time::Duration::from_millis(10)
            } else {
                far()
            };
            let super::Step::Start(flight, id, outcome) = auth.step(key, ip, deadline) else {
                return Err("expected a new check".into());
            };
            let claim = Arc::new(claim_of(&auth, flight, id).await?);
            if case == "taken back" {
                drop(super::TakeBack(Arc::clone(&claim)));
            } else if case == "late" {
                tokio::time::sleep_until(deadline).await;
            }
            super::work(&claim);
            let ended = *outcome.borrow();
            let expected = if case == "in time" {
                AuthDecision::Denied
            } else {
                AuthDecision::Unavailable
            };
            assert_eq!(
                ended.map(|(decision, _)| decision),
                Some(expected),
                "{case}"
            );
            assert_eq!(
                auth.failures.slots.available_permits(),
                MAX_CONCURRENT_CHECKS_PER_SITE
            );
        }
        assert_eq!(count_of(&auth, ip), 1);
        Ok(())
    }

    /// An area is the path of its users file: replacing the file keeps it, another file has its
    /// own (also when it was the same file before), and another name of a loaded file is not
    /// loaded (Codex 62 P1 1, 65 P1 1-4).
    #[tokio::test]
    async fn an_area_is_its_users_file_path() -> TestResult {
        let users = TempUsersFile::new("names")?;
        let config = |name: &str| BasicAuthConfig {
            users_file: users.path.with_file_name(name).display().to_string(),
            realm: "Test".to_owned(),
        };
        let both = [config("users"), config("other")];
        let load = || {
            let (areas, files) = LoadedAreas::load(&both, &[]);
            let [first, second] = both
                .each_ref()
                .map(|cfg| CompiledBasicAuth::load(cfg, &areas));
            (first, second, files.len())
        };
        let other = users.path.with_file_name("other");
        std::fs::hard_link(&users.path, &other)?;
        let (linked, alias, files) = load();
        assert_eq!(files, 2);
        assert!(linked.load_error().is_none());
        assert!(
            alias
                .load_error()
                .is_some_and(|reason| reason.contains("same file as"))
        );
        // Another case of the name on a case-insensitive volume.
        if users.path.with_file_name("USERS").exists() {
            let cased = config("USERS");
            let (areas, _) = LoadedAreas::load([&config("users"), &cased], &[]);
            assert!(
                CompiledBasicAuth::load(&cased, &areas)
                    .load_error()
                    .is_some()
            );
        }
        // Replaced by files of their own: both load, each with the area of its path.
        for path in [&users.path, &other] {
            let fresh = users.path.with_file_name("fresh");
            std::fs::copy(path, &fresh)?;
            std::fs::rename(&fresh, path)?;
        }
        let (own, separate, _) = load();
        assert!(own.load_error().is_none() && separate.load_error().is_none());
        assert!(Arc::ptr_eq(&own.failures, &linked.failures));
        assert!(!Arc::ptr_eq(&own.failures, &separate.failures));
        Ok(())
    }

    /// A reading counts only when the next one agrees: a file replaced, edited in place (within
    /// one clock tick), created, removed or given another mode between them, or in a directory
    /// that was, is read again (Codex 65 P1 1, 66 P1 2, 4 and 6, 67 P1 2 and 3).
    #[test]
    fn a_file_changed_while_loading_is_seen() -> TestResult {
        let users = TempUsersFile::new("replaced")?;
        let path = users.path.as_path();
        let read = || super::read_users_file(path, &[]);
        let text = std::fs::read_to_string(path)?;
        let first = read();
        assert!(first.content.is_ok() && first.is_same_as(&read()));
        std::fs::write(path, text.replace("ann:", "bob:"))?;
        let edited = read();
        assert!(!first.is_same_as(&edited), "edited in place, same size");
        let fresh = path.with_file_name("fresh");
        std::fs::copy(path, &fresh)?;
        std::fs::rename(&fresh, path)?;
        let replaced = read();
        assert!(replaced.content.is_ok() && !edited.is_same_as(&replaced));
        std::fs::remove_file(path)?;
        let missing = read();
        assert!(missing.content.is_err() && !missing.is_same_as(&replaced));
        assert!(missing.is_same_as(&read()));
        std::fs::write(path, &text)?;
        assert!(!missing.is_same_as(&read()), "created");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let dir = path.parent().ok_or("parent")?;
            for (target, good, bad) in [(path, 0o600, 0o660), (dir, 0o700, 0o770)] {
                std::fs::set_permissions(target, std::fs::Permissions::from_mode(bad))?;
                let refused = read();
                assert!(refused.content.is_err());
                std::fs::set_permissions(target, std::fs::Permissions::from_mode(good))?;
                let repaired = read();
                assert!(repaired.content.is_ok() && !repaired.is_same_as(&refused));
            }
            let file = std::fs::File::open(path)?;
            assert!(miraserve_static::opened_credential_problem(&file).is_none());
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
            assert!(miraserve_static::opened_credential_problem(&file).is_some());
        }
        Ok(())
    }

    /// No room to wait is 503, not a throttle, for a request that only running checks hold back
    /// (Codex 66 P1 3).
    #[tokio::test]
    async fn no_room_to_wait_is_no_throttle() -> TestResult {
        let users = TempUsersFile::new("no-room-429")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 207)));
        charge_failures(&auth, ip, MAX_FAILURES_PER_MINUTE - 1);
        let key = key_of(&auth, "ann", "s3cret");
        assert!(matches!(auth.step(key, ip, far()), super::Step::Start(..)));
        auth.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .followers = super::MAX_FOLLOWERS_PER_AREA;
        for password in ["s3cret", "other"] {
            let key = key_of(&auth, "ann", password);
            assert!(unavailable(&auth.step(key, ip, far())));
        }
        assert_eq!(auth.malformed(ip, far()).await, AuthDecision::Unavailable);
        charge_failures(&auth, ip, 1);
        assert!(matches!(
            auth.step(key, ip, far()),
            super::Step::Decided(AuthDecision::Throttled)
        ));
        assert_eq!(auth.malformed(ip, far()).await, AuthDecision::Throttled);
        Ok(())
    }

    /// Sites that name one users file have the same users, whatever replaces the file while
    /// the configuration is loaded (Codex 64 P1 5).
    #[tokio::test]
    async fn one_load_reads_a_users_file_once() -> TestResult {
        let users = TempUsersFile::new("one-read")?;
        let areas = LoadedAreas::load(&[users.config()], &[]).0;
        let first = CompiledBasicAuth::load(&users.config(), &areas);
        std::fs::write(&users.path, format!("bob:{}\n", bcrypt::hash("x", 4)?))?;
        let mut respelled = users.config();
        respelled.users_file = respelled.users_file.replace("/users", "/./users");
        let second = CompiledBasicAuth::load(&respelled, &areas);
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 201)));
        for site in [first, second] {
            assert_eq!(
                site.check(&[basic("ann:s3cret")], ip).await,
                AuthDecision::Allowed
            );
        }
        Ok(())
    }

    /// A remembered login let in by comparison answers the same address's check of it: its
    /// requests are let in and nothing stays charged; its place in the queue is given back when
    /// its job ends (Codex 64 P1 2).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_remembered_login_answers_its_addresss_check() -> TestResult {
        let users = TempUsersFile::new("answers")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 202)));
        let other = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 203)));
        let held = hold_slots(&auth).await?;
        let mut tasks = Vec::new();
        for (address, followers) in [(ip, 0), (ip, 1), (other, 1)] {
            let shared = Arc::clone(&auth);
            tasks.push(tokio::spawn(async move {
                shared.check(&[basic("ann:s3cret")], address).await
            }));
            let flights = usize::from(address == other) + 1;
            until(&auth, |state| {
                state.followers == followers && state.running == flights
            })
            .await?;
        }
        let last = tasks.pop().ok_or("task")?;
        auth.remember(key_of(&auth, "ann", "s3cret"));
        assert_eq!(
            auth.check(&[basic("ann:s3cret")], ip).await,
            AuthDecision::Allowed
        );
        for task in tasks {
            assert_eq!(task.await?, AuthDecision::Allowed);
        }
        assert_eq!((count_of(&auth, ip), count_of(&auth, other)), (0, 1));
        // The answered job leaves without waiting for a bcrypt slot.
        until(&auth, |state| state.running == 1).await?;
        drop(held);
        assert_eq!(last.await?, AuthDecision::Allowed);
        Ok(())
    }

    /// An answered check keeps its queue place until its job ends, runs no bcrypt and is settled
    /// once.
    #[tokio::test]
    async fn an_answered_check_holds_its_place_and_is_not_started() -> TestResult {
        let users = TempUsersFile::new("answered-place")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 204)));
        let key = key_of(&auth, "ann", "s3cret");
        let super::Step::Start(flight, id, outcome) = auth.step(key, ip, far()) else {
            return Err("expected a new check".into());
        };
        auth.remember(key);
        assert!(matches!(
            auth.step(key, ip, far()),
            super::Step::Decided(AuthDecision::Allowed)
        ));
        let mut state = auth.failures.lock().unwrap_or_else(PoisonError::into_inner);
        let now = std::time::Instant::now();
        assert_eq!(state.running, 1);
        // A request that may not compare gets nothing from the answered check (Codex 65 P1 8).
        assert!(state.flights.is_empty());
        assert!(state.start(&flight, id, now).is_none());
        state.settle(&flight, id, AuthDecision::Unavailable, now);
        assert_eq!(state.running, 0);
        assert_eq!(state.unanswered.failures_of(address_of(ip), now), 0);
        assert_eq!(state.table.failures_of(address_of(ip), now), 0);
        let ended = *outcome.borrow();
        assert_eq!(
            ended.map(|(decision, _)| decision),
            Some(AuthDecision::Allowed)
        );
        Ok(())
    }

    /// The deadline of a request that has gone no longer makes a late denial count (Codex 64
    /// P1 3).
    #[tokio::test]
    async fn a_cancelled_follower_wants_no_verdict() -> TestResult {
        let users = TempUsersFile::new("cancelled-follower")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 205)));
        let key = key_of(&auth, "ann", "guess");
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
        let later = deadline + std::time::Duration::from_secs(2);
        let ended = deadline.into_std() + std::time::Duration::from_secs(1);
        let super::Step::Start(flight, id, _) = auth.step(key, ip, deadline) else {
            return Err("expected a new check".into());
        };
        let follower = auth.step(key, ip, later);
        assert!(matches!(follower, super::Step::Follow(..)));
        drop(follower);
        let mut state = auth.failures.lock().unwrap_or_else(PoisonError::into_inner);
        assert!(
            state
                .start(&flight, id, std::time::Instant::now())
                .is_some()
        );
        state.settle(&flight, id, AuthDecision::Denied, ended);
        assert_eq!(state.followers, 0);
        drop(state);
        assert_eq!(count_of(&auth, ip), 0);
        Ok(())
    }

    /// A page whose address may not compare any more, on its last attempt: all its requests
    /// share the one check instead of being checked one after the other (Antigravity 21 P2 3,
    /// Codex 63 P1 5).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_page_on_its_last_attempt_shares_one_check() -> TestResult {
        let users = TempUsersFile::new("last-page")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 199)));
        charge_failures(&auth, ip, MAX_FAILURES_PER_MINUTE - 1);
        auth.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .count_unanswered(ip, std::time::Instant::now());
        let held = hold_slots(&auth).await?;
        let mut tasks = Vec::new();
        for _ in 0..26 {
            let shared = Arc::clone(&auth);
            tasks.push(tokio::spawn(async move {
                shared.check(&[basic("ann:s3cret")], ip).await
            }));
        }
        until(&auth, |state| state.followers == 25).await?;
        set_running(&auth, MAX_WAITING_PER_AREA);
        drop(held);
        for task in tasks {
            assert_eq!(task.await?, AuthDecision::Allowed);
        }
        assert_eq!(count_of(&auth, ip), MAX_FAILURES_PER_MINUTE - 1);
        Ok(())
    }

    /// Malformed credentials out of time charge nothing (Codex 64 P1 4).
    #[tokio::test]
    async fn malformed_credentials_out_of_time_charge_nothing() -> TestResult {
        let users = TempUsersFile::new("malformed-late")?;
        let auth = load_area(&users.config());
        let ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 206)));
        let now = tokio::time::Instant::now();
        assert_eq!(auth.malformed(ip, now).await, AuthDecision::Unavailable);
        assert_eq!(count_of(&auth, ip), 0);
        assert_eq!(auth.malformed(ip, far()).await, AuthDecision::Denied);
        assert_eq!(count_of(&auth, ip), 1);
        Ok(())
    }

    /// A users file with another name of its own (a backup hard link) loads again while a
    /// running configuration has its identity on the deny list (Codex 68 P1 1).
    #[tokio::test]
    async fn a_users_file_with_a_backup_link_loads_on_reload() -> TestResult {
        let users = TempUsersFile::new("backup-link")?;
        std::fs::hard_link(&users.path, users.path.with_file_name("users.bak"))?;
        let handles = [std::fs::File::open(&users.path)?];
        let running = miraserve_static::handle_identities(&handles);
        miraserve_static::publish_secret_files(&running);
        let auth = load_area(&users.config());
        assert_eq!(auth.load_error(), None);
        Ok(())
    }
}

//! A budget for bodies held whole in memory.
//!
//! FastCGI and WASM routes buffer the request before the backend sees it and the answer before
//! the client does. Each is capped on its own (`max-body-bytes`, the FastCGI answer limit), but
//! nothing bounded all of them together: many uploads at once, or answers slow clients have not
//! taken yet, could use up the memory of the worker every site shares. Every such byte is
//! counted here, per visitor address and in total; a request that does not fit gets 503.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};

/// What one address may hold at least: enough for a few of the largest uploads.
const MIN_ADDRESS_SHARE: u64 = 128 * 1024 * 1024;
/// How many addresses can hold their full share at once.
const FULL_SHARES: u64 = 4;

#[derive(Default)]
struct Held {
    total: u64,
    by_address: HashMap<Option<IpAddr>, u64>,
}

static HELD: Mutex<Option<Held>> = Mutex::new(None);

/// The address the bytes are counted for: an IPv6 address counts as its /64.
fn counted_as(address: Option<IpAddr>) -> Option<IpAddr> {
    address.map(|ip| match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mut segments = v6.segments();
            for segment in segments.iter_mut().skip(4) {
                *segment = 0;
            }
            IpAddr::V6(segments.into())
        }
        v4 @ IpAddr::V4(_) => v4,
    })
}

/// Buffered bytes of one request, given back when it is dropped.
#[derive(Debug)]
pub(crate) struct Buffered {
    address: Option<IpAddr>,
    share: u64,
    held: u64,
}

impl Buffered {
    /// Starts counting for a request of `address`; `max_body_bytes` is the configured upload
    /// limit (an address may always hold two uploads of that size).
    pub(crate) fn for_address(address: Option<IpAddr>, max_body_bytes: u64) -> Self {
        Self {
            address: counted_as(address),
            share: MIN_ADDRESS_SHARE.max(max_body_bytes.saturating_mul(2)),
            held: 0,
        }
    }

    /// Counts `bytes` more; `false` when the address or the server holds too much already
    /// (nothing is counted then).
    pub(crate) fn grow(&mut self, bytes: usize) -> bool {
        let bytes = bytes as u64;
        let mut held = HELD.lock().unwrap_or_else(PoisonError::into_inner);
        let held = held.get_or_insert_with(Held::default);
        let of_address = held.by_address.get(&self.address).copied().unwrap_or(0);
        let fits = of_address.saturating_add(bytes) <= self.share
            && held.total.saturating_add(bytes) <= self.share.saturating_mul(FULL_SHARES);
        if fits {
            held.total = held.total.saturating_add(bytes);
            held.by_address
                .insert(self.address, of_address.saturating_add(bytes));
            self.held = self.held.saturating_add(bytes);
        }
        fits
    }

    /// Gives `bytes` back (a buffer that has been dropped).
    pub(crate) fn shrink(&mut self, bytes: usize) {
        let bytes = (bytes as u64).min(self.held);
        self.held -= bytes;
        let mut held = HELD.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(held) = held.as_mut() else {
            return;
        };
        held.total = held.total.saturating_sub(bytes);
        if let Some(of_address) = held.by_address.get_mut(&self.address) {
            *of_address = of_address.saturating_sub(bytes);
            if *of_address == 0 {
                held.by_address.remove(&self.address);
            }
        }
    }
}

/// Answers one address may have streaming from a backend at once
/// (`limits.max-streamed-answers-per-ip`). Each of them holds a backend worker for as long as
/// the visitor takes to download it. One value for the process, set when a configuration is
/// loaded.
static MAX_STREAMED_PER_ADDRESS: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(8);

/// Answers that may be streaming from one backend at once
/// (`limits.max-streamed-answers-per-backend`), whatever the visitors' addresses: a pool of
/// workers must keep some for ordinary requests.
static MAX_STREAMED_PER_BACKEND: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(4);

/// Sets how many answers one address, and one backend, may have streaming at once.
pub(crate) fn set_max_streamed(per_address: u32, per_backend: u32) {
    use std::sync::atomic::Ordering;
    MAX_STREAMED_PER_ADDRESS.store(per_address.max(1), Ordering::Relaxed);
    MAX_STREAMED_PER_BACKEND.store(per_backend.max(1), Ordering::Relaxed);
}

/// Why an answer may not be streamed now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamedRefusal {
    /// The visitor's address has as many as it may.
    Address,
    /// The backend has as many as it may.
    Backend,
}

#[derive(Default)]
struct StreamedCounts {
    by_address: HashMap<Option<IpAddr>, u32>,
    by_backend: HashMap<String, u32>,
}

static STREAMED: Mutex<Option<StreamedCounts>> = Mutex::new(None);

/// One answer that is being streamed from a backend to a visitor's address; counted for both
/// until it is dropped.
#[derive(Debug)]
pub(crate) struct Streamed {
    address: Option<IpAddr>,
    backend: String,
}

impl Streamed {
    /// Counts one more for `address` and for `backend`, or says which of them has as many
    /// as it may (nothing is counted then).
    ///
    /// `backend_max` is the backend's own limit, when its route sets one; the general limit
    /// applies otherwise.
    pub(crate) fn start(
        address: Option<IpAddr>,
        backend: &str,
        backend_max: Option<u32>,
    ) -> Result<Self, StreamedRefusal> {
        use std::sync::atomic::Ordering;
        let address = counted_as(address);
        let mut streamed = STREAMED.lock().unwrap_or_else(PoisonError::into_inner);
        let counts = streamed.get_or_insert_with(StreamedCounts::default);
        let of_address = counts.by_address.get(&address).copied().unwrap_or(0);
        if of_address >= MAX_STREAMED_PER_ADDRESS.load(Ordering::Relaxed) {
            return Err(StreamedRefusal::Address);
        }
        let of_backend = counts.by_backend.get(backend).copied().unwrap_or(0);
        let backend_max =
            backend_max.unwrap_or_else(|| MAX_STREAMED_PER_BACKEND.load(Ordering::Relaxed));
        if of_backend >= backend_max.max(1) {
            return Err(StreamedRefusal::Backend);
        }
        counts
            .by_address
            .insert(address, of_address.saturating_add(1));
        counts
            .by_backend
            .insert(backend.to_owned(), of_backend.saturating_add(1));
        Ok(Self {
            address,
            backend: backend.to_owned(),
        })
    }
}

impl Drop for Streamed {
    fn drop(&mut self) {
        let mut streamed = STREAMED.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(counts) = streamed.as_mut() else {
            return;
        };
        if let Some(count) = counts.by_address.get_mut(&self.address) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.by_address.remove(&self.address);
            }
        }
        if let Some(count) = counts.by_backend.get_mut(&self.backend) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.by_backend.remove(&self.backend);
            }
        }
    }
}

impl Drop for Buffered {
    fn drop(&mut self) {
        let all = usize::try_from(self.held).unwrap_or(usize::MAX);
        self.shrink(all);
    }
}

#[cfg(test)]
mod tests {
    use super::{Buffered, FULL_SHARES, HELD, MIN_ADDRESS_SHARE};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// The count is one for the process: these tests take turns.
    static TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn of(address: Option<IpAddr>) -> u64 {
        let held = HELD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        held.as_ref()
            .and_then(|held| held.by_address.get(&super::counted_as(address)).copied())
            .unwrap_or(0)
    }

    /// An address streams a few answers at once and no more, and so does a backend; another
    /// address or backend is not affected; an answer that ends makes room.
    #[test]
    fn an_address_streams_a_few_answers_at_once() {
        use super::{
            MAX_STREAMED_PER_ADDRESS, MAX_STREAMED_PER_BACKEND, Streamed, StreamedRefusal,
        };
        use std::sync::atomic::Ordering;
        let per_address = MAX_STREAMED_PER_ADDRESS.load(Ordering::Relaxed);
        let per_backend = MAX_STREAMED_PER_BACKEND.load(Ordering::Relaxed);
        let address = |n: u8| Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, n)));

        // One address, a backend of its own for each answer: the address is the limit.
        let mut running: Vec<Streamed> = (0..per_address)
            .filter_map(|n| Streamed::start(address(1), &format!("unix:/test/own-{n}"), None).ok())
            .collect();
        assert_eq!(running.len(), per_address as usize);
        assert_eq!(
            Streamed::start(address(1), "unix:/test/own-more", None).err(),
            Some(StreamedRefusal::Address)
        );
        assert!(Streamed::start(address(2), "unix:/test/other", None).is_ok());
        running.pop();
        assert!(Streamed::start(address(1), "unix:/test/own-more", None).is_ok());

        // One backend, an address of its own for each answer: the backend is the limit, and
        // another backend is not affected.
        let mut pool: Vec<Streamed> = (0..per_backend)
            .filter_map(|n| {
                let n = u8::try_from(n).unwrap_or(0).saturating_add(10);
                Streamed::start(address(n), "unix:/test/pool", None).ok()
            })
            .collect();
        assert_eq!(pool.len(), per_backend as usize);
        assert_eq!(
            Streamed::start(address(200), "unix:/test/pool", None).err(),
            Some(StreamedRefusal::Backend)
        );
        assert!(Streamed::start(address(200), "unix:/test/second-pool", None).is_ok());
        pool.pop();
        assert!(Streamed::start(address(200), "unix:/test/pool", None).is_ok());

        // A backend with a number of its own.
        let first = Streamed::start(address(210), "unix:/test/small-pool", Some(1));
        assert!(first.is_ok());
        assert_eq!(
            Streamed::start(address(211), "unix:/test/small-pool", Some(1)).err(),
            Some(StreamedRefusal::Backend)
        );
    }

    /// An address holds its share and no more; other addresses still fit until the server's
    /// total is reached; dropping gives everything back.
    #[test]
    fn an_address_and_the_server_have_limits() {
        let _turn = TURN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let share = usize::try_from(MIN_ADDRESS_SHARE).unwrap_or(usize::MAX);
        let address = |n: u8| Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, n)));
        let mut first = Buffered::for_address(address(1), 0);
        assert!(first.grow(share - 10));
        assert!(!first.grow(11));
        assert!(first.grow(10));
        // A second request of the same address shares its count.
        let mut again = Buffered::for_address(address(1), 0);
        assert!(!again.grow(1));
        first.shrink(100);
        assert!(again.grow(100));
        assert_eq!(of(address(1)), MIN_ADDRESS_SHARE);

        let mut others: Vec<Buffered> = Vec::new();
        for n in 2..=u8::try_from(FULL_SHARES).unwrap_or(4) {
            let mut other = Buffered::for_address(address(n), 0);
            assert!(other.grow(share), "address {n}");
            others.push(other);
        }
        // The server's total is used up: another address does not fit.
        let mut late = Buffered::for_address(address(200), 0);
        assert!(!late.grow(1));
        drop(others);
        assert!(late.grow(1));
        drop((first, again, late));
        assert_eq!(of(address(1)), 0);
    }

    /// IPv6 addresses of one /64 are one address; a larger upload limit raises the share.
    #[test]
    fn an_ipv6_network_counts_as_one_and_the_share_follows_the_upload_limit() {
        let _turn = TURN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let v6 = |host: u16| {
            Some(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xdb8, 7, 7, 0, 0, 0, host,
            )))
        };
        let big = MIN_ADDRESS_SHARE * 2;
        let mut one = Buffered::for_address(v6(1), big);
        let wanted = usize::try_from(big * 2).unwrap_or(usize::MAX);
        assert!(one.grow(wanted));
        let mut two = Buffered::for_address(v6(2), big);
        assert!(!two.grow(1));
        drop(one);
        assert!(two.grow(1));
    }
}

//! Lock-free configuration store supporting atomic, fail-safe hot reload via [`arc_swap::ArcSwap`].

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::{ArcSwap, Guard};

use crate::error::{ConfigError, ValidationReport};
use crate::schema::Config;
use crate::{load_file, parse_kdl};

/// Thread-safe, lock-free configuration store backed by [`ArcSwap`].
///
/// Readers call [`ConfigStore::current`] or [`ConfigStore::snapshot`] without acquiring
/// any mutex or blocking writers. Reloads parse and fully validate the incoming KDL
/// before atomically swapping the active configuration; failed reloads leave the live
/// configuration completely untouched.
#[derive(Debug)]
pub struct ConfigStore {
    inner: ArcSwap<Config>,
    generation: AtomicU64,
}

impl ConfigStore {
    /// Creates a new store initialized with a validated [`Config`] at generation `1`.
    #[must_use]
    pub fn new(config: Config) -> Self {
        Self {
            inner: ArcSwap::from_pointee(config),
            generation: AtomicU64::new(1),
        }
    }

    /// Loads and validates a configuration file from disk into a new [`ConfigStore`].
    ///
    /// # Errors
    /// Returns [`ConfigError`] if reading, parsing, or validating the file fails.
    pub fn from_file(path: impl AsRef<Path>) -> Result<(Self, ValidationReport), ConfigError> {
        let (config, report) = load_file(path)?;
        Ok((Self::new(config), report))
    }

    /// Returns a lock-free guard borrowing the current active [`Config`].
    #[must_use]
    pub fn current(&self) -> Guard<Arc<Config>> {
        self.inner.load()
    }

    /// Returns an owned `Arc<Config>` snapshot of the current active configuration.
    #[must_use]
    pub fn snapshot(&self) -> Arc<Config> {
        self.inner.load_full()
    }

    /// Returns the monotonic configuration generation counter (starts at `1`).
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Atomically replaces the active configuration with a pre-validated [`Config`]
    /// and returns the new generation number.
    pub fn swap(&self, next: Config) -> u64 {
        self.inner.store(Arc::new(next));
        self.generation.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Parses and validates a KDL configuration string and atomically swaps it in.
    ///
    /// If parsing or validation fails, the currently active configuration and generation
    /// remain completely unchanged.
    ///
    /// # Errors
    /// Returns [`ConfigError::Validation`] if the replacement KDL is invalid.
    pub fn reload_from_str(
        &self,
        source_name: &str,
        kdl: &str,
    ) -> Result<(u64, ValidationReport), ConfigError> {
        let (next, report) = parse_kdl(source_name, kdl)?;
        let generation = self.swap(next);
        Ok((generation, report))
    }

    /// Reads, parses, and validates a KDL file from disk and atomically swaps it in.
    ///
    /// If reading, parsing, or validation fails, the currently active configuration and
    /// generation remain completely unchanged.
    ///
    /// # Errors
    /// Returns [`ConfigError`] if reading, parsing, or validation fails.
    pub fn reload_from_file(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<(u64, ValidationReport), ConfigError> {
        let (next, report) = load_file(path)?;
        let generation = self.swap(next);
        Ok((generation, report))
    }
}

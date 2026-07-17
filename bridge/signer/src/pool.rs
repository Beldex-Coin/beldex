//! Preprocessed-material pool (**S3**).
//!
//! Both signing legs pre-compute message-independent material ahead of demand:
//! CGGMP21 **presignature tuples** (`Pevm`) and FROST **nonce-commitment pairs**
//! (`Pgw`). This material is *key-equivalent*: reusing one item for two different
//! messages leaks the secret key (the classic ECDSA nonce-reuse / FROST
//! nonce-reuse break). So the lifecycle is a hard security rule (S3):
//!
//!   * **Single use, atomic consume-and-erase** — an item is removed from the
//!     pool the instant it is handed out; there is no path that returns the same
//!     item twice. ([`Pool::consume`] moves the item out by value.)
//!   * **Erase at refresh** — every unused item is destroyed on a proactive key
//!     refresh/reshare. ([`Pool::erase_all`].)
//!   * **Bounded** — the pool never exceeds a hard cap `L <= 128`
//!     ([`Pool::MAX_CAPACITY`]); CGGMP21 unforgeability degrades with `L`.
//!
//! This module owns the *lifecycle*, not the cryptography: `T` is opaque
//! (`PresignatureTuple` / `FrostNoncePair` from the TSS crates). In production the
//! backing store is the [`crate::share_store`] (so a crash cannot leave a reusable
//! item on disk); this in-memory pool models and tests the invariants.

/// Errors from pool operations.
#[derive(Debug, PartialEq, Eq)]
pub enum PoolError {
    /// Adding would exceed the hard cap `L` (self-audit panics elsewhere; here we
    /// return an error so callers can stop refilling).
    Full,
    /// A capacity outside `1..=MAX_CAPACITY` was requested.
    BadCapacity,
}

/// A bounded, single-use pool of preprocessed signing material.
#[derive(Debug)]
pub struct Pool<T> {
    items: Vec<T>,
    capacity: usize,
    low_water: usize,
}

impl<T> Pool<T> {
    /// The absolute cap on outstanding preprocessed items (S3, Shoup–Groth).
    pub const MAX_CAPACITY: usize = 128;

    /// Create an empty pool. `capacity` is the hard cap `L` (`1..=128`);
    /// `low_water` is the threshold at or below which [`Pool::needs_refill`] is
    /// true (clamped to `capacity`).
    pub fn new(capacity: usize, low_water: usize) -> Result<Self, PoolError> {
        if capacity == 0 || capacity > Self::MAX_CAPACITY {
            return Err(PoolError::BadCapacity);
        }
        Ok(Pool {
            items: Vec::with_capacity(capacity),
            capacity,
            low_water: low_water.min(capacity),
        })
    }

    /// Number of items currently available.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// True if the pool is empty (no signing can proceed until refilled).
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The hard cap `L`.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// True when the pool has drained to the low-water mark and should be
    /// topped up (by running more preprocessing).
    pub fn needs_refill(&self) -> bool {
        self.items.len() <= self.low_water
    }

    /// How many items may still be added before hitting the cap.
    pub fn headroom(&self) -> usize {
        self.capacity - self.items.len()
    }

    /// Add one preprocessed item. Fails with [`PoolError::Full`] at the cap — the
    /// pool is *never* unbounded (S3).
    pub fn add(&mut self, item: T) -> Result<(), PoolError> {
        if self.items.len() >= self.capacity {
            return Err(PoolError::Full);
        }
        self.items.push(item);
        Ok(())
    }

    /// Atomically consume one item: it is **moved out and removed** in a single
    /// step, so the same item can never be returned twice (single-use, S3).
    /// Returns `None` when the pool is empty.
    pub fn consume(&mut self) -> Option<T> {
        self.items.pop()
    }

    /// Destroy all unused items (called on every key refresh / reshare, S3/S7).
    pub fn erase_all(&mut self) {
        self.items.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in for a presignature tuple / FROST nonce pair with a unique id,
    /// so tests can assert no item is ever handed out twice.
    #[derive(Debug, PartialEq, Eq, Clone)]
    struct FakeItem(u64);

    #[test]
    fn rejects_bad_capacity() {
        assert_eq!(Pool::<FakeItem>::new(0, 0).err(), Some(PoolError::BadCapacity));
        assert_eq!(
            Pool::<FakeItem>::new(Pool::<FakeItem>::MAX_CAPACITY + 1, 0).err(),
            Some(PoolError::BadCapacity)
        );
        assert!(Pool::<FakeItem>::new(128, 32).is_ok());
    }

    #[test]
    fn is_bounded_at_capacity() {
        let mut p = Pool::new(4, 1).unwrap();
        for i in 0..4 {
            p.add(FakeItem(i)).unwrap();
        }
        assert_eq!(p.len(), 4);
        assert_eq!(p.headroom(), 0);
        // The 5th add is refused — the pool is never unbounded.
        assert_eq!(p.add(FakeItem(99)), Err(PoolError::Full));
        assert_eq!(p.len(), 4);
    }

    #[test]
    fn consume_is_single_use_no_item_returned_twice() {
        let mut p = Pool::new(8, 2).unwrap();
        for i in 0..8 {
            p.add(FakeItem(i)).unwrap();
        }
        let mut seen = std::collections::HashSet::new();
        while let Some(item) = p.consume() {
            // Every consumed item is unique: reuse is impossible by construction.
            assert!(seen.insert(item.0), "item {} was handed out twice", item.0);
        }
        assert_eq!(seen.len(), 8);
        assert!(p.is_empty());
        // Consuming an empty pool yields None (signing must wait for a refill).
        assert_eq!(p.consume(), None);
    }

    #[test]
    fn consume_removes_exactly_one() {
        let mut p = Pool::new(3, 1).unwrap();
        p.add(FakeItem(1)).unwrap();
        p.add(FakeItem(2)).unwrap();
        assert_eq!(p.len(), 2);
        let _ = p.consume().unwrap();
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn erase_all_clears_on_refresh() {
        let mut p = Pool::new(16, 4).unwrap();
        for i in 0..10 {
            p.add(FakeItem(i)).unwrap();
        }
        assert_eq!(p.len(), 10);
        p.erase_all(); // proactive refresh: all unused material destroyed
        assert!(p.is_empty());
        assert_eq!(p.consume(), None);
    }

    #[test]
    fn low_water_triggers_refill() {
        let mut p = Pool::new(10, 3).unwrap();
        for i in 0..10 {
            p.add(FakeItem(i)).unwrap();
        }
        assert!(!p.needs_refill()); // full
        // Drain down to the low-water mark.
        while p.len() > 3 {
            p.consume();
        }
        assert!(p.needs_refill()); // at 3 (<= low_water) -> refill
        assert_eq!(p.headroom(), 7);
    }
}

//! Rate limiting for token processing.
//!
//! Provides a sliding-window rate limiter with per-minute and per-hour limits
//! to prevent spam and replay attacks.

use std::collections::VecDeque;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use lru::LruCache;
use tokio::sync::Mutex;
use tokio::time::Instant;

pub use crate::defaults::{
    DEFAULT_MAX_SIZE, DEFAULT_RATE_LIMIT_PER_HOUR, DEFAULT_RATE_LIMIT_PER_MINUTE,
};
/// Maximum entries to scan per cleanup cycle.
const CLEANUP_BATCH_SIZE: usize = 1000;

/// Maximum entries scanned by the admission-path eviction probe.
///
/// Distinct from [`CLEANUP_BATCH_SIZE`]: admission runs under the hot per-check
/// write lock, so it must cost bounded, small work even when a stripe is at
/// capacity under a cardinality flood (see #123). The periodic [`cleanup`]
/// path — which runs on a timer, not the hot path — keeps the larger
/// [`CLEANUP_BATCH_SIZE`] sweep. A stale or below-limit victim is almost always
/// found near the LRU tail within this window; if none is, the unknown key is
/// rejected with `ExceededCapacityLimit` exactly as before, just after scanning
/// far fewer entries.
///
/// [`cleanup`]: RateLimiter::cleanup
const ADMISSION_SCAN_LIMIT: usize = 32;

/// Target entries per stripe. Integer division means sharding begins at 512
/// entries (`2 * MIN_ENTRIES_PER_SHARD`).
///
/// Sharding a tiny cache would make per-stripe capacity zero or one, changing
/// the LRU admission-eviction semantics that callers (and tests) rely on for
/// small `max_entries`. Below this threshold the limiter keeps a single stripe
/// so its behavior is byte-for-byte identical to the pre-sharding limiter;
/// above it, entries are striped for lock locality under cardinality pressure.
const MIN_ENTRIES_PER_SHARD: usize = 256;

/// Maximum number of stripes a sharded limiter uses.
///
/// Bounds lock/allocation overhead; production caches (100k keys) land here,
/// giving 32-way lock locality so a cardinality flood contends 1/32 of the
/// admission checks per lock instead of serializing them all (see #123).
const MAX_SHARDS: usize = 32;

/// Sampling divisor for the opportunistic live cache-size gauge.
///
/// The gauge is refreshed on roughly one in `GAUGE_SAMPLE_INTERVAL` admissions
/// that mutate a stripe, so cache-saturation onset is visible within a few
/// dozen admissions instead of only at the 60s cleanup tick (#125), without
/// paying a metric write on every hot-path check. The sampling check uses
/// `is_multiple_of`, so the interval does not need to be a power of two.
const GAUGE_SAMPLE_INTERVAL: u64 = 64;

/// Token identifying one admitted hit for identity-aware rollback.
///
/// IDs are unique within a limiter instance, including across entry eviction and
/// recreation, so a delayed rollback cannot remove a newer hit for the same key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitReservation(u64);

/// Result of a rate limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitResult {
    /// Request is allowed.
    Allowed(RateLimitReservation),
    /// Exceeded per-minute limit.
    ExceededMinuteLimit,
    /// Exceeded per-hour limit.
    ExceededHourLimit,
    /// Cache is full and no entry can be evicted safely for a new key.
    ExceededCapacityLimit,
}

/// Outcome of [`RateLimiter::check_and_increment`], including admission side effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitCheck {
    result: RateLimitResult,
    admission_evicted: bool,
    /// A sampled snapshot of the limiter's total entry count, present only on
    /// the roughly one-in-[`GAUGE_SAMPLE_INTERVAL`] admissions selected for an
    /// opportunistic live cache-size gauge update (#125). `None` on the calls
    /// that were not sampled, so the caller updates the gauge cheaply and
    /// rarely rather than on every hot-path check.
    sampled_cache_len: Option<usize>,
}

impl RateLimitCheck {
    /// Returns `true` if the request was allowed.
    #[must_use]
    pub fn is_allowed(self) -> bool {
        self.result.is_allowed()
    }

    /// Returns the reason string for metrics/logging (if rate limited).
    #[must_use]
    pub fn limit_reason(self) -> Option<&'static str> {
        self.result.limit_reason()
    }

    /// Returns `true` when a stale or below-limit entry was evicted to admit a new key.
    #[must_use]
    pub fn admission_evicted(self) -> bool {
        self.admission_evicted
    }

    /// Returns the reservation for an allowed request.
    #[must_use]
    pub fn reservation(self) -> Option<RateLimitReservation> {
        self.result.reservation()
    }

    /// Returns a sampled total-entry count for opportunistic gauge updates.
    ///
    /// `Some(len)` on the sampled fraction of admissions (see
    /// `GAUGE_SAMPLE_INTERVAL`); `None` otherwise. Lets the caller keep the
    /// `transponder_rate_limit_cache_size` gauge fresh as the cache grows
    /// toward capacity without a metric write per check.
    #[must_use]
    pub fn sampled_cache_len(self) -> Option<usize> {
        self.sampled_cache_len
    }
}

impl PartialEq<RateLimitResult> for RateLimitCheck {
    fn eq(&self, other: &RateLimitResult) -> bool {
        self.result == *other
    }
}

impl RateLimitResult {
    /// Returns `true` if the request was allowed.
    #[must_use]
    pub fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed(_))
    }

    /// Returns the reason string for metrics/logging (if rate limited).
    #[must_use]
    pub fn limit_reason(self) -> Option<&'static str> {
        match self {
            Self::Allowed(_) => None,
            Self::ExceededMinuteLimit => Some("minute"),
            Self::ExceededHourLimit => Some("hour"),
            Self::ExceededCapacityLimit => Some("capacity"),
        }
    }

    /// Returns the reservation for an allowed request.
    #[must_use]
    pub fn reservation(self) -> Option<RateLimitReservation> {
        match self {
            Self::Allowed(reservation) => Some(reservation),
            _ => None,
        }
    }
}

/// Entry tracking rate limit counters for a single key.
#[derive(Debug, Clone)]
struct RateLimitEntry {
    hits: VecDeque<(Instant, u64)>,
}

impl RateLimitEntry {
    fn new() -> Self {
        Self {
            hits: VecDeque::new(),
        }
    }

    fn prune(&mut self, now: Instant) {
        prune_hits(&mut self.hits, now, Duration::from_secs(3600));
    }

    fn is_empty(&self) -> bool {
        self.hits.is_empty()
    }

    fn is_below_limits(&self, max_per_minute: u32, max_per_hour: u32) -> bool {
        self.minute_count(Instant::now()) < max_per_minute as usize
            && self.hits.len() < max_per_hour as usize
    }

    fn minute_count(&self, now: Instant) -> usize {
        self.hits
            .iter()
            .rev()
            .take_while(|(hit, _)| now.duration_since(*hit) < Duration::from_secs(60))
            .count()
    }
}

fn prune_hits(hits: &mut VecDeque<(Instant, u64)>, now: Instant, window: Duration) {
    let old_len = hits.len();

    while hits
        .front()
        .is_some_and(|(hit, _)| now.duration_since(*hit) >= window)
    {
        hits.pop_front();
    }

    let new_len = hits.len();
    if old_len > new_len && (new_len == 0 || hits.capacity() > new_len.saturating_mul(2).max(8)) {
        hits.shrink_to_fit();
    }
}

/// Statistics returned from rate limiter cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupStats {
    /// Number of entries evicted during cleanup.
    pub evicted: usize,
    /// Number of entries remaining after cleanup.
    pub remaining: usize,
}

/// Configuration for rate limiting.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    /// Maximum requests per minute.
    pub max_per_minute: u32,
    /// Maximum requests per hour.
    pub max_per_hour: u32,
    /// Maximum aggregate entries in the cache.
    ///
    /// This caps the total number of tracked keys across all stripes, not the
    /// total number of stored timestamps. Each key may retain up to
    /// `max_per_hour` admitted-hit records until its window expires; the minute
    /// count is derived from the tail of the same deque. Each `(Instant, u64)`
    /// record is 24 bytes before deque overhead. For caches large
    /// enough to shard, the aggregate budget is divided across stripes and
    /// admission is stripe-local: a key can be rejected when its routed stripe
    /// has no stale or below-limit victim, even if other stripes still have
    /// free entries. This preserves hot-path locality and avoids cross-stripe
    /// scans in the capacity-failure path.
    ///
    /// `NonZeroUsize` so a zero capacity is unrepresentable here: production
    /// config rejects `server.max_rate_limit_cache_size = 0` at load time with
    /// a named-field error instead of the constructor silently substituting a
    /// default.
    pub max_entries: NonZeroUsize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_per_minute: DEFAULT_RATE_LIMIT_PER_MINUTE,
            max_per_hour: DEFAULT_RATE_LIMIT_PER_HOUR,
            max_entries: NonZeroUsize::new(DEFAULT_MAX_SIZE).expect("DEFAULT_MAX_SIZE is non-zero"),
        }
    }
}

/// Sliding-window rate limiter with per-minute and per-hour limits.
///
/// Each active entry stores admitted request hit records for true
/// sliding-window enforcement, so memory scales with the number of admitted hits
/// per key. With the defaults, a hot key can hold up to roughly 5,240 records
/// across the minute and hour windows before older hits are pruned.
///
/// The aggregate memory bound is the per-key bound multiplied by the configured
/// cache size: `max_entries * max_per_hour` hit records per limiter. With the
/// default 100,000-key cache and 5,000/hour limit, one fully saturated limiter
/// can retain roughly 500,000,000 `(Instant, u64)` records (about 12 GB at 24
/// bytes per record, before deque/map overhead). Production owns two such
/// limiters, so size `max_entries` and host memory for both caches.
///
/// Uses a bounded, striped cache to limit tracked key cardinality. The
/// configured `max_entries` is a hard aggregate budget divided across stripes,
/// but admission and eviction remain local to the stripe selected by the key
/// hash. When that stripe is full, admission first evicts a
/// least-recently-used stale entry from the same stripe; if none is found in
/// the bounded scan window, it falls back to a least-recently-used
/// still-unlimited entry from that stripe. A key can therefore receive
/// `ExceededCapacityLimit` when its stripe has no safe victim even if sibling
/// stripes have unused capacity. This favors hot-path locality under
/// cardinality pressure over global LRU behavior.
///
/// Evicting a below-limit key resets its accumulated sliding-window hits; that
/// weakens per-key precision but does not bypass limits because the global
/// unwrap limiter still bounds total admission.
pub struct RateLimiter<K: Hash + Eq + Clone + Send + Sync + 'static> {
    /// Independent LRU stripes, each behind its own `Mutex`. A key is routed
    /// to `stripes[hash(key) % stripes.len()]`, so admission checks for keys in
    /// different stripes never contend on the same lock — localizing both the
    /// bounded admission scan and lock waits under a cardinality flood (#123).
    stripes: Vec<Mutex<LruCache<K, RateLimitEntry>>>,
    /// Stable per-limiter hasher so a key always routes to the same stripe.
    hasher: RandomState,
    max_per_minute: u32,
    max_per_hour: u32,
    /// Per-stripe reservation-id sources. Keys are stripe-stable, so rollback
    /// identity only needs to be unique within the owning stripe.
    next_hit_ids: Vec<AtomicU64>,
    /// Counts stripe-mutating admissions to drive the sampled gauge (#125).
    gauge_sample_counter: AtomicU64,
    /// Exact aggregate entry count for lock-free gauge samples on the hot path.
    entry_count: AtomicUsize,
}

impl<K: Hash + Eq + Clone + Send + Sync + 'static> RateLimiter<K> {
    /// Creates a new rate limiter with the given configuration.
    pub fn new(config: RateLimitConfig) -> Self {
        let max_entries = config.max_entries.get();
        // Keep tiny caches single-stripe so small-`max_entries` LRU eviction
        // semantics are byte-for-byte identical to the pre-sharding limiter;
        // only stripe larger caches, and divide capacity evenly across stripes.
        let shard_count = (max_entries / MIN_ENTRIES_PER_SHARD)
            .clamp(1, MAX_SHARDS)
            .max(1);
        let base = max_entries / shard_count;
        let remainder = max_entries % shard_count;

        let stripes = (0..shard_count)
            .map(|i| {
                // Distribute the remainder so the summed stripe capacity equals
                // the configured `max_entries` exactly.
                let cap = base + usize::from(i < remainder);
                let cap = NonZeroUsize::new(cap).expect("per-stripe capacity is non-zero");
                Mutex::new(LruCache::new(cap))
            })
            .collect();

        Self {
            stripes,
            hasher: RandomState::new(),
            max_per_minute: config.max_per_minute,
            max_per_hour: config.max_per_hour,
            next_hit_ids: (0..shard_count).map(|_| AtomicU64::new(0)).collect(),
            gauge_sample_counter: AtomicU64::new(0),
            entry_count: AtomicUsize::new(0),
        }
    }

    /// Returns the stripe index for a key by stable hash.
    fn stripe_index(&self, key: &K) -> usize {
        if self.stripes.len() == 1 {
            return 0;
        }
        (self.hasher.hash_one(key) as usize) % self.stripes.len()
    }

    /// Routes a key to its stripe by stable hash.
    fn stripe_for(&self, key: &K) -> &Mutex<LruCache<K, RateLimitEntry>> {
        &self.stripes[self.stripe_index(key)]
    }

    fn evict_lru_admission_candidate(
        entries: &mut LruCache<K, RateLimitEntry>,
        now: Instant,
        max_per_minute: u32,
        max_per_hour: u32,
    ) -> bool {
        let mut stale_candidate = None;
        let mut below_limit_candidate = None;

        // Bounded, small scan: unlike the periodic cleanup sweep this runs on
        // the admission hot path under the stripe write lock, so it must be O(K)
        // with a small K even when the stripe is full (#123).
        for (key, entry) in entries.iter_mut().rev().take(ADMISSION_SCAN_LIMIT) {
            entry.prune(now);
            if entry.is_empty() {
                stale_candidate = Some(key.clone());
                break;
            }

            if below_limit_candidate.is_none()
                && entry.is_below_limits(max_per_minute, max_per_hour)
            {
                below_limit_candidate = Some(key.clone());
            }
        }

        if let Some(key) = stale_candidate.or(below_limit_candidate) {
            entries.pop(&key);
            return true;
        }

        false
    }

    /// Samples the total entry count for the live gauge (#125).
    ///
    /// Returns `Some(total_len)` roughly once per [`GAUGE_SAMPLE_INTERVAL`]
    /// stripe-mutating admissions, and `None` otherwise, so the caller refreshes
    /// the cache-size gauge frequently enough to catch saturation onset without
    /// a metric write on every check. The total comes from an aggregate atomic
    /// counter, not a cross-stripe read-lock sweep, so sampled admissions stay
    /// local to the current stripe.
    fn sampled_total_len(&self) -> Option<usize> {
        let n = self.gauge_sample_counter.fetch_add(1, Ordering::Relaxed);
        if !n.is_multiple_of(GAUGE_SAMPLE_INTERVAL) {
            return None;
        }
        Some(self.entry_count.load(Ordering::Relaxed))
    }

    /// Sums the entry count across all stripes.
    #[cfg(test)]
    async fn total_len(&self) -> usize {
        let mut total = 0;
        for stripe in &self.stripes {
            total += stripe.lock().await.len();
        }
        total
    }

    /// Checks if a request is allowed and increments counters if so.
    ///
    /// Returns:
    /// - `Allowed` if the request is within limits (counters are incremented)
    /// - `ExceededMinuteLimit` if per-minute limit is reached
    /// - `ExceededHourLimit` if per-hour limit is reached
    /// - `ExceededCapacityLimit` if the cache is full and has no safe eviction
    ///   victim for the unknown key
    pub async fn check_and_increment(&self, key: &K) -> RateLimitCheck {
        let (result, admission_evicted) = {
            let stripe_index = self.stripe_index(key);
            let mut entries = self.stripes[stripe_index].lock().await;
            // Timestamp after acquiring the stripe lock so hits for one key
            // are appended in monotonic lock-acquisition order.
            let now = Instant::now();
            let mut admission_evicted = false;

            // Get or create entry (updates access position). At capacity, admit
            // an unknown key by evicting an old stale or still-unlimited entry.
            // Entries already sitting at their rate limit are protected so cache
            // pressure cannot reset a limited key's counters.
            let entry = if let Some(entry) = entries.get_mut(key) {
                entry
            } else {
                if entries.len() >= entries.cap().get() {
                    if Self::evict_lru_admission_candidate(
                        &mut entries,
                        now,
                        self.max_per_minute,
                        self.max_per_hour,
                    ) {
                        admission_evicted = true;
                    } else {
                        return RateLimitCheck {
                            result: RateLimitResult::ExceededCapacityLimit,
                            admission_evicted: false,
                            sampled_cache_len: None,
                        };
                    }
                }
                entries.put(key.clone(), RateLimitEntry::new());
                if !admission_evicted {
                    self.entry_count.fetch_add(1, Ordering::Relaxed);
                }
                entries.get_mut(key).expect("just inserted")
            };

            entry.prune(now);

            // Check minute limit first (more likely to be hit)
            if entry.minute_count(now) >= self.max_per_minute as usize {
                return RateLimitCheck {
                    result: RateLimitResult::ExceededMinuteLimit,
                    admission_evicted,
                    sampled_cache_len: None,
                };
            }

            // Check hour limit
            if entry.hits.len() >= self.max_per_hour as usize {
                return RateLimitCheck {
                    result: RateLimitResult::ExceededHourLimit,
                    admission_evicted,
                    sampled_cache_len: None,
                };
            }

            // Increment counters
            let hit_id = self.next_hit_ids[stripe_index].fetch_add(1, Ordering::Relaxed);
            entry.hits.push_back((now, hit_id));

            (
                RateLimitResult::Allowed(RateLimitReservation(hit_id)),
                admission_evicted,
            )
        };

        // Opportunistically refresh the live size gauge outside the stripe lock
        // just taken. Only sampled admissions read the (cross-stripe) length so
        // the hot path stays cheap (#125).
        let sampled_cache_len = self.sampled_total_len();

        RateLimitCheck {
            result,
            admission_evicted,
            sampled_cache_len,
        }
    }

    /// Rolls back one previously allowed increment for a key.
    ///
    /// This is used when downstream admission fails after a rate-limit check
    /// has already reserved capacity for work that will not run. The
    /// [`RateLimitReservation`] returned by [`Self::check_and_increment`] must
    /// be passed so concurrent admits for the same key cannot remove another
    /// task's hit. If both counters reach zero, the entry is removed so the
    /// failed admission leaves no window-start trace for the next real request.
    pub async fn rollback_increment(&self, key: &K, reservation: RateLimitReservation) {
        let hit_id = reservation.0;
        let mut entries = self.stripe_for(key).lock().await;
        let should_remove = if let Some(entry) = entries.peek_mut(key) {
            remove_hit(&mut entry.hits, hit_id);
            entry.hits.is_empty()
        } else {
            false
        };

        if should_remove && entries.pop(key).is_some() {
            self.entry_count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Removes stale entries that haven't been accessed recently.
    ///
    /// Entries are considered stale if both windows have expired
    /// (no activity in the last hour). Processes up to `CLEANUP_BATCH_SIZE`
    /// entries per stripe per call.
    pub async fn cleanup(&self) -> CleanupStats {
        let now = Instant::now();
        let hour = Duration::from_secs(3600);
        let mut evicted = 0;
        let mut remaining = 0;

        for stripe in &self.stripes {
            let mut entries = stripe.lock().await;
            let before = entries.len();

            // Collect stale keys (hour window expired)
            let stale: Vec<K> = entries
                .iter()
                .rev()
                .take(CLEANUP_BATCH_SIZE)
                .filter(|(_, entry)| match entry.hits.back() {
                    Some((hit, _)) => now.duration_since(*hit) >= hour,
                    None => true,
                })
                .map(|(k, _)| k.clone())
                .collect();

            let removed = stale
                .iter()
                .filter(|key| entries.pop(key).is_some())
                .count();

            if removed > 0 {
                self.entry_count.fetch_sub(removed, Ordering::Relaxed);
            }
            evicted += removed;
            remaining += before - removed;
        }

        CleanupStats { evicted, remaining }
    }

    /// Returns the current number of entries in the rate limiter.
    #[cfg(test)]
    pub async fn len(&self) -> usize {
        self.total_len().await
    }

    /// Returns whether the rate limiter has no entries.
    #[cfg(test)]
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Checks the current count without incrementing.
    #[cfg(test)]
    pub async fn peek_counts(&self, key: &K) -> Option<(u32, u32)> {
        let entries = self.stripe_for(key).lock().await;
        entries.peek(key).map(|entry| {
            (
                entry.minute_count(Instant::now()) as u32,
                entry.hits.len() as u32,
            )
        })
    }
}

fn remove_hit(hits: &mut VecDeque<(Instant, u64)>, hit_id: u64) {
    if let Some(pos) = hits.iter().rposition(|(_, id)| *id == hit_id) {
        hits.remove(pos);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).expect("test max_entries must be non-zero")
    }

    #[tokio::test]
    async fn test_allows_within_limits() {
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 10,
            max_per_hour: 100,
            max_entries: entries(100),
        });

        for _ in 0..10 {
            assert!(limiter.check_and_increment(&1u64).await.is_allowed());
        }
    }

    #[tokio::test]
    async fn test_minute_limit() {
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 5,
            max_per_hour: 100,
            max_entries: entries(100),
        });

        for _ in 0..5 {
            assert!(limiter.check_and_increment(&1u64).await.is_allowed());
        }

        assert_eq!(
            limiter.check_and_increment(&1u64).await,
            RateLimitResult::ExceededMinuteLimit
        );

        // Different key should still work
        assert!(limiter.check_and_increment(&2u64).await.is_allowed());
    }

    #[tokio::test]
    async fn test_rollback_increment_refunds_allowed_request() {
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 1,
            max_per_hour: 1,
            max_entries: entries(100),
        });

        let reservation = limiter
            .check_and_increment(&1u64)
            .await
            .reservation()
            .expect("first admit");
        assert!(!limiter.check_and_increment(&1u64).await.is_allowed());

        limiter.rollback_increment(&1u64, reservation).await;

        assert!(limiter.is_empty().await);
        assert!(limiter.check_and_increment(&1u64).await.is_allowed());
    }

    #[tokio::test]
    async fn test_is_empty_reports_false_with_entries() {
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 10,
            max_per_hour: 100,
            max_entries: entries(100),
        });

        assert!(limiter.is_empty().await);
        limiter.check_and_increment(&1u64).await;
        assert!(!limiter.is_empty().await);
    }

    #[tokio::test]
    async fn test_rollback_increment_removes_only_reserved_hit() {
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 10,
            max_per_hour: 100,
            max_entries: entries(100),
        });

        let first = limiter
            .check_and_increment(&1u64)
            .await
            .reservation()
            .expect("first admit");
        assert!(limiter.check_and_increment(&1u64).await.is_allowed());

        limiter.rollback_increment(&1u64, first).await;

        assert_eq!(limiter.peek_counts(&1u64).await, Some((1, 1)));
    }

    #[test]
    fn test_remove_hit_prefers_recent_back_match() {
        let now = Instant::now();
        let mut hits = VecDeque::from([(now, 7), (now, 8), (now, 7)]);

        remove_hit(&mut hits, 7);

        let remaining: Vec<u64> = hits.iter().map(|(_, id)| *id).collect();
        assert_eq!(remaining, vec![7, 8]);
    }

    #[tokio::test]
    async fn test_rollback_increment_ignores_recreated_entry_with_same_key() {
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 10,
            max_per_hour: 100,
            max_entries: entries(1),
        });

        let first = limiter
            .check_and_increment(&1u64)
            .await
            .reservation()
            .expect("first admit");

        assert!(limiter.check_and_increment(&2u64).await.is_allowed());
        assert_eq!(limiter.peek_counts(&1u64).await, None);

        assert!(limiter.check_and_increment(&1u64).await.is_allowed());
        limiter.rollback_increment(&1u64, first).await;

        assert_eq!(limiter.peek_counts(&1u64).await, Some((1, 1)));
    }

    #[tokio::test]
    async fn test_hour_limit() {
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 100,
            max_per_hour: 5,
            max_entries: entries(100),
        });

        for _ in 0..5 {
            assert!(limiter.check_and_increment(&1u64).await.is_allowed());
        }

        assert_eq!(
            limiter.check_and_increment(&1u64).await,
            RateLimitResult::ExceededHourLimit
        );
    }

    #[tokio::test]
    async fn test_minute_window_reset() {
        tokio::time::pause();

        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 5,
            max_per_hour: 100,
            max_entries: entries(100),
        });

        for _ in 0..5 {
            assert!(limiter.check_and_increment(&1u64).await.is_allowed());
        }
        assert!(!limiter.check_and_increment(&1u64).await.is_allowed());

        // Advance past minute window
        tokio::time::advance(Duration::from_secs(61)).await;

        assert!(limiter.check_and_increment(&1u64).await.is_allowed());
    }

    #[tokio::test]
    async fn test_admission_timestamp_is_captured_after_stripe_lock_wait() {
        use std::sync::Arc;

        tokio::time::pause();

        let key = 1u64;
        let limiter: Arc<RateLimiter<u64>> = Arc::new(RateLimiter::new(RateLimitConfig {
            max_per_minute: 1,
            max_per_hour: 100,
            max_entries: entries(100),
        }));

        let blocked = limiter.stripe_for(&key).lock().await;
        let task_limiter = Arc::clone(&limiter);
        let handle = tokio::spawn(async move { task_limiter.check_and_increment(&key).await });

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(61)).await;
        drop(blocked);

        assert!(
            handle
                .await
                .expect("admission task should not panic")
                .is_allowed()
        );
        assert_eq!(
            limiter.check_and_increment(&key).await,
            RateLimitResult::ExceededMinuteLimit
        );
    }

    #[tokio::test]
    async fn test_minute_limit_slides_across_window_boundary() {
        tokio::time::pause();

        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 5,
            max_per_hour: 100,
            max_entries: entries(100),
        });

        assert!(limiter.check_and_increment(&1u64).await.is_allowed());

        tokio::time::advance(Duration::from_millis(59_900)).await;

        for _ in 0..4 {
            assert!(limiter.check_and_increment(&1u64).await.is_allowed());
        }
        assert_eq!(
            limiter.check_and_increment(&1u64).await,
            RateLimitResult::ExceededMinuteLimit
        );

        tokio::time::advance(Duration::from_millis(100)).await;

        assert!(limiter.check_and_increment(&1u64).await.is_allowed());
        assert_eq!(
            limiter.check_and_increment(&1u64).await,
            RateLimitResult::ExceededMinuteLimit
        );
    }

    #[tokio::test]
    async fn test_hour_window_reset() {
        tokio::time::pause();

        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 100,
            max_per_hour: 5,
            max_entries: entries(100),
        });

        for _ in 0..5 {
            assert!(limiter.check_and_increment(&1u64).await.is_allowed());
        }
        assert!(!limiter.check_and_increment(&1u64).await.is_allowed());

        // Advance past hour window
        tokio::time::advance(Duration::from_secs(3601)).await;

        assert!(limiter.check_and_increment(&1u64).await.is_allowed());
    }

    #[tokio::test]
    async fn test_hour_limit_slides_across_window_boundary() {
        tokio::time::pause();

        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 100,
            max_per_hour: 5,
            max_entries: entries(100),
        });

        assert!(limiter.check_and_increment(&1u64).await.is_allowed());

        tokio::time::advance(Duration::from_millis(3_599_900)).await;

        for _ in 0..4 {
            assert!(limiter.check_and_increment(&1u64).await.is_allowed());
        }
        assert_eq!(
            limiter.check_and_increment(&1u64).await,
            RateLimitResult::ExceededHourLimit
        );

        tokio::time::advance(Duration::from_millis(100)).await;

        assert!(limiter.check_and_increment(&1u64).await.is_allowed());
        assert_eq!(
            limiter.check_and_increment(&1u64).await,
            RateLimitResult::ExceededHourLimit
        );
    }

    #[tokio::test]
    async fn test_independent_keys() {
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 2,
            max_per_hour: 10,
            max_entries: entries(100),
        });

        // Key 1 hits limit
        assert!(limiter.check_and_increment(&1u64).await.is_allowed());
        assert!(limiter.check_and_increment(&1u64).await.is_allowed());
        assert!(!limiter.check_and_increment(&1u64).await.is_allowed());

        // Key 2 is independent
        assert!(limiter.check_and_increment(&2u64).await.is_allowed());
        assert!(limiter.check_and_increment(&2u64).await.is_allowed());
        assert!(!limiter.check_and_increment(&2u64).await.is_allowed());
    }

    #[tokio::test]
    async fn test_cleanup() {
        tokio::time::pause();

        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 10,
            max_per_hour: 100,
            max_entries: entries(100),
        });

        limiter.check_and_increment(&1u64).await;
        limiter.check_and_increment(&2u64).await;
        assert_eq!(limiter.len().await, 2);

        // Advance past hour window
        tokio::time::advance(Duration::from_secs(3601)).await;

        let stats = limiter.cleanup().await;
        assert_eq!(stats.evicted, 2);
        assert_eq!(stats.remaining, 0);
    }

    #[tokio::test]
    async fn test_cleanup_scans_stale_lru_entries_first() {
        tokio::time::pause();

        // Single-stripe capacity (below MIN_ENTRIES_PER_SHARD) but larger than
        // ADMISSION_SCAN_LIMIT, so the fill never triggers admission eviction
        // and cleanup's per-stripe CLEANUP_BATCH_SIZE scan reclaims every stale
        // entry while the recently-touched key survives. Sharding-aware variant
        // lives in test_cleanup_reclaims_stale_entries_across_stripes.
        let capacity = MIN_ENTRIES_PER_SHARD - 1;
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 10,
            max_per_hour: 100,
            max_entries: entries(capacity),
        });

        for key in 0..capacity as u64 {
            assert!(limiter.check_and_increment(&key).await.is_allowed());
        }

        tokio::time::advance(Duration::from_secs(3601)).await;

        assert!(limiter.check_and_increment(&0u64).await.is_allowed());

        let stats = limiter.cleanup().await;
        assert_eq!(stats.evicted, capacity - 1);
        assert_eq!(stats.remaining, 1);
    }

    #[tokio::test]
    async fn test_cleanup_reclaims_stale_entries_across_stripes() {
        tokio::time::pause();

        // A cache large enough to shard: cleanup must reclaim stale entries in
        // every stripe (each stripe scans up to CLEANUP_BATCH_SIZE, far more
        // than any single stripe holds here) and keep the recently-touched key.
        let capacity = MIN_ENTRIES_PER_SHARD * MAX_SHARDS;
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 10,
            max_per_hour: 100,
            max_entries: entries(capacity),
        });

        for key in 0..capacity as u64 {
            assert!(limiter.check_and_increment(&key).await.is_allowed());
        }
        // Uneven hash routing can evict a few below-limit keys during the fill,
        // so occupancy may be at or just below the aggregate capacity.
        let filled = limiter.len().await;
        assert!(filled <= capacity && filled >= capacity * 9 / 10);

        tokio::time::advance(Duration::from_secs(3601)).await;

        // Refresh one key so it is no longer stale; its stripe still holds it.
        assert!(limiter.check_and_increment(&0u64).await.is_allowed());
        let refreshed = limiter.peek_counts(&0u64).await;

        let stats = limiter.cleanup().await;
        // Every stale entry across every stripe is reclaimed; only the refreshed
        // key (if it survived the fill) remains.
        let survivors = usize::from(refreshed.is_some());
        assert_eq!(stats.remaining, survivors);
        assert_eq!(limiter.len().await, survivors);
        if survivors == 1 {
            assert_eq!(limiter.peek_counts(&0u64).await, Some((1, 1)));
        }
    }

    #[tokio::test]
    async fn test_admission_eviction_reports_side_effect() {
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 10,
            max_per_hour: 100,
            max_entries: entries(3),
        });

        for key in 1..=3 {
            let check = limiter.check_and_increment(&key).await;
            assert!(check.is_allowed());
            assert!(!check.admission_evicted());
        }

        let check = limiter.check_and_increment(&4u64).await;
        assert!(check.is_allowed());
        assert!(check.admission_evicted());
    }

    #[tokio::test]
    async fn test_capacity_limit_does_not_report_admission_eviction() {
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 1,
            max_per_hour: 100,
            max_entries: entries(3),
        });

        for key in 1..=3 {
            assert!(limiter.check_and_increment(&key).await.is_allowed());
        }

        let check = limiter.check_and_increment(&4u64).await;
        assert_eq!(check, RateLimitResult::ExceededCapacityLimit);
        assert!(!check.admission_evicted());
    }

    #[tokio::test]
    async fn test_cache_pressure_evicts_oldest_unlimited_key_for_new_key() {
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 10,
            max_per_hour: 100,
            max_entries: entries(3),
        });

        limiter.check_and_increment(&1u64).await;
        limiter.check_and_increment(&2u64).await;
        limiter.check_and_increment(&3u64).await;
        assert_eq!(limiter.len().await, 3);

        assert!(limiter.check_and_increment(&4u64).await.is_allowed());
        assert_eq!(limiter.len().await, 3);
        assert_eq!(limiter.peek_counts(&1u64).await, None);
        assert_eq!(limiter.peek_counts(&2u64).await, Some((1, 1)));
        assert_eq!(limiter.peek_counts(&4u64).await, Some((1, 1)));
    }

    #[test]
    fn test_admission_eviction_prefers_stale_victim_over_below_limit_victim() {
        let now = Instant::now();
        let stale_hit = now
            .checked_sub(Duration::from_secs(3601))
            .expect("test instant should support one-hour subtraction");
        let mut below_limit_entry = RateLimitEntry::new();
        below_limit_entry.hits.push_back((now, 0));
        let mut stale_entry = RateLimitEntry::new();
        stale_entry.hits.push_back((stale_hit, 1));

        let mut entries = LruCache::new(NonZeroUsize::new(3).expect("non-zero test capacity"));
        entries.put(1u64, below_limit_entry);
        entries.put(2u64, stale_entry);
        entries.put(3u64, RateLimitEntry::new());

        assert!(RateLimiter::evict_lru_admission_candidate(
            &mut entries,
            now,
            10,
            100
        ));

        assert!(entries.contains(&1u64));
        assert!(!entries.contains(&2u64));
        assert!(entries.contains(&3u64));
    }

    #[tokio::test]
    async fn test_admission_scan_prunes_stale_candidate_within_bounded_window() {
        tokio::time::pause();

        // Single-stripe capacity larger than the bounded admission scan window
        // but below MIN_ENTRIES_PER_SHARD. When the whole stripe is stale, the
        // admission scan (capped at ADMISSION_SCAN_LIMIT from the LRU tail) still
        // finds a stale victim near the tail, prunes it, evicts it, and admits
        // the new key — the previously-hit entries stay untouched and total size
        // is unchanged.
        let capacity = MIN_ENTRIES_PER_SHARD - 1;
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 10,
            max_per_hour: 100,
            max_entries: entries(capacity),
        });

        for key in 0..capacity as u64 {
            assert!(limiter.check_and_increment(&key).await.is_allowed());
        }
        assert_eq!(limiter.len().await, capacity);

        tokio::time::advance(Duration::from_secs(3601)).await;

        let new_key = capacity as u64;
        let check = limiter.check_and_increment(&new_key).await;
        assert!(check.is_allowed());
        assert!(check.admission_evicted());

        // Total capacity is unchanged: a stale LRU-tail victim (key 0) was
        // evicted to admit the new key, and the most-recently-inserted prior key
        // is retained.
        assert_eq!(limiter.len().await, capacity);
        assert_eq!(limiter.peek_counts(&0u64).await, None);
        assert_eq!(
            limiter.peek_counts(&(capacity as u64 - 1)).await,
            Some((0, 1))
        );
        assert_eq!(limiter.peek_counts(&new_key).await, Some((1, 1)));
    }

    #[test]
    fn test_admission_scan_bound_is_small_relative_to_cleanup_batch() {
        // The admission-path scan must be far smaller than the periodic-cleanup
        // batch so a full stripe costs bounded, small work per check under a
        // cardinality flood (#123), rather than reusing the 1000-entry sweep.
        const {
            assert!(ADMISSION_SCAN_LIMIT < CLEANUP_BATCH_SIZE);
            assert!(ADMISSION_SCAN_LIMIT <= 32);
        }
    }

    #[tokio::test]
    async fn test_rejects_new_keys_at_capacity_when_no_safe_eviction_exists() {
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 1,
            max_per_hour: 100,
            max_entries: entries(3),
        });

        limiter.check_and_increment(&1u64).await;
        limiter.check_and_increment(&2u64).await;
        limiter.check_and_increment(&3u64).await;
        assert_eq!(limiter.len().await, 3);

        assert_eq!(
            limiter.check_and_increment(&4u64).await,
            RateLimitResult::ExceededCapacityLimit
        );
        assert_eq!(limiter.len().await, 3);
        assert_eq!(limiter.peek_counts(&1u64).await, Some((1, 1)));
    }

    #[tokio::test]
    async fn test_cache_pressure_does_not_reset_limited_key() {
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 1,
            max_per_hour: 100,
            max_entries: entries(2),
        });

        assert!(limiter.check_and_increment(&1u64).await.is_allowed());
        assert_eq!(
            limiter.check_and_increment(&1u64).await,
            RateLimitResult::ExceededMinuteLimit
        );

        assert!(limiter.check_and_increment(&2u64).await.is_allowed());
        assert!(!limiter.check_and_increment(&3u64).await.is_allowed());

        assert_eq!(
            limiter.check_and_increment(&1u64).await,
            RateLimitResult::ExceededMinuteLimit
        );
    }

    #[tokio::test]
    async fn test_result_helpers() {
        assert!(RateLimitResult::Allowed(RateLimitReservation(0)).is_allowed());
        assert!(!RateLimitResult::ExceededMinuteLimit.is_allowed());
        assert!(!RateLimitResult::ExceededHourLimit.is_allowed());
        assert!(!RateLimitResult::ExceededCapacityLimit.is_allowed());

        assert_eq!(
            RateLimitResult::Allowed(RateLimitReservation(0)).limit_reason(),
            None
        );
        assert_eq!(
            RateLimitResult::ExceededMinuteLimit.limit_reason(),
            Some("minute")
        );
        assert_eq!(
            RateLimitResult::ExceededHourLimit.limit_reason(),
            Some("hour")
        );
        assert_eq!(
            RateLimitResult::ExceededCapacityLimit.limit_reason(),
            Some("capacity")
        );
    }

    #[tokio::test]
    async fn test_with_byte_array_keys() {
        let limiter: RateLimiter<[u8; 32]> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 5,
            max_per_hour: 100,
            max_entries: entries(100),
        });

        let key1 = [1u8; 32];
        let key2 = [2u8; 32];

        for _ in 0..5 {
            assert!(limiter.check_and_increment(&key1).await.is_allowed());
        }

        // Key 1 is rate limited
        assert!(!limiter.check_and_increment(&key1).await.is_allowed());

        // Key 2 is independent
        assert!(limiter.check_and_increment(&key2).await.is_allowed());
    }

    #[tokio::test]
    async fn test_small_cache_uses_single_stripe() {
        // Caches below MIN_ENTRIES_PER_SHARD keep a single stripe so their LRU
        // admission-eviction semantics are identical to the pre-sharding limiter.
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 10,
            max_per_hour: 100,
            max_entries: entries(MIN_ENTRIES_PER_SHARD - 1),
        });
        assert_eq!(limiter.stripes.len(), 1);
    }

    #[tokio::test]
    async fn test_large_cache_is_sharded_and_capacity_sums_to_max_entries() {
        // A large cache is striped, and the summed per-stripe capacity equals
        // the configured max_entries exactly (remainder distributed), so the
        // aggregate key bound is preserved.
        let max = MIN_ENTRIES_PER_SHARD * MAX_SHARDS + 7;
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 10,
            max_per_hour: 100,
            max_entries: entries(max),
        });
        assert_eq!(limiter.stripes.len(), MAX_SHARDS);

        let mut summed = 0usize;
        for stripe in &limiter.stripes {
            summed += stripe.lock().await.cap().get();
        }
        assert_eq!(summed, max);
    }

    #[tokio::test]
    async fn test_sharded_capacity_rejection_is_stripe_local() {
        // The configured max_entries is an aggregate memory/cardinality budget,
        // but admission does not borrow from sibling stripes. A full target
        // stripe whose entries are all at-limit rejects a new key routed there
        // while another stripe can still admit its own key.
        let max = MIN_ENTRIES_PER_SHARD * 2;
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 1,
            max_per_hour: 100,
            max_entries: entries(max),
        });
        assert_eq!(limiter.stripes.len(), 2);

        let target_stripe = 0usize;
        let other_stripe = 1usize;
        let target_capacity = limiter.stripes[target_stripe].lock().await.cap().get();
        assert!(target_capacity < max, "test must leave aggregate headroom");

        let mut target_keys = Vec::with_capacity(target_capacity + 1);
        let mut other_key = None;
        let mut candidate = 0u64;
        while target_keys.len() < target_capacity + 1 || other_key.is_none() {
            match limiter.stripe_index(&candidate) {
                idx if idx == target_stripe => target_keys.push(candidate),
                idx if idx == other_stripe && other_key.is_none() => other_key = Some(candidate),
                _ => {}
            }
            candidate += 1;
        }

        for key in target_keys.iter().take(target_capacity) {
            assert!(limiter.check_and_increment(key).await.is_allowed());
        }
        assert_eq!(limiter.len().await, target_capacity);

        assert_eq!(
            limiter
                .check_and_increment(&target_keys[target_capacity])
                .await,
            RateLimitResult::ExceededCapacityLimit
        );
        assert_eq!(limiter.len().await, target_capacity);

        let other_key = other_key.expect("found a key for the other stripe");
        assert!(limiter.check_and_increment(&other_key).await.is_allowed());
        assert_eq!(limiter.len().await, target_capacity + 1);
    }

    #[tokio::test]
    async fn test_sharded_limiter_tracks_distinct_keys_and_limits_repeats() {
        // Distinct keys spread across stripes. Sharding routes keys by hash, so
        // stripe occupancy is uneven and the aggregate tracked-key count can sit
        // slightly below max_entries once some stripe fills and rejects its
        // overflow — an inherent, documented property of a sharded LRU. What
        // must hold: every admitted key is independently rate-limited on repeat.
        let max = MIN_ENTRIES_PER_SHARD * 2;
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 1,
            max_per_hour: 100,
            max_entries: entries(max),
        });

        let mut admitted = Vec::new();
        for key in 0..max as u64 {
            if limiter.check_and_increment(&key).await.is_allowed() {
                admitted.push(key);
            }
        }
        // The vast majority of distinct keys are admitted (uneven hashing costs
        // only a small tail to per-stripe capacity rejection).
        assert!(
            admitted.len() >= max * 9 / 10,
            "expected most distinct keys admitted, got {}/{max}",
            admitted.len()
        );
        // Every admitted key is at its per-minute limit of 1; a repeat is
        // rejected by the minute limit, proving per-key accounting survives.
        for key in &admitted {
            assert_eq!(
                limiter.check_and_increment(key).await,
                RateLimitResult::ExceededMinuteLimit
            );
        }
        assert!(limiter.len().await <= max);
    }

    #[tokio::test]
    async fn test_reservation_ids_need_only_be_unique_within_a_stripe() {
        let max = MIN_ENTRIES_PER_SHARD * 4;
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 10,
            max_per_hour: 100,
            max_entries: entries(max),
        });

        let first_key = 0u64;
        let first_stripe = limiter.stripe_index(&first_key);
        let second_key = (1..max as u64)
            .find(|key| limiter.stripe_index(key) != first_stripe)
            .expect("sharded limiter routes some key elsewhere");
        let first = limiter
            .check_and_increment(&first_key)
            .await
            .reservation()
            .expect("first admit");
        let second = limiter
            .check_and_increment(&second_key)
            .await
            .reservation()
            .expect("second admit");

        // Per-stripe counters may collide, but rollback always routes through
        // the key's stable stripe and therefore cannot touch the other hit.
        assert_eq!(first, second);
        limiter.rollback_increment(&first_key, first).await;
        assert_eq!(limiter.peek_counts(&first_key).await, None);
        assert_eq!(limiter.peek_counts(&second_key).await, Some((1, 1)));
    }

    #[tokio::test]
    async fn test_check_and_increment_samples_live_cache_size() {
        // The very first admission is sampled (counter starts at 0), so the
        // caller can seed the live gauge immediately; subsequent admissions are
        // sampled about once per GAUGE_SAMPLE_INTERVAL.
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 1_000,
            max_per_hour: 100_000,
            max_entries: entries(1),
        });

        let first = limiter.check_and_increment(&0u64).await;
        assert_eq!(
            first.sampled_cache_len(),
            Some(1),
            "first admission must publish a live size sample"
        );

        // The next GAUGE_SAMPLE_INTERVAL-1 admissions are not sampled.
        let mut sampled = 0usize;
        for _ in 1..GAUGE_SAMPLE_INTERVAL {
            if limiter
                .check_and_increment(&0u64)
                .await
                .sampled_cache_len()
                .is_some()
            {
                sampled += 1;
            }
        }
        assert_eq!(sampled, 0, "only 1-in-interval admissions are sampled");

        // The interval-th admission after the first is sampled again.
        assert!(
            limiter
                .check_and_increment(&0u64)
                .await
                .sampled_cache_len()
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_sampled_cache_size_does_not_lock_unrelated_stripes() {
        let max = MIN_ENTRIES_PER_SHARD * 2;
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 10,
            max_per_hour: 100,
            max_entries: entries(max),
        });
        assert_eq!(limiter.stripes.len(), 2);

        let blocked_stripe = 0usize;
        let key = (0u64..)
            .find(|candidate| limiter.stripe_index(candidate) != blocked_stripe)
            .expect("test key for unblocked stripe");

        let _blocked = limiter.stripes[blocked_stripe].lock().await;
        let check = tokio::time::timeout(Duration::from_secs(1), limiter.check_and_increment(&key))
            .await
            .expect("sampled cache-size gauge must not wait on unrelated stripes");

        assert!(check.is_allowed());
        assert_eq!(check.sampled_cache_len(), Some(1));
    }

    #[tokio::test]
    async fn test_rejected_admission_carries_no_gauge_sample() {
        // A capacity/limit rejection must not publish a size sample: it neither
        // mutated a stripe nor advanced growth.
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 1,
            max_per_hour: 100,
            max_entries: entries(1),
        });

        assert!(limiter.check_and_increment(&0u64).await.is_allowed());
        let rejected = limiter.check_and_increment(&0u64).await;
        assert_eq!(rejected, RateLimitResult::ExceededMinuteLimit);
        assert_eq!(rejected.sampled_cache_len(), None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_admissions_across_stripes_do_not_deadlock() {
        use std::sync::Arc;

        // A cardinality flood of distinct keys hammering a sharded limiter
        // concurrently must make progress (stripes lock independently) and admit
        // every distinct key within aggregate capacity.
        let max = MIN_ENTRIES_PER_SHARD * MAX_SHARDS;
        let limiter: Arc<RateLimiter<u64>> = Arc::new(RateLimiter::new(RateLimitConfig {
            max_per_minute: 5,
            max_per_hour: 1_000,
            max_entries: entries(max),
        }));

        let mut handles = Vec::new();
        for shard in 0..8u64 {
            let limiter = Arc::clone(&limiter);
            handles.push(tokio::spawn(async move {
                for i in 0..500u64 {
                    let key = shard * 1_000 + i;
                    let _ = limiter.check_and_increment(&key).await;
                }
            }));
        }
        for handle in handles {
            handle.await.expect("task panicked");
        }
        // No panic/deadlock; the limiter stays within its aggregate bound.
        assert!(limiter.len().await <= max);
    }
}

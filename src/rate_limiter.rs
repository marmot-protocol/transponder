//! Rate limiting for token processing.
//!
//! Provides a sliding-window rate limiter with per-minute and per-hour limits
//! to prevent spam and replay attacks.

use std::collections::VecDeque;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use lru::LruCache;
use tokio::sync::RwLock;
use tokio::time::Instant;

/// Default maximum cache size (100,000 entries).
pub const DEFAULT_MAX_SIZE: usize = 100_000;

/// Default rate limit per minute (240 = 4 per second).
pub const DEFAULT_RATE_LIMIT_PER_MINUTE: u32 = 240;

/// Default rate limit per hour.
pub const DEFAULT_RATE_LIMIT_PER_HOUR: u32 = 5000;

/// Default global pre-unwrap admission limit per minute.
///
/// This caps how many gift wraps the server is willing to unwrap (ECDH + seal
/// decryption) per minute across all senders. The server pubkey is public, so
/// anyone can flood it with valid kind-1059 gift wraps; this budget sheds that
/// traffic before spending asymmetric-crypto cycles. 600/minute (10/second) is
/// far above any legitimate single-server load while still bounding attacker
/// CPU cost.
pub const DEFAULT_GLOBAL_UNWRAP_LIMIT_PER_MINUTE: u32 = 600;

/// Default global pre-unwrap admission limit per hour.
///
/// Companion to [`DEFAULT_GLOBAL_UNWRAP_LIMIT_PER_MINUTE`]; bounds sustained
/// flooding over a longer window.
pub const DEFAULT_GLOBAL_UNWRAP_LIMIT_PER_HOUR: u32 = 30_000;

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

/// Number of entries below which the limiter uses a single stripe.
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
/// paying a metric write on every hot-path check. Must be a power of two so the
/// sampling test is a cheap bit-mask.
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
    /// [`GAUGE_SAMPLE_INTERVAL`]); `None` otherwise. Lets the caller keep the
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
    minute_hits: VecDeque<(Instant, u64)>,
    hour_hits: VecDeque<(Instant, u64)>,
}

impl RateLimitEntry {
    fn new() -> Self {
        Self {
            minute_hits: VecDeque::new(),
            hour_hits: VecDeque::new(),
        }
    }

    fn prune(&mut self, now: Instant) {
        prune_hits(&mut self.minute_hits, now, Duration::from_secs(60));
        prune_hits(&mut self.hour_hits, now, Duration::from_secs(3600));
    }

    fn is_empty(&self) -> bool {
        self.minute_hits.is_empty() && self.hour_hits.is_empty()
    }

    fn is_below_limits(&self, max_per_minute: u32, max_per_hour: u32) -> bool {
        self.minute_hits.len() < max_per_minute as usize
            && self.hour_hits.len() < max_per_hour as usize
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
    /// Maximum entries in the cache.
    ///
    /// This caps the number of tracked keys, not the total number of stored
    /// timestamps. Each key may retain up to `max_per_minute + max_per_hour`
    /// admitted-hit timestamps until its windows expire, so worst-case
    /// timestamp storage per limiter is `max_entries * (max_per_minute +
    /// max_per_hour)`. When this key capacity is reached, admission first looks
    /// for a least-recently-used stale entry to evict, then falls back to the
    /// least-recently-used entry that is still below its own rate limits; if no
    /// safe victim is found, the unknown key is rejected.
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
/// The aggregate bound is the per-key bound multiplied by the configured cache
/// size: `max_entries * (max_per_minute + max_per_hour)` hit records per
/// limiter. With the default 100,000-key cache and 240/minute plus 5,000/hour
/// limits, one fully saturated limiter can retain roughly 524,000,000 records
/// before pruning. Production event processing owns separate encrypted-token and
/// device-token limiters, so size `max_entries` and process memory for both
/// caches.
///
/// Uses a bounded cache to limit tracked key cardinality. When the cache is
/// full, admission first evicts the least-recently-used stale entry; if none is
/// found in the bounded scan window, it falls back to a least-recently-used
/// still-unlimited entry. This favors availability for legitimate new tokens
/// over perfect accounting for below-limit keys under active cache pressure,
/// while preserving counters for keys already at their rate limit. Evicting a
/// below-limit key resets its accumulated sliding-window hits; that weakens
/// per-key precision but does not bypass limits because the global unwrap
/// limiter still bounds total admission.
pub struct RateLimiter<K: Hash + Eq + Clone + Send + Sync + 'static> {
    /// Independent LRU stripes, each behind its own `RwLock`. A key is routed
    /// to `stripes[hash(key) % stripes.len()]`, so admission checks for keys in
    /// different stripes never contend on the same lock — localizing both the
    /// bounded admission scan and lock waits under a cardinality flood (#123).
    stripes: Vec<RwLock<LruCache<K, RateLimitEntry>>>,
    /// Stable per-limiter hasher so a key always routes to the same stripe.
    hasher: RandomState,
    max_per_minute: u32,
    max_per_hour: u32,
    /// Process-wide monotonic reservation-id source. Shared across ALL stripes
    /// so a [`RateLimitReservation`] is unique within the limiter regardless of
    /// which stripe holds the key — preserving the #206 identity guarantee that
    /// a delayed rollback cannot remove a newer hit for the same key.
    next_hit_id: AtomicU64,
    /// Counts stripe-mutating admissions to drive the sampled gauge (#125).
    gauge_sample_counter: AtomicU64,
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
                RwLock::new(LruCache::new(cap))
            })
            .collect();

        Self {
            stripes,
            hasher: RandomState::new(),
            max_per_minute: config.max_per_minute,
            max_per_hour: config.max_per_hour,
            next_hit_id: AtomicU64::new(0),
            gauge_sample_counter: AtomicU64::new(0),
        }
    }

    /// Routes a key to its stripe by stable hash.
    fn stripe_for(&self, key: &K) -> &RwLock<LruCache<K, RateLimitEntry>> {
        if self.stripes.len() == 1 {
            return &self.stripes[0];
        }
        let idx = (self.hasher.hash_one(key) as usize) % self.stripes.len();
        &self.stripes[idx]
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
    /// a metric write on every check. The total is summed across stripes to keep
    /// the metric's existing per-`cache_type` label shape (one value per
    /// limiter, not per stripe).
    async fn sampled_total_len(&self) -> Option<usize> {
        let n = self.gauge_sample_counter.fetch_add(1, Ordering::Relaxed);
        if !n.is_multiple_of(GAUGE_SAMPLE_INTERVAL) {
            return None;
        }
        Some(self.total_len().await)
    }

    /// Sums the entry count across all stripes.
    async fn total_len(&self) -> usize {
        let mut total = 0;
        for stripe in &self.stripes {
            total += stripe.read().await.len();
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
        let now = Instant::now();
        let mutated;
        let (result, admission_evicted) = {
            let mut entries = self.stripe_for(key).write().await;
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
                entries.get_mut(key).expect("just inserted")
            };

            entry.prune(now);

            // Check minute limit first (more likely to be hit)
            if entry.minute_hits.len() >= self.max_per_minute as usize {
                return RateLimitCheck {
                    result: RateLimitResult::ExceededMinuteLimit,
                    admission_evicted,
                    sampled_cache_len: None,
                };
            }

            // Check hour limit
            if entry.hour_hits.len() >= self.max_per_hour as usize {
                return RateLimitCheck {
                    result: RateLimitResult::ExceededHourLimit,
                    admission_evicted,
                    sampled_cache_len: None,
                };
            }

            // Increment counters
            let hit_id = self.next_hit_id.fetch_add(1, Ordering::Relaxed);
            entry.minute_hits.push_back((now, hit_id));
            entry.hour_hits.push_back((now, hit_id));
            mutated = true;

            (
                RateLimitResult::Allowed(RateLimitReservation(hit_id)),
                admission_evicted,
            )
        };

        // Opportunistically refresh the live size gauge outside the stripe lock
        // just taken. Only sampled admissions read the (cross-stripe) length so
        // the hot path stays cheap (#125).
        let sampled_cache_len = if mutated {
            self.sampled_total_len().await
        } else {
            None
        };

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
        let mut entries = self.stripe_for(key).write().await;
        let should_remove = if let Some(entry) = entries.get_mut(key) {
            remove_hit(&mut entry.minute_hits, hit_id);
            remove_hit(&mut entry.hour_hits, hit_id);
            entry.minute_hits.is_empty() && entry.hour_hits.is_empty()
        } else {
            false
        };

        if should_remove {
            entries.pop(key);
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
            let mut entries = stripe.write().await;
            let before = entries.len();

            // Collect stale keys (hour window expired)
            let stale: Vec<K> = entries
                .iter()
                .rev()
                .take(CLEANUP_BATCH_SIZE)
                .filter(|(_, entry)| match entry.hour_hits.back() {
                    Some((hit, _)) => now.duration_since(*hit) >= hour,
                    None => true,
                })
                .map(|(k, _)| k.clone())
                .collect();

            for key in &stale {
                entries.pop(key);
            }

            evicted += stale.len();
            remaining += before - stale.len();
        }

        CleanupStats { evicted, remaining }
    }

    /// Returns the current number of entries in the rate limiter.
    #[cfg(test)]
    pub async fn len(&self) -> usize {
        self.total_len().await
    }

    /// Checks the current count without incrementing.
    #[cfg(test)]
    pub async fn peek_counts(&self, key: &K) -> Option<(u32, u32)> {
        let entries = self.stripe_for(key).read().await;
        entries
            .peek(key)
            .map(|entry| (entry.minute_hits.len() as u32, entry.hour_hits.len() as u32))
    }
}

fn remove_hit(hits: &mut VecDeque<(Instant, u64)>, hit_id: u64) {
    if let Some(pos) = hits.iter().position(|(_, id)| *id == hit_id) {
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

        assert_eq!(limiter.len().await, 0);
        assert!(limiter.check_and_increment(&1u64).await.is_allowed());
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
        below_limit_entry.minute_hits.push_back((now, 0));
        below_limit_entry.hour_hits.push_back((now, 0));
        let mut stale_entry = RateLimitEntry::new();
        stale_entry.minute_hits.push_back((stale_hit, 1));
        stale_entry.hour_hits.push_back((stale_hit, 1));

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
            Some((1, 1))
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
            summed += stripe.read().await.cap().get();
        }
        assert_eq!(summed, max);
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
    async fn test_reservation_ids_unique_across_stripes() {
        // The reservation-id source is shared process-wide, so a rollback with a
        // reservation from one stripe never removes a hit in another stripe even
        // when ids would collide under per-stripe counters (#206 identity).
        let max = MIN_ENTRIES_PER_SHARD * 4;
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 10,
            max_per_hour: 100,
            max_entries: entries(max),
        });

        let mut reservations = Vec::new();
        for key in 0..max as u64 {
            let reservation = limiter
                .check_and_increment(&key)
                .await
                .reservation()
                .expect("admit");
            reservations.push(reservation);
        }
        let unique: std::collections::HashSet<u64> = reservations.iter().map(|r| r.0).collect();
        assert_eq!(
            unique.len(),
            reservations.len(),
            "reservation ids must be globally unique across stripes"
        );
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

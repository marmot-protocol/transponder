//! Rate limiting for token processing.
//!
//! Provides a sliding-window rate limiter with per-minute and per-hour limits
//! to prevent spam and replay attacks.

use std::collections::VecDeque;
use std::hash::Hash;
use std::num::NonZeroUsize;
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

/// Result of a rate limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitResult {
    /// Request is allowed.
    Allowed,
    /// Exceeded per-minute limit.
    ExceededMinuteLimit,
    /// Exceeded per-hour limit.
    ExceededHourLimit,
    /// Cache is full and no entry can be evicted safely for a new key.
    ExceededCapacityLimit,
}

impl RateLimitResult {
    /// Returns `true` if the request was allowed.
    #[must_use]
    pub fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }

    /// Returns the reason string for metrics/logging (if rate limited).
    #[must_use]
    pub fn limit_reason(self) -> Option<&'static str> {
        match self {
            Self::Allowed => None,
            Self::ExceededMinuteLimit => Some("minute"),
            Self::ExceededHourLimit => Some("hour"),
            Self::ExceededCapacityLimit => Some("capacity"),
        }
    }
}

/// Entry tracking rate limit counters for a single key.
#[derive(Debug, Clone)]
struct RateLimitEntry {
    minute_hits: VecDeque<Instant>,
    hour_hits: VecDeque<Instant>,
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

fn prune_hits(hits: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    let old_len = hits.len();

    while hits
        .front()
        .is_some_and(|hit| now.duration_since(*hit) >= window)
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
    pub max_entries: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_per_minute: DEFAULT_RATE_LIMIT_PER_MINUTE,
            max_per_hour: DEFAULT_RATE_LIMIT_PER_HOUR,
            max_entries: DEFAULT_MAX_SIZE,
        }
    }
}

/// Sliding-window rate limiter with per-minute and per-hour limits.
///
/// Each active entry stores admitted request timestamps for true sliding-window
/// enforcement, so memory scales with the number of admitted hits per key. With
/// the defaults, a hot key can hold up to roughly 5,240 `Instant` values across
/// the minute and hour windows before older hits are pruned.
///
/// The aggregate bound is the per-key bound multiplied by the configured cache
/// size: `max_entries * (max_per_minute + max_per_hour)` timestamp values per
/// limiter. With the default 100,000-key cache and 240/minute plus 5,000/hour
/// limits, one fully saturated limiter can retain roughly 524,000,000 `Instant`
/// values before pruning (about 8.4 GB at 16 bytes per timestamp, before
/// `VecDeque` overhead). Production event processing owns separate encrypted-
/// token and device-token limiters, so size `max_entries` and process memory for
/// both caches.
///
/// Uses a bounded cache to limit tracked key cardinality. When the cache is
/// full, admission first evicts the least-recently-used stale entry; if none is
/// found in the bounded scan window, it falls back to a least-recently-used
/// still-unlimited entry. This favors availability for legitimate new tokens
/// over perfect accounting for below-limit keys under active cache pressure,
/// while preserving counters for keys already at their rate limit.
pub struct RateLimiter<K: Hash + Eq + Clone + Send + Sync + 'static> {
    entries: RwLock<LruCache<K, RateLimitEntry>>,
    max_per_minute: u32,
    max_per_hour: u32,
}

impl<K: Hash + Eq + Clone + Send + Sync + 'static> RateLimiter<K> {
    /// Creates a new rate limiter with the given configuration.
    pub fn new(config: RateLimitConfig) -> Self {
        let size = NonZeroUsize::new(config.max_entries)
            .unwrap_or(NonZeroUsize::new(DEFAULT_MAX_SIZE).expect("DEFAULT_MAX_SIZE is non-zero"));

        Self {
            entries: RwLock::new(LruCache::new(size)),
            max_per_minute: config.max_per_minute,
            max_per_hour: config.max_per_hour,
        }
    }

    fn evict_lru_admission_candidate(
        entries: &mut LruCache<K, RateLimitEntry>,
        now: Instant,
        max_per_minute: u32,
        max_per_hour: u32,
    ) -> bool {
        let mut stale_candidate = None;
        let mut below_limit_candidate = None;

        for (key, entry) in entries.iter_mut().rev().take(CLEANUP_BATCH_SIZE) {
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

    /// Checks if a request is allowed and increments counters if so.
    ///
    /// Returns:
    /// - `Allowed` if the request is within limits (counters are incremented)
    /// - `ExceededMinuteLimit` if per-minute limit is reached
    /// - `ExceededHourLimit` if per-hour limit is reached
    /// - `ExceededCapacityLimit` if the cache is full and has no safe eviction
    ///   victim for the unknown key
    pub async fn check_and_increment(&self, key: &K) -> RateLimitResult {
        let now = Instant::now();
        let mut entries = self.entries.write().await;

        // Get or create entry (updates access position). At capacity, admit an
        // unknown key by evicting an old stale or still-unlimited entry. Entries
        // already sitting at their rate limit are protected so cache pressure
        // cannot reset a limited key's counters.
        let entry = if let Some(entry) = entries.get_mut(key) {
            entry
        } else {
            if entries.len() >= entries.cap().get()
                && !Self::evict_lru_admission_candidate(
                    &mut entries,
                    now,
                    self.max_per_minute,
                    self.max_per_hour,
                )
            {
                return RateLimitResult::ExceededCapacityLimit;
            }
            entries.put(key.clone(), RateLimitEntry::new());
            entries.get_mut(key).expect("just inserted")
        };

        entry.prune(now);

        // Check minute limit first (more likely to be hit)
        if entry.minute_hits.len() >= self.max_per_minute as usize {
            return RateLimitResult::ExceededMinuteLimit;
        }

        // Check hour limit
        if entry.hour_hits.len() >= self.max_per_hour as usize {
            return RateLimitResult::ExceededHourLimit;
        }

        // Increment counters
        entry.minute_hits.push_back(now);
        entry.hour_hits.push_back(now);

        RateLimitResult::Allowed
    }

    /// Rolls back one previously allowed increment for a key.
    ///
    /// This is used when downstream admission fails after a rate-limit check
    /// has already reserved capacity for work that will not run. If both
    /// counters reach zero, the entry is removed so the failed admission leaves
    /// no window-start trace for the next real request.
    pub async fn rollback_increment(&self, key: &K) {
        let mut entries = self.entries.write().await;
        let should_remove = if let Some(entry) = entries.get_mut(key) {
            entry.minute_hits.pop_back();
            entry.hour_hits.pop_back();
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
    /// entries per call.
    pub async fn cleanup(&self) -> CleanupStats {
        let mut entries = self.entries.write().await;
        let now = Instant::now();
        let before = entries.len();
        let hour = Duration::from_secs(3600);

        // Collect stale keys (hour window expired)
        let stale: Vec<K> = entries
            .iter()
            .rev()
            .take(CLEANUP_BATCH_SIZE)
            .filter(|(_, entry)| match entry.hour_hits.back() {
                Some(hit) => now.duration_since(*hit) >= hour,
                None => true,
            })
            .map(|(k, _)| k.clone())
            .collect();

        for key in &stale {
            entries.pop(key);
        }

        CleanupStats {
            evicted: stale.len(),
            remaining: before - stale.len(),
        }
    }

    /// Returns the current number of entries in the rate limiter.
    #[cfg(test)]
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Checks the current count without incrementing.
    #[cfg(test)]
    pub async fn peek_counts(&self, key: &K) -> Option<(u32, u32)> {
        let entries = self.entries.read().await;
        entries
            .peek(key)
            .map(|entry| (entry.minute_hits.len() as u32, entry.hour_hits.len() as u32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_allows_within_limits() {
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 10,
            max_per_hour: 100,
            max_entries: 100,
        });

        for _ in 0..10 {
            assert_eq!(
                limiter.check_and_increment(&1u64).await,
                RateLimitResult::Allowed
            );
        }
    }

    #[tokio::test]
    async fn test_minute_limit() {
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 5,
            max_per_hour: 100,
            max_entries: 100,
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
            max_entries: 100,
        });

        assert!(limiter.check_and_increment(&1u64).await.is_allowed());
        assert!(!limiter.check_and_increment(&1u64).await.is_allowed());

        limiter.rollback_increment(&1u64).await;

        assert_eq!(limiter.len().await, 0);
        assert!(limiter.check_and_increment(&1u64).await.is_allowed());
    }

    #[tokio::test]
    async fn test_hour_limit() {
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 100,
            max_per_hour: 5,
            max_entries: 100,
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
            max_entries: 100,
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
            max_entries: 100,
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
            max_entries: 100,
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
            max_entries: 100,
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
            max_entries: 100,
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
            max_entries: 100,
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

        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 10,
            max_per_hour: 100,
            max_entries: CLEANUP_BATCH_SIZE + 1,
        });

        for key in 0..=CLEANUP_BATCH_SIZE as u64 {
            assert!(limiter.check_and_increment(&key).await.is_allowed());
        }

        tokio::time::advance(Duration::from_secs(3601)).await;

        assert!(limiter.check_and_increment(&0u64).await.is_allowed());

        let stats = limiter.cleanup().await;
        assert_eq!(stats.evicted, CLEANUP_BATCH_SIZE);
        assert_eq!(stats.remaining, 1);
    }

    #[tokio::test]
    async fn test_cache_pressure_evicts_oldest_unlimited_key_for_new_key() {
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 10,
            max_per_hour: 100,
            max_entries: 3,
        });

        limiter.check_and_increment(&1u64).await;
        limiter.check_and_increment(&2u64).await;
        limiter.check_and_increment(&3u64).await;
        assert_eq!(limiter.len().await, 3);

        assert_eq!(
            limiter.check_and_increment(&4u64).await,
            RateLimitResult::Allowed
        );
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
        below_limit_entry.minute_hits.push_back(now);
        below_limit_entry.hour_hits.push_back(now);
        let mut stale_entry = RateLimitEntry::new();
        stale_entry.minute_hits.push_back(stale_hit);
        stale_entry.hour_hits.push_back(stale_hit);

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
    async fn test_admission_scan_prunes_stale_candidate_when_cache_exceeds_batch_size() {
        tokio::time::pause();

        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 10,
            max_per_hour: 100,
            max_entries: CLEANUP_BATCH_SIZE + 1,
        });

        for key in 0..=CLEANUP_BATCH_SIZE as u64 {
            assert!(limiter.check_and_increment(&key).await.is_allowed());
        }
        assert_eq!(limiter.len().await, CLEANUP_BATCH_SIZE + 1);

        tokio::time::advance(Duration::from_secs(3601)).await;

        let new_key = CLEANUP_BATCH_SIZE as u64 + 1;
        assert_eq!(
            limiter.check_and_increment(&new_key).await,
            RateLimitResult::Allowed
        );

        assert_eq!(limiter.len().await, CLEANUP_BATCH_SIZE + 1);
        assert_eq!(limiter.peek_counts(&0u64).await, None);
        assert_eq!(
            limiter.peek_counts(&(CLEANUP_BATCH_SIZE as u64)).await,
            Some((1, 1))
        );
        assert_eq!(limiter.peek_counts(&new_key).await, Some((1, 1)));
    }

    #[tokio::test]
    async fn test_rejects_new_keys_at_capacity_when_no_safe_eviction_exists() {
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 1,
            max_per_hour: 100,
            max_entries: 3,
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
            max_entries: 2,
        });

        assert_eq!(
            limiter.check_and_increment(&1u64).await,
            RateLimitResult::Allowed
        );
        assert_eq!(
            limiter.check_and_increment(&1u64).await,
            RateLimitResult::ExceededMinuteLimit
        );

        assert_eq!(
            limiter.check_and_increment(&2u64).await,
            RateLimitResult::Allowed
        );
        assert!(!limiter.check_and_increment(&3u64).await.is_allowed());

        assert_eq!(
            limiter.check_and_increment(&1u64).await,
            RateLimitResult::ExceededMinuteLimit
        );
    }

    #[tokio::test]
    async fn test_result_helpers() {
        assert!(RateLimitResult::Allowed.is_allowed());
        assert!(!RateLimitResult::ExceededMinuteLimit.is_allowed());
        assert!(!RateLimitResult::ExceededHourLimit.is_allowed());
        assert!(!RateLimitResult::ExceededCapacityLimit.is_allowed());

        assert_eq!(RateLimitResult::Allowed.limit_reason(), None);
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
            max_entries: 100,
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
}

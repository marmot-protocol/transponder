//! Rate limiting for token processing.
//!
//! Provides a fixed-window rate limiter with per-minute and per-hour limits
//! to prevent spam and replay attacks.

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
        }
    }
}

/// Entry tracking rate limit counters for a single key.
#[derive(Debug, Clone)]
struct RateLimitEntry {
    minute_count: u32,
    minute_window_start: Instant,
    hour_count: u32,
    hour_window_start: Instant,
}

impl RateLimitEntry {
    fn new(now: Instant) -> Self {
        Self {
            minute_count: 0,
            minute_window_start: now,
            hour_count: 0,
            hour_window_start: now,
        }
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
    /// Maximum entries in the cache (LRU eviction).
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

/// Fixed-window rate limiter with per-minute and per-hour limits.
///
/// Uses an LRU cache to bound memory usage. When the cache is full,
/// the least recently used entries are evicted.
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

    /// Checks if a request is allowed and increments counters if so.
    ///
    /// Returns:
    /// - `Allowed` if the request is within limits (counters are incremented)
    /// - `ExceededMinuteLimit` if per-minute limit is reached
    /// - `ExceededHourLimit` if per-hour limit is reached
    pub async fn check_and_increment(&self, key: &K) -> RateLimitResult {
        let now = Instant::now();
        let mut entries = self.entries.write().await;

        // Get or create entry (updates LRU position)
        let entry = if let Some(entry) = entries.get_mut(key) {
            entry
        } else {
            entries.put(key.clone(), RateLimitEntry::new(now));
            entries.get_mut(key).expect("just inserted")
        };

        // Reset minute window if expired
        if now.duration_since(entry.minute_window_start) >= Duration::from_secs(60) {
            entry.minute_count = 0;
            entry.minute_window_start = now;
        }

        // Reset hour window if expired
        if now.duration_since(entry.hour_window_start) >= Duration::from_secs(3600) {
            entry.hour_count = 0;
            entry.hour_window_start = now;
        }

        // Check minute limit first (more likely to be hit)
        if entry.minute_count >= self.max_per_minute {
            return RateLimitResult::ExceededMinuteLimit;
        }

        // Check hour limit
        if entry.hour_count >= self.max_per_hour {
            return RateLimitResult::ExceededHourLimit;
        }

        // Increment counters
        entry.minute_count += 1;
        entry.hour_count += 1;

        RateLimitResult::Allowed
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
            .take(CLEANUP_BATCH_SIZE)
            .filter(|(_, entry)| now.duration_since(entry.hour_window_start) >= hour)
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
            .map(|entry| (entry.minute_count, entry.hour_count))
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
    async fn test_lru_eviction() {
        let limiter: RateLimiter<u64> = RateLimiter::new(RateLimitConfig {
            max_per_minute: 10,
            max_per_hour: 100,
            max_entries: 3,
        });

        limiter.check_and_increment(&1u64).await;
        limiter.check_and_increment(&2u64).await;
        limiter.check_and_increment(&3u64).await;
        assert_eq!(limiter.len().await, 3);

        // Adding 4th should evict LRU (key 1)
        limiter.check_and_increment(&4u64).await;
        assert_eq!(limiter.len().await, 3);

        // Key 1 should have been evicted
        assert_eq!(limiter.peek_counts(&1u64).await, None);
    }

    #[tokio::test]
    async fn test_result_helpers() {
        assert!(RateLimitResult::Allowed.is_allowed());
        assert!(!RateLimitResult::ExceededMinuteLimit.is_allowed());
        assert!(!RateLimitResult::ExceededHourLimit.is_allowed());

        assert_eq!(RateLimitResult::Allowed.limit_reason(), None);
        assert_eq!(
            RateLimitResult::ExceededMinuteLimit.limit_reason(),
            Some("minute")
        );
        assert_eq!(
            RateLimitResult::ExceededHourLimit.limit_reason(),
            Some("hour")
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

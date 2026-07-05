//! Centralized default values for configuration and runtime components.
//!
//! Single source of truth for serde defaults in [`crate::config`] and for
//! runtime components that share the same tuning knobs.

use nostr_sdk::prelude::nip59;

/// Maximum NIP-59 timestamp randomization window for gift wraps (seconds).
pub const NIP59_TIMESTAMP_TWEAK_WINDOW_SECS: u64 = nip59::RANGE_RANDOM_TIMESTAMP_TWEAK.end;

// === Rate limiting ===

/// Default maximum cache size (100,000 entries).
pub const DEFAULT_MAX_SIZE: usize = 100_000;

/// Default rate limit per minute (240 = 4 per second).
pub const DEFAULT_RATE_LIMIT_PER_MINUTE: u32 = 240;

/// Default rate limit per hour.
pub const DEFAULT_RATE_LIMIT_PER_HOUR: u32 = 5000;

/// Default global pre-unwrap admission limit per minute.
pub const DEFAULT_GLOBAL_UNWRAP_LIMIT_PER_MINUTE: u32 = 600;

/// Default global pre-unwrap admission limit per hour.
pub const DEFAULT_GLOBAL_UNWRAP_LIMIT_PER_HOUR: u32 = 30_000;

// === Event processing / replay protection ===

/// Default maximum size for the volatile deduplication cache.
pub const DEFAULT_MAX_DEDUP_CACHE_SIZE: usize = 100_000;

/// Default maximum age for the unwrapped kind:446 notification request rumor.
pub const DEFAULT_MAX_NOTIFICATION_AGE_SECS: u64 = 3_600;

/// Default tolerated clock skew for future-dated notification rumors.
pub const DEFAULT_MAX_NOTIFICATION_FUTURE_SKEW_SECS: u64 = 300;

/// Default duration to keep processed gift-wrap event IDs in replay state.
pub const DEFAULT_DEDUP_RETENTION_SECS: u64 =
    NIP59_TIMESTAMP_TWEAK_WINDOW_SECS + DEFAULT_MAX_NOTIFICATION_FUTURE_SKEW_SECS;

/// Default maximum number of encrypted tokens accepted in one notification event.
pub const DEFAULT_MAX_TOKENS_PER_EVENT: usize = 100;

/// Default maximum number of events processed concurrently.
pub const DEFAULT_MAX_CONCURRENT_EVENT_PROCESSING: usize = 64;

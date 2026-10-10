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

/// Default per-token rate limit per minute (20 = one every 3 seconds).
///
/// Kept low because push-token records are gossiped to every group member, so
/// anyone holding one (including a removed member) can trigger pushes to that
/// device. Pushes are wake hints, so a faster rate adds nothing for users.
pub const DEFAULT_RATE_LIMIT_PER_MINUTE: u32 = 20;

/// Default per-token rate limit per hour (300 = one every 12 seconds sustained).
pub const DEFAULT_RATE_LIMIT_PER_HOUR: u32 = 300;

/// Default global pre-unwrap admission limit per minute.
pub const DEFAULT_GLOBAL_UNWRAP_LIMIT_PER_MINUTE: u32 = 600;

/// Default global pre-unwrap admission limit per hour.
pub const DEFAULT_GLOBAL_UNWRAP_LIMIT_PER_HOUR: u32 = 30_000;

// === Event processing / replay protection ===

/// Default maximum size for the volatile deduplication cache.
pub const DEFAULT_MAX_DEDUP_CACHE_SIZE: usize = 100_000;

/// Default duration to keep decoded trigger-content hashes in memory.
pub const DEFAULT_DEDUP_RETENTION_SECS: u64 = 300;

/// Marmot Push v1 maximum number of encrypted-token or padding chunks in one trigger.
pub const MAX_TOKENS_PER_EVENT: usize = 32;

/// Default maximum number of encrypted tokens accepted in one notification event.
pub const DEFAULT_MAX_TOKENS_PER_EVENT: usize = MAX_TOKENS_PER_EVENT;

/// Default maximum number of events processed concurrently.
pub const DEFAULT_MAX_CONCURRENT_EVENT_PROCESSING: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_retention_is_short_lived() {
        assert_eq!(DEFAULT_DEDUP_RETENTION_SECS, 5 * 60);
    }
}

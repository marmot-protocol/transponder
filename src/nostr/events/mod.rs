//! Event processing for incoming Nostr events.
//!
//! Handles deduplication and processing of gift-wrapped notification requests,
//! including rate limiting to prevent spam and replay attacks.

mod admission;
mod dedup;
mod processor;

pub use processor::{EventProcessor, ReplayProtectionConfig, TokenRateLimitConfig};

#[cfg(test)]
pub(crate) use processor::EventProcessorBuilder;

#[allow(unused_imports)]
pub use crate::defaults::{
    DEFAULT_DEDUP_RETENTION_SECS, DEFAULT_MAX_DEDUP_CACHE_SIZE, DEFAULT_MAX_NOTIFICATION_AGE_SECS,
    DEFAULT_MAX_NOTIFICATION_FUTURE_SKEW_SECS,
};

#[allow(unused_imports)]
pub(crate) use dedup::DEDUP_WINDOW;

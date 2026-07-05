//! Shared test fixtures for constructing common configuration shapes.

use std::path::PathBuf;

use zeroize::Zeroizing;

use crate::config::ServerConfig;
use crate::defaults::{
    DEFAULT_DEDUP_RETENTION_SECS, DEFAULT_GLOBAL_UNWRAP_LIMIT_PER_HOUR,
    DEFAULT_GLOBAL_UNWRAP_LIMIT_PER_MINUTE, DEFAULT_MAX_DEDUP_CACHE_SIZE,
    DEFAULT_MAX_NOTIFICATION_AGE_SECS, DEFAULT_MAX_NOTIFICATION_FUTURE_SKEW_SECS, DEFAULT_MAX_SIZE,
    DEFAULT_MAX_TOKENS_PER_EVENT, DEFAULT_RATE_LIMIT_PER_HOUR, DEFAULT_RATE_LIMIT_PER_MINUTE,
};

/// Return a [`ServerConfig`] populated with production-default tuning values.
#[must_use]
pub fn default_server_config() -> ServerConfig {
    ServerConfig {
        private_key: Zeroizing::new(String::new()),
        private_key_file: String::new(),
        shutdown_timeout_secs: 10,
        max_dedup_cache_size: DEFAULT_MAX_DEDUP_CACHE_SIZE,
        dedup_state_path: PathBuf::new(),
        dedup_retention_secs: DEFAULT_DEDUP_RETENTION_SECS,
        max_notification_age_secs: DEFAULT_MAX_NOTIFICATION_AGE_SECS,
        max_notification_future_skew_secs: DEFAULT_MAX_NOTIFICATION_FUTURE_SKEW_SECS,
        max_rate_limit_cache_size: DEFAULT_MAX_SIZE,
        max_tokens_per_event: DEFAULT_MAX_TOKENS_PER_EVENT,
        encrypted_token_rate_limit_per_minute: DEFAULT_RATE_LIMIT_PER_MINUTE,
        encrypted_token_rate_limit_per_hour: DEFAULT_RATE_LIMIT_PER_HOUR,
        device_token_rate_limit_per_minute: DEFAULT_RATE_LIMIT_PER_MINUTE,
        device_token_rate_limit_per_hour: DEFAULT_RATE_LIMIT_PER_HOUR,
        max_concurrent_event_processing: crate::defaults::DEFAULT_MAX_CONCURRENT_EVENT_PROCESSING,
        global_unwrap_rate_limit_per_minute: DEFAULT_GLOBAL_UNWRAP_LIMIT_PER_MINUTE,
        global_unwrap_rate_limit_per_hour: DEFAULT_GLOBAL_UNWRAP_LIMIT_PER_HOUR,
    }
}

/// Apply overrides to a default [`ServerConfig`].
#[must_use]
pub fn server_config_with(
    mut config: ServerConfig,
    f: impl FnOnce(&mut ServerConfig),
) -> ServerConfig {
    f(&mut config);
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_server_config_has_no_zeroed_limits() {
        let config = default_server_config();
        assert_ne!(config.max_dedup_cache_size, 0);
        assert_ne!(config.max_rate_limit_cache_size, 0);
        assert_ne!(config.max_tokens_per_event, 0);
        assert_ne!(config.shutdown_timeout_secs, 0);
        assert_ne!(config.max_concurrent_event_processing, 0);
    }

    #[test]
    fn server_config_with_applies_override() {
        let config = server_config_with(default_server_config(), |c| {
            c.max_tokens_per_event = 42;
        });
        assert_eq!(config.max_tokens_per_event, 42);
    }
}

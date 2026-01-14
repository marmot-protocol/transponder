//! Configuration loading and management.
//!
//! Supports TOML configuration files with environment variable overrides.
//! Environment variables follow the pattern: `TRANSPONDER_<SECTION>_<KEY>`

use config::{Config, Environment, File};
use serde::Deserialize;
use std::path::Path;

use crate::error::Result;

/// Root configuration structure.
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    /// Server configuration.
    pub server: ServerConfig,

    /// Relay configuration.
    pub relays: RelayConfig,

    /// APNs configuration.
    pub apns: ApnsConfig,

    /// FCM configuration.
    pub fcm: FcmConfig,

    /// Health check server configuration.
    pub health: HealthConfig,

    /// Metrics configuration.
    pub metrics: MetricsConfig,

    /// Logging configuration.
    pub logging: LoggingConfig,
}

/// Default maximum size for the deduplication cache.
const DEFAULT_MAX_DEDUP_CACHE_SIZE: usize = 100_000;

fn default_max_dedup_cache_size() -> usize {
    DEFAULT_MAX_DEDUP_CACHE_SIZE
}

/// Server-specific configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Server's Nostr private key (hex or nsec format).
    pub private_key: String,

    /// Graceful shutdown timeout in seconds.
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout_secs: u64,

    /// Maximum size for the event deduplication cache.
    ///
    /// The cache uses LRU eviction to prevent unbounded memory growth.
    /// Default: 100,000 entries.
    #[serde(default = "default_max_dedup_cache_size")]
    pub max_dedup_cache_size: usize,
}

fn default_shutdown_timeout() -> u64 {
    10
}

/// Relay connection configuration.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct RelayConfig {
    /// ClearNet relay URLs.
    #[serde(default)]
    pub clearnet: Vec<String>,

    /// Tor/onion relay URLs.
    #[serde(default)]
    pub onion: Vec<String>,

    /// Reconnection interval in seconds (reserved for future use).
    #[serde(default = "default_reconnect_interval")]
    pub reconnect_interval_secs: u64,

    /// Maximum reconnection attempts (reserved for future use).
    #[serde(default = "default_max_reconnect_attempts")]
    pub max_reconnect_attempts: u32,

    /// Timeout in seconds to wait for at least one relay to connect during startup.
    /// Default: 30 seconds.
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_secs: u64,
}

fn default_connection_timeout() -> u64 {
    30
}

fn default_reconnect_interval() -> u64 {
    5
}

fn default_max_reconnect_attempts() -> u32 {
    10
}

/// APNs push notification configuration.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ApnsConfig {
    /// Whether APNs is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Key ID for token-based auth.
    #[serde(default)]
    pub key_id: String,

    /// Team ID for token-based auth.
    #[serde(default)]
    pub team_id: String,

    /// Path to the .p8 private key file for token auth.
    #[serde(default)]
    pub private_key_path: String,

    /// APNs environment: "production" or "sandbox".
    #[serde(default = "default_apns_environment")]
    pub environment: String,

    /// Bundle ID for the iOS app.
    #[serde(default)]
    pub bundle_id: String,
}

fn default_apns_environment() -> String {
    "production".to_string()
}

/// FCM push notification configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct FcmConfig {
    /// Whether FCM is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Path to the service account JSON file.
    #[serde(default)]
    pub service_account_path: String,

    /// FCM project ID.
    #[serde(default)]
    pub project_id: String,
}

/// Health check server configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct HealthConfig {
    /// Whether the health check server is enabled.
    #[serde(default = "default_health_enabled")]
    pub enabled: bool,

    /// Bind address for the health check server.
    #[serde(default = "default_health_bind_address")]
    pub bind_address: String,
}

fn default_health_enabled() -> bool {
    true
}

fn default_health_bind_address() -> String {
    "0.0.0.0:8080".to_string()
}

/// Metrics configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct MetricsConfig {
    /// Whether metrics are enabled.
    #[serde(default = "default_metrics_enabled")]
    pub enabled: bool,
}

fn default_metrics_enabled() -> bool {
    true
}

/// Logging configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    /// Log level: "trace", "debug", "info", "warn", "error", "off".
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Log format: "json" or "pretty".
    #[serde(default = "default_log_format")]
    pub format: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "json".to_string()
}

impl AppConfig {
    /// Load configuration from a file path with environment variable overrides.
    ///
    /// Environment variables follow the pattern: `TRANSPONDER_<SECTION>_<KEY>`
    /// For example: `TRANSPONDER_SERVER_PRIVATE_KEY`
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let config = Config::builder()
            // Start with default values
            .set_default("server.private_key", "")?
            .set_default("server.shutdown_timeout_secs", 10)?
            .set_default(
                "server.max_dedup_cache_size",
                DEFAULT_MAX_DEDUP_CACHE_SIZE as i64,
            )?
            .set_default("relays.clearnet", Vec::<String>::new())?
            .set_default("relays.onion", Vec::<String>::new())?
            .set_default("relays.reconnect_interval_secs", 5)?
            .set_default("relays.max_reconnect_attempts", 10)?
            .set_default("relays.connection_timeout_secs", 30)?
            .set_default("apns.enabled", false)?
            .set_default("apns.key_id", "")?
            .set_default("apns.team_id", "")?
            .set_default("apns.private_key_path", "")?
            .set_default("apns.environment", "production")?
            .set_default("apns.bundle_id", "")?
            .set_default("fcm.enabled", false)?
            .set_default("fcm.service_account_path", "")?
            .set_default("fcm.project_id", "")?
            .set_default("health.enabled", true)?
            .set_default("health.bind_address", "0.0.0.0:8080")?
            .set_default("metrics.enabled", true)?
            .set_default("logging.level", "info")?
            .set_default("logging.format", "json")?
            // Load from config file
            .add_source(File::from(path.as_ref()))
            // Override with environment variables
            .add_source(
                Environment::with_prefix("TRANSPONDER")
                    .separator("_")
                    .try_parsing(true),
            )
            .build()?;

        Ok(config.try_deserialize()?)
    }

    /// Load configuration from environment variables only (no config file).
    #[allow(dead_code)]
    pub fn from_env() -> Result<Self> {
        let config = Config::builder()
            // Set defaults
            .set_default("server.private_key", "")?
            .set_default("server.shutdown_timeout_secs", 10)?
            .set_default(
                "server.max_dedup_cache_size",
                DEFAULT_MAX_DEDUP_CACHE_SIZE as i64,
            )?
            .set_default("relays.clearnet", Vec::<String>::new())?
            .set_default("relays.onion", Vec::<String>::new())?
            .set_default("relays.reconnect_interval_secs", 5)?
            .set_default("relays.max_reconnect_attempts", 10)?
            .set_default("relays.connection_timeout_secs", 30)?
            .set_default("apns.enabled", false)?
            .set_default("apns.key_id", "")?
            .set_default("apns.team_id", "")?
            .set_default("apns.private_key_path", "")?
            .set_default("apns.environment", "production")?
            .set_default("apns.bundle_id", "")?
            .set_default("fcm.enabled", false)?
            .set_default("fcm.service_account_path", "")?
            .set_default("fcm.project_id", "")?
            .set_default("health.enabled", true)?
            .set_default("health.bind_address", "0.0.0.0:8080")?
            .set_default("metrics.enabled", true)?
            .set_default("logging.level", "info")?
            .set_default("logging.format", "json")?
            // Load from environment
            .add_source(
                Environment::with_prefix("TRANSPONDER")
                    .separator("_")
                    .try_parsing(true),
            )
            .build()?;

        Ok(config.try_deserialize()?)
    }
}

impl ApnsConfig {
    /// Returns true if targeting production APNs environment.
    #[must_use]
    pub fn is_production(&self) -> bool {
        self.environment == "production"
    }

    /// Returns the APNs base URL for the configured environment.
    #[must_use]
    pub fn base_url(&self) -> &'static str {
        if self.is_production() {
            "https://api.push.apple.com"
        } else {
            "https://api.sandbox.push.apple.com"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::Builder;

    fn create_temp_config(content: &str) -> tempfile::NamedTempFile {
        let mut file = Builder::new().suffix(".toml").tempfile().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file
    }

    #[test]
    fn test_load_minimal_config() {
        let config_content = r#"
            [server]
            private_key = "abc123"

            [relays]
            clearnet = ["wss://relay.example.com"]

            [apns]
            enabled = false

            [fcm]
            enabled = false

            [health]
            enabled = true

            [metrics]
            enabled = true

            [logging]
            level = "info"
        "#;

        let file = create_temp_config(config_content);
        let config = AppConfig::load(file.path()).unwrap();

        assert_eq!(config.server.private_key, "abc123");
        assert_eq!(config.server.shutdown_timeout_secs, 10); // default
        assert_eq!(config.relays.clearnet.len(), 1);
        assert!(!config.apns.enabled);
        assert!(!config.fcm.enabled);
        assert!(config.metrics.enabled);
    }

    #[test]
    fn test_apns_config_helpers() {
        let config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM123".to_string(),
            private_key_path: "/path/to/key.p8".to_string(),
            environment: "production".to_string(),
            bundle_id: "com.example.app".to_string(),
        };

        assert!(config.is_production());
        assert_eq!(config.base_url(), "https://api.push.apple.com");
    }

    #[test]
    fn test_apns_sandbox_url() {
        let config = ApnsConfig {
            enabled: true,
            key_id: String::new(),
            team_id: String::new(),
            private_key_path: String::new(),
            environment: "sandbox".to_string(),
            bundle_id: String::new(),
        };

        assert!(!config.is_production());
        assert_eq!(config.base_url(), "https://api.sandbox.push.apple.com");
    }

    #[test]
    fn test_load_full_config() {
        let config_content = r#"
            [server]
            private_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            shutdown_timeout_secs = 30

            [relays]
            clearnet = ["wss://relay1.example.com", "wss://relay2.example.com"]
            onion = ["ws://abc123.onion"]
            reconnect_interval_secs = 10
            max_reconnect_attempts = 5

            [apns]
            enabled = true
            auth_method = "token"
            key_id = "KEY123"
            team_id = "TEAM456"
            private_key_path = "/path/to/key.p8"
            environment = "sandbox"
            bundle_id = "com.test.app"

            [fcm]
            enabled = true
            service_account_path = "/path/to/service.json"
            project_id = "my-project"

            [health]
            enabled = true
            bind_address = "127.0.0.1:9090"

            [metrics]
            enabled = true

            [logging]
            level = "debug"
            format = "pretty"
        "#;

        let file = create_temp_config(config_content);
        let config = AppConfig::load(file.path()).unwrap();

        assert_eq!(
            config.server.private_key,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(config.server.shutdown_timeout_secs, 30);
        assert_eq!(config.relays.clearnet.len(), 2);
        assert_eq!(config.relays.onion.len(), 1);
        assert_eq!(config.relays.reconnect_interval_secs, 10);
        assert_eq!(config.relays.max_reconnect_attempts, 5);
        assert!(config.apns.enabled);
        assert_eq!(config.apns.key_id, "KEY123");
        assert_eq!(config.apns.team_id, "TEAM456");
        assert!(!config.apns.is_production());
        assert!(config.fcm.enabled);
        assert_eq!(config.fcm.project_id, "my-project");
        assert_eq!(config.health.bind_address, "127.0.0.1:9090");
        assert!(config.metrics.enabled);
        assert_eq!(config.logging.level, "debug");
        assert_eq!(config.logging.format, "pretty");
    }

    #[test]
    fn test_default_values() {
        // Config with only required fields - should use defaults for others
        let config_content = r#"
            [server]
            private_key = "test"
        "#;

        let file = create_temp_config(config_content);
        let config = AppConfig::load(file.path()).unwrap();

        // Check defaults
        assert_eq!(config.server.shutdown_timeout_secs, 10);
        assert!(config.relays.clearnet.is_empty());
        assert!(config.relays.onion.is_empty());
        assert_eq!(config.relays.reconnect_interval_secs, 5);
        assert_eq!(config.relays.max_reconnect_attempts, 10);
        assert_eq!(config.relays.connection_timeout_secs, 30);
        assert!(!config.apns.enabled);
        assert_eq!(config.apns.environment, "production");
        assert!(!config.fcm.enabled);
        assert!(config.health.enabled);
        assert_eq!(config.health.bind_address, "0.0.0.0:8080");
        assert!(config.metrics.enabled);
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.logging.format, "json");
    }

    #[test]
    fn test_config_invalid_toml() {
        let config_content = "this is not valid toml {{{";

        let file = create_temp_config(config_content);
        let result = AppConfig::load(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_from_env_with_defaults() {
        // Clear any existing TRANSPONDER_ env vars that might interfere
        // This test verifies from_env works with defaults
        let config = AppConfig::from_env().unwrap();

        // Should have default values
        assert_eq!(config.server.shutdown_timeout_secs, 10);
        assert!(config.relays.clearnet.is_empty());
        assert!(config.relays.onion.is_empty());
        assert_eq!(config.relays.reconnect_interval_secs, 5);
        assert_eq!(config.relays.max_reconnect_attempts, 10);
        assert_eq!(config.relays.connection_timeout_secs, 30);
        assert!(!config.apns.enabled);
        assert_eq!(config.apns.environment, "production");
        assert!(!config.fcm.enabled);
        assert!(config.health.enabled);
        assert_eq!(config.health.bind_address, "0.0.0.0:8080");
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.logging.format, "json");
    }

    #[test]
    fn test_config_nonexistent_file() {
        let result = AppConfig::load("/nonexistent/path/to/config.toml");
        assert!(result.is_err());
    }

    #[test]
    fn test_relay_config_defaults() {
        // Test that default functions return correct values
        assert_eq!(default_reconnect_interval(), 5);
        assert_eq!(default_max_reconnect_attempts(), 10);
        assert_eq!(default_connection_timeout(), 30);
    }

    #[test]
    fn test_apns_config_defaults() {
        assert_eq!(default_apns_environment(), "production");
    }

    #[test]
    fn test_health_config_defaults() {
        assert!(default_health_enabled());
        assert_eq!(default_health_bind_address(), "0.0.0.0:8080");
    }

    #[test]
    fn test_metrics_config_defaults() {
        assert!(default_metrics_enabled());
    }

    #[test]
    fn test_logging_config_defaults() {
        assert_eq!(default_log_level(), "info");
        assert_eq!(default_log_format(), "json");
    }

    #[test]
    fn test_server_config_defaults() {
        assert_eq!(default_shutdown_timeout(), 10);
        assert_eq!(default_max_dedup_cache_size(), 100_000);
    }

    #[test]
    fn test_apns_is_production_true() {
        let config = ApnsConfig {
            enabled: true,
            key_id: String::new(),
            team_id: String::new(),
            private_key_path: String::new(),
            environment: "production".to_string(),
            bundle_id: String::new(),
        };
        assert!(config.is_production());
    }

    #[test]
    fn test_apns_is_production_false() {
        let config = ApnsConfig {
            enabled: true,
            key_id: String::new(),
            team_id: String::new(),
            private_key_path: String::new(),
            environment: "development".to_string(),
            bundle_id: String::new(),
        };
        assert!(!config.is_production());
    }

    #[test]
    fn test_config_partial_sections() {
        // Config that only specifies some sections - others should get defaults
        let config_content = r#"
            [server]
            private_key = "test-key"

            [relays]
            clearnet = ["wss://relay.example.com"]

            [apns]
            enabled = true
            key_id = "MYKEY"
            # Missing other fields - should get defaults
        "#;

        let file = create_temp_config(config_content);
        let config = AppConfig::load(file.path()).unwrap();

        assert_eq!(config.server.private_key, "test-key");
        assert!(config.apns.enabled);
        assert_eq!(config.apns.key_id, "MYKEY");
        assert_eq!(config.apns.environment, "production"); // default
        assert!(!config.fcm.enabled); // default
    }

    #[test]
    fn test_max_dedup_cache_size_default() {
        let config_content = r#"
            [server]
            private_key = "test"
        "#;

        let file = create_temp_config(config_content);
        let config = AppConfig::load(file.path()).unwrap();

        assert_eq!(config.server.max_dedup_cache_size, 100_000);
    }

    #[test]
    fn test_max_dedup_cache_size_custom() {
        let config_content = r#"
            [server]
            private_key = "test"
            max_dedup_cache_size = 50000
        "#;

        let file = create_temp_config(config_content);
        let config = AppConfig::load(file.path()).unwrap();

        assert_eq!(config.server.max_dedup_cache_size, 50_000);
    }
}

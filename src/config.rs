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

    /// Logging configuration.
    pub logging: LoggingConfig,
}

/// Server-specific configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Server's Nostr private key (hex or nsec format).
    pub private_key: String,
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

    /// Authentication method: "certificate" or "token".
    #[serde(default = "default_auth_method")]
    pub auth_method: String,

    /// Key ID for token-based auth.
    #[serde(default)]
    pub key_id: String,

    /// Team ID for token-based auth.
    #[serde(default)]
    pub team_id: String,

    /// Path to the .p8 private key file for token auth.
    #[serde(default)]
    pub private_key_path: String,

    /// Path to the .p12 certificate file for certificate auth.
    #[serde(default)]
    pub certificate_path: String,

    /// Password for the .p12 certificate (for certificate auth).
    #[serde(default)]
    pub certificate_password: String,

    /// APNs environment: "production" or "sandbox".
    #[serde(default = "default_apns_environment")]
    pub environment: String,

    /// Bundle ID for the iOS app.
    #[serde(default)]
    pub bundle_id: String,
}

fn default_auth_method() -> String {
    "token".to_string()
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
            .set_default("relays.clearnet", Vec::<String>::new())?
            .set_default("relays.onion", Vec::<String>::new())?
            .set_default("relays.reconnect_interval_secs", 5)?
            .set_default("relays.max_reconnect_attempts", 10)?
            .set_default("apns.enabled", false)?
            .set_default("apns.auth_method", "token")?
            .set_default("apns.key_id", "")?
            .set_default("apns.team_id", "")?
            .set_default("apns.private_key_path", "")?
            .set_default("apns.certificate_path", "")?
            .set_default("apns.certificate_password", "")?
            .set_default("apns.environment", "production")?
            .set_default("apns.bundle_id", "")?
            .set_default("fcm.enabled", false)?
            .set_default("fcm.service_account_path", "")?
            .set_default("fcm.project_id", "")?
            .set_default("health.enabled", true)?
            .set_default("health.bind_address", "0.0.0.0:8080")?
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
            .set_default("relays.clearnet", Vec::<String>::new())?
            .set_default("relays.onion", Vec::<String>::new())?
            .set_default("relays.reconnect_interval_secs", 5)?
            .set_default("relays.max_reconnect_attempts", 10)?
            .set_default("apns.enabled", false)?
            .set_default("apns.auth_method", "token")?
            .set_default("apns.key_id", "")?
            .set_default("apns.team_id", "")?
            .set_default("apns.private_key_path", "")?
            .set_default("apns.certificate_path", "")?
            .set_default("apns.certificate_password", "")?
            .set_default("apns.environment", "production")?
            .set_default("apns.bundle_id", "")?
            .set_default("fcm.enabled", false)?
            .set_default("fcm.service_account_path", "")?
            .set_default("fcm.project_id", "")?
            .set_default("health.enabled", true)?
            .set_default("health.bind_address", "0.0.0.0:8080")?
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
    /// Returns true if using token-based authentication.
    #[must_use]
    pub fn is_token_auth(&self) -> bool {
        self.auth_method == "token"
    }

    /// Returns true if using certificate-based authentication.
    #[must_use]
    #[allow(dead_code)]
    pub fn is_certificate_auth(&self) -> bool {
        self.auth_method == "certificate"
    }

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

            [logging]
            level = "info"
        "#;

        let file = create_temp_config(config_content);
        let config = AppConfig::load(file.path()).unwrap();

        assert_eq!(config.server.private_key, "abc123");
        assert_eq!(config.relays.clearnet.len(), 1);
        assert!(!config.apns.enabled);
        assert!(!config.fcm.enabled);
    }

    #[test]
    fn test_apns_config_helpers() {
        let config = ApnsConfig {
            enabled: true,
            auth_method: "token".to_string(),
            key_id: "KEY123".to_string(),
            team_id: "TEAM123".to_string(),
            private_key_path: "/path/to/key.p8".to_string(),
            certificate_path: String::new(),
            certificate_password: String::new(),
            environment: "production".to_string(),
            bundle_id: "com.example.app".to_string(),
        };

        assert!(config.is_token_auth());
        assert!(!config.is_certificate_auth());
        assert!(config.is_production());
        assert_eq!(config.base_url(), "https://api.push.apple.com");
    }

    #[test]
    fn test_apns_sandbox_url() {
        let config = ApnsConfig {
            enabled: true,
            auth_method: "token".to_string(),
            key_id: String::new(),
            team_id: String::new(),
            private_key_path: String::new(),
            certificate_path: String::new(),
            certificate_password: String::new(),
            environment: "sandbox".to_string(),
            bundle_id: String::new(),
        };

        assert!(!config.is_production());
        assert_eq!(config.base_url(), "https://api.sandbox.push.apple.com");
    }

    #[test]
    fn test_apns_certificate_auth() {
        let config = ApnsConfig {
            enabled: true,
            auth_method: "certificate".to_string(),
            key_id: String::new(),
            team_id: String::new(),
            private_key_path: String::new(),
            certificate_path: "/path/to/cert.p12".to_string(),
            certificate_password: "secret".to_string(),
            environment: "production".to_string(),
            bundle_id: "com.example.app".to_string(),
        };

        assert!(!config.is_token_auth());
        assert!(config.is_certificate_auth());
    }

    #[test]
    fn test_load_full_config() {
        let config_content = r#"
            [server]
            private_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

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
        assert!(config.relays.clearnet.is_empty());
        assert!(config.relays.onion.is_empty());
        assert_eq!(config.relays.reconnect_interval_secs, 5);
        assert_eq!(config.relays.max_reconnect_attempts, 10);
        assert!(!config.apns.enabled);
        assert_eq!(config.apns.auth_method, "token");
        assert_eq!(config.apns.environment, "production");
        assert!(!config.fcm.enabled);
        assert!(config.health.enabled);
        assert_eq!(config.health.bind_address, "0.0.0.0:8080");
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
        assert!(config.relays.clearnet.is_empty());
        assert!(config.relays.onion.is_empty());
        assert_eq!(config.relays.reconnect_interval_secs, 5);
        assert_eq!(config.relays.max_reconnect_attempts, 10);
        assert!(!config.apns.enabled);
        assert_eq!(config.apns.auth_method, "token");
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
    }

    #[test]
    fn test_apns_config_defaults() {
        assert_eq!(default_auth_method(), "token");
        assert_eq!(default_apns_environment(), "production");
    }

    #[test]
    fn test_health_config_defaults() {
        assert!(default_health_enabled());
        assert_eq!(default_health_bind_address(), "0.0.0.0:8080");
    }

    #[test]
    fn test_logging_config_defaults() {
        assert_eq!(default_log_level(), "info");
        assert_eq!(default_log_format(), "json");
    }

    #[test]
    fn test_apns_is_production_true() {
        let config = ApnsConfig {
            enabled: true,
            auth_method: "token".to_string(),
            key_id: String::new(),
            team_id: String::new(),
            private_key_path: String::new(),
            certificate_path: String::new(),
            certificate_password: String::new(),
            environment: "production".to_string(),
            bundle_id: String::new(),
        };
        assert!(config.is_production());
    }

    #[test]
    fn test_apns_is_production_false() {
        let config = ApnsConfig {
            enabled: true,
            auth_method: "token".to_string(),
            key_id: String::new(),
            team_id: String::new(),
            private_key_path: String::new(),
            certificate_path: String::new(),
            certificate_password: String::new(),
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
        assert_eq!(config.apns.auth_method, "token"); // default
        assert_eq!(config.apns.environment, "production"); // default
        assert!(!config.fcm.enabled); // default
    }
}

//! Configuration loading and management.
//!
//! Supports TOML configuration files with environment variable overrides.
//! Environment variables follow the pattern: `TRANSPONDER_<SECTION>_<KEY>`.
//! Everything after the first underscore becomes the key name, so
//! `TRANSPONDER_SERVER_PRIVATE_KEY` maps to `server.private_key`.
//! Relay lists must use comma-separated strings such as
//! `TRANSPONDER_RELAYS_CLEARNET="a,b,c"`; bracketed syntax like `"[a, b, c]"`
//! is rejected.

use config::{Config, ConfigBuilder, File, builder::DefaultState};
use serde::Deserialize;
use std::{env, ffi::OsString, path::Path};

use crate::error::Result;
use crate::rate_limiter::{
    DEFAULT_MAX_SIZE as DEFAULT_MAX_RATE_LIMIT_CACHE_SIZE, DEFAULT_RATE_LIMIT_PER_HOUR,
    DEFAULT_RATE_LIMIT_PER_MINUTE,
};

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
const ENV_PREFIX: &str = "TRANSPONDER_";

fn default_max_dedup_cache_size() -> usize {
    DEFAULT_MAX_DEDUP_CACHE_SIZE
}

fn default_max_rate_limit_cache_size() -> usize {
    DEFAULT_MAX_RATE_LIMIT_CACHE_SIZE
}

fn default_rate_limit_per_minute() -> u32 {
    DEFAULT_RATE_LIMIT_PER_MINUTE
}

fn default_rate_limit_per_hour() -> u32 {
    DEFAULT_RATE_LIMIT_PER_HOUR
}

/// Server-specific configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Server's Nostr private key (hex or nsec format).
    pub private_key: String,

    /// Path to a file containing the server's Nostr private key.
    #[serde(default)]
    pub private_key_file: String,

    /// Graceful shutdown timeout in seconds.
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout_secs: u64,

    /// Maximum size for the event deduplication cache.
    ///
    /// The cache uses LRU eviction to prevent unbounded memory growth.
    /// Default: 100,000 entries.
    #[serde(default = "default_max_dedup_cache_size")]
    pub max_dedup_cache_size: usize,

    /// Maximum size for rate limit caches (encrypted token and device token).
    ///
    /// Each cache uses LRU eviction to prevent unbounded memory growth.
    /// Default: 100,000 entries per cache.
    #[serde(default = "default_max_rate_limit_cache_size")]
    pub max_rate_limit_cache_size: usize,

    /// Maximum notifications per encrypted token per minute.
    ///
    /// Rate limits identical encrypted blobs to prevent replay attacks.
    /// Default: 240 (4 per second).
    #[serde(default = "default_rate_limit_per_minute")]
    pub encrypted_token_rate_limit_per_minute: u32,

    /// Maximum notifications per encrypted token per hour.
    ///
    /// Default: 5,000.
    #[serde(default = "default_rate_limit_per_hour")]
    pub encrypted_token_rate_limit_per_hour: u32,

    /// Maximum notifications per device token per minute.
    ///
    /// Rate limits notifications to the same device to prevent spam.
    /// Default: 240 (4 per second).
    #[serde(default = "default_rate_limit_per_minute")]
    pub device_token_rate_limit_per_minute: u32,

    /// Maximum notifications per device token per hour.
    ///
    /// Default: 5,000.
    #[serde(default = "default_rate_limit_per_hour")]
    pub device_token_rate_limit_per_hour: u32,
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

fn base_config_builder() -> Result<ConfigBuilder<DefaultState>> {
    Ok(Config::builder()
        // Start with default values
        .set_default("server.private_key", "")?
        .set_default("server.private_key_file", "")?
        .set_default("server.shutdown_timeout_secs", 10)?
        .set_default(
            "server.max_dedup_cache_size",
            DEFAULT_MAX_DEDUP_CACHE_SIZE as i64,
        )?
        .set_default(
            "server.max_rate_limit_cache_size",
            DEFAULT_MAX_RATE_LIMIT_CACHE_SIZE as i64,
        )?
        .set_default(
            "server.encrypted_token_rate_limit_per_minute",
            DEFAULT_RATE_LIMIT_PER_MINUTE as i64,
        )?
        .set_default(
            "server.encrypted_token_rate_limit_per_hour",
            DEFAULT_RATE_LIMIT_PER_HOUR as i64,
        )?
        .set_default(
            "server.device_token_rate_limit_per_minute",
            DEFAULT_RATE_LIMIT_PER_MINUTE as i64,
        )?
        .set_default(
            "server.device_token_rate_limit_per_hour",
            DEFAULT_RATE_LIMIT_PER_HOUR as i64,
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
        .set_default("logging.format", "json")?)
}

fn apply_env_overrides<I>(
    mut builder: ConfigBuilder<DefaultState>,
    env_iter: I,
) -> Result<ConfigBuilder<DefaultState>>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    for (key, value) in env_iter {
        let Some((env_key, config_key)) = env_var_to_config_key(key)? else {
            continue;
        };

        let value = value.into_string().map_err(|os_string| {
            config::ConfigError::Message(format!(
                "env variable {env_key:?} contains non-Unicode data: {os_string:?}"
            ))
        })?;

        builder = if is_string_list_key(&config_key) {
            builder.set_override(&config_key, parse_string_list_env(&env_key, &value)?)?
        } else {
            builder.set_override(&config_key, value)?
        };
    }

    Ok(builder)
}

// Preserve underscores in field names by splitting only once after the section.
fn env_var_to_config_key(
    key: OsString,
) -> std::result::Result<Option<(String, String)>, config::ConfigError> {
    let key = match key.into_string() {
        Ok(key) => key,
        Err(_) => return Ok(None),
    };

    let Some(remainder) = key.strip_prefix(ENV_PREFIX) else {
        return Ok(None);
    };
    let Some((section, field)) = remainder.split_once('_') else {
        return Err(config::ConfigError::Message(format!(
            "env variable {key} must follow {ENV_PREFIX}<SECTION>_<KEY>"
        )));
    };
    if section.is_empty() || field.is_empty() {
        return Err(config::ConfigError::Message(format!(
            "env variable {key} must follow {ENV_PREFIX}<SECTION>_<KEY>"
        )));
    }

    let config_key = format!(
        "{}.{}",
        section.to_ascii_lowercase(),
        field.to_ascii_lowercase()
    );

    if !is_supported_config_key(&config_key) {
        return Err(config::ConfigError::Message(format!(
            "env variable {key} maps to unsupported config key `{config_key}`"
        )));
    }

    Ok(Some((key, config_key)))
}

fn is_string_list_key(config_key: &str) -> bool {
    matches!(config_key, "relays.clearnet" | "relays.onion")
}

fn is_supported_config_key(config_key: &str) -> bool {
    is_string_list_key(config_key)
        || matches!(
            config_key,
            "server.private_key"
                | "server.private_key_file"
                | "server.shutdown_timeout_secs"
                | "server.max_dedup_cache_size"
                | "server.max_rate_limit_cache_size"
                | "server.encrypted_token_rate_limit_per_minute"
                | "server.encrypted_token_rate_limit_per_hour"
                | "server.device_token_rate_limit_per_minute"
                | "server.device_token_rate_limit_per_hour"
                | "relays.reconnect_interval_secs"
                | "relays.max_reconnect_attempts"
                | "relays.connection_timeout_secs"
                | "apns.enabled"
                | "apns.key_id"
                | "apns.team_id"
                | "apns.private_key_path"
                | "apns.environment"
                | "apns.bundle_id"
                | "fcm.enabled"
                | "fcm.service_account_path"
                | "fcm.project_id"
                | "health.enabled"
                | "health.bind_address"
                | "metrics.enabled"
                | "logging.level"
                | "logging.format"
        )
}

fn parse_string_list_env(
    env_key: &str,
    value: &str,
) -> std::result::Result<Vec<String>, config::ConfigError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    if trimmed.starts_with('[') {
        return Err(config::ConfigError::Message(format!(
            "env variable {env_key} must use a comma-separated list, not JSON"
        )));
    }

    Ok(trimmed
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

impl AppConfig {
    fn load_with_env_iter<P, I>(path: P, env_iter: I) -> Result<Self>
    where
        P: AsRef<Path>,
        I: IntoIterator<Item = (OsString, OsString)>,
    {
        let builder = base_config_builder()?.add_source(File::from(path.as_ref()));
        let config = apply_env_overrides(builder, env_iter)?.build()?;

        Ok(config.try_deserialize()?)
    }

    fn from_env_iter<I>(env_iter: I) -> Result<Self>
    where
        I: IntoIterator<Item = (OsString, OsString)>,
    {
        let config = apply_env_overrides(base_config_builder()?, env_iter)?.build()?;

        Ok(config.try_deserialize()?)
    }

    /// Load configuration from a file path with environment variable overrides.
    ///
    /// Environment variables follow the pattern: `TRANSPONDER_<SECTION>_<KEY>`.
    /// Everything after the first underscore becomes the key name, so
    /// `TRANSPONDER_SERVER_PRIVATE_KEY` maps to `server.private_key`.
    /// Relay lists must use comma-separated strings such as
    /// `TRANSPONDER_RELAYS_CLEARNET="a,b,c"`; bracketed syntax like `"[a, b, c]"`
    /// is rejected.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::load_with_env_iter(path, env::vars_os())
    }

    /// Load configuration from environment variables only (no config file).
    #[allow(dead_code)]
    pub fn from_env() -> Result<Self> {
        Self::from_env_iter(env::vars_os())
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
    use std::{ffi::OsString, io::Write};
    use tempfile::Builder;

    fn env_pairs(vars: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        vars.iter()
            .map(|(key, value)| (OsString::from(*key), OsString::from(*value)))
            .collect()
    }

    fn load_with_test_env<P: AsRef<Path>>(path: P, vars: &[(&str, &str)]) -> Result<AppConfig> {
        AppConfig::load_with_env_iter(path, env_pairs(vars))
    }

    fn from_test_env(vars: &[(&str, &str)]) -> Result<AppConfig> {
        AppConfig::from_env_iter(env_pairs(vars))
    }

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
        let config = load_with_test_env(file.path(), &[]).unwrap();

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
        let config = load_with_test_env(file.path(), &[]).unwrap();

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
        let config = load_with_test_env(file.path(), &[]).unwrap();

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
        let result = load_with_test_env(file.path(), &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_env_with_defaults() {
        let config = from_test_env(&[]).unwrap();

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
    fn test_from_env_overrides_keys_with_underscores() {
        let config = from_test_env(&[
            ("TRANSPONDER_SERVER_PRIVATE_KEY", "env-private-key"),
            ("TRANSPONDER_SERVER_SHUTDOWN_TIMEOUT_SECS", "30"),
            ("TRANSPONDER_SERVER_MAX_DEDUP_CACHE_SIZE", "50000"),
            ("TRANSPONDER_APNS_KEY_ID", "KEY123"),
            ("TRANSPONDER_HEALTH_BIND_ADDRESS", "127.0.0.1:9090"),
        ])
        .unwrap();

        assert_eq!(config.server.private_key, "env-private-key");
        assert_eq!(config.server.shutdown_timeout_secs, 30);
        assert_eq!(config.server.max_dedup_cache_size, 50_000);
        assert_eq!(config.apns.key_id, "KEY123");
        assert_eq!(config.health.bind_address, "127.0.0.1:9090");
    }

    #[test]
    fn test_load_env_overrides_file_values() {
        let file = create_temp_config(
            r#"
            [server]
            private_key = "file-private-key"

            [apns]
            private_key_path = "/file/key.p8"
        "#,
        );

        let config = load_with_test_env(
            file.path(),
            &[
                ("TRANSPONDER_SERVER_PRIVATE_KEY", "env-private-key"),
                ("TRANSPONDER_APNS_PRIVATE_KEY_PATH", "/env/key.p8"),
            ],
        )
        .unwrap();

        assert_eq!(config.server.private_key, "env-private-key");
        assert_eq!(config.apns.private_key_path, "/env/key.p8");
    }

    #[test]
    fn test_from_env_parses_comma_separated_relay_lists() {
        let config = from_test_env(&[
            (
                "TRANSPONDER_RELAYS_CLEARNET",
                "wss://relay.example.com, wss://relay2.example.com",
            ),
            ("TRANSPONDER_RELAYS_ONION", "ws://relay.onion"),
        ])
        .unwrap();

        assert_eq!(
            config.relays.clearnet,
            vec![
                "wss://relay.example.com".to_string(),
                "wss://relay2.example.com".to_string(),
            ]
        );
        assert_eq!(config.relays.onion, vec!["ws://relay.onion".to_string()]);
    }

    #[test]
    fn test_from_env_rejects_json_relay_lists() {
        let error = from_test_env(&[(
            "TRANSPONDER_RELAYS_CLEARNET",
            r#"["wss://relay.example.com"]"#,
        )])
        .unwrap_err();
        assert!(error.to_string().contains("comma-separated"));
    }

    #[test]
    fn test_from_env_rejects_malformed_prefixed_variable() {
        let error = from_test_env(&[("TRANSPONDER_SERVER", "value")]).unwrap_err();
        assert!(error.to_string().contains("must follow"));
    }

    #[test]
    fn test_from_env_rejects_unknown_prefixed_variable() {
        let error = from_test_env(&[("TRANSPONDER_SERVER_PRVATE_KEY", "value")]).unwrap_err();
        assert!(error.to_string().contains("unsupported config key"));
    }

    #[test]
    fn test_config_nonexistent_file() {
        let result = load_with_test_env("/nonexistent/path/to/config.toml", &[]);
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
        assert_eq!(default_max_rate_limit_cache_size(), 100_000);
        assert_eq!(default_rate_limit_per_minute(), 240);
        assert_eq!(default_rate_limit_per_hour(), 5000);
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
        let config = load_with_test_env(file.path(), &[]).unwrap();

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
        let config = load_with_test_env(file.path(), &[]).unwrap();

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
        let config = load_with_test_env(file.path(), &[]).unwrap();

        assert_eq!(config.server.max_dedup_cache_size, 50_000);
    }

    #[test]
    fn test_rate_limit_cache_size_default() {
        let config_content = r#"
            [server]
            private_key = "test"
        "#;

        let file = create_temp_config(config_content);
        let config = load_with_test_env(file.path(), &[]).unwrap();

        assert_eq!(config.server.max_rate_limit_cache_size, 100_000);
    }

    #[test]
    fn test_rate_limit_cache_size_custom() {
        let config_content = r#"
            [server]
            private_key = "test"
            max_rate_limit_cache_size = 50000
        "#;

        let file = create_temp_config(config_content);
        let config = load_with_test_env(file.path(), &[]).unwrap();

        assert_eq!(config.server.max_rate_limit_cache_size, 50_000);
    }

    #[test]
    fn test_rate_limit_defaults() {
        let config_content = r#"
            [server]
            private_key = "test"
        "#;

        let file = create_temp_config(config_content);
        let config = load_with_test_env(file.path(), &[]).unwrap();

        assert_eq!(config.server.encrypted_token_rate_limit_per_minute, 240);
        assert_eq!(config.server.encrypted_token_rate_limit_per_hour, 5000);
        assert_eq!(config.server.device_token_rate_limit_per_minute, 240);
        assert_eq!(config.server.device_token_rate_limit_per_hour, 5000);
    }

    #[test]
    fn test_rate_limit_custom() {
        let config_content = r#"
            [server]
            private_key = "test"
            encrypted_token_rate_limit_per_minute = 100
            encrypted_token_rate_limit_per_hour = 2000
            device_token_rate_limit_per_minute = 50
            device_token_rate_limit_per_hour = 1000
        "#;

        let file = create_temp_config(config_content);
        let config = load_with_test_env(file.path(), &[]).unwrap();

        assert_eq!(config.server.encrypted_token_rate_limit_per_minute, 100);
        assert_eq!(config.server.encrypted_token_rate_limit_per_hour, 2000);
        assert_eq!(config.server.device_token_rate_limit_per_minute, 50);
        assert_eq!(config.server.device_token_rate_limit_per_hour, 1000);
    }
}

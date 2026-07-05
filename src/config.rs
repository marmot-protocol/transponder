//! Configuration loading and management.
//!
//! Supports TOML configuration files with environment variable overrides.
//! Environment variables follow the pattern: `TRANSPONDER_<SECTION>_<KEY>`.
//! Everything after the first underscore becomes the key name, so
//! `TRANSPONDER_SERVER_PRIVATE_KEY` maps to `server.private_key`.
//! Relay lists must use comma-separated strings such as
//! `TRANSPONDER_RELAYS_CLEARNET="a,b,c"`; bracketed syntax like `"[a, b, c]"`
//! is rejected.
//!
//! Prefixed variables that are malformed or map to an unknown config key are
//! ignored rather than treated as errors, so ambient service-discovery
//! variables injected by Kubernetes and Docker (e.g. `TRANSPONDER_SERVICE_HOST`,
//! `TRANSPONDER_PORT_8080_TCP`) do not abort startup.

use config::{Config, ConfigBuilder, File, builder::DefaultState};
use serde::{Deserialize, Deserializer};
use std::{
    env,
    ffi::OsString,
    path::{Path, PathBuf},
};
use tokio::sync::Semaphore;
use tracing::debug;
use zeroize::Zeroizing;

use crate::crypto::nip59::DEFAULT_MAX_TOKENS_PER_EVENT;
use crate::error::Result;
use crate::nostr::events::{
    DEFAULT_DEDUP_RETENTION_SECS, DEFAULT_MAX_NOTIFICATION_AGE_SECS,
    DEFAULT_MAX_NOTIFICATION_FUTURE_SKEW_SECS,
};
use crate::rate_limiter::{
    DEFAULT_GLOBAL_UNWRAP_LIMIT_PER_HOUR, DEFAULT_GLOBAL_UNWRAP_LIMIT_PER_MINUTE,
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

    /// GlitchTip error-reporting configuration.
    pub glitchtip: GlitchtipConfig,
}

/// Default maximum size for the deduplication cache.
const DEFAULT_MAX_DEDUP_CACHE_SIZE: usize = 100_000;
const DEFAULT_HEALTH_BIND_ADDRESS: &str = "127.0.0.1:8080";
const ENV_PREFIX: &str = "TRANSPONDER_";

/// Default maximum number of events processed concurrently.
///
/// Caps the total in-flight gift-wrap unwrap (ECDH) work so a flood cannot
/// spawn unbounded crypto tasks, while still draining the relay broadcast
/// channel quickly enough to avoid `Lagged` overflow.
const DEFAULT_MAX_CONCURRENT_EVENT_PROCESSING: usize = 64;

fn default_max_dedup_cache_size() -> usize {
    DEFAULT_MAX_DEDUP_CACHE_SIZE
}

fn default_dedup_retention_secs() -> u64 {
    DEFAULT_DEDUP_RETENTION_SECS
}

fn default_max_notification_age_secs() -> u64 {
    DEFAULT_MAX_NOTIFICATION_AGE_SECS
}

fn default_max_notification_future_skew_secs() -> u64 {
    DEFAULT_MAX_NOTIFICATION_FUTURE_SKEW_SECS
}

fn default_max_concurrent_event_processing() -> usize {
    DEFAULT_MAX_CONCURRENT_EVENT_PROCESSING
}

fn default_global_unwrap_rate_limit_per_minute() -> u32 {
    DEFAULT_GLOBAL_UNWRAP_LIMIT_PER_MINUTE
}

fn default_global_unwrap_rate_limit_per_hour() -> u32 {
    DEFAULT_GLOBAL_UNWRAP_LIMIT_PER_HOUR
}

fn default_max_rate_limit_cache_size() -> usize {
    DEFAULT_MAX_RATE_LIMIT_CACHE_SIZE
}

fn default_max_tokens_per_event() -> usize {
    DEFAULT_MAX_TOKENS_PER_EVENT
}

fn default_rate_limit_per_minute() -> u32 {
    DEFAULT_RATE_LIMIT_PER_MINUTE
}

fn default_rate_limit_per_hour() -> u32 {
    DEFAULT_RATE_LIMIT_PER_HOUR
}

/// Server-specific configuration.
#[derive(Clone, Deserialize)]
pub struct ServerConfig {
    /// Server's Nostr private key (hex or nsec format).
    #[serde(deserialize_with = "deserialize_zeroizing_string")]
    pub private_key: Zeroizing<String>,

    /// Path to a file containing the server's Nostr private key.
    #[serde(default)]
    pub private_key_file: String,

    /// Graceful shutdown timeout in seconds.
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout_secs: u64,

    /// Maximum size for the volatile event deduplication cache.
    ///
    /// Applies when durable replay state is disabled. When `dedup_state_path`
    /// is configured, Transponder retains all terminal event IDs inside
    /// `dedup_retention_secs` so restart/reconnect replay suppression covers the
    /// full NIP-59 subscription lookback window instead of being capped by this
    /// LRU size.
    /// Default: 100,000 entries.
    #[serde(default = "default_max_dedup_cache_size")]
    pub max_dedup_cache_size: usize,

    /// Optional path for durable event-ID replay state.
    ///
    /// Stores only public Nostr gift-wrap event IDs and processing timestamps,
    /// never notification payloads, device tokens, private keys, sender
    /// identities, recipient identities, or relay URLs. Empty disables durable
    /// replay state.
    #[serde(default)]
    pub dedup_state_path: PathBuf,

    /// Duration to retain event IDs in replay state.
    ///
    /// Default covers NIP-59's 2-day outer timestamp randomization window plus
    /// tolerated future skew.
    #[serde(default = "default_dedup_retention_secs")]
    pub dedup_retention_secs: u64,

    /// Maximum accepted age for the unwrapped kind:446 notification rumor.
    ///
    /// Outer gift-wrap timestamps are intentionally randomized by NIP-59, so
    /// freshness is checked against the inner rumor timestamp. Set to 0 to
    /// disable this stateless freshness bound.
    #[serde(default = "default_max_notification_age_secs")]
    pub max_notification_age_secs: u64,

    /// Tolerated future clock skew for the unwrapped notification rumor.
    #[serde(default = "default_max_notification_future_skew_secs")]
    pub max_notification_future_skew_secs: u64,

    /// Maximum tracked keys for each rate limit cache (encrypted token and
    /// device token).
    ///
    /// This caps key cardinality, not total timestamp storage. Each tracked key
    /// can retain up to `per_minute + per_hour` admitted-hit timestamps, so
    /// worst-case timestamp storage is `max_rate_limit_cache_size *
    /// (per_minute + per_hour)` per limiter. With the defaults, that is roughly
    /// 524,000,000 `Instant` values per limiter (about 8.4 GB at 16 bytes per
    /// timestamp, before `VecDeque` overhead), and Transponder creates two such
    /// limiters.
    ///
    /// Unknown keys are rate limited at capacity until cleanup removes stale
    /// entries. Default: 100,000 entries per cache.
    #[serde(default = "default_max_rate_limit_cache_size")]
    pub max_rate_limit_cache_size: usize,

    /// Maximum encrypted tokens accepted in a single notification event.
    ///
    /// Default: 100.
    #[serde(default = "default_max_tokens_per_event")]
    pub max_tokens_per_event: usize,

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

    /// Maximum number of events processed concurrently.
    ///
    /// Bounds total in-flight gift-wrap unwrap (ECDH) work. The relay event
    /// loop admits up to this many events at once; excess events wait for a
    /// permit. This drains the broadcast channel quickly (avoiding `Lagged`
    /// overflow) while capping CPU spent on asymmetric crypto.
    /// Default: 64.
    #[serde(default = "default_max_concurrent_event_processing")]
    pub max_concurrent_event_processing: usize,

    /// Global maximum gift-wrap unwraps (ECDH) per minute, across all senders.
    ///
    /// Cheap admission control checked BEFORE the gift-wrap unwrap. The server
    /// pubkey is public and gift wraps are sender-anonymous, so this global
    /// throttle sheds floods before spending asymmetric-crypto cycles.
    /// Default: 600 (10 per second).
    #[serde(default = "default_global_unwrap_rate_limit_per_minute")]
    pub global_unwrap_rate_limit_per_minute: u32,

    /// Global maximum gift-wrap unwraps (ECDH) per hour, across all senders.
    ///
    /// Default: 30,000.
    #[serde(default = "default_global_unwrap_rate_limit_per_hour")]
    pub global_unwrap_rate_limit_per_hour: u32,
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("private_key", &"[REDACTED]")
            .field("private_key_file", &self.private_key_file)
            .field("shutdown_timeout_secs", &self.shutdown_timeout_secs)
            .field("max_dedup_cache_size", &self.max_dedup_cache_size)
            .field("dedup_state_path", &self.dedup_state_path)
            .field("dedup_retention_secs", &self.dedup_retention_secs)
            .field("max_notification_age_secs", &self.max_notification_age_secs)
            .field(
                "max_notification_future_skew_secs",
                &self.max_notification_future_skew_secs,
            )
            .field("max_rate_limit_cache_size", &self.max_rate_limit_cache_size)
            .field("max_tokens_per_event", &self.max_tokens_per_event)
            .field(
                "encrypted_token_rate_limit_per_minute",
                &self.encrypted_token_rate_limit_per_minute,
            )
            .field(
                "encrypted_token_rate_limit_per_hour",
                &self.encrypted_token_rate_limit_per_hour,
            )
            .field(
                "device_token_rate_limit_per_minute",
                &self.device_token_rate_limit_per_minute,
            )
            .field(
                "device_token_rate_limit_per_hour",
                &self.device_token_rate_limit_per_hour,
            )
            .field(
                "max_concurrent_event_processing",
                &self.max_concurrent_event_processing,
            )
            .field(
                "global_unwrap_rate_limit_per_minute",
                &self.global_unwrap_rate_limit_per_minute,
            )
            .field(
                "global_unwrap_rate_limit_per_hour",
                &self.global_unwrap_rate_limit_per_hour,
            )
            .finish()
    }
}

fn default_shutdown_timeout() -> u64 {
    10
}

fn deserialize_zeroizing_string<'de, D>(
    deserializer: D,
) -> std::result::Result<Zeroizing<String>, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(Zeroizing::new)
}

/// Relay connection configuration.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct RelayConfig {
    /// ClearNet relay URLs.
    #[serde(default)]
    pub clearnet: Vec<String>,

    /// Whether unencrypted ws:// ClearNet relay URLs are allowed.
    ///
    /// This should remain false in production. It exists for local development
    /// and tests that use loopback mock relays without TLS.
    #[serde(default)]
    pub allow_unencrypted_clearnet_relays: bool,

    /// Tor/onion relay URLs.
    #[serde(default)]
    pub onion: Vec<String>,

    /// Base relay reconnection interval in seconds.
    #[serde(default = "default_reconnect_interval")]
    pub reconnect_interval_secs: u64,

    /// Maximum reconnect attempts after the initial connection attempt.
    ///
    /// A value of `0` disables automatic retries after the first failed attempt.
    /// The counter resets after a successful relay connection.
    #[serde(default = "default_max_reconnect_attempts")]
    pub max_reconnect_attempts: u32,

    /// Timeout in seconds to wait for at least one relay to connect during startup.
    /// Default: 30 seconds.
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_secs: u64,
}

/// Upper bound for the relay duration fields, in seconds.
///
/// `connection_timeout_secs` and `reconnect_interval_secs` are startup/retry
/// waits, so an unbounded value (e.g. `u64::MAX`) makes startup hang effectively
/// forever when relays are unreachable. Five minutes comfortably covers slow
/// networks and Tor bootstrapping while keeping a misconfiguration from wedging
/// the process, so anything larger is rejected at load time.
const MAX_RELAY_DURATION_SECS: u64 = 300;

/// Upper bound for [`ServerConfig::max_concurrent_event_processing`].
///
/// [`Semaphore::new`] panics when the permit count exceeds
/// [`Semaphore::MAX_PERMITS`], so oversized values are rejected at load time
/// rather than aborting startup.
const MAX_CONCURRENT_EVENT_PROCESSING: usize = Semaphore::MAX_PERMITS;

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
    pub environment: ApnsEnvironment,

    /// Bundle ID for the iOS app.
    #[serde(default)]
    pub bundle_id: String,

    /// APNs payload mode.
    #[serde(default)]
    pub payload_mode: ApnsPayloadMode,
}

/// APNs gateway environment.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ApnsEnvironment {
    /// Production APNs gateway for App Store builds.
    #[default]
    Production,

    /// Sandbox APNs gateway for development builds.
    Sandbox,
}

impl ApnsEnvironment {
    fn is_production(self) -> bool {
        matches!(self, Self::Production)
    }
}

impl std::fmt::Display for ApnsEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Production => f.write_str("production"),
            Self::Sandbox => f.write_str("sandbox"),
        }
    }
}

/// APNs payload mode.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApnsPayloadMode {
    /// Silent background push used by the normal MIP-05 flow.
    #[default]
    Silent,

    /// Alert payload for exercising the iOS Notification Service Extension prototype.
    NsePrototypeAlert,
}

impl ApnsPayloadMode {
    pub(crate) fn push_type(self) -> &'static str {
        match self {
            Self::Silent => "background",
            Self::NsePrototypeAlert => "alert",
        }
    }

    pub(crate) fn priority(self) -> &'static str {
        match self {
            Self::Silent => "5",
            Self::NsePrototypeAlert => "10",
        }
    }
}

impl std::fmt::Display for ApnsPayloadMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Silent => f.write_str("silent"),
            Self::NsePrototypeAlert => f.write_str("nse_prototype_alert"),
        }
    }
}

fn default_apns_environment() -> ApnsEnvironment {
    ApnsEnvironment::Production
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
    DEFAULT_HEALTH_BIND_ADDRESS.to_string()
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

/// GlitchTip (Sentry-compatible) error-reporting configuration.
///
/// Reporting is enabled by the presence of a non-empty `dsn`; there is no
/// separate on/off flag, so there is no way to configure an enabled-but-unusable
/// state.
#[derive(Clone, Deserialize)]
pub struct GlitchtipConfig {
    /// GlitchTip DSN. Empty disables error reporting.
    #[serde(default)]
    pub dsn: String,

    /// Deployment environment tag attached to every event (e.g. "production").
    #[serde(default = "default_glitchtip_environment")]
    pub environment: String,

    /// Performance-trace sample rate in the range `0.0..=1.0`.
    ///
    /// Default `0.0` (errors only). Transponder is an event loop with no request
    /// transactions to trace, so raise this only after adding span instrumentation.
    #[serde(default)]
    pub traces_sample_rate: f32,
}

impl std::fmt::Debug for GlitchtipConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The DSN embeds a write-auth key; redact it so a config debug dump never
        // leaks it, mirroring `ServerConfig`. Empty is shown as-is so a disabled
        // reporter is not mistaken for a hidden secret.
        let dsn = if self.dsn.is_empty() {
            ""
        } else {
            "[REDACTED]"
        };
        f.debug_struct("GlitchtipConfig")
            .field("dsn", &dsn)
            .field("environment", &self.environment)
            .field("traces_sample_rate", &self.traces_sample_rate)
            .finish()
    }
}

fn default_glitchtip_environment() -> String {
    "production".to_string()
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
        .set_default("server.dedup_state_path", "")?
        .set_default(
            "server.dedup_retention_secs",
            DEFAULT_DEDUP_RETENTION_SECS as i64,
        )?
        .set_default(
            "server.max_notification_age_secs",
            DEFAULT_MAX_NOTIFICATION_AGE_SECS as i64,
        )?
        .set_default(
            "server.max_notification_future_skew_secs",
            DEFAULT_MAX_NOTIFICATION_FUTURE_SKEW_SECS as i64,
        )?
        .set_default(
            "server.max_rate_limit_cache_size",
            DEFAULT_MAX_RATE_LIMIT_CACHE_SIZE as i64,
        )?
        .set_default(
            "server.max_tokens_per_event",
            DEFAULT_MAX_TOKENS_PER_EVENT as i64,
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
        .set_default(
            "server.max_concurrent_event_processing",
            DEFAULT_MAX_CONCURRENT_EVENT_PROCESSING as i64,
        )?
        .set_default(
            "server.global_unwrap_rate_limit_per_minute",
            DEFAULT_GLOBAL_UNWRAP_LIMIT_PER_MINUTE as i64,
        )?
        .set_default(
            "server.global_unwrap_rate_limit_per_hour",
            DEFAULT_GLOBAL_UNWRAP_LIMIT_PER_HOUR as i64,
        )?
        .set_default("relays.clearnet", Vec::<String>::new())?
        .set_default("relays.allow_unencrypted_clearnet_relays", false)?
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
        .set_default("apns.payload_mode", "silent")?
        .set_default("fcm.enabled", false)?
        .set_default("fcm.service_account_path", "")?
        .set_default("fcm.project_id", "")?
        .set_default("health.enabled", true)?
        .set_default("health.bind_address", DEFAULT_HEALTH_BIND_ADDRESS)?
        .set_default("metrics.enabled", true)?
        .set_default("logging.level", "info")?
        .set_default("logging.format", "json")?
        .set_default("glitchtip.dsn", "")?
        .set_default("glitchtip.environment", "production")?
        .set_default("glitchtip.traces_sample_rate", 0.0)?)
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

        let value = value.into_string().map_err(|_| {
            config::ConfigError::Message(format!(
                "env variable {env_key} contains non-Unicode data"
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
//
// Prefixed variables that are malformed (no second underscore, empty section or
// field) or map to an unsupported config key are ambient rather than genuine
// overrides: Kubernetes and Docker auto-inject service-discovery variables such
// as `TRANSPONDER_SERVICE_HOST`, `TRANSPONDER_PORT`, and
// `TRANSPONDER_PORT_8080_TCP` that share the service-name prefix. Skipping them
// (returning `Ok(None)`) keeps those deployments from aborting startup, while a
// typo in a real override key just falls back to its default instead of failing
// loudly. The variable name is logged at debug for troubleshooting; the value is
// never logged because an override value can be a secret (e.g. the private key).
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
        debug!("ignoring ambient prefixed env variable {key}: no {ENV_PREFIX}<SECTION>_<KEY> form");
        return Ok(None);
    };
    if section.is_empty() || field.is_empty() {
        debug!("ignoring ambient prefixed env variable {key}: empty section or field");
        return Ok(None);
    }

    let config_key = format!(
        "{}.{}",
        section.to_ascii_lowercase(),
        field.to_ascii_lowercase()
    );

    if !is_supported_config_key(&config_key) {
        debug!(
            "ignoring ambient prefixed env variable {key}: unsupported config key `{config_key}`"
        );
        return Ok(None);
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
                | "server.dedup_state_path"
                | "server.dedup_retention_secs"
                | "server.max_notification_age_secs"
                | "server.max_notification_future_skew_secs"
                | "server.max_rate_limit_cache_size"
                | "server.max_tokens_per_event"
                | "server.encrypted_token_rate_limit_per_minute"
                | "server.encrypted_token_rate_limit_per_hour"
                | "server.device_token_rate_limit_per_minute"
                | "server.device_token_rate_limit_per_hour"
                | "server.max_concurrent_event_processing"
                | "server.global_unwrap_rate_limit_per_minute"
                | "server.global_unwrap_rate_limit_per_hour"
                | "relays.allow_unencrypted_clearnet_relays"
                | "relays.reconnect_interval_secs"
                | "relays.max_reconnect_attempts"
                | "relays.connection_timeout_secs"
                | "apns.enabled"
                | "apns.key_id"
                | "apns.team_id"
                | "apns.private_key_path"
                | "apns.environment"
                | "apns.bundle_id"
                | "apns.payload_mode"
                | "fcm.enabled"
                | "fcm.service_account_path"
                | "fcm.project_id"
                | "health.enabled"
                | "health.bind_address"
                | "metrics.enabled"
                | "logging.level"
                | "logging.format"
                | "glitchtip.dsn"
                | "glitchtip.environment"
                | "glitchtip.traces_sample_rate"
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

        let config: Self = config.try_deserialize()?;
        config.validate()?;
        Ok(config)
    }

    fn from_env_iter<I>(env_iter: I) -> Result<Self>
    where
        I: IntoIterator<Item = (OsString, OsString)>,
    {
        let config = apply_env_overrides(base_config_builder()?, env_iter)?.build()?;

        let config: Self = config.try_deserialize()?;
        config.validate()?;
        Ok(config)
    }

    /// Validates configuration values that cannot be expressed by the type
    /// system or `serde` defaults.
    ///
    /// Rejects `0` for the rate-limit count fields and the rate-limit cache
    /// size. A `0` count would either block every request for that limiter
    /// dimension (a silent push outage) or be silently swapped for the default,
    /// so an explicit error at load time surfaces the misconfiguration instead
    /// of letting it reach runtime. Duration fields are also range-checked so a
    /// degenerate value cannot defeat graceful shutdown or hang startup.
    fn validate(&self) -> Result<()> {
        self.server.validate()?;
        self.relays.validate()?;
        self.glitchtip.validate()?;
        Ok(())
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

impl ServerConfig {
    /// Rejects rate-limit count fields and the rate-limit cache size set to `0`,
    /// `shutdown_timeout_secs` set to `0`, and
    /// `max_concurrent_event_processing` above [`MAX_CONCURRENT_EVENT_PROCESSING`].
    ///
    /// A `0` per-minute/per-hour limit blocks every request for that limiter
    /// dimension, and a `0` cache size is silently replaced by the default
    /// rather than honoured. A `0` `shutdown_timeout_secs` makes the graceful
    /// drain time out immediately, abandoning in-flight push notifications, so
    /// it is rejected rather than silently skipping the drain. An oversized
    /// `max_concurrent_event_processing` would panic in `Semaphore::new` at
    /// startup, so it is range-checked here. Each error names the offending
    /// config field.
    fn validate(&self) -> std::result::Result<(), config::ConfigError> {
        if self.shutdown_timeout_secs == 0 {
            return Err(config::ConfigError::Message(
                "server.shutdown_timeout_secs must be greater than 0; a value of 0 makes graceful shutdown time out immediately and abandon in-flight push notifications".to_string(),
            ));
        }

        let zero_checked_fields = [
            (
                "server.encrypted_token_rate_limit_per_minute",
                u64::from(self.encrypted_token_rate_limit_per_minute),
            ),
            (
                "server.encrypted_token_rate_limit_per_hour",
                u64::from(self.encrypted_token_rate_limit_per_hour),
            ),
            (
                "server.device_token_rate_limit_per_minute",
                u64::from(self.device_token_rate_limit_per_minute),
            ),
            (
                "server.device_token_rate_limit_per_hour",
                u64::from(self.device_token_rate_limit_per_hour),
            ),
            (
                "server.global_unwrap_rate_limit_per_minute",
                u64::from(self.global_unwrap_rate_limit_per_minute),
            ),
            (
                "server.global_unwrap_rate_limit_per_hour",
                u64::from(self.global_unwrap_rate_limit_per_hour),
            ),
            (
                "server.max_rate_limit_cache_size",
                self.max_rate_limit_cache_size as u64,
            ),
            ("server.dedup_retention_secs", self.dedup_retention_secs),
        ];

        for (field, value) in zero_checked_fields {
            if value == 0 {
                return Err(config::ConfigError::Message(format!(
                    "{field} must be greater than 0"
                )));
            }
        }

        if self.max_concurrent_event_processing > MAX_CONCURRENT_EVENT_PROCESSING {
            return Err(config::ConfigError::Message(format!(
                "server.max_concurrent_event_processing must be at most {MAX_CONCURRENT_EVENT_PROCESSING}"
            )));
        }

        Ok(())
    }
}

impl RelayConfig {
    /// Range-checks the relay duration fields.
    ///
    /// `connection_timeout_secs` is the startup wait for the first relay to
    /// connect: `0` would time out instantly and never connect, while an
    /// unbounded value hangs startup effectively forever when relays are
    /// unreachable. `reconnect_interval_secs` is likewise range-checked so a
    /// degenerate value cannot busy-loop or stall reconnection once used. Both
    /// are capped at [`MAX_RELAY_DURATION_SECS`], and each error names the
    /// offending field.
    fn validate(&self) -> std::result::Result<(), config::ConfigError> {
        let duration_fields = [
            (
                "relays.connection_timeout_secs",
                self.connection_timeout_secs,
            ),
            (
                "relays.reconnect_interval_secs",
                self.reconnect_interval_secs,
            ),
        ];

        for (field, value) in duration_fields {
            if value == 0 {
                return Err(config::ConfigError::Message(format!(
                    "{field} must be greater than 0"
                )));
            }
            if value > MAX_RELAY_DURATION_SECS {
                return Err(config::ConfigError::Message(format!(
                    "{field} must be at most {MAX_RELAY_DURATION_SECS} seconds"
                )));
            }
        }

        Ok(())
    }
}

impl GlitchtipConfig {
    /// Rejects a `traces_sample_rate` outside `0.0..=1.0`.
    ///
    /// The Sentry protocol interprets the rate as a probability; a value outside
    /// the unit interval is a misconfiguration, so it is rejected at load time
    /// rather than silently clamped.
    fn validate(&self) -> std::result::Result<(), config::ConfigError> {
        if !(0.0..=1.0).contains(&self.traces_sample_rate) {
            return Err(config::ConfigError::Message(
                "glitchtip.traces_sample_rate must be between 0.0 and 1.0".to_string(),
            ));
        }
        Ok(())
    }
}

impl ApnsConfig {
    /// Returns true if targeting production APNs environment.
    #[must_use]
    pub fn is_production(&self) -> bool {
        self.environment.is_production()
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

    fn test_server_config(private_key: &str) -> ServerConfig {
        ServerConfig {
            private_key: Zeroizing::new(private_key.to_string()),
            private_key_file: String::new(),
            shutdown_timeout_secs: 10,
            max_dedup_cache_size: 100_000,
            dedup_state_path: PathBuf::new(),
            dedup_retention_secs: DEFAULT_DEDUP_RETENTION_SECS,
            max_notification_age_secs: DEFAULT_MAX_NOTIFICATION_AGE_SECS,
            max_notification_future_skew_secs: DEFAULT_MAX_NOTIFICATION_FUTURE_SKEW_SECS,
            max_rate_limit_cache_size: 100_000,
            max_tokens_per_event: DEFAULT_MAX_TOKENS_PER_EVENT,
            encrypted_token_rate_limit_per_minute: 240,
            encrypted_token_rate_limit_per_hour: 5000,
            device_token_rate_limit_per_minute: 240,
            device_token_rate_limit_per_hour: 5000,
            max_concurrent_event_processing: 64,
            global_unwrap_rate_limit_per_minute: 600,
            global_unwrap_rate_limit_per_hour: 30_000,
        }
    }

    #[test]
    fn test_server_config_debug_redacts_private_key() {
        let config = test_server_config("deadbeef1234");

        let debug_output = format!("{config:?}");

        assert!(!debug_output.contains("deadbeef1234"));
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn test_app_config_debug_redacts_server_private_key() {
        let config = from_test_env(&[("TRANSPONDER_SERVER_PRIVATE_KEY", "deadbeef1234")]).unwrap();

        let debug_output = format!("{config:?}");

        assert!(!debug_output.contains("deadbeef1234"));
        assert!(debug_output.contains("[REDACTED]"));
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

        assert_eq!(config.server.private_key.as_str(), "abc123");
        assert_eq!(config.server.shutdown_timeout_secs, 10); // default
        assert_eq!(config.relays.clearnet.len(), 1);
        assert!(!config.relays.allow_unencrypted_clearnet_relays);
        assert!(!config.apns.enabled);
        assert!(!config.fcm.enabled);
        assert!(config.metrics.enabled);
    }

    #[test]
    fn test_server_private_key_is_zeroizing_and_debug_redacted() {
        let config_content = r#"
            [server]
            private_key = "abc123"
        "#;

        let file = create_temp_config(config_content);
        let config = load_with_test_env(file.path(), &[]).unwrap();

        fn assert_zeroizing_string(_: &Zeroizing<String>) {}
        assert_zeroizing_string(&config.server.private_key);

        let debug = format!("{:?}", config.server);
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("abc123"));
    }

    #[test]
    fn test_apns_config_helpers() {
        let config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM123".to_string(),
            private_key_path: "/path/to/key.p8".to_string(),
            environment: ApnsEnvironment::Production,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
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
            environment: ApnsEnvironment::Sandbox,
            bundle_id: String::new(),
            payload_mode: Default::default(),
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
            dedup_state_path = "/var/lib/transponder/dedup-events.log"
            dedup_retention_secs = 173100
            max_notification_age_secs = 7200
            max_notification_future_skew_secs = 120

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
            config.server.private_key.as_str(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(config.server.shutdown_timeout_secs, 30);
        assert_eq!(
            config.server.dedup_state_path,
            PathBuf::from("/var/lib/transponder/dedup-events.log")
        );
        assert_eq!(config.server.dedup_retention_secs, 173_100);
        assert_eq!(config.server.max_notification_age_secs, 7_200);
        assert_eq!(config.server.max_notification_future_skew_secs, 120);
        assert_eq!(config.relays.clearnet.len(), 2);
        assert_eq!(config.relays.onion.len(), 1);
        assert!(!config.relays.allow_unencrypted_clearnet_relays);
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
        assert!(config.server.dedup_state_path.as_os_str().is_empty());
        assert_eq!(
            config.server.dedup_retention_secs,
            DEFAULT_DEDUP_RETENTION_SECS
        );
        assert_eq!(
            config.server.max_notification_age_secs,
            DEFAULT_MAX_NOTIFICATION_AGE_SECS
        );
        assert_eq!(
            config.server.max_notification_future_skew_secs,
            DEFAULT_MAX_NOTIFICATION_FUTURE_SKEW_SECS
        );
        assert!(config.relays.clearnet.is_empty());
        assert!(config.relays.onion.is_empty());
        assert!(!config.relays.allow_unencrypted_clearnet_relays);
        assert_eq!(config.relays.reconnect_interval_secs, 5);
        assert_eq!(config.relays.max_reconnect_attempts, 10);
        assert_eq!(config.relays.connection_timeout_secs, 30);
        assert!(!config.apns.enabled);
        assert_eq!(config.apns.environment, ApnsEnvironment::Production);
        assert!(!config.fcm.enabled);
        assert!(config.health.enabled);
        assert_eq!(config.health.bind_address, "127.0.0.1:8080");
        assert!(config.metrics.enabled);
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.logging.format, "json");
    }

    #[test]
    fn test_replay_default_helpers_match_event_defaults() {
        assert_eq!(default_dedup_retention_secs(), DEFAULT_DEDUP_RETENTION_SECS);
        assert_eq!(
            default_max_notification_age_secs(),
            DEFAULT_MAX_NOTIFICATION_AGE_SECS
        );
        assert_eq!(
            default_max_notification_future_skew_secs(),
            DEFAULT_MAX_NOTIFICATION_FUTURE_SKEW_SECS
        );
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
        assert!(!config.relays.allow_unencrypted_clearnet_relays);
        assert_eq!(config.relays.reconnect_interval_secs, 5);
        assert_eq!(config.relays.max_reconnect_attempts, 10);
        assert_eq!(config.relays.connection_timeout_secs, 30);
        assert!(!config.apns.enabled);
        assert_eq!(config.apns.environment, ApnsEnvironment::Production);
        assert!(!config.fcm.enabled);
        assert!(config.health.enabled);
        assert_eq!(config.health.bind_address, "127.0.0.1:8080");
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.logging.format, "json");
    }

    #[test]
    fn test_from_env_overrides_keys_with_underscores() {
        let config = from_test_env(&[
            ("TRANSPONDER_SERVER_PRIVATE_KEY", "env-private-key"),
            ("TRANSPONDER_SERVER_SHUTDOWN_TIMEOUT_SECS", "30"),
            ("TRANSPONDER_SERVER_MAX_DEDUP_CACHE_SIZE", "50000"),
            (
                "TRANSPONDER_SERVER_DEDUP_STATE_PATH",
                "/var/lib/transponder/dedup-events.log",
            ),
            ("TRANSPONDER_SERVER_DEDUP_RETENTION_SECS", "173100"),
            ("TRANSPONDER_SERVER_MAX_NOTIFICATION_AGE_SECS", "7200"),
            (
                "TRANSPONDER_SERVER_MAX_NOTIFICATION_FUTURE_SKEW_SECS",
                "120",
            ),
            ("TRANSPONDER_SERVER_MAX_TOKENS_PER_EVENT", "25"),
            (
                "TRANSPONDER_RELAYS_ALLOW_UNENCRYPTED_CLEARNET_RELAYS",
                "true",
            ),
            ("TRANSPONDER_APNS_KEY_ID", "KEY123"),
            ("TRANSPONDER_HEALTH_BIND_ADDRESS", "127.0.0.1:9090"),
        ])
        .unwrap();

        assert_eq!(config.server.private_key.as_str(), "env-private-key");
        assert_eq!(config.server.shutdown_timeout_secs, 30);
        assert_eq!(config.server.max_dedup_cache_size, 50_000);
        assert_eq!(
            config.server.dedup_state_path,
            PathBuf::from("/var/lib/transponder/dedup-events.log")
        );
        assert_eq!(config.server.dedup_retention_secs, 173_100);
        assert_eq!(config.server.max_notification_age_secs, 7_200);
        assert_eq!(config.server.max_notification_future_skew_secs, 120);
        assert_eq!(config.server.max_tokens_per_event, 25);
        assert!(config.relays.allow_unencrypted_clearnet_relays);
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

        assert_eq!(config.server.private_key.as_str(), "env-private-key");
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
    fn test_from_env_ignores_malformed_prefixed_variable() {
        // A prefixed variable with no second underscore is ambient (e.g. Docker's
        // `TRANSPONDER_PORT`), not a genuine override, so it is skipped rather
        // than aborting startup.
        let config = from_test_env(&[("TRANSPONDER_SERVER", "value")]).unwrap();
        assert_eq!(config.server.private_key.as_str(), "");
    }

    #[test]
    fn test_from_env_ignores_unknown_prefixed_variable() {
        // A typo like `PRVATE` maps to an unsupported config key; it is skipped
        // (falling back to defaults) instead of failing to load.
        let config = from_test_env(&[("TRANSPONDER_SERVER_PRVATE_KEY", "value")]).unwrap();
        assert_eq!(config.server.private_key.as_str(), "");
    }

    #[test]
    fn test_from_env_ignores_ambient_service_discovery_variables() {
        // Kubernetes and Docker auto-inject service-discovery variables that
        // share the `TRANSPONDER_` prefix. They must be ignored, while a genuine
        // override in the same env set still applies.
        let config = from_test_env(&[
            ("TRANSPONDER_SERVICE_HOST", "10.0.0.1"),
            ("TRANSPONDER_SERVICE_PORT", "8080"),
            ("TRANSPONDER_PORT", "tcp://10.0.0.1:8080"),
            ("TRANSPONDER_PORT_8080_TCP", "tcp://10.0.0.1:8080"),
            ("TRANSPONDER_PORT_8080_TCP_PROTO", "tcp"),
            ("TRANSPONDER_PORT_8080_TCP_ADDR", "10.0.0.1"),
            ("TRANSPONDER_SERVER_PRVATE_KEY", "typo-should-be-ignored"),
            ("TRANSPONDER_SERVER_PRIVATE_KEY", "real-private-key"),
        ])
        .unwrap();

        // The genuine override still applies.
        assert_eq!(config.server.private_key.as_str(), "real-private-key");
        // Ambient variables did not bleed into unrelated config.
        assert_eq!(config.health.bind_address, "127.0.0.1:8080");
    }

    #[test]
    fn test_from_env_non_unicode_private_key_value_is_not_leaked() {
        use std::os::unix::ffi::OsStringExt;

        let secret_value = "SECRET-PRIVATE-KEY-DO-NOT-LOG";
        let mut secret_bytes = secret_value.as_bytes().to_vec();
        // Add a lone continuation byte so `OsString::into_string` fails after a
        // recognizable secret prefix.
        secret_bytes.push(0x80);
        let env_iter = vec![(
            OsString::from("TRANSPONDER_SERVER_PRIVATE_KEY"),
            OsString::from_vec(secret_bytes),
        )];

        let error = AppConfig::from_env_iter(env_iter).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("TRANSPONDER_SERVER_PRIVATE_KEY"));
        assert!(message.contains("non-Unicode data"));
        assert!(!message.contains(secret_value));
        assert!(!message.contains("SECRET-PRIVATE-KEY"));
        assert!(!message.contains(r"\x80"));
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
        assert_eq!(default_apns_environment(), ApnsEnvironment::Production);
    }

    #[test]
    fn test_apns_payload_mode_defaults_to_silent() {
        let config = from_test_env(&[]).unwrap();

        assert_eq!(config.apns.payload_mode, ApnsPayloadMode::Silent);
    }

    #[test]
    fn test_apns_payload_mode_parses_nse_prototype_alert() {
        let config_content = r#"
            [server]
            private_key = "test"

            [apns]
            payload_mode = "nse_prototype_alert"
        "#;

        let file = create_temp_config(config_content);
        let config = load_with_test_env(file.path(), &[]).unwrap();

        assert_eq!(config.apns.payload_mode, ApnsPayloadMode::NsePrototypeAlert);
    }

    #[test]
    fn test_apns_payload_mode_rejects_unknown_value() {
        let config_content = r#"
            [server]
            private_key = "test"

            [apns]
            payload_mode = "loud_plaintext"
        "#;

        let file = create_temp_config(config_content);
        let error = load_with_test_env(file.path(), &[]).unwrap_err();

        assert!(error.to_string().contains("payload_mode"), "{error}");
        assert!(error.to_string().contains("loud_plaintext"), "{error}");
    }

    #[test]
    fn test_apns_environment_display() {
        assert_eq!(ApnsEnvironment::Production.to_string(), "production");
        assert_eq!(ApnsEnvironment::Sandbox.to_string(), "sandbox");
    }

    #[test]
    fn test_apns_environment_parses_sandbox_from_file() {
        let config_content = r#"
            [server]
            private_key = "test"

            [apns]
            environment = "sandbox"
        "#;

        let file = create_temp_config(config_content);
        let config = load_with_test_env(file.path(), &[]).unwrap();

        assert_eq!(config.apns.environment, ApnsEnvironment::Sandbox);
        assert!(!config.apns.is_production());
        assert_eq!(config.apns.base_url(), "https://api.sandbox.push.apple.com");
    }

    #[test]
    fn test_apns_environment_parses_sandbox_from_env() {
        let config = from_test_env(&[("TRANSPONDER_APNS_ENVIRONMENT", "sandbox")]).unwrap();

        assert_eq!(config.apns.environment, ApnsEnvironment::Sandbox);
        assert!(!config.apns.is_production());
    }

    #[test]
    fn test_apns_environment_rejects_unknown_file_value() {
        for invalid in ["Production", "prod", "production "] {
            let config_content = format!(
                r#"
                [server]
                private_key = "test"

                [apns]
                environment = "{invalid}"
            "#
            );

            let file = create_temp_config(&config_content);
            let error = load_with_test_env(file.path(), &[]).unwrap_err();
            let message = error.to_string();

            assert!(message.contains("environment"), "{message}");
            assert!(message.contains(invalid), "{message}");
        }
    }

    #[test]
    fn test_apns_environment_rejects_unknown_env_value() {
        let error = from_test_env(&[("TRANSPONDER_APNS_ENVIRONMENT", "prod")]).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("environment"), "{message}");
        assert!(message.contains("prod"), "{message}");
    }

    #[test]
    fn test_health_config_defaults() {
        assert!(default_health_enabled());
        assert_eq!(default_health_bind_address(), "127.0.0.1:8080");
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
    fn test_glitchtip_config_debug_redacts_dsn() {
        let config = GlitchtipConfig {
            dsn: "https://public@glitch.example/1".to_string(),
            environment: "production".to_string(),
            traces_sample_rate: 0.0,
        };

        let debug_output = format!("{config:?}");

        assert!(!debug_output.contains("public@glitch.example"));
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn test_glitchtip_config_debug_shows_empty_dsn_as_disabled() {
        let config = GlitchtipConfig {
            dsn: String::new(),
            environment: "production".to_string(),
            traces_sample_rate: 0.0,
        };

        // An empty DSN is shown as empty (disabled), not "[REDACTED]", which would
        // misleadingly imply a secret is present.
        assert!(!format!("{config:?}").contains("[REDACTED]"));
    }

    #[test]
    fn test_glitchtip_defaults_disable_reporting() {
        let config = from_test_env(&[]).unwrap();

        assert_eq!(config.glitchtip.dsn, "");
        assert_eq!(config.glitchtip.environment, "production");
        assert_eq!(config.glitchtip.traces_sample_rate, 0.0);
    }

    #[test]
    fn test_glitchtip_env_overrides() {
        // Also exercises the string -> f32 coercion path: `traces_sample_rate`
        // is the only floating-point config field, so this locks it in.
        let config = from_test_env(&[
            ("TRANSPONDER_GLITCHTIP_DSN", "https://key@glitch.example/1"),
            ("TRANSPONDER_GLITCHTIP_ENVIRONMENT", "staging"),
            ("TRANSPONDER_GLITCHTIP_TRACES_SAMPLE_RATE", "0.25"),
        ])
        .unwrap();

        assert_eq!(config.glitchtip.dsn, "https://key@glitch.example/1");
        assert_eq!(config.glitchtip.environment, "staging");
        assert_eq!(config.glitchtip.traces_sample_rate, 0.25);
    }

    #[test]
    fn test_glitchtip_traces_sample_rate_above_one_rejected() {
        let error = from_test_env(&[("TRANSPONDER_GLITCHTIP_TRACES_SAMPLE_RATE", "1.5")])
            .expect_err("a sample rate above 1.0 should be rejected");

        assert!(
            error
                .to_string()
                .contains("glitchtip.traces_sample_rate must be between 0.0 and 1.0"),
            "{error}"
        );
    }

    #[test]
    fn test_glitchtip_traces_sample_rate_negative_rejected() {
        let error = from_test_env(&[("TRANSPONDER_GLITCHTIP_TRACES_SAMPLE_RATE", "-0.1")])
            .expect_err("a negative sample rate should be rejected");

        assert!(
            error
                .to_string()
                .contains("glitchtip.traces_sample_rate must be between 0.0 and 1.0"),
            "{error}"
        );
    }

    #[test]
    fn test_glitchtip_traces_sample_rate_nan_rejected() {
        // `RangeInclusive::contains` compares with `PartialOrd`, so NaN is not
        // contained and is rejected rather than silently accepted.
        let error = from_test_env(&[("TRANSPONDER_GLITCHTIP_TRACES_SAMPLE_RATE", "nan")])
            .expect_err("a NaN sample rate should be rejected");

        assert!(
            error
                .to_string()
                .contains("glitchtip.traces_sample_rate must be between 0.0 and 1.0"),
            "{error}"
        );
    }

    #[test]
    fn test_server_config_defaults() {
        assert_eq!(default_shutdown_timeout(), 10);
        assert_eq!(default_max_dedup_cache_size(), 100_000);
        assert_eq!(default_max_rate_limit_cache_size(), 100_000);
        assert_eq!(default_max_tokens_per_event(), DEFAULT_MAX_TOKENS_PER_EVENT);
        assert_eq!(default_rate_limit_per_minute(), 240);
        assert_eq!(default_rate_limit_per_hour(), 5000);
        assert_eq!(default_max_concurrent_event_processing(), 64);
        assert_eq!(default_global_unwrap_rate_limit_per_minute(), 600);
        assert_eq!(default_global_unwrap_rate_limit_per_hour(), 30_000);
    }

    #[test]
    fn test_apns_is_production_true() {
        let config = ApnsConfig {
            enabled: true,
            key_id: String::new(),
            team_id: String::new(),
            private_key_path: String::new(),
            environment: ApnsEnvironment::Production,
            bundle_id: String::new(),
            payload_mode: Default::default(),
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
            environment: ApnsEnvironment::Sandbox,
            bundle_id: String::new(),
            payload_mode: Default::default(),
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

        assert_eq!(config.server.private_key.as_str(), "test-key");
        assert!(config.apns.enabled);
        assert_eq!(config.apns.key_id, "MYKEY");
        assert_eq!(config.apns.environment, ApnsEnvironment::Production); // default
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
        assert_eq!(config.server.max_tokens_per_event, 100);
        assert_eq!(config.server.max_concurrent_event_processing, 64);
        assert_eq!(config.server.global_unwrap_rate_limit_per_minute, 600);
        assert_eq!(config.server.global_unwrap_rate_limit_per_hour, 30_000);
    }

    #[test]
    fn test_rate_limit_custom() {
        let config_content = r#"
            [server]
            private_key = "test"
            max_tokens_per_event = 25
            encrypted_token_rate_limit_per_minute = 100
            encrypted_token_rate_limit_per_hour = 2000
            device_token_rate_limit_per_minute = 50
            device_token_rate_limit_per_hour = 1000
            max_concurrent_event_processing = 32
            global_unwrap_rate_limit_per_minute = 300
            global_unwrap_rate_limit_per_hour = 15000
        "#;

        let file = create_temp_config(config_content);
        let config = load_with_test_env(file.path(), &[]).unwrap();

        assert_eq!(config.server.encrypted_token_rate_limit_per_minute, 100);
        assert_eq!(config.server.encrypted_token_rate_limit_per_hour, 2000);
        assert_eq!(config.server.device_token_rate_limit_per_minute, 50);
        assert_eq!(config.server.device_token_rate_limit_per_hour, 1000);
        assert_eq!(config.server.max_tokens_per_event, 25);
        assert_eq!(config.server.max_concurrent_event_processing, 32);
        assert_eq!(config.server.global_unwrap_rate_limit_per_minute, 300);
        assert_eq!(config.server.global_unwrap_rate_limit_per_hour, 15_000);
    }

    #[test]
    fn test_global_unwrap_admission_env_overrides() {
        let config = from_test_env(&[
            ("TRANSPONDER_SERVER_MAX_CONCURRENT_EVENT_PROCESSING", "16"),
            (
                "TRANSPONDER_SERVER_GLOBAL_UNWRAP_RATE_LIMIT_PER_MINUTE",
                "120",
            ),
            (
                "TRANSPONDER_SERVER_GLOBAL_UNWRAP_RATE_LIMIT_PER_HOUR",
                "7200",
            ),
        ])
        .unwrap();

        assert_eq!(config.server.max_concurrent_event_processing, 16);
        assert_eq!(config.server.global_unwrap_rate_limit_per_minute, 120);
        assert_eq!(config.server.global_unwrap_rate_limit_per_hour, 7200);
    }

    /// Config fields that must reject a `0` value at load time, paired with the
    /// TOML key used to set them.
    const ZERO_REJECTED_FIELDS: &[&str] = &[
        "encrypted_token_rate_limit_per_minute",
        "encrypted_token_rate_limit_per_hour",
        "device_token_rate_limit_per_minute",
        "device_token_rate_limit_per_hour",
        "global_unwrap_rate_limit_per_minute",
        "global_unwrap_rate_limit_per_hour",
        "max_rate_limit_cache_size",
    ];

    #[test]
    fn test_zero_rate_limit_count_fields_rejected_from_file() {
        for field in ZERO_REJECTED_FIELDS {
            let config_content = format!(
                r#"
                [server]
                private_key = "test"
                {field} = 0
            "#
            );

            let file = create_temp_config(&config_content);
            let error = load_with_test_env(file.path(), &[]).unwrap_err();
            let message = error.to_string();

            assert!(
                message.contains(&format!("server.{field}")),
                "expected error to name `server.{field}`, got: {message}"
            );
            assert!(
                message.contains("must be greater than 0"),
                "expected `must be greater than 0` for `{field}`, got: {message}"
            );
        }
    }

    #[test]
    fn test_zero_rate_limit_count_fields_rejected_from_env() {
        for field in ZERO_REJECTED_FIELDS {
            let env_key = format!("TRANSPONDER_SERVER_{}", field.to_ascii_uppercase());
            let error = from_test_env(&[(env_key.as_str(), "0")]).unwrap_err();
            let message = error.to_string();

            assert!(
                message.contains(&format!("server.{field}")),
                "expected error to name `server.{field}`, got: {message}"
            );
            assert!(
                message.contains("must be greater than 0"),
                "expected `must be greater than 0` for `{field}`, got: {message}"
            );
        }
    }

    #[test]
    fn test_nonzero_rate_limit_count_fields_accepted() {
        // Defaults (no overrides) plus a minimal `1` for every guarded field
        // must both pass validation, so valid custom values keep working.
        assert!(from_test_env(&[]).is_ok());

        let config = from_test_env(&[
            (
                "TRANSPONDER_SERVER_ENCRYPTED_TOKEN_RATE_LIMIT_PER_MINUTE",
                "1",
            ),
            (
                "TRANSPONDER_SERVER_ENCRYPTED_TOKEN_RATE_LIMIT_PER_HOUR",
                "1",
            ),
            ("TRANSPONDER_SERVER_DEVICE_TOKEN_RATE_LIMIT_PER_MINUTE", "1"),
            ("TRANSPONDER_SERVER_DEVICE_TOKEN_RATE_LIMIT_PER_HOUR", "1"),
            (
                "TRANSPONDER_SERVER_GLOBAL_UNWRAP_RATE_LIMIT_PER_MINUTE",
                "1",
            ),
            ("TRANSPONDER_SERVER_GLOBAL_UNWRAP_RATE_LIMIT_PER_HOUR", "1"),
            ("TRANSPONDER_SERVER_MAX_RATE_LIMIT_CACHE_SIZE", "1"),
        ])
        .unwrap();

        assert_eq!(config.server.encrypted_token_rate_limit_per_minute, 1);
        assert_eq!(config.server.encrypted_token_rate_limit_per_hour, 1);
        assert_eq!(config.server.device_token_rate_limit_per_minute, 1);
        assert_eq!(config.server.device_token_rate_limit_per_hour, 1);
        assert_eq!(config.server.global_unwrap_rate_limit_per_minute, 1);
        assert_eq!(config.server.global_unwrap_rate_limit_per_hour, 1);
        assert_eq!(config.server.max_rate_limit_cache_size, 1);
    }

    #[test]
    fn test_zero_shutdown_timeout_rejected_from_file() {
        let config_content = r#"
            [server]
            private_key = "test"
            shutdown_timeout_secs = 0
        "#;

        let file = create_temp_config(config_content);
        let error = load_with_test_env(file.path(), &[]).unwrap_err();
        let message = error.to_string();

        assert!(
            message.contains("server.shutdown_timeout_secs"),
            "expected error to name `server.shutdown_timeout_secs`, got: {message}"
        );
        assert!(
            message.contains("must be greater than 0"),
            "expected `must be greater than 0`, got: {message}"
        );
    }

    #[test]
    fn test_zero_shutdown_timeout_rejected_from_env() {
        let error =
            from_test_env(&[("TRANSPONDER_SERVER_SHUTDOWN_TIMEOUT_SECS", "0")]).unwrap_err();
        let message = error.to_string();

        assert!(
            message.contains("server.shutdown_timeout_secs"),
            "expected error to name `server.shutdown_timeout_secs`, got: {message}"
        );
        assert!(
            message.contains("must be greater than 0"),
            "expected `must be greater than 0`, got: {message}"
        );
    }

    #[test]
    fn test_minimal_shutdown_timeout_accepted() {
        let config = from_test_env(&[("TRANSPONDER_SERVER_SHUTDOWN_TIMEOUT_SECS", "1")]).unwrap();

        assert_eq!(config.server.shutdown_timeout_secs, 1);
    }

    #[test]
    fn test_zero_connection_timeout_rejected() {
        let error =
            from_test_env(&[("TRANSPONDER_RELAYS_CONNECTION_TIMEOUT_SECS", "0")]).unwrap_err();
        let message = error.to_string();

        assert!(
            message.contains("relays.connection_timeout_secs"),
            "expected error to name `relays.connection_timeout_secs`, got: {message}"
        );
        assert!(
            message.contains("must be greater than 0"),
            "expected `must be greater than 0`, got: {message}"
        );
    }

    #[test]
    fn test_zero_reconnect_interval_rejected() {
        let error =
            from_test_env(&[("TRANSPONDER_RELAYS_RECONNECT_INTERVAL_SECS", "0")]).unwrap_err();
        let message = error.to_string();

        assert!(
            message.contains("relays.reconnect_interval_secs"),
            "expected error to name `relays.reconnect_interval_secs`, got: {message}"
        );
        assert!(
            message.contains("must be greater than 0"),
            "expected `must be greater than 0`, got: {message}"
        );
    }

    #[test]
    fn test_oversized_connection_timeout_rejected() {
        let over = (MAX_RELAY_DURATION_SECS + 1).to_string();
        let error = from_test_env(&[("TRANSPONDER_RELAYS_CONNECTION_TIMEOUT_SECS", over.as_str())])
            .unwrap_err();
        let message = error.to_string();

        assert!(
            message.contains("relays.connection_timeout_secs"),
            "expected error to name `relays.connection_timeout_secs`, got: {message}"
        );
        assert!(
            message.contains(&format!("at most {MAX_RELAY_DURATION_SECS}")),
            "expected `at most {MAX_RELAY_DURATION_SECS}`, got: {message}"
        );
    }

    #[test]
    fn test_unbounded_connection_timeout_rejected() {
        // The degenerate `u64::MAX` from the issue must be rejected rather than
        // hanging startup effectively forever when relays are unreachable.
        let error = from_test_env(&[(
            "TRANSPONDER_RELAYS_CONNECTION_TIMEOUT_SECS",
            "18446744073709551615",
        )])
        .unwrap_err();

        assert!(
            error.to_string().contains("relays.connection_timeout_secs"),
            "{error}"
        );
    }

    #[test]
    fn test_oversized_reconnect_interval_rejected() {
        let over = (MAX_RELAY_DURATION_SECS + 1).to_string();
        let error = from_test_env(&[("TRANSPONDER_RELAYS_RECONNECT_INTERVAL_SECS", over.as_str())])
            .unwrap_err();
        let message = error.to_string();

        assert!(
            message.contains("relays.reconnect_interval_secs"),
            "expected error to name `relays.reconnect_interval_secs`, got: {message}"
        );
        assert!(
            message.contains(&format!("at most {MAX_RELAY_DURATION_SECS}")),
            "expected `at most {MAX_RELAY_DURATION_SECS}`, got: {message}"
        );
    }

    #[test]
    fn test_relay_duration_upper_bound_accepted() {
        // The exact cap must pass so operators on slow networks or Tor can use
        // the full budget without tripping validation.
        let cap = MAX_RELAY_DURATION_SECS.to_string();
        let config = from_test_env(&[
            ("TRANSPONDER_RELAYS_CONNECTION_TIMEOUT_SECS", cap.as_str()),
            ("TRANSPONDER_RELAYS_RECONNECT_INTERVAL_SECS", cap.as_str()),
        ])
        .unwrap();

        assert_eq!(
            config.relays.connection_timeout_secs,
            MAX_RELAY_DURATION_SECS
        );
        assert_eq!(
            config.relays.reconnect_interval_secs,
            MAX_RELAY_DURATION_SECS
        );
    }

    #[test]
    fn test_oversized_max_concurrent_event_processing_rejected_from_env() {
        let over = (MAX_CONCURRENT_EVENT_PROCESSING + 1).to_string();
        let error = from_test_env(&[(
            "TRANSPONDER_SERVER_MAX_CONCURRENT_EVENT_PROCESSING",
            over.as_str(),
        )])
        .unwrap_err();
        let message = error.to_string();

        assert!(
            message.contains("server.max_concurrent_event_processing"),
            "expected error to name `server.max_concurrent_event_processing`, got: {message}"
        );
        assert!(
            message.contains(&format!("at most {MAX_CONCURRENT_EVENT_PROCESSING}")),
            "expected `at most {MAX_CONCURRENT_EVENT_PROCESSING}`, got: {message}"
        );
    }

    #[test]
    fn test_unbounded_max_concurrent_event_processing_rejected() {
        // The degenerate `u64::MAX` from the issue must be rejected rather than
        // panicking in `Semaphore::new` at startup.
        let error = from_test_env(&[(
            "TRANSPONDER_SERVER_MAX_CONCURRENT_EVENT_PROCESSING",
            "18446744073709551615",
        )])
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("server.max_concurrent_event_processing"),
            "{error}"
        );
    }

    #[test]
    fn test_max_concurrent_event_processing_upper_bound_accepted() {
        let cap = MAX_CONCURRENT_EVENT_PROCESSING.to_string();
        let config = from_test_env(&[(
            "TRANSPONDER_SERVER_MAX_CONCURRENT_EVENT_PROCESSING",
            cap.as_str(),
        )])
        .unwrap();

        assert_eq!(
            config.server.max_concurrent_event_processing,
            MAX_CONCURRENT_EVENT_PROCESSING
        );
    }
}

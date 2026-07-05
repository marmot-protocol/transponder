//! Nostr relay client implementation.
//!
//! Handles connections to ClearNet relays, optional Tor relays, subscription
//! management, and automatic reconnection.

use std::collections::{BTreeMap, BTreeSet};
use std::future;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use nostr_sdk::prelude::*;
use tokio::sync::{RwLock, broadcast};
use tracing::{debug, error, info, warn};

use crate::config::RelayConfig;
use crate::error::{Error, Result};
use crate::metrics::Metrics;

// Type alias to avoid confusion with our RelayStatus
use nostr_sdk::RelayStatus as NostrRelayStatus;

/// Maximum NIP-59 timestamp randomization window for gift wraps.
///
/// NIP-59 gift wraps intentionally randomize `created_at` into the past to
/// reduce timing correlation. Relay subscriptions must look back by the same
/// window or relays will filter out compliant gift wraps before delivery.
const NIP59_TIMESTAMP_TWEAK_WINDOW_SECS: u64 = nip59::RANGE_RANDOM_TIMESTAMP_TWEAK.end;
const INBOX_RELAY_FETCH_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(feature = "tor")]
const TOR_FEATURE_ENABLED: bool = true;
#[cfg(not(feature = "tor"))]
const TOR_FEATURE_ENABLED: bool = false;
const RELAY_MONITOR_CHANNEL_SIZE: usize = 64;

#[derive(Debug, Clone)]
struct ReconnectAttemptLimiter {
    max_reconnect_attempts: u32,
    attempts_since_connection: Arc<Mutex<BTreeMap<RelayUrl, u32>>>,
}

impl ReconnectAttemptLimiter {
    fn new(max_reconnect_attempts: u32) -> Self {
        Self {
            max_reconnect_attempts,
            attempts_since_connection: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    fn attempts_since_connection(&self) -> MutexGuard<'_, BTreeMap<RelayUrl, u32>> {
        self.attempts_since_connection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn admit_relay_connection(&self, relay_url: &RelayUrl) -> AdmitStatus {
        let mut attempts_since_connection = self.attempts_since_connection();
        let attempts = attempts_since_connection
            .entry(relay_url.clone())
            .or_default();

        if *attempts > self.max_reconnect_attempts {
            return AdmitStatus::rejected(format!(
                "relays.max_reconnect_attempts ({}) exceeded",
                self.max_reconnect_attempts
            ));
        }

        *attempts = attempts.saturating_add(1);
        AdmitStatus::success()
    }

    fn reset(&self, relay_url: &RelayUrl) {
        self.attempts_since_connection()
            .insert(relay_url.clone(), 0);
    }

    fn remove(&self, relay_url: &RelayUrl) {
        self.attempts_since_connection().remove(relay_url);
    }
}

impl AdmitPolicy for ReconnectAttemptLimiter {
    fn admit_connection<'a>(
        &'a self,
        relay_url: &'a RelayUrl,
    ) -> BoxedFuture<'a, std::result::Result<AdmitStatus, PolicyError>> {
        Box::pin(future::ready(Ok(self.admit_relay_connection(relay_url))))
    }
}

fn spawn_reconnect_attempt_monitor(monitor: Monitor, limiter: ReconnectAttemptLimiter) {
    let mut notifications = monitor.subscribe();
    std::mem::drop(tokio::spawn(async move {
        loop {
            match notifications.recv().await {
                Ok(MonitorNotification::StatusChanged { relay_url, status }) => match status {
                    NostrRelayStatus::Connected => limiter.reset(&relay_url),
                    NostrRelayStatus::Terminated | NostrRelayStatus::Banned => {
                        limiter.remove(&relay_url);
                    }
                    NostrRelayStatus::Initialized
                    | NostrRelayStatus::Pending
                    | NostrRelayStatus::Connecting
                    | NostrRelayStatus::Disconnected
                    | NostrRelayStatus::Sleeping => {}
                },
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(
                        skipped,
                        "Relay reconnect attempt monitor lagged; attempt counters may reset late"
                    );
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    }));
}

fn relay_options_for_config(config: &RelayConfig, relay_url: &str) -> RelayOptions {
    #[cfg(not(feature = "tor"))]
    let _ = relay_url;

    let opts =
        RelayOptions::default().retry_interval(Duration::from_secs(config.reconnect_interval_secs));

    #[cfg(feature = "tor")]
    {
        if relay_url.contains(".onion") {
            return opts.connection_mode(ConnectionMode::tor());
        }
    }

    opts
}

/// Status of relay connections.
#[derive(Debug, Clone, Default)]
pub struct RelayStatus {
    /// Number of connected ClearNet relays.
    pub clearnet_connected: usize,
    /// Number of connected Tor relays.
    pub tor_connected: usize,
    /// Total number of configured relays.
    pub total_configured: usize,
}

/// Nostr relay client with support for ClearNet and optional Tor relays.
pub struct RelayClient {
    client: Client,
    config: RelayConfig,
    status: Arc<RwLock<RelayStatus>>,
    metrics: Option<Metrics>,
}

impl RelayClient {
    /// Create a new relay client with the given keys and configuration.
    #[allow(dead_code)]
    pub async fn new(keys: Keys, config: RelayConfig) -> Result<Self> {
        Self::with_metrics(keys, config, None).await
    }

    /// Create a new relay client with metrics.
    pub async fn with_metrics(
        keys: Keys,
        config: RelayConfig,
        metrics: Option<Metrics>,
    ) -> Result<Self> {
        validate_relay_config(&config)?;

        let reconnect_attempt_limiter = ReconnectAttemptLimiter::new(config.max_reconnect_attempts);
        let relay_monitor = Monitor::new(RELAY_MONITOR_CHANNEL_SIZE);
        spawn_reconnect_attempt_monitor(relay_monitor.clone(), reconnect_attempt_limiter.clone());

        let client = Client::builder()
            .signer(keys)
            .admit_policy(reconnect_attempt_limiter)
            .monitor(relay_monitor)
            .build();

        let total = config.clearnet.len() + config.onion.len();

        if let Some(metrics) = &metrics {
            metrics.set_relay_counts(config.clearnet.len(), config.onion.len());
            metrics.set_relay_subscription_lookback(NIP59_TIMESTAMP_TWEAK_WINDOW_SECS);
        }

        Ok(Self {
            client,
            config,
            status: Arc::new(RwLock::new(RelayStatus {
                clearnet_connected: 0,
                tor_connected: 0,
                total_configured: total,
            })),
            metrics,
        })
    }

    /// Connect to all configured relays.
    ///
    /// This method initiates connections to all configured relays and waits up to
    /// `connection_timeout_secs` for at least one relay to establish a connection.
    /// The timeout allows for network latency and relay responsiveness during startup.
    pub async fn connect(&self) -> Result<()> {
        // Add ClearNet relays
        for url in &self.config.clearnet {
            match self.add_configured_relay(url).await {
                Ok(_) => {
                    debug!(relay = %url, "Added ClearNet relay");
                }
                Err(e) => {
                    warn!(relay = %url, error = %e, "Failed to add ClearNet relay");
                }
            }
        }

        // Add Tor relays (nostr-sdk handles Tor via arti automatically)
        for url in &self.config.onion {
            match self.add_configured_relay(url).await {
                Ok(_) => {
                    debug!(relay = %url, "Added Tor relay");
                }
                Err(e) => {
                    warn!(relay = %url, error = %e, "Failed to add Tor relay");
                }
            }
        }

        info!(
            clearnet = self.config.clearnet.len(),
            tor = self.config.onion.len(),
            "Configured relay subscriptions"
        );

        // Connect to all added relays (nostr-sdk connects in the background)
        self.client.connect().await;

        // Wait for at least one relay to connect with timeout
        let timeout = Duration::from_secs(self.config.connection_timeout_secs);
        let poll_interval = Duration::from_millis(100);
        let start = std::time::Instant::now();

        info!(
            timeout_secs = self.config.connection_timeout_secs,
            "Waiting for relay connections"
        );

        loop {
            self.update_status().await;
            let status = self.status.read().await;
            let connected = status.clearnet_connected + status.tor_connected;

            if connected > 0 {
                info!(
                    clearnet = status.clearnet_connected,
                    tor = status.tor_connected,
                    total = status.total_configured,
                    elapsed_ms = start.elapsed().as_millis() as u64,
                    "Connected to relays"
                );

                warn_on_degraded_relay_classes(&self.config, &status);

                return Ok(());
            }

            if start.elapsed() >= timeout {
                warn!(
                    timeout_secs = self.config.connection_timeout_secs,
                    total_configured = status.total_configured,
                    "Timeout waiting for relay connections"
                );
                return Err(Error::Nostr(format!(
                    "Failed to connect to any relay within {} seconds",
                    self.config.connection_timeout_secs
                )));
            }

            drop(status); // Release lock before sleeping
            tokio::time::sleep(poll_interval).await;
        }
    }

    /// Subscribe to gift-wrapped events for the server's public key.
    pub async fn subscribe(&self, server_pubkey: PublicKey) -> Result<()> {
        let since = Timestamp::from_secs(
            Timestamp::now()
                .as_secs()
                .saturating_sub(NIP59_TIMESTAMP_TWEAK_WINDOW_SECS),
        );

        // Create filter for kind 1059 (gift wrap) events addressed to us
        let filter = Filter::new()
            .kind(Kind::GiftWrap)
            .pubkey(server_pubkey)
            .since(since);

        debug!(
            pubkey = %server_pubkey,
            lookback_secs = NIP59_TIMESTAMP_TWEAK_WINDOW_SECS,
            "Subscribing to gift wrap events"
        );

        self.client
            .subscribe(filter, None)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to subscribe: {e}")))?;

        info!("Subscribed to gift wrap events");
        Ok(())
    }

    /// Get the event stream for handling incoming events.
    pub fn notifications(&self) -> broadcast::Receiver<RelayPoolNotification> {
        self.client.notifications()
    }

    /// Update the connection status.
    async fn update_status(&self) {
        let relays = self.client.relays().await;

        let mut clearnet = 0;
        let mut tor = 0;

        for (url, relay) in &relays {
            if relay.status() == NostrRelayStatus::Connected {
                if url.as_str().contains(".onion") {
                    tor += 1;
                } else {
                    clearnet += 1;
                }
            }
        }

        if let Some(metrics) = &self.metrics {
            metrics.set_relays_connected("clearnet", clearnet);
            metrics.set_relays_connected("onion", tor);
        }

        let mut status = self.status.write().await;
        status.clearnet_connected = clearnet;
        status.tor_connected = tor;
    }

    /// Get the current relay connection status.
    pub async fn get_status(&self) -> RelayStatus {
        self.update_status().await;
        self.status.read().await.clone()
    }

    /// Check if at least one relay is connected.
    pub async fn is_connected(&self) -> bool {
        let status = self.get_status().await;
        status.clearnet_connected + status.tor_connected > 0
    }

    /// Disconnect from all relays.
    pub async fn disconnect(&self) -> Result<()> {
        info!("Disconnecting from all relays");
        self.client.disconnect().await;
        Ok(())
    }

    async fn add_configured_relay(&self, url: &str) -> std::result::Result<bool, String> {
        self.client
            .pool()
            .add_relay(url, relay_options_for_config(&self.config, url))
            .await
            .map_err(|e| e.to_string())
    }

    /// Get the underlying nostr-sdk client.
    #[allow(dead_code)]
    pub fn inner(&self) -> &Client {
        &self.client
    }

    /// Publish a kind 10050 event to advertise inbox relays.
    ///
    /// Publication is best-effort and non-fatal: a failure to reach any relay
    /// (either an outright send error or a send whose `success` set is empty) is
    /// logged and signaled via the `transponder_inbox_relay_publish_failed_total`
    /// metric, but this method still returns `Ok(())`. Callers therefore must not
    /// treat `Ok(())` as proof that the inbox relay list was advertised; rely on
    /// the metric/logs for that signal.
    pub async fn publish_inbox_relays(&self) -> Result<()> {
        let relay_urls = self.configured_inbox_relays();

        if relay_urls.is_empty() {
            warn!("No relays configured for kind 10050 publication");
            return Ok(());
        }

        let event_is_current = match self.inbox_relay_event_is_current(&relay_urls).await {
            Ok(current) => current,
            Err(e) => {
                warn!(
                    error = %e,
                    "Skipping kind 10050 publish; could not verify existing inbox relay list"
                );
                return Ok(());
            }
        };

        if event_is_current {
            info!("Skipping kind 10050 publish; inbox relay list unchanged");
            return Ok(());
        }

        let relay_tags: Vec<Tag> = relay_urls
            .iter()
            .map(|url| Tag::custom(TagKind::Relay, [url.as_str()]))
            .collect();
        let builder = EventBuilder::new(Kind::Custom(10050), "").tags(relay_tags);

        match self.client.send_event_builder(builder).await {
            Ok(output) if !output.success.is_empty() => {
                debug!(event_id = %output.id(), "Published kind 10050 inbox relay list");
                info!("Published kind 10050 inbox relay list");
            }
            Ok(output) => {
                error!(
                    relays_failed = output.failed.len(),
                    "Failed to publish kind 10050 event to any relay"
                );
                self.record_inbox_relay_publish_failed();
            }
            Err(e) => {
                error!(error = %e, "Failed to publish kind 10050 event");
                self.record_inbox_relay_publish_failed();
            }
        }

        Ok(())
    }

    fn record_inbox_relay_publish_failed(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.record_inbox_relay_publish_failed();
        }
    }

    fn configured_inbox_relays(&self) -> BTreeSet<String> {
        self.config
            .clearnet
            .iter()
            .chain(self.config.onion.iter())
            .cloned()
            .collect()
    }

    async fn inbox_relay_event_is_current(&self, relay_urls: &BTreeSet<String>) -> Result<bool> {
        let public_key = self
            .client
            .public_key()
            .await
            .map_err(|e| Error::Nostr(format!("Failed to get signer public key: {e}")))?;

        let filter = Filter::new()
            .kind(Kind::Custom(10050))
            .author(public_key)
            .limit(1);
        let events = self
            .client
            .fetch_events(filter, INBOX_RELAY_FETCH_TIMEOUT)
            .await
            .map_err(|e| Error::Nostr(format!("Failed to fetch existing kind 10050 event: {e}")))?;

        Ok(events
            .first()
            .is_some_and(|event| inbox_relay_tags(event) == *relay_urls))
    }
}

fn inbox_relay_tags(event: &Event) -> BTreeSet<String> {
    event
        .tags
        .as_slice()
        .iter()
        .filter(|tag| tag.kind() == TagKind::Relay)
        .filter_map(|tag| tag.content().map(str::to_owned))
        .collect()
}

fn warn_on_degraded_relay_classes(config: &RelayConfig, status: &RelayStatus) {
    let (clearnet_degraded, tor_degraded) = degraded_relay_classes(config, status);

    // A configured relay class with zero live connections silently degrades
    // the deployment's guarantees: losing all Tor relays weakens the privacy
    // property, losing all ClearNet relays weakens reachability. Warn
    // prominently for each such class.
    if clearnet_degraded {
        warn!(
            configured = config.clearnet.len(),
            "No ClearNet relays connected at startup; configured ClearNet relays are all down"
        );
    }

    if tor_degraded {
        warn!(
            configured = config.onion.len(),
            "No Tor relays connected at startup; privacy is degraded because configured Tor relays are all down"
        );
    }
}

fn degraded_relay_classes(config: &RelayConfig, status: &RelayStatus) -> (bool, bool) {
    (
        degraded_relay_class(config.clearnet.len(), status.clearnet_connected),
        degraded_relay_class(config.onion.len(), status.tor_connected),
    )
}

/// Returns `true` when a relay class is configured but has zero live
/// connections, signalling a degraded startup for that class.
fn degraded_relay_class(configured: usize, connected: usize) -> bool {
    configured > 0 && connected == 0
}

fn validate_relay_config(config: &RelayConfig) -> Result<()> {
    for url in &config.clearnet {
        if clearnet_relay_uses_tls(url) {
            continue;
        }

        if clearnet_relay_uses_plaintext_ws(url) {
            if config.allow_unencrypted_clearnet_relays {
                warn!(
                    relay = %url,
                    "Unencrypted ClearNet relay URL explicitly allowed; use only for local development"
                );
                continue;
            }

            return Err(Error::Nostr(format!(
                "ClearNet relay '{url}' must use wss://; set relays.allow_unencrypted_clearnet_relays=true only for local development"
            )));
        }

        return Err(Error::Nostr(format!(
            "ClearNet relay '{url}' must use wss://"
        )));
    }

    if !TOR_FEATURE_ENABLED && !config.onion.is_empty() {
        return Err(Error::Nostr(
            "Onion relays are configured, but this build does not include Tor support. Rebuild with `--features tor`.".to_string(),
        ));
    }

    Ok(())
}

fn clearnet_relay_uses_tls(url: &str) -> bool {
    clearnet_relay_scheme(url).is_some_and(|scheme| scheme.eq_ignore_ascii_case("wss"))
}

fn clearnet_relay_uses_plaintext_ws(url: &str) -> bool {
    clearnet_relay_scheme(url).is_some_and(|scheme| scheme.eq_ignore_ascii_case("ws"))
}

fn clearnet_relay_scheme(url: &str) -> Option<&str> {
    url.split_once("://").map(|(scheme, _)| scheme)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn receive_gift_wrap(
        notifications: &mut broadcast::Receiver<RelayPoolNotification>,
        timeout: std::time::Duration,
    ) -> Option<Box<Event>> {
        tokio::time::timeout(timeout, async {
            loop {
                match notifications.recv().await {
                    Ok(RelayPoolNotification::Event { event, .. }) => {
                        if event.kind == Kind::GiftWrap {
                            return Some(event);
                        }
                    }
                    Ok(_) => continue,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        })
        .await
        .ok()
        .flatten()
    }

    #[test]
    fn test_degraded_relay_class_flags_configured_class_with_no_connections() {
        // A configured class with zero live connections is degraded.
        assert!(degraded_relay_class(2, 0));
        // A configured class with at least one connection is healthy.
        assert!(!degraded_relay_class(2, 1));
        // An unconfigured class is never considered degraded.
        assert!(!degraded_relay_class(0, 0));
    }

    #[test]
    fn test_degraded_relay_classes_and_startup_warnings_cover_each_configured_class() {
        let config = RelayConfig {
            clearnet: vec!["wss://relay.example.com".to_string()],
            allow_unencrypted_clearnet_relays: false,
            onion: vec!["wss://example.onion".to_string()],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 5,
        };

        for (status, expected) in [
            (
                RelayStatus {
                    clearnet_connected: 0,
                    tor_connected: 1,
                    total_configured: 2,
                },
                (true, false),
            ),
            (
                RelayStatus {
                    clearnet_connected: 1,
                    tor_connected: 0,
                    total_configured: 2,
                },
                (false, true),
            ),
            (
                RelayStatus {
                    clearnet_connected: 1,
                    tor_connected: 1,
                    total_configured: 2,
                },
                (false, false),
            ),
        ] {
            assert_eq!(degraded_relay_classes(&config, &status), expected);
            warn_on_degraded_relay_classes(&config, &status);
        }
    }

    #[test]
    fn test_relay_status_default() {
        let status = RelayStatus::default();
        assert_eq!(status.clearnet_connected, 0);
        assert_eq!(status.tor_connected, 0);
        assert_eq!(status.total_configured, 0);
    }

    /// Helper to create a test RelayConfig with default settings
    fn test_relay_config(clearnet: Vec<String>) -> RelayConfig {
        RelayConfig {
            clearnet,
            allow_unencrypted_clearnet_relays: true,
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 5, // Short timeout for tests
        }
    }

    #[test]
    fn test_relay_options_use_configured_reconnect_interval() {
        let mut config = test_relay_config(vec![]);
        config.reconnect_interval_secs = 17;

        let opts = relay_options_for_config(&config, "ws://127.0.0.1:12345");
        let debug = format!("{opts:?}");

        assert!(
            debug.contains("retry_interval: 17s"),
            "relay options must use configured retry interval, got: {debug}"
        );
    }

    #[test]
    fn test_reconnect_attempt_limiter_allows_initial_attempt_plus_configured_retries() {
        let limiter = ReconnectAttemptLimiter::new(1);
        let relay_url = RelayUrl::parse("wss://relay.example.com").unwrap();

        assert_eq!(
            limiter.admit_relay_connection(&relay_url),
            AdmitStatus::Success
        );
        assert_eq!(
            limiter.admit_relay_connection(&relay_url),
            AdmitStatus::Success
        );
        assert!(matches!(
            limiter.admit_relay_connection(&relay_url),
            AdmitStatus::Rejected { .. }
        ));

        limiter.reset(&relay_url);
        assert_eq!(
            limiter.admit_relay_connection(&relay_url),
            AdmitStatus::Success,
            "successful relay connection should reset the reconnect-attempt counter"
        );
    }

    #[tokio::test]
    async fn test_connect_adds_relays_with_configured_options() {
        let relay_url = "ws://127.0.0.1:12345";
        let mut config = test_relay_config(vec![relay_url.to_string()]);
        config.reconnect_interval_secs = 23;

        let client = RelayClient::new(Keys::generate(), config).await.unwrap();
        client.add_configured_relay(relay_url).await.unwrap();

        let relay = client.client.relay(relay_url).await.unwrap();
        let debug = format!("{:?}", relay.opts());
        assert!(
            debug.contains("retry_interval: 23s"),
            "configured relays must inherit reconnect_interval_secs, got: {debug}"
        );
    }

    #[tokio::test]
    async fn test_relay_client_rejects_unencrypted_clearnet_relays() {
        let keys = Keys::generate();
        let config = RelayConfig {
            clearnet: vec!["ws://relay.example.com".to_string()],
            allow_unencrypted_clearnet_relays: false,
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 5,
        };

        let result = RelayClient::new(keys, config).await;

        assert!(result.is_err());
        let err = result
            .err()
            .expect("ws:// clearnet relay should be rejected");
        assert!(err.to_string().contains("must use wss://"));
    }

    #[tokio::test]
    async fn test_relay_client_allows_unencrypted_clearnet_relays_when_enabled() {
        let keys = Keys::generate();
        let config = test_relay_config(vec!["ws://127.0.0.1:12345".to_string()]);

        let result = RelayClient::new(keys, config).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_relay_client_rejects_malformed_clearnet_relay_even_when_unencrypted_enabled() {
        let keys = Keys::generate();
        let config = test_relay_config(vec!["relay.example.com".to_string()]);

        let result = RelayClient::new(keys, config).await;

        assert!(result.is_err());
        let err = result
            .err()
            .expect("malformed clearnet relay should be rejected");
        assert!(err.to_string().contains("must use wss://"));
    }

    #[tokio::test]
    async fn test_relay_client_connects_to_mock_relay() {
        use nostr_relay_builder::MockRelay;
        use std::time::Duration;

        // Start a mock relay
        let mock = MockRelay::run().await.unwrap();
        let relay_url = mock.url().await;

        // Create relay client with the mock relay URL
        let keys = Keys::generate();
        let config = test_relay_config(vec![relay_url.to_string()]);

        let client = RelayClient::new(keys, config).await.unwrap();

        // Add relays (but don't call our connect() which checks status immediately)
        client.client.add_relay(&relay_url).await.unwrap();
        client.client.connect().await;

        // Wait for connection to establish
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify we're connected
        let status = client.get_status().await;
        assert_eq!(status.clearnet_connected, 1);
        assert_eq!(status.tor_connected, 0);
        assert!(client.is_connected().await);

        // Disconnect
        client.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn test_relay_client_subscribe_to_gift_wrap() {
        use nostr_relay_builder::MockRelay;
        use std::time::Duration;

        // Start a mock relay
        let mock = MockRelay::run().await.unwrap();
        let relay_url = mock.url().await;

        // Create relay client
        let keys = Keys::generate();
        let server_pubkey = keys.public_key();
        let config = test_relay_config(vec![relay_url.to_string()]);

        let client = RelayClient::new(keys, config).await.unwrap();

        // Connect directly through the inner client
        client.client.add_relay(&relay_url).await.unwrap();
        client.client.connect().await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Subscribe to gift wrap events - should succeed
        let result = client.subscribe(server_pubkey).await;
        assert!(result.is_ok());

        client.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn test_relay_client_receives_nip59_backdated_gift_wraps() {
        use nostr_relay_builder::MockRelay;
        use std::time::Duration;

        let mock = MockRelay::run().await.unwrap();
        let relay_url = mock.url().await;

        let server_keys = Keys::generate();
        let server_pubkey = server_keys.public_key();
        let config = test_relay_config(vec![relay_url.to_string()]);

        let receiver = RelayClient::new(server_keys, config).await.unwrap();
        receiver.client.add_relay(&relay_url).await.unwrap();
        receiver.client.connect().await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        receiver.subscribe(server_pubkey).await.unwrap();
        let mut notifications = receiver.notifications();

        let sender_keys = Keys::generate();
        let sender = Client::builder().signer(sender_keys.clone()).build();
        sender.add_relay(&relay_url).await.unwrap();
        sender.connect().await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let backdated = Timestamp::from_secs(
            Timestamp::now()
                .as_secs()
                .saturating_sub(NIP59_TIMESTAMP_TWEAK_WINDOW_SECS),
        );
        let gift_wrap = EventBuilder::new(Kind::GiftWrap, "ignored")
            .tags([Tag::public_key(server_pubkey)])
            .custom_created_at(backdated)
            .sign_with_keys(&sender_keys)
            .unwrap();

        sender.send_event(&gift_wrap).await.unwrap();

        let received = receive_gift_wrap(&mut notifications, Duration::from_secs(2)).await;

        assert!(
            matches!(received.as_deref(), Some(event) if event.id == gift_wrap.id),
            "subscription must receive kind 1059 events backdated within the NIP-59 tweak window"
        );

        receiver.disconnect().await.unwrap();
        sender.disconnect().await;
    }

    #[test]
    fn test_subscription_lookback_matches_nip59_tweak_window() {
        assert_eq!(
            NIP59_TIMESTAMP_TWEAK_WINDOW_SECS, 172_800,
            "lookback must cover NIP-59's 2-day timestamp tweak window"
        );
    }

    #[tokio::test]
    async fn test_relay_client_fails_with_no_relays() {
        let keys = Keys::generate();
        let config = RelayConfig {
            clearnet: vec![],
            allow_unencrypted_clearnet_relays: false,
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 1, // Very short timeout for test
        };

        let client = RelayClient::new(keys, config).await.unwrap();

        // Should fail because no relays are configured (times out)
        let result = client.connect().await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to connect to any relay")
        );
    }

    #[tokio::test]
    async fn test_relay_client_multiple_relays() {
        use nostr_relay_builder::MockRelay;
        use std::time::Duration;

        // Start multiple mock relays
        let mock1 = MockRelay::run().await.unwrap();
        let mock2 = MockRelay::run().await.unwrap();
        let url1 = mock1.url().await;
        let url2 = mock2.url().await;

        let keys = Keys::generate();
        let config = test_relay_config(vec![url1.to_string(), url2.to_string()]);

        let client = RelayClient::new(keys, config).await.unwrap();

        // Connect directly through the inner client
        client.client.add_relay(&url1).await.unwrap();
        client.client.add_relay(&url2).await.unwrap();
        client.client.connect().await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let status = client.get_status().await;
        assert_eq!(status.clearnet_connected, 2);
        assert_eq!(status.total_configured, 2);

        client.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn test_relay_client_receives_events() {
        use nostr_relay_builder::MockRelay;
        use std::time::Duration;

        // Start a mock relay
        let mock = MockRelay::run().await.unwrap();
        let relay_url = mock.url().await;

        // Create two clients: one to send events, one to receive
        let receiver_keys = Keys::generate();
        let sender_keys = Keys::generate();

        // Setup receiver client
        let receiver_config = test_relay_config(vec![relay_url.to_string()]);
        let receiver = RelayClient::new(receiver_keys.clone(), receiver_config)
            .await
            .unwrap();

        receiver.client.add_relay(&relay_url).await.unwrap();
        receiver.client.connect().await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Subscribe to text notes (kind 1) for testing
        let filter = Filter::new().kind(Kind::TextNote).limit(10);
        receiver.client.subscribe(filter, None).await.unwrap();

        // Get notification receiver before sending
        let mut notifications = receiver.notifications();

        // Setup sender client
        let sender = Client::builder().signer(sender_keys).build();
        sender.add_relay(&relay_url).await.unwrap();
        sender.connect().await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Send a text note
        let event_builder = EventBuilder::text_note("Hello from mock relay test!");
        sender.send_event_builder(event_builder).await.unwrap();

        // Wait for the event to arrive
        let received = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match notifications.recv().await {
                    Ok(RelayPoolNotification::Event { event, .. }) => {
                        if event.kind == Kind::TextNote {
                            return Some(event);
                        }
                    }
                    Ok(_) => continue,
                    Err(_) => return None,
                }
            }
        })
        .await;

        assert!(received.is_ok(), "Should receive event within timeout");
        let event = received.unwrap().expect("Should have received an event");
        assert_eq!(event.content, "Hello from mock relay test!");

        receiver.disconnect().await.unwrap();
        sender.disconnect().await;
    }

    #[tokio::test]
    async fn test_inner_returns_client() {
        let keys = Keys::generate();
        let config = test_relay_config(vec![]);

        let relay_client = RelayClient::new(keys, config).await.unwrap();

        // Verify inner() returns the underlying client
        let inner = relay_client.inner();
        assert!(inner.relays().await.is_empty());
    }

    #[tokio::test]
    async fn test_publish_inbox_relays_with_no_relays() {
        let keys = Keys::generate();
        let config = RelayConfig {
            clearnet: vec![],
            allow_unencrypted_clearnet_relays: false,
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 5,
        };

        let client = RelayClient::new(keys, config).await.unwrap();

        // Should return Ok even with no relays (just logs warning)
        let result = client.publish_inbox_relays().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_publish_inbox_relays_with_configured_relays() {
        use nostr_relay_builder::MockRelay;

        // Start a mock relay
        let mock = MockRelay::run().await.unwrap();
        let relay_url = mock.url().await;

        let keys = Keys::generate();
        let config = RelayConfig {
            clearnet: vec![relay_url.to_string()],
            allow_unencrypted_clearnet_relays: true,
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 5,
        };

        let client = RelayClient::new(keys.clone(), config).await.unwrap();

        // Connect to the relay first
        client.client.add_relay(&relay_url).await.unwrap();
        client.client.connect().await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Publish inbox relays
        let result = client.publish_inbox_relays().await;
        assert!(result.is_ok());

        // Give it time to publish
        tokio::time::sleep(Duration::from_millis(100)).await;

        client.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn test_publish_inbox_relays_records_metric_when_publish_reaches_no_relays() {
        use crate::test_metrics::counter_value;
        use nostr_relay_builder::MockRelay;

        let mock = MockRelay::run().await.unwrap();
        let relay_url = mock.url().await;

        let keys = Keys::generate();
        let config = test_relay_config(vec![relay_url.to_string()]);
        let metrics = Metrics::new().unwrap();

        let client = RelayClient::with_metrics(keys, config, Some(metrics.clone()))
            .await
            .unwrap();
        client.client.add_relay(&relay_url).await.unwrap();
        client.client.connect().await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Shut the relay down so the kind 10050 publish reaches zero relays and
        // therefore fails to advertise the inbox relay list.
        mock.shutdown();
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Publication is best-effort, so the call still returns Ok(()).
        let result = client.publish_inbox_relays().await;
        assert!(result.is_ok());

        assert_eq!(
            counter_value(
                &metrics,
                "transponder_inbox_relay_publish_failed_total",
                &[]
            ),
            1.0,
            "a kind 10050 publish that reaches no relays must increment the failure counter"
        );

        client.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn test_publish_inbox_relays_skips_when_existing_relay_list_matches() {
        use nostr_relay_builder::MockRelay;

        let mock = MockRelay::run().await.unwrap();
        let relay_url = mock.url().await;
        let relay_url_string = relay_url.to_string();

        let keys = Keys::generate();
        let original_event = EventBuilder::new(Kind::Custom(10050), "")
            .tag(Tag::custom(TagKind::Relay, [relay_url_string.as_str()]))
            .custom_created_at(Timestamp::from_secs(1_700_000_000))
            .sign_with_keys(&keys)
            .unwrap();

        let publisher = Client::builder().signer(keys.clone()).build();
        publisher.add_relay(&relay_url).await.unwrap();
        publisher.connect().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        publisher.send_event(&original_event).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let config = RelayConfig {
            clearnet: vec![relay_url_string],
            allow_unencrypted_clearnet_relays: true,
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 5,
        };

        let client = RelayClient::new(keys.clone(), config).await.unwrap();
        client.client.add_relay(&relay_url).await.unwrap();
        client.client.connect().await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let result = client.publish_inbox_relays().await;
        assert!(result.is_ok());
        tokio::time::sleep(Duration::from_millis(100)).await;

        let observer = Client::builder().signer(Keys::generate()).build();
        observer.add_relay(&relay_url).await.unwrap();
        observer.connect().await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let events = observer
            .fetch_events(
                Filter::new()
                    .kind(Kind::Custom(10050))
                    .author(keys.public_key())
                    .limit(1),
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        let latest = events.first().expect("kind 10050 event should exist");

        assert_eq!(
            latest.id, original_event.id,
            "matching relay list must not be republished with a fresh timestamp"
        );
        assert_eq!(latest.created_at, original_event.created_at);

        client.disconnect().await.unwrap();
        publisher.disconnect().await;
        observer.disconnect().await;
    }

    #[cfg(feature = "tor")]
    #[tokio::test]
    async fn test_publish_inbox_relays_with_onion_relays() {
        let keys = Keys::generate();
        let config = RelayConfig {
            clearnet: vec![],
            allow_unencrypted_clearnet_relays: false,
            onion: vec!["ws://example.onion".to_string()],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 5,
        };

        let client = RelayClient::new(keys, config).await.unwrap();

        // Should attempt to publish (will fail since no real connection, but tests the path)
        let result = client.publish_inbox_relays().await;
        // The function always returns Ok, even if publishing fails
        assert!(result.is_ok());
    }

    #[cfg(not(feature = "tor"))]
    #[tokio::test]
    async fn test_relay_client_rejects_onion_relays_without_tor_feature() {
        let keys = Keys::generate();
        let config = RelayConfig {
            clearnet: vec![],
            allow_unencrypted_clearnet_relays: false,
            onion: vec!["wss://example.onion".to_string()],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 5,
        };

        let result = RelayClient::new(keys, config).await;
        assert!(result.is_err());
        let err = result.err().expect("onion relays should be rejected");
        assert!(err.to_string().contains("does not include Tor support"));
    }

    #[cfg(feature = "tor")]
    #[tokio::test]
    async fn test_relay_client_allows_onion_relays_with_tor_feature() {
        let keys = Keys::generate();
        let config = RelayConfig {
            clearnet: vec![],
            allow_unencrypted_clearnet_relays: false,
            onion: vec!["wss://example.onion".to_string()],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 5,
        };

        let result = RelayClient::new(keys, config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_relay_client_connect_waits_for_connection() {
        use nostr_relay_builder::MockRelay;

        // Start a mock relay
        let mock = MockRelay::run().await.unwrap();
        let relay_url = mock.url().await;

        let keys = Keys::generate();
        let config = RelayConfig {
            clearnet: vec![relay_url.to_string()],
            allow_unencrypted_clearnet_relays: true,
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 10, // Generous timeout
        };

        let client = RelayClient::new(keys, config).await.unwrap();

        // The new connect() method should wait for the connection to establish
        let result = client.connect().await;
        assert!(result.is_ok(), "Should successfully connect to mock relay");

        // Verify we're connected
        let status = client.get_status().await;
        assert_eq!(status.clearnet_connected, 1);

        client.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn test_relay_client_connect_times_out_with_unreachable_relay() {
        let keys = Keys::generate();
        let config = RelayConfig {
            // Use a relay URL that won't connect
            clearnet: vec!["ws://192.0.2.1:9999".to_string()], // TEST-NET address, won't route
            allow_unencrypted_clearnet_relays: true,
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 2, // Short timeout for test
        };

        let client = RelayClient::new(keys, config).await.unwrap();

        // Should fail after timeout because relay is unreachable
        let start = std::time::Instant::now();
        let result = client.connect().await;
        let elapsed = start.elapsed();

        assert!(result.is_err());
        assert!(
            elapsed >= Duration::from_secs(2),
            "Should wait at least 2 seconds before timing out"
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to connect to any relay within 2 seconds")
        );
    }
}

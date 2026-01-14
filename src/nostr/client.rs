//! Nostr relay client implementation.
//!
//! Handles connections to ClearNet and Tor relays, subscription management,
//! and automatic reconnection.

use std::sync::Arc;
use std::time::Duration;

use nostr_sdk::prelude::*;
use tokio::sync::{RwLock, broadcast};
use tracing::{debug, error, info, warn};

use crate::config::RelayConfig;
use crate::error::{Error, Result};
use crate::metrics::Metrics;

// Type alias to avoid confusion with our RelayStatus
use nostr_sdk::RelayStatus as NostrRelayStatus;

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

/// Nostr relay client with support for ClearNet and Tor relays.
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
        let client = Client::builder().signer(keys).build();

        let total = config.clearnet.len() + config.onion.len();

        if let Some(metrics) = &metrics {
            metrics.set_relay_counts(config.clearnet.len(), config.onion.len());
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
            match self.client.add_relay(url).await {
                Ok(_) => {
                    info!(relay = %url, "Added ClearNet relay");
                }
                Err(e) => {
                    warn!(relay = %url, error = %e, "Failed to add ClearNet relay");
                }
            }
        }

        // Add Tor relays (nostr-sdk handles Tor via arti automatically)
        for url in &self.config.onion {
            match self.client.add_relay(url).await {
                Ok(_) => {
                    info!(relay = %url, "Added Tor relay");
                }
                Err(e) => {
                    warn!(relay = %url, error = %e, "Failed to add Tor relay");
                }
            }
        }

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
        // Create filter for kind 1059 (gift wrap) events addressed to us
        let filter = Filter::new()
            .kind(Kind::GiftWrap)
            .pubkey(server_pubkey)
            .since(Timestamp::now());

        debug!(pubkey = %server_pubkey, "Subscribing to gift wrap events");

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

    /// Get the underlying nostr-sdk client.
    #[allow(dead_code)]
    pub fn inner(&self) -> &Client {
        &self.client
    }

    /// Publish a kind 10050 event to advertise inbox relays.
    pub async fn publish_inbox_relays(&self) -> Result<()> {
        let relay_urls: Vec<Tag> = self
            .config
            .clearnet
            .iter()
            .chain(self.config.onion.iter())
            .map(|url| Tag::custom(TagKind::Relay, [url.as_str()]))
            .collect();

        if relay_urls.is_empty() {
            warn!("No relays configured for kind 10050 publication");
            return Ok(());
        }

        let builder = EventBuilder::new(Kind::Custom(10050), "").tags(relay_urls);

        match self.client.send_event_builder(builder).await {
            Ok(output) => {
                info!(event_id = %output.id(), "Published kind 10050 inbox relay list");
            }
            Err(e) => {
                error!(error = %e, "Failed to publish kind 10050 event");
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 5, // Short timeout for tests
        }
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
    async fn test_relay_client_fails_with_no_relays() {
        let keys = Keys::generate();
        let config = RelayConfig {
            clearnet: vec![],
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
    async fn test_publish_inbox_relays_with_onion_relays() {
        let keys = Keys::generate();
        let config = RelayConfig {
            clearnet: vec![],
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

    #[tokio::test]
    async fn test_relay_client_connect_waits_for_connection() {
        use nostr_relay_builder::MockRelay;

        // Start a mock relay
        let mock = MockRelay::run().await.unwrap();
        let relay_url = mock.url().await;

        let keys = Keys::generate();
        let config = RelayConfig {
            clearnet: vec![relay_url.to_string()],
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

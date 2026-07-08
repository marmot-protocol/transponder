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
use crate::defaults::NIP59_TIMESTAMP_TWEAK_WINDOW_SECS;
use crate::error::{Error, Result};
use crate::metrics::Metrics;

// Type alias to avoid confusion with our RelayStatus
use nostr_sdk::RelayStatus as NostrRelayStatus;

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

fn spawn_reconnect_attempt_monitor(
    monitor: Monitor,
    limiter: ReconnectAttemptLimiter,
    client: Client,
) {
    let notifications = monitor.subscribe();
    std::mem::drop(tokio::spawn(run_reconnect_attempt_monitor(
        notifications,
        limiter,
        client,
    )));
}

fn resync_reconnect_attempts<I>(limiter: &ReconnectAttemptLimiter, relays: I)
where
    I: IntoIterator<Item = (RelayUrl, NostrRelayStatus)>,
{
    for (relay_url, status) in relays {
        match status {
            NostrRelayStatus::Connected => limiter.reset(&relay_url),
            NostrRelayStatus::Terminated | NostrRelayStatus::Banned => {
                limiter.remove(&relay_url);
            }
            NostrRelayStatus::Initialized
            | NostrRelayStatus::Pending
            | NostrRelayStatus::Connecting
            | NostrRelayStatus::Disconnected
            | NostrRelayStatus::Sleeping => {}
        }
    }
}

async fn resync_reconnect_attempts_from_client(client: &Client, limiter: &ReconnectAttemptLimiter) {
    let relays = client
        .relays()
        .await
        .into_iter()
        .map(|(relay_url, relay)| (relay_url, relay.status()));
    resync_reconnect_attempts(limiter, relays);
}

async fn run_reconnect_attempt_monitor(
    mut notifications: broadcast::Receiver<MonitorNotification>,
    limiter: ReconnectAttemptLimiter,
    client: Client,
) {
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
                    "Relay reconnect attempt monitor lagged; resynchronizing attempt counters from current relay status"
                );
                resync_reconnect_attempts_from_client(&client, &limiter).await;
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

fn relay_options_for_config(config: &RelayConfig, kind: RelayKind) -> RelayOptions {
    let opts =
        RelayOptions::default().retry_interval(Duration::from_secs(config.reconnect_interval_secs));

    #[cfg(feature = "tor")]
    {
        if matches!(kind, RelayKind::Onion) {
            return opts.connection_mode(ConnectionMode::tor());
        }
    }

    #[cfg(not(feature = "tor"))]
    let _ = kind;

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

/// Provenance of a relay: which configured list (`relays.clearnet` vs
/// `relays.onion`) it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayKind {
    Clearnet,
    Onion,
}

/// Classify a relay by the configured list it came from (its provenance).
///
/// Membership in the configured lists is authoritative: a clearnet relay whose
/// URL merely contains `.onion` somewhere (subdomain, path) must not be counted
/// as Tor, and an onion-list relay is Tor regardless of its URL shape. Relays
/// absent from both lists (possible only when relays are added outside
/// `connect()`, e.g. in tests) fall back to a lexical check anchored to the
/// host suffix via [`RelayUrl::is_onion`], never a substring scan.
fn classify_relay_kind(url: &RelayUrl, origins: &BTreeMap<RelayUrl, RelayKind>) -> RelayKind {
    match origins.get(url) {
        Some(kind) => *kind,
        None if url.is_onion() => RelayKind::Onion,
        None => RelayKind::Clearnet,
    }
}

/// Nostr relay client with support for ClearNet and optional Tor relays.
pub struct RelayClient {
    client: Client,
    config: RelayConfig,
    status: Arc<RwLock<RelayStatus>>,
    /// Provenance of each configured relay, recorded when the relay is added
    /// in [`RelayClient::connect`]. Used by [`RelayClient::refresh_status`] to
    /// classify connected relays by origin list instead of URL shape.
    origins: Mutex<BTreeMap<RelayUrl, RelayKind>>,
    metrics: Metrics,
}

impl RelayClient {
    /// Create a new relay client with the given keys and configuration.
    #[allow(dead_code)]
    pub async fn new(keys: Keys, config: RelayConfig) -> Result<Self> {
        Self::with_metrics(keys, config, Metrics::disabled()).await
    }

    /// Create a new relay client with metrics.
    pub async fn with_metrics(keys: Keys, config: RelayConfig, metrics: Metrics) -> Result<Self> {
        validate_relay_config(&config)?;

        let reconnect_attempt_limiter = ReconnectAttemptLimiter::new(config.max_reconnect_attempts);
        let relay_monitor = Monitor::new(RELAY_MONITOR_CHANNEL_SIZE);

        let client = Client::builder()
            .signer(keys)
            .admit_policy(reconnect_attempt_limiter.clone())
            .monitor(relay_monitor.clone())
            .build();
        spawn_reconnect_attempt_monitor(
            relay_monitor.clone(),
            reconnect_attempt_limiter.clone(),
            client.clone(),
        );

        let total = config.clearnet.len() + config.onion.len();

        metrics.set_relay_counts(config.clearnet.len(), config.onion.len());
        metrics.set_relay_subscription_lookback(NIP59_TIMESTAMP_TWEAK_WINDOW_SECS);

        Ok(Self {
            client,
            config,
            status: Arc::new(RwLock::new(RelayStatus {
                clearnet_connected: 0,
                tor_connected: 0,
                total_configured: total,
            })),
            origins: Mutex::new(BTreeMap::new()),
            metrics,
        })
    }

    fn origins(&self) -> MutexGuard<'_, BTreeMap<RelayUrl, RelayKind>> {
        self.origins
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Connect to all configured relays.
    ///
    /// This method initiates connections to all configured relays and waits up to
    /// `connection_timeout_secs` for at least one relay to establish a connection.
    /// The timeout allows for network latency and relay responsiveness during startup.
    pub async fn connect(&self) -> Result<()> {
        // Add ClearNet relays
        for url in &self.config.clearnet {
            match self.add_configured_relay(url, RelayKind::Clearnet).await {
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
            match self.add_configured_relay(url, RelayKind::Onion).await {
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
            self.refresh_status().await;
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

    /// Recompute the relay connection status and publish it.
    ///
    /// This is the only place the cached [`RelayStatus`] and the
    /// `transponder_relays_connected` gauges are written: it enumerates the
    /// relay pool, classifies each connected relay by the configured list it
    /// came from (see `classify_relay_kind`), and stores the result. It is
    /// driven by `connect()` while polling for the first connection and by
    /// the periodic status-refresher task in `main` — never by the read paths
    /// ([`Self::get_status`]/[`Self::is_connected`]), so readiness probes are
    /// side-effect-free and the gauges update on refresh cadence, not probe
    /// cadence.
    pub async fn refresh_status(&self) {
        let relays = self.client.relays().await;

        let mut clearnet = 0;
        let mut tor = 0;

        {
            let origins = self.origins();
            for (url, relay) in &relays {
                if relay.status() == NostrRelayStatus::Connected {
                    match classify_relay_kind(url, &origins) {
                        RelayKind::Clearnet => clearnet += 1,
                        RelayKind::Onion => tor += 1,
                    }
                }
            }
        }

        self.metrics.set_relays_connected("clearnet", clearnet);
        self.metrics.set_relays_connected("onion", tor);

        let mut status = self.status.write().await;
        status.clearnet_connected = clearnet;
        status.tor_connected = tor;
    }

    /// Get the current relay connection status.
    ///
    /// Pure read of the cached status snapshot: no relay-pool enumeration, no
    /// gauge writes, no write-lock acquisition. The snapshot is kept fresh by
    /// [`Self::refresh_status`].
    pub async fn get_status(&self) -> RelayStatus {
        self.status.read().await.clone()
    }

    /// Check if at least one relay is connected.
    ///
    /// Pure read of the cached status snapshot (see [`Self::get_status`]).
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

    async fn add_configured_relay(
        &self,
        url: &str,
        kind: RelayKind,
    ) -> std::result::Result<bool, String> {
        let added = self
            .client
            .pool()
            .add_relay(url, relay_options_for_config(&self.config, kind))
            .await
            .map_err(|e| e.to_string())?;

        // Record which configured list the relay came from so status
        // refreshes classify it by provenance instead of guessing from the
        // URL string. Parsing cannot realistically fail here (the pool just
        // accepted the same string), but a parse failure only means the relay
        // falls back to the lexical classification.
        if let Ok(relay_url) = RelayUrl::parse(url) {
            self.origins().insert(relay_url, kind);
        }

        Ok(added)
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
        self.metrics.record_inbox_relay_publish_failed();
    }

    /// The configured relay URLs to advertise, as raw config strings.
    ///
    /// The `r`-tag values published in the kind-10050 event preserve the
    /// operator's exact spelling; change-detection normalizes separately (see
    /// [`Self::inbox_relay_event_is_current`]).
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

        // kind 10050 is replaceable: compare against the newest fetched event by
        // `created_at`, not an arbitrary `events.first()` that can land on a
        // stale reply from a slow/secondary relay.
        let Some(newest) = events.iter().max_by_key(|event| event.created_at) else {
            return Ok(false);
        };

        // Normalize both sides through `RelayUrl` before comparing so cosmetic
        // differences (trailing slash, host case) between the config spelling
        // and the published tag do not trigger a spurious republish. Config
        // entries are already validated, so a parse failure there is a real
        // error; unparseable tag values on the network side are skipped.
        let configured = normalize_relay_urls(relay_urls.iter().map(String::as_str))?;
        let published = normalize_relay_tags(newest);

        Ok(configured == published)
    }
}

/// Normalize an iterator of config relay strings into a canonical set.
///
/// Returns an error if any entry fails to parse; config URLs are validated at
/// startup, so a failure here is a real misconfiguration rather than
/// network-supplied noise.
fn normalize_relay_urls<'a, I>(urls: I) -> Result<BTreeSet<RelayUrl>>
where
    I: IntoIterator<Item = &'a str>,
{
    urls.into_iter()
        .map(|url| {
            RelayUrl::parse(url)
                .map_err(|e| Error::Nostr(format!("Invalid configured relay URL '{url}': {e}")))
        })
        .collect()
}

/// Collect the `r`-tag relay URLs from an event, normalized through
/// [`RelayUrl`]. Unparseable tag values are skipped rather than failing the
/// comparison, since the event is network-supplied.
fn normalize_relay_tags(event: &Event) -> BTreeSet<RelayUrl> {
    event
        .tags
        .as_slice()
        .iter()
        .filter(|tag| tag.kind() == TagKind::Relay)
        .filter_map(|tag| tag.content())
        .filter_map(|content| RelayUrl::parse(content).ok())
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

    // Validate the onion list symmetrically with clearnet: without this, a
    // plaintext `ws://` or a misspelled `.onion` entry passed config validation
    // and was added blindly, defeating the wss-only TLS enforcement and
    // silently routing traffic over clearnet at connect time (only a `warn!`).
    for url in &config.onion {
        validate_onion_relay_url(url)?;
    }

    Ok(())
}

/// Rejects an onion relay URL that does not parse as a `ws://`/`wss://` URL
/// with a `.onion` host.
///
/// A plaintext `ws://` entry in `relays.onion` would defeat the wss-only TLS
/// enforcement, and a typo'd `.onion` URL would be silently dropped at connect
/// time — either way the deployment degrades to clearnet without a hard
/// failure. Parsing through nostr-sdk's [`RelayUrl`] (the same type the pool
/// uses) rejects both fast at startup with a named error.
fn validate_onion_relay_url(url: &str) -> Result<()> {
    let parsed = RelayUrl::parse(url).map_err(|e| {
        Error::Nostr(format!(
            "Onion relay '{url}' is not a valid ws:// or wss:// URL: {e}"
        ))
    })?;

    if !parsed.is_onion() {
        return Err(Error::Nostr(format!(
            "Onion relay '{url}' must have a .onion host"
        )));
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

    #[test]
    fn test_classify_relay_kind_prefers_provenance_over_url_shape() {
        let onion_by_provenance = RelayUrl::parse("wss://127.0.0.1:2121").unwrap();
        let clearnet_with_onion_label =
            RelayUrl::parse("wss://relay.onionmail.example.com").unwrap();

        let mut origins = BTreeMap::new();
        origins.insert(onion_by_provenance.clone(), RelayKind::Onion);
        origins.insert(clearnet_with_onion_label.clone(), RelayKind::Clearnet);

        // Membership in the configured lists is authoritative: an onion-list
        // relay counts as Tor even without a .onion host...
        assert_eq!(
            classify_relay_kind(&onion_by_provenance, &origins),
            RelayKind::Onion
        );
        // ...and a clearnet relay whose host merely contains ".onion" is not
        // misreported as Tor.
        assert_eq!(
            classify_relay_kind(&clearnet_with_onion_label, &origins),
            RelayKind::Clearnet
        );
    }

    #[test]
    fn test_classify_relay_kind_fallback_anchors_to_onion_host_suffix() {
        let origins = BTreeMap::new();
        let onion = RelayUrl::parse("wss://example.onion").unwrap();
        let clearnet = RelayUrl::parse("wss://relay.example.com").unwrap();
        let onion_substring = RelayUrl::parse("wss://relay.onionmail.example.com").unwrap();

        // Unknown relays fall back to the host-suffix check.
        assert_eq!(classify_relay_kind(&onion, &origins), RelayKind::Onion);
        assert_eq!(
            classify_relay_kind(&clearnet, &origins),
            RelayKind::Clearnet
        );
        // The fallback must not degrade to a substring scan over the URL.
        assert_eq!(
            classify_relay_kind(&onion_substring, &origins),
            RelayKind::Clearnet
        );
    }

    #[tokio::test]
    async fn test_connect_records_clearnet_provenance() {
        use nostr_relay_builder::MockRelay;

        let mock = MockRelay::run().await.unwrap();
        let relay_url = mock.url().await;

        let config = test_relay_config(vec![relay_url.to_string()]);
        let client = RelayClient::new(Keys::generate(), config).await.unwrap();
        client.connect().await.unwrap();

        let parsed = RelayUrl::parse(&relay_url.to_string()).unwrap();
        assert_eq!(
            client.origins().get(&parsed).copied(),
            Some(RelayKind::Clearnet),
            "connect() must record which configured list each relay came from"
        );

        client.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn test_refresh_status_updates_gauges_on_refresh_not_on_reads() {
        use crate::test_metrics::gauge_value;
        use nostr_relay_builder::MockRelay;

        let mock = MockRelay::run().await.unwrap();
        let relay_url = mock.url().await;

        let keys = Keys::generate();
        let config = test_relay_config(vec![relay_url.to_string()]);
        let metrics = Metrics::new().unwrap();

        let client = RelayClient::with_metrics(keys, config, metrics.clone())
            .await
            .unwrap();
        client.client.add_relay(&relay_url).await.unwrap();
        client.client.connect().await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Reads never touch the gauges: despite the live connection, nothing
        // has refreshed yet, so the gauge family has not even been written.
        let _ = client.get_status().await;
        let _ = client.is_connected().await;
        assert!(
            !metrics
                .gather()
                .iter()
                .any(|family| family.name() == "transponder_relays_connected"),
            "pure reads must not write the relays_connected gauges"
        );

        client.refresh_status().await;
        assert_eq!(
            gauge_value(
                &metrics,
                "transponder_relays_connected",
                &[("type", "clearnet")]
            ),
            1.0,
            "an explicit refresh must publish the recomputed gauge"
        );

        client.disconnect().await.unwrap();
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

        let opts = relay_options_for_config(&config, RelayKind::Clearnet);
        let debug = format!("{opts:?}");

        assert!(
            debug.contains("retry_interval: 17s"),
            "relay options must use configured retry interval, got: {debug}"
        );
    }

    #[cfg(feature = "tor")]
    #[test]
    fn test_relay_options_use_relay_kind_for_tor_mode() {
        let config = test_relay_config(vec![]);

        let clearnet_opts = relay_options_for_config(&config, RelayKind::Clearnet);
        let onion_opts = relay_options_for_config(&config, RelayKind::Onion);
        let clearnet_debug = format!("{clearnet_opts:?}");
        let onion_debug = format!("{onion_opts:?}");

        assert!(
            !clearnet_debug.contains("Tor"),
            "clearnet provenance must not be forced over Tor, got: {clearnet_debug}"
        );
        assert!(
            onion_debug.contains("Tor"),
            "onion provenance must select Tor connection mode, got: {onion_debug}"
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
    async fn test_admit_policy_rejects_after_exhausting_attempts() {
        let limiter = ReconnectAttemptLimiter::new(0);
        let relay_url = RelayUrl::parse("wss://relay.example.com").unwrap();

        // Exercise the AdmitPolicy trait entry point the relay pool calls.
        let first = AdmitPolicy::admit_connection(&limiter, &relay_url)
            .await
            .unwrap();
        assert_eq!(first, AdmitStatus::Success);

        let second = AdmitPolicy::admit_connection(&limiter, &relay_url)
            .await
            .unwrap();
        assert!(
            matches!(second, AdmitStatus::Rejected { .. }),
            "attempt beyond the initial connection must be rejected at max_reconnect_attempts = 0"
        );
    }

    #[test]
    fn test_reconnect_attempt_limiter_remove_clears_tracked_state() {
        let limiter = ReconnectAttemptLimiter::new(0);
        let relay_url = RelayUrl::parse("wss://relay.example.com").unwrap();

        assert_eq!(
            limiter.admit_relay_connection(&relay_url),
            AdmitStatus::Success
        );
        assert!(matches!(
            limiter.admit_relay_connection(&relay_url),
            AdmitStatus::Rejected { .. }
        ));

        limiter.remove(&relay_url);
        assert!(
            !limiter.attempts_since_connection().contains_key(&relay_url),
            "remove must drop the relay's entry so the map cannot grow unbounded"
        );
        assert_eq!(
            limiter.admit_relay_connection(&relay_url),
            AdmitStatus::Success,
            "a removed relay starts over with a fresh attempt budget"
        );
    }

    #[tokio::test]
    async fn test_reconnect_attempt_monitor_resets_and_removes_counters() {
        let limiter = ReconnectAttemptLimiter::new(0);
        let connected_url = RelayUrl::parse("wss://connected.example.com").unwrap();
        let terminated_url = RelayUrl::parse("wss://terminated.example.com").unwrap();

        // Exhaust both relays' budgets so the monitor's effect is observable.
        for url in [&connected_url, &terminated_url] {
            assert_eq!(limiter.admit_relay_connection(url), AdmitStatus::Success);
            assert!(matches!(
                limiter.admit_relay_connection(url),
                AdmitStatus::Rejected { .. }
            ));
        }

        let (sender, receiver) = broadcast::channel(8);
        let monitor_task = tokio::spawn(run_reconnect_attempt_monitor(
            receiver,
            limiter.clone(),
            Client::default(),
        ));

        sender
            .send(MonitorNotification::StatusChanged {
                relay_url: connected_url.clone(),
                status: NostrRelayStatus::Connected,
            })
            .unwrap();
        sender
            .send(MonitorNotification::StatusChanged {
                relay_url: terminated_url.clone(),
                status: NostrRelayStatus::Terminated,
            })
            .unwrap();
        // Ignored transitions must not disturb the counters.
        sender
            .send(MonitorNotification::StatusChanged {
                relay_url: connected_url.clone(),
                status: NostrRelayStatus::Connecting,
            })
            .unwrap();
        drop(sender);

        // Channel closed -> the monitor loop exits; all sends were processed.
        tokio::time::timeout(Duration::from_secs(5), monitor_task)
            .await
            .expect("monitor task must exit when the channel closes")
            .unwrap();

        assert_eq!(
            limiter.attempts_since_connection().get(&connected_url),
            Some(&0),
            "Connected must reset the counter to zero"
        );
        assert!(
            !limiter
                .attempts_since_connection()
                .contains_key(&terminated_url),
            "Terminated must remove the relay's entry"
        );
        assert_eq!(
            limiter.admit_relay_connection(&connected_url),
            AdmitStatus::Success
        );
        assert_eq!(
            limiter.admit_relay_connection(&terminated_url),
            AdmitStatus::Success
        );
    }

    #[test]
    fn test_reconnect_attempt_lag_resyncs_current_relay_statuses() {
        let limiter = ReconnectAttemptLimiter::new(0);
        let connected_url = RelayUrl::parse("wss://connected.example.com").unwrap();
        let terminated_url = RelayUrl::parse("wss://terminated.example.com").unwrap();
        let disconnected_url = RelayUrl::parse("wss://disconnected.example.com").unwrap();

        for url in [&connected_url, &terminated_url, &disconnected_url] {
            assert_eq!(limiter.admit_relay_connection(url), AdmitStatus::Success);
            assert!(matches!(
                limiter.admit_relay_connection(url),
                AdmitStatus::Rejected { .. }
            ));
        }

        resync_reconnect_attempts(
            &limiter,
            [
                (connected_url.clone(), NostrRelayStatus::Connected),
                (terminated_url.clone(), NostrRelayStatus::Terminated),
                (disconnected_url.clone(), NostrRelayStatus::Disconnected),
            ],
        );

        assert_eq!(
            limiter.attempts_since_connection().get(&connected_url),
            Some(&0),
            "lag resync must repair a missed Connected reset"
        );
        assert!(
            !limiter
                .attempts_since_connection()
                .contains_key(&terminated_url),
            "lag resync must remove terminal relay state"
        );
        assert!(
            matches!(
                limiter.admit_relay_connection(&disconnected_url),
                AdmitStatus::Rejected { .. }
            ),
            "lag resync must not erase counters for still-disconnected relays"
        );
    }

    #[tokio::test]
    async fn test_connect_adds_relays_with_configured_options() {
        let relay_url = "ws://127.0.0.1:12345";
        let mut config = test_relay_config(vec![relay_url.to_string()]);
        config.reconnect_interval_secs = 23;

        let client = RelayClient::new(Keys::generate(), config).await.unwrap();
        client
            .add_configured_relay(relay_url, RelayKind::Clearnet)
            .await
            .unwrap();

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

        // get_status()/is_connected() are pure reads of the cached snapshot;
        // nothing has refreshed it yet, so they still report zero connections
        // even though the relay is connected.
        let status = client.get_status().await;
        assert_eq!(status.clearnet_connected, 0);
        assert!(!client.is_connected().await);

        // An explicit refresh recomputes the snapshot from the relay pool.
        client.refresh_status().await;
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

        client.refresh_status().await;
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

        let client = RelayClient::with_metrics(keys, config, metrics.clone())
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

    // ---- #122: onion relay URL validation (feature-independent parser) ----

    #[test]
    fn test_validate_onion_relay_url_accepts_ws_and_wss_onion() {
        assert!(validate_onion_relay_url("ws://abcabcabcabcabcd.onion").is_ok());
        assert!(validate_onion_relay_url("wss://abcabcabcabcabcd.onion").is_ok());
        // With an explicit port, too.
        assert!(validate_onion_relay_url("ws://abcabcabcabcabcd.onion:8080").is_ok());
    }

    #[test]
    fn test_validate_onion_relay_url_rejects_non_onion_host() {
        // A clearnet host slipped into relays.onion must be rejected.
        let error = validate_onion_relay_url("wss://relay.example.com").unwrap_err();
        assert!(error.to_string().contains(".onion"), "{error}");
    }

    #[test]
    fn test_validate_onion_relay_url_rejects_missing_scheme() {
        // A bare host (no ws://) must be rejected instead of silently dropped.
        let error = validate_onion_relay_url("abcabcabcabcabcd.onion").unwrap_err();
        assert!(
            error.to_string().contains("valid ws:// or wss:// URL"),
            "{error}"
        );
    }

    #[test]
    fn test_validate_onion_relay_url_rejects_non_ws_scheme() {
        // http:// is not a websocket scheme; RelayUrl::parse rejects it.
        let error = validate_onion_relay_url("http://abcabcabcabcabcd.onion").unwrap_err();
        assert!(
            error.to_string().contains("valid ws:// or wss:// URL"),
            "{error}"
        );
    }

    #[cfg(feature = "tor")]
    #[test]
    fn test_validate_relay_config_rejects_plaintext_ws_in_onion_list() {
        // The concrete #122 footgun: a plaintext ws:// entry with a clearnet
        // host in relays.onion. Only reachable when the tor feature is on
        // (otherwise the "requires tor feature" error fires first).
        let config = RelayConfig {
            clearnet: vec![],
            allow_unencrypted_clearnet_relays: false,
            onion: vec!["ws://plaintext.example.com".to_string()],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 5,
        };
        let error = validate_relay_config(&config).unwrap_err();
        assert!(error.to_string().contains(".onion"), "{error}");
    }

    #[cfg(feature = "tor")]
    #[test]
    fn test_validate_relay_config_accepts_valid_onion() {
        let config = RelayConfig {
            clearnet: vec![],
            allow_unencrypted_clearnet_relays: false,
            onion: vec!["ws://abcabcabcabcabcd.onion".to_string()],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 5,
        };
        assert!(validate_relay_config(&config).is_ok());
    }

    // ---- #124: normalized inbox comparison + newest-event selection ----

    fn kind_10050_event(keys: &Keys, created_at: Timestamp, relay_urls: &[&str]) -> Event {
        let tags: Vec<Tag> = relay_urls
            .iter()
            .map(|url| Tag::custom(TagKind::Relay, [*url]))
            .collect();
        EventBuilder::new(Kind::Custom(10050), "")
            .tags(tags)
            .custom_created_at(created_at)
            .sign_with_keys(keys)
            .unwrap()
    }

    #[test]
    fn test_normalize_relay_tags_ignores_trailing_slash_and_case() {
        let keys = Keys::generate();
        // The published event uses a trailing slash and mixed host case.
        let event = kind_10050_event(&keys, Timestamp::now(), &["wss://Relay.Example.com/"]);
        let published = normalize_relay_tags(&event);
        // The config side uses the bare, lowercase form.
        let configured = normalize_relay_urls(["wss://relay.example.com"]).unwrap();
        assert_eq!(
            published, configured,
            "cosmetic URL differences must normalize to the same set (no spurious republish)"
        );
    }

    #[test]
    fn test_normalize_relay_tags_skips_unparseable_tag_values() {
        let keys = Keys::generate();
        let event = kind_10050_event(
            &keys,
            Timestamp::now(),
            &["wss://relay.example.com", "not a url"],
        );
        let published = normalize_relay_tags(&event);
        // Only the parseable URL survives.
        assert_eq!(published.len(), 1);
        assert!(published.contains(&RelayUrl::parse("wss://relay.example.com").unwrap()));
    }

    #[test]
    fn test_normalize_relay_urls_errors_on_bad_config_entry() {
        let error = normalize_relay_urls(["totally invalid"]).unwrap_err();
        assert!(
            error.to_string().contains("Invalid configured relay URL"),
            "{error}"
        );
    }

    #[test]
    fn test_newest_kind_10050_event_selected_by_created_at() {
        // Verifies the max_by_key(created_at) selection logic: given two events,
        // the newest one's normalized tag set is what change-detection compares
        // against, regardless of fetch order.
        let keys = Keys::generate();
        let older = kind_10050_event(
            &keys,
            Timestamp::from(1_000),
            &["wss://old-relay.example.com"],
        );
        let newer = kind_10050_event(
            &keys,
            Timestamp::from(2_000),
            &["wss://new-relay.example.com"],
        );

        let events = [older.clone(), newer.clone()];
        let selected = events.iter().max_by_key(|e| e.created_at).unwrap();
        assert_eq!(selected.id, newer.id, "the newest event must be selected");

        let published = normalize_relay_tags(selected);
        let configured = normalize_relay_urls(["wss://new-relay.example.com"]).unwrap();
        assert_eq!(published, configured);
    }
}

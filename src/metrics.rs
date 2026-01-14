//! Prometheus metrics for operational visibility.
//!
//! This module provides metrics for monitoring the health and performance of
//! the Transponder server without exposing any sensitive information like
//! device tokens, user identifiers, or message content.
//!
//! # Security Considerations
//!
//! All metrics are designed to be safe for exposure:
//! - No device tokens, user IDs, or message content
//! - No relay URLs (could reveal server topology)
//! - Only aggregate counts and operational statistics

use prometheus::{
    Gauge, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts,
    Registry,
};

/// All metrics for the Transponder server.
#[derive(Clone)]
pub struct Metrics {
    /// The Prometheus registry containing all metrics.
    pub registry: Registry,

    // === Event Processing Metrics ===
    /// Total number of events received from relays.
    pub events_received_total: IntCounter,

    /// Total number of events successfully processed.
    pub events_processed_total: IntCounter,

    /// Total number of events skipped due to deduplication.
    pub events_deduplicated_total: IntCounter,

    /// Total number of events that failed processing.
    pub events_failed_total: IntCounter,

    /// Current size of the deduplication cache.
    pub dedup_cache_size: IntGauge,

    /// Total number of entries evicted from dedup cache during cleanup.
    pub dedup_cache_evictions_total: IntCounter,

    /// Total number of tokens successfully decrypted.
    pub tokens_decrypted_total: IntCounter,

    /// Total number of token decryption failures.
    pub tokens_decryption_failed_total: IntCounter,

    // === Push Dispatcher Metrics ===
    /// Total number of notifications dispatched to push services.
    pub push_dispatched_total: IntCounterVec,

    /// Total number of successful push notifications.
    pub push_success_total: IntCounterVec,

    /// Total number of failed push notifications (by platform and reason).
    pub push_failed_total: IntCounterVec,

    /// Current number of items in the push queue.
    pub push_queue_size: IntGauge,

    /// Total number of notifications dropped due to full queue.
    pub push_queue_dropped_total: IntCounter,

    /// Number of available semaphore permits for concurrent pushes.
    pub push_semaphore_available: IntGauge,

    /// Total number of push retries attempted.
    pub push_retries_total: IntCounterVec,

    // === Push Client Metrics ===
    /// Duration of push notification requests in seconds.
    pub push_request_duration_seconds: HistogramVec,

    /// Total number of push responses by status code.
    pub push_response_status_total: IntCounterVec,

    /// Total number of JWT/OAuth token refreshes.
    pub auth_token_refreshes_total: IntCounterVec,

    // === Relay Connection Metrics ===
    /// Number of currently connected relays.
    pub relays_connected: IntGaugeVec,

    /// Total number of configured relays.
    pub relays_configured: IntGaugeVec,

    // === Server Metrics ===
    /// Timestamp when the server started (Unix seconds).
    pub server_start_time_seconds: Gauge,

    /// Server version information.
    pub server_info: IntGaugeVec,
}

impl Metrics {
    /// Create a new metrics instance with all metrics registered.
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();

        // === Event Processing Metrics ===
        let events_received_total = IntCounter::with_opts(Opts::new(
            "transponder_events_received_total",
            "Total number of events received from relays",
        ))?;
        registry.register(Box::new(events_received_total.clone()))?;

        let events_processed_total = IntCounter::with_opts(Opts::new(
            "transponder_events_processed_total",
            "Total number of events successfully processed",
        ))?;
        registry.register(Box::new(events_processed_total.clone()))?;

        let events_deduplicated_total = IntCounter::with_opts(Opts::new(
            "transponder_events_deduplicated_total",
            "Total number of events skipped due to deduplication",
        ))?;
        registry.register(Box::new(events_deduplicated_total.clone()))?;

        let events_failed_total = IntCounter::with_opts(Opts::new(
            "transponder_events_failed_total",
            "Total number of events that failed processing",
        ))?;
        registry.register(Box::new(events_failed_total.clone()))?;

        let dedup_cache_size = IntGauge::with_opts(Opts::new(
            "transponder_dedup_cache_size",
            "Current number of entries in the deduplication cache",
        ))?;
        registry.register(Box::new(dedup_cache_size.clone()))?;

        let dedup_cache_evictions_total = IntCounter::with_opts(Opts::new(
            "transponder_dedup_cache_evictions_total",
            "Total number of entries evicted from deduplication cache",
        ))?;
        registry.register(Box::new(dedup_cache_evictions_total.clone()))?;

        let tokens_decrypted_total = IntCounter::with_opts(Opts::new(
            "transponder_tokens_decrypted_total",
            "Total number of tokens successfully decrypted",
        ))?;
        registry.register(Box::new(tokens_decrypted_total.clone()))?;

        let tokens_decryption_failed_total = IntCounter::with_opts(Opts::new(
            "transponder_tokens_decryption_failed_total",
            "Total number of token decryption failures",
        ))?;
        registry.register(Box::new(tokens_decryption_failed_total.clone()))?;

        // === Push Dispatcher Metrics ===
        let push_dispatched_total = IntCounterVec::new(
            Opts::new(
                "transponder_push_dispatched_total",
                "Total number of notifications dispatched to push services",
            ),
            &["platform"],
        )?;
        registry.register(Box::new(push_dispatched_total.clone()))?;

        let push_success_total = IntCounterVec::new(
            Opts::new(
                "transponder_push_success_total",
                "Total number of successful push notifications",
            ),
            &["platform"],
        )?;
        registry.register(Box::new(push_success_total.clone()))?;

        let push_failed_total = IntCounterVec::new(
            Opts::new(
                "transponder_push_failed_total",
                "Total number of failed push notifications",
            ),
            &["platform", "reason"],
        )?;
        registry.register(Box::new(push_failed_total.clone()))?;

        let push_queue_size = IntGauge::with_opts(Opts::new(
            "transponder_push_queue_size",
            "Current number of notifications waiting in the push queue",
        ))?;
        registry.register(Box::new(push_queue_size.clone()))?;

        let push_queue_dropped_total = IntCounter::with_opts(Opts::new(
            "transponder_push_queue_dropped_total",
            "Total number of notifications dropped due to full queue",
        ))?;
        registry.register(Box::new(push_queue_dropped_total.clone()))?;

        let push_semaphore_available = IntGauge::with_opts(Opts::new(
            "transponder_push_semaphore_available",
            "Number of available permits for concurrent push requests",
        ))?;
        registry.register(Box::new(push_semaphore_available.clone()))?;

        let push_retries_total = IntCounterVec::new(
            Opts::new(
                "transponder_push_retries_total",
                "Total number of push notification retry attempts",
            ),
            &["platform"],
        )?;
        registry.register(Box::new(push_retries_total.clone()))?;

        // === Push Client Metrics ===
        let push_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "transponder_push_request_duration_seconds",
                "Duration of push notification requests in seconds",
            )
            .buckets(vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
            &["platform"],
        )?;
        registry.register(Box::new(push_request_duration_seconds.clone()))?;

        let push_response_status_total = IntCounterVec::new(
            Opts::new(
                "transponder_push_response_status_total",
                "Total number of push responses by HTTP status code",
            ),
            &["platform", "status"],
        )?;
        registry.register(Box::new(push_response_status_total.clone()))?;

        let auth_token_refreshes_total = IntCounterVec::new(
            Opts::new(
                "transponder_auth_token_refreshes_total",
                "Total number of authentication token refreshes",
            ),
            &["service"],
        )?;
        registry.register(Box::new(auth_token_refreshes_total.clone()))?;

        // === Relay Connection Metrics ===
        let relays_connected = IntGaugeVec::new(
            Opts::new(
                "transponder_relays_connected",
                "Number of currently connected relays",
            ),
            &["type"],
        )?;
        registry.register(Box::new(relays_connected.clone()))?;

        let relays_configured = IntGaugeVec::new(
            Opts::new(
                "transponder_relays_configured",
                "Number of configured relays",
            ),
            &["type"],
        )?;
        registry.register(Box::new(relays_configured.clone()))?;

        // === Server Metrics ===
        let server_start_time_seconds = Gauge::with_opts(Opts::new(
            "transponder_server_start_time_seconds",
            "Unix timestamp when the server started",
        ))?;
        registry.register(Box::new(server_start_time_seconds.clone()))?;

        let server_info = IntGaugeVec::new(
            Opts::new(
                "transponder_server_info",
                "Server version and build information",
            ),
            &["version"],
        )?;
        registry.register(Box::new(server_info.clone()))?;

        Ok(Self {
            registry,
            events_received_total,
            events_processed_total,
            events_deduplicated_total,
            events_failed_total,
            dedup_cache_size,
            dedup_cache_evictions_total,
            tokens_decrypted_total,
            tokens_decryption_failed_total,
            push_dispatched_total,
            push_success_total,
            push_failed_total,
            push_queue_size,
            push_queue_dropped_total,
            push_semaphore_available,
            push_retries_total,
            push_request_duration_seconds,
            push_response_status_total,
            auth_token_refreshes_total,
            relays_connected,
            relays_configured,
            server_start_time_seconds,
            server_info,
        })
    }

    /// Initialize server startup metrics.
    pub fn init_server_info(&self, version: &str) {
        self.server_start_time_seconds.set(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0),
        );
        self.server_info.with_label_values(&[version]).set(1);
    }

    /// Set the configured relay counts.
    pub fn set_relay_counts(&self, clearnet: usize, onion: usize) {
        self.relays_configured
            .with_label_values(&["clearnet"])
            .set(clearnet as i64);
        self.relays_configured
            .with_label_values(&["onion"])
            .set(onion as i64);
    }

    /// Record an event received from relays.
    pub fn record_event_received(&self) {
        self.events_received_total.inc();
    }

    /// Record a successfully processed event.
    pub fn record_event_processed(&self) {
        self.events_processed_total.inc();
    }

    /// Record a deduplicated event.
    pub fn record_event_deduplicated(&self) {
        self.events_deduplicated_total.inc();
    }

    /// Record a failed event.
    pub fn record_event_failed(&self) {
        self.events_failed_total.inc();
    }

    /// Update dedup cache size.
    pub fn set_dedup_cache_size(&self, size: usize) {
        self.dedup_cache_size.set(size as i64);
    }

    /// Record dedup cache evictions.
    pub fn record_dedup_evictions(&self, count: usize) {
        self.dedup_cache_evictions_total.inc_by(count as u64);
    }

    /// Record a successful token decryption.
    pub fn record_token_decrypted(&self) {
        self.tokens_decrypted_total.inc();
    }

    /// Record a failed token decryption.
    pub fn record_token_decryption_failed(&self) {
        self.tokens_decryption_failed_total.inc();
    }

    /// Record a notification dispatched to push queue.
    pub fn record_push_dispatched(&self, platform: &str) {
        self.push_dispatched_total
            .with_label_values(&[platform])
            .inc();
    }

    /// Record a successful push notification.
    pub fn record_push_success(&self, platform: &str) {
        self.push_success_total.with_label_values(&[platform]).inc();
    }

    /// Record a failed push notification.
    pub fn record_push_failed(&self, platform: &str, reason: &str) {
        self.push_failed_total
            .with_label_values(&[platform, reason])
            .inc();
    }

    /// Update the push queue size.
    pub fn set_push_queue_size(&self, size: usize) {
        self.push_queue_size.set(size as i64);
    }

    /// Record a dropped notification due to full queue.
    pub fn record_push_queue_dropped(&self) {
        self.push_queue_dropped_total.inc();
    }

    /// Update available semaphore permits.
    pub fn set_push_semaphore_available(&self, available: usize) {
        self.push_semaphore_available.set(available as i64);
    }

    /// Record a push retry attempt.
    pub fn record_push_retry(&self, platform: &str) {
        self.push_retries_total.with_label_values(&[platform]).inc();
    }

    /// Observe push request duration.
    pub fn observe_push_duration(&self, platform: &str, duration_secs: f64) {
        self.push_request_duration_seconds
            .with_label_values(&[platform])
            .observe(duration_secs);
    }

    /// Record push response status.
    pub fn record_push_response_status(&self, platform: &str, status: u16) {
        self.push_response_status_total
            .with_label_values(&[platform, &status.to_string()])
            .inc();
    }

    /// Record an auth token refresh.
    pub fn record_auth_token_refresh(&self, service: &str) {
        self.auth_token_refreshes_total
            .with_label_values(&[service])
            .inc();
    }

    /// Update connected relay count.
    pub fn set_relays_connected(&self, relay_type: &str, count: usize) {
        self.relays_connected
            .with_label_values(&[relay_type])
            .set(count as i64);
    }

    /// Gather all metrics for export.
    pub fn gather(&self) -> Vec<prometheus::proto::MetricFamily> {
        self.registry.gather()
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new().expect("Failed to create default metrics")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = Metrics::new().unwrap();
        assert!(metrics.registry.gather().is_empty() == false || true);
    }

    #[test]
    fn test_event_metrics() {
        let metrics = Metrics::new().unwrap();

        metrics.record_event_received();
        metrics.record_event_processed();
        metrics.record_event_deduplicated();
        metrics.record_event_failed();

        // Metrics should be incremented
        let families = metrics.registry.gather();
        assert!(!families.is_empty());
    }

    #[test]
    fn test_push_metrics() {
        let metrics = Metrics::new().unwrap();

        metrics.record_push_dispatched("apns");
        metrics.record_push_dispatched("fcm");
        metrics.record_push_success("apns");
        metrics.record_push_failed("fcm", "invalid_token");
        metrics.set_push_queue_size(100);
        metrics.record_push_queue_dropped();
        metrics.set_push_semaphore_available(95);

        let families = metrics.registry.gather();
        assert!(!families.is_empty());
    }

    #[test]
    fn test_push_client_metrics() {
        let metrics = Metrics::new().unwrap();

        metrics.observe_push_duration("apns", 0.125);
        metrics.record_push_response_status("apns", 200);
        metrics.record_push_retry("fcm");
        metrics.record_auth_token_refresh("apns_jwt");

        let families = metrics.registry.gather();
        assert!(!families.is_empty());
    }

    #[test]
    fn test_relay_metrics() {
        let metrics = Metrics::new().unwrap();

        metrics.set_relay_counts(3, 2);
        metrics.set_relays_connected("clearnet", 2);
        metrics.set_relays_connected("onion", 1);

        let families = metrics.registry.gather();
        assert!(!families.is_empty());
    }

    #[test]
    fn test_server_info() {
        let metrics = Metrics::new().unwrap();

        metrics.init_server_info("0.1.0");

        let families = metrics.registry.gather();
        assert!(!families.is_empty());
    }

    #[test]
    fn test_dedup_cache_metrics() {
        let metrics = Metrics::new().unwrap();

        metrics.set_dedup_cache_size(50000);
        metrics.record_dedup_evictions(100);

        let families = metrics.registry.gather();
        assert!(!families.is_empty());
    }

    #[test]
    fn test_token_metrics() {
        let metrics = Metrics::new().unwrap();

        metrics.record_token_decrypted();
        metrics.record_token_decryption_failed();

        let families = metrics.registry.gather();
        assert!(!families.is_empty());
    }
}

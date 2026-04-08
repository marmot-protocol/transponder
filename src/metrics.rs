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
    Gauge, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, Opts, Registry,
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

    /// Current number of events actively being processed.
    pub events_in_flight: IntGauge,

    /// End-to-end duration of event processing by outcome.
    pub event_processing_duration_seconds: HistogramVec,

    /// Duration of gift-wrap unwrap operations by outcome.
    pub gift_wrap_unwrap_duration_seconds: HistogramVec,

    /// Duration of notification parsing operations by outcome.
    pub notification_parse_duration_seconds: HistogramVec,

    /// Number of encrypted tokens carried by each parsed event.
    pub tokens_per_event: Histogram,

    /// Size in bytes of the base64-decoded encrypted token blob from kind 446
    /// notification content.
    pub notification_content_size_bytes: Histogram,

    /// Current size of the deduplication cache.
    pub dedup_cache_size: IntGauge,

    /// Total number of entries evicted from dedup cache during cleanup.
    pub dedup_cache_evictions_total: IntCounter,

    // === Token Rate Limiting Metrics ===
    /// Total number of tokens rate limited (by cache type and reason).
    pub tokens_rate_limited_total: IntCounterVec,

    /// Current size of rate limit caches (by type).
    pub rate_limit_cache_size: IntGaugeVec,

    /// Total number of entries evicted from rate limit caches (by type).
    pub rate_limit_evictions_total: IntCounterVec,

    /// Total number of tokens successfully decrypted.
    pub tokens_decrypted_total: IntCounter,

    /// Total number of token decryption failures.
    pub tokens_decryption_failed_total: IntCounter,

    /// Duration of individual token decrypt operations by outcome.
    pub token_decrypt_duration_seconds: HistogramVec,

    /// Number of notifications admitted to the push dispatcher per event.
    pub notifications_admitted_per_event: Histogram,

    // === Push Dispatcher Metrics ===
    /// Total number of notifications dispatched to push services.
    pub push_dispatched_total: IntCounterVec,

    /// Total number of successful push notifications.
    pub push_success_total: IntCounterVec,

    /// Total number of failed push notifications (by platform and reason).
    pub push_failed_total: IntCounterVec,

    /// Current number of items in the push queue.
    pub push_queue_size: IntGauge,

    /// Maximum number of items the push queue can hold.
    pub push_queue_capacity: IntGauge,

    /// Number of available semaphore permits for concurrent pushes.
    pub push_semaphore_available: IntGauge,

    /// Maximum number of concurrent outbound push requests.
    pub push_concurrency_limit: IntGauge,

    /// Total number of notifications rejected because the push queue was full,
    /// the dispatcher was shutting down, or the queue channel was closed.
    pub push_queue_rejected_total: IntCounter,

    /// Duration of push dispatcher admission by outcome.
    pub push_dispatch_admission_duration_seconds: HistogramVec,

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

    /// Total number of lagged relay notification events encountered.
    pub relay_notifications_lagged_total: IntCounter,

    /// Total number of relay notifications dropped because the receiver lagged.
    pub relay_notifications_dropped_total: IntCounter,

    // === Server Metrics ===
    /// Timestamp when the server started (Unix seconds).
    pub server_start_time_seconds: Gauge,

    /// Server version information.
    pub server_info: IntGaugeVec,
}

/// Fixed set of outcome label values used by the event-level processing histogram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventOutcome {
    /// Event processing failed.
    Failed,
    /// Event was processed successfully.
    Processed,
    /// Event was skipped because it was already seen.
    Duplicate,
}

impl EventOutcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Failed => "failed",
            Self::Processed => "processed",
            Self::Duplicate => "duplicate",
        }
    }
}

/// Fixed set of outcome label values used by sub-operation histograms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationOutcome {
    /// Operation completed successfully.
    Success,
    /// Operation failed.
    Failed,
}

impl OperationOutcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failed => "failed",
        }
    }
}

const EVENT_DURATION_BUCKETS: [f64; 12] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];
const PARSE_DURATION_BUCKETS: [f64; 10] = [
    0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1,
];
const TOKEN_DECRYPT_DURATION_BUCKETS: [f64; 10] = [
    0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05,
];
const PUSH_ADMISSION_DURATION_BUCKETS: [f64; 8] =
    [0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01];
const PER_EVENT_COUNT_BUCKETS: [f64; 9] = [1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0];
const NOTIFICATION_CONTENT_SIZE_BUCKETS: [f64; 9] = [
    128.0, 256.0, 512.0, 1024.0, 2048.0, 4096.0, 8192.0, 16384.0, 32768.0,
];

fn observe_label_value(histogram: &HistogramVec, label: &str, value: f64) {
    histogram.with_label_values(&[label]).observe(value);
}

fn set_usize_gauge(gauge: &IntGauge, value: usize) {
    gauge.set(value as i64);
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

        let events_in_flight = IntGauge::with_opts(Opts::new(
            "transponder_events_in_flight",
            "Current number of events actively being processed",
        ))?;
        registry.register(Box::new(events_in_flight.clone()))?;

        let event_processing_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "transponder_event_processing_duration_seconds",
                "End-to-end duration of event processing by outcome",
            )
            .buckets(EVENT_DURATION_BUCKETS.to_vec()),
            &["outcome"],
        )?;
        registry.register(Box::new(event_processing_duration_seconds.clone()))?;

        let gift_wrap_unwrap_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "transponder_gift_wrap_unwrap_duration_seconds",
                "Duration of gift-wrap unwrap operations by outcome",
            )
            .buckets(EVENT_DURATION_BUCKETS.to_vec()),
            &["outcome"],
        )?;
        registry.register(Box::new(gift_wrap_unwrap_duration_seconds.clone()))?;

        let notification_parse_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "transponder_notification_parse_duration_seconds",
                "Duration of notification parsing operations by outcome",
            )
            .buckets(PARSE_DURATION_BUCKETS.to_vec()),
            &["outcome"],
        )?;
        registry.register(Box::new(notification_parse_duration_seconds.clone()))?;

        let tokens_per_event = Histogram::with_opts(
            HistogramOpts::new(
                "transponder_tokens_per_event",
                "Number of encrypted tokens carried by each parsed event",
            )
            .buckets(PER_EVENT_COUNT_BUCKETS.to_vec()),
        )?;
        registry.register(Box::new(tokens_per_event.clone()))?;

        let notification_content_size_bytes = Histogram::with_opts(
            HistogramOpts::new(
                "transponder_notification_content_size_bytes",
                "Size in bytes of the base64-decoded encrypted token blob from kind 446 notification content",
            )
            .buckets(NOTIFICATION_CONTENT_SIZE_BUCKETS.to_vec()),
        )?;
        registry.register(Box::new(notification_content_size_bytes.clone()))?;

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

        // === Token Rate Limiting Metrics ===
        let tokens_rate_limited_total = IntCounterVec::new(
            Opts::new(
                "transponder_tokens_rate_limited_total",
                "Total number of tokens skipped due to rate limiting",
            ),
            &["type", "reason"],
        )?;
        registry.register(Box::new(tokens_rate_limited_total.clone()))?;

        let rate_limit_cache_size = IntGaugeVec::new(
            Opts::new(
                "transponder_rate_limit_cache_size",
                "Current number of entries in rate limit caches",
            ),
            &["type"],
        )?;
        registry.register(Box::new(rate_limit_cache_size.clone()))?;

        let rate_limit_evictions_total = IntCounterVec::new(
            Opts::new(
                "transponder_rate_limit_evictions_total",
                "Total number of entries evicted from rate limit caches",
            ),
            &["type"],
        )?;
        registry.register(Box::new(rate_limit_evictions_total.clone()))?;

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

        let token_decrypt_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "transponder_token_decrypt_duration_seconds",
                "Duration of individual token decrypt operations by outcome",
            )
            .buckets(TOKEN_DECRYPT_DURATION_BUCKETS.to_vec()),
            &["outcome"],
        )?;
        registry.register(Box::new(token_decrypt_duration_seconds.clone()))?;

        let notifications_admitted_per_event = Histogram::with_opts(
            HistogramOpts::new(
                "transponder_notifications_admitted_per_event",
                "Number of notifications admitted to the push dispatcher per event",
            )
            .buckets(PER_EVENT_COUNT_BUCKETS.to_vec()),
        )?;
        registry.register(Box::new(notifications_admitted_per_event.clone()))?;

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

        let push_queue_capacity = IntGauge::with_opts(Opts::new(
            "transponder_push_queue_capacity",
            "Maximum number of notifications the push queue can hold",
        ))?;
        registry.register(Box::new(push_queue_capacity.clone()))?;

        let push_semaphore_available = IntGauge::with_opts(Opts::new(
            "transponder_push_semaphore_available",
            "Number of available permits for concurrent push requests",
        ))?;
        registry.register(Box::new(push_semaphore_available.clone()))?;

        let push_concurrency_limit = IntGauge::with_opts(Opts::new(
            "transponder_push_concurrency_limit",
            "Maximum number of concurrent outbound push requests",
        ))?;
        registry.register(Box::new(push_concurrency_limit.clone()))?;

        let push_queue_rejected_total = IntCounter::with_opts(Opts::new(
            "transponder_push_queue_rejected_total",
            "Total number of notifications rejected because the push queue was full, the dispatcher was shutting down, or the queue channel was closed",
        ))?;
        registry.register(Box::new(push_queue_rejected_total.clone()))?;

        let push_dispatch_admission_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "transponder_push_dispatch_admission_duration_seconds",
                "Duration of push dispatcher admission by outcome",
            )
            .buckets(PUSH_ADMISSION_DURATION_BUCKETS.to_vec()),
            &["outcome"],
        )?;
        registry.register(Box::new(push_dispatch_admission_duration_seconds.clone()))?;

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

        let relay_notifications_lagged_total = IntCounter::with_opts(Opts::new(
            "transponder_relay_notifications_lagged_total",
            "Total number of lagged relay notification events encountered",
        ))?;
        registry.register(Box::new(relay_notifications_lagged_total.clone()))?;

        let relay_notifications_dropped_total = IntCounter::with_opts(Opts::new(
            "transponder_relay_notifications_dropped_total",
            "Total number of relay notifications dropped because the receiver lagged",
        ))?;
        registry.register(Box::new(relay_notifications_dropped_total.clone()))?;

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
            events_in_flight,
            event_processing_duration_seconds,
            gift_wrap_unwrap_duration_seconds,
            notification_parse_duration_seconds,
            tokens_per_event,
            notification_content_size_bytes,
            dedup_cache_size,
            dedup_cache_evictions_total,
            tokens_rate_limited_total,
            rate_limit_cache_size,
            rate_limit_evictions_total,
            tokens_decrypted_total,
            tokens_decryption_failed_total,
            token_decrypt_duration_seconds,
            notifications_admitted_per_event,
            push_dispatched_total,
            push_success_total,
            push_failed_total,
            push_queue_size,
            push_queue_capacity,
            push_semaphore_available,
            push_concurrency_limit,
            push_queue_rejected_total,
            push_dispatch_admission_duration_seconds,
            push_retries_total,
            push_request_duration_seconds,
            push_response_status_total,
            auth_token_refreshes_total,
            relays_connected,
            relays_configured,
            relay_notifications_lagged_total,
            relay_notifications_dropped_total,
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

    /// Increment the number of in-flight events.
    pub fn inc_events_in_flight(&self) {
        self.events_in_flight.inc();
    }

    /// Decrement the number of in-flight events.
    pub fn dec_events_in_flight(&self) {
        self.events_in_flight.dec();
    }

    /// Observe end-to-end event processing duration.
    pub fn observe_event_processing_duration(&self, outcome: EventOutcome, duration_secs: f64) {
        observe_label_value(
            &self.event_processing_duration_seconds,
            outcome.as_str(),
            duration_secs,
        );
    }

    /// Observe gift-wrap unwrap duration.
    pub fn observe_gift_wrap_unwrap_duration(&self, outcome: OperationOutcome, duration_secs: f64) {
        observe_label_value(
            &self.gift_wrap_unwrap_duration_seconds,
            outcome.as_str(),
            duration_secs,
        );
    }

    /// Observe notification parse duration.
    pub fn observe_notification_parse_duration(
        &self,
        outcome: OperationOutcome,
        duration_secs: f64,
    ) {
        observe_label_value(
            &self.notification_parse_duration_seconds,
            outcome.as_str(),
            duration_secs,
        );
    }

    /// Observe encrypted token count per event.
    pub fn observe_tokens_per_event(&self, count: usize) {
        self.tokens_per_event.observe(count as f64);
    }

    /// Observe the size in bytes of the base64-decoded encrypted token blob.
    pub fn observe_notification_content_size_bytes(&self, size: usize) {
        self.notification_content_size_bytes.observe(size as f64);
    }

    /// Update dedup cache size.
    pub fn set_dedup_cache_size(&self, size: usize) {
        set_usize_gauge(&self.dedup_cache_size, size);
    }

    /// Record dedup cache evictions.
    pub fn record_dedup_evictions(&self, count: usize) {
        self.dedup_cache_evictions_total.inc_by(count as u64);
    }

    /// Record a rate limited token.
    ///
    /// `cache_type` should be "encrypted_token" or "device_token".
    /// `reason` should be "minute" or "hour".
    pub fn record_rate_limited(&self, cache_type: &str, reason: Option<&str>) {
        self.tokens_rate_limited_total
            .with_label_values(&[cache_type, reason.unwrap_or("unknown")])
            .inc();
    }

    /// Update rate limit cache size.
    ///
    /// `cache_type` should be "encrypted_token" or "device_token".
    pub fn set_rate_limit_cache_size(&self, cache_type: &str, size: usize) {
        self.rate_limit_cache_size
            .with_label_values(&[cache_type])
            .set(size as i64);
    }

    /// Record rate limit cache evictions.
    ///
    /// `cache_type` should be "encrypted_token" or "device_token".
    pub fn record_rate_limit_evictions(&self, cache_type: &str, count: usize) {
        self.rate_limit_evictions_total
            .with_label_values(&[cache_type])
            .inc_by(count as u64);
    }

    /// Record a successful token decryption.
    pub fn record_token_decrypted(&self) {
        self.tokens_decrypted_total.inc();
    }

    /// Record a failed token decryption.
    pub fn record_token_decryption_failed(&self) {
        self.tokens_decryption_failed_total.inc();
    }

    /// Observe per-token decryption duration.
    pub fn observe_token_decrypt_duration(&self, outcome: OperationOutcome, duration_secs: f64) {
        observe_label_value(
            &self.token_decrypt_duration_seconds,
            outcome.as_str(),
            duration_secs,
        );
    }

    /// Observe the number of notifications admitted to the push dispatcher per event.
    pub fn observe_notifications_admitted_per_event(&self, count: usize) {
        self.notifications_admitted_per_event.observe(count as f64);
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
        set_usize_gauge(&self.push_queue_size, size);
    }

    /// Update the push queue capacity.
    pub fn set_push_queue_capacity(&self, size: usize) {
        set_usize_gauge(&self.push_queue_capacity, size);
    }

    /// Update available semaphore permits.
    pub fn set_push_semaphore_available(&self, available: usize) {
        set_usize_gauge(&self.push_semaphore_available, available);
    }

    /// Update the push concurrency limit.
    pub fn set_push_concurrency_limit(&self, limit: usize) {
        set_usize_gauge(&self.push_concurrency_limit, limit);
    }

    /// Record a push queue rejection.
    pub fn record_push_queue_rejected(&self, count: u64) {
        self.push_queue_rejected_total.inc_by(count);
    }

    /// Observe push dispatcher admission duration.
    pub fn observe_push_dispatch_admission_duration(
        &self,
        outcome: OperationOutcome,
        duration_secs: f64,
    ) {
        observe_label_value(
            &self.push_dispatch_admission_duration_seconds,
            outcome.as_str(),
            duration_secs,
        );
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

    /// Record a lagged relay notification event.
    pub fn record_relay_notifications_lagged(&self) {
        self.relay_notifications_lagged_total.inc();
    }

    /// Record relay notifications dropped due to receiver lag.
    pub fn record_relay_notifications_dropped(&self, count: u64) {
        self.relay_notifications_dropped_total.inc_by(count);
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
    use crate::test_metrics::{
        counter_value, gauge_value, histogram_sample_count, histogram_sample_sum,
    };

    #[test]
    fn test_metrics_creation() {
        let metrics = Metrics::new().unwrap();
        assert!(!metrics.registry.gather().is_empty());
    }

    #[test]
    fn test_event_metrics() {
        let metrics = Metrics::new().unwrap();

        metrics.record_event_received();
        metrics.record_event_processed();
        metrics.record_event_deduplicated();
        metrics.record_event_failed();
        metrics.inc_events_in_flight();
        metrics.observe_event_processing_duration(EventOutcome::Processed, 0.01);
        metrics.observe_gift_wrap_unwrap_duration(OperationOutcome::Success, 0.005);
        metrics.observe_notification_parse_duration(OperationOutcome::Success, 0.001);
        metrics.observe_tokens_per_event(3);
        metrics.observe_notification_content_size_bytes(512);
        metrics.dec_events_in_flight();

        assert_eq!(
            counter_value(&metrics, "transponder_events_received_total", &[]),
            1.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_events_processed_total", &[]),
            1.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_events_deduplicated_total", &[]),
            1.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_events_failed_total", &[]),
            1.0
        );
        assert_eq!(
            gauge_value(&metrics, "transponder_events_in_flight", &[]),
            0.0
        );
        assert_eq!(
            histogram_sample_count(
                &metrics,
                "transponder_event_processing_duration_seconds",
                &[("outcome", EventOutcome::Processed.as_str())],
            ),
            1
        );
        assert_eq!(
            histogram_sample_count(
                &metrics,
                "transponder_gift_wrap_unwrap_duration_seconds",
                &[("outcome", OperationOutcome::Success.as_str())],
            ),
            1
        );
        assert_eq!(
            histogram_sample_count(
                &metrics,
                "transponder_notification_parse_duration_seconds",
                &[("outcome", OperationOutcome::Success.as_str())],
            ),
            1
        );
        assert_eq!(
            histogram_sample_count(&metrics, "transponder_tokens_per_event", &[]),
            1
        );
        assert_eq!(
            histogram_sample_sum(&metrics, "transponder_tokens_per_event", &[]),
            3.0
        );
        assert_eq!(
            histogram_sample_count(&metrics, "transponder_notification_content_size_bytes", &[]),
            1
        );
        assert_eq!(
            histogram_sample_sum(&metrics, "transponder_notification_content_size_bytes", &[]),
            512.0
        );
    }

    #[test]
    fn test_push_metrics() {
        let metrics = Metrics::new().unwrap();

        metrics.record_push_dispatched("apns");
        metrics.record_push_dispatched("fcm");
        metrics.record_push_success("apns");
        metrics.record_push_failed("fcm", "invalid_token");
        metrics.set_push_queue_size(100);
        metrics.set_push_queue_capacity(10_000);
        metrics.set_push_semaphore_available(95);
        metrics.set_push_concurrency_limit(100);
        metrics.record_push_queue_rejected(2);
        metrics.observe_push_dispatch_admission_duration(OperationOutcome::Success, 0.001);
        metrics.observe_notifications_admitted_per_event(2);

        assert_eq!(
            counter_value(
                &metrics,
                "transponder_push_dispatched_total",
                &[("platform", "apns")]
            ),
            1.0
        );
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_push_dispatched_total",
                &[("platform", "fcm")]
            ),
            1.0
        );
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_push_success_total",
                &[("platform", "apns")]
            ),
            1.0
        );
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_push_failed_total",
                &[("platform", "fcm"), ("reason", "invalid_token")],
            ),
            1.0
        );
        assert_eq!(
            gauge_value(&metrics, "transponder_push_queue_size", &[]),
            100.0
        );
        assert_eq!(
            gauge_value(&metrics, "transponder_push_queue_capacity", &[]),
            10_000.0
        );
        assert_eq!(
            gauge_value(&metrics, "transponder_push_semaphore_available", &[]),
            95.0
        );
        assert_eq!(
            gauge_value(&metrics, "transponder_push_concurrency_limit", &[]),
            100.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_push_queue_rejected_total", &[]),
            2.0
        );
        assert_eq!(
            histogram_sample_count(
                &metrics,
                "transponder_push_dispatch_admission_duration_seconds",
                &[("outcome", OperationOutcome::Success.as_str())],
            ),
            1
        );
        assert_eq!(
            histogram_sample_count(
                &metrics,
                "transponder_notifications_admitted_per_event",
                &[]
            ),
            1
        );
        assert_eq!(
            histogram_sample_sum(
                &metrics,
                "transponder_notifications_admitted_per_event",
                &[]
            ),
            2.0
        );
    }

    #[test]
    fn test_push_client_metrics() {
        let metrics = Metrics::new().unwrap();

        metrics.observe_push_duration("apns", 0.125);
        metrics.record_push_response_status("apns", 200);
        metrics.record_push_retry("fcm");
        metrics.record_auth_token_refresh("apns_jwt");

        assert_eq!(
            histogram_sample_count(
                &metrics,
                "transponder_push_request_duration_seconds",
                &[("platform", "apns")],
            ),
            1
        );
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_push_response_status_total",
                &[("platform", "apns"), ("status", "200")],
            ),
            1.0
        );
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_push_retries_total",
                &[("platform", "fcm")]
            ),
            1.0
        );
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_auth_token_refreshes_total",
                &[("service", "apns_jwt")],
            ),
            1.0
        );
    }

    #[test]
    fn test_relay_metrics() {
        let metrics = Metrics::new().unwrap();

        metrics.set_relay_counts(3, 2);
        metrics.set_relays_connected("clearnet", 2);
        metrics.set_relays_connected("onion", 1);
        metrics.record_relay_notifications_lagged();
        metrics.record_relay_notifications_dropped(4);

        assert_eq!(
            gauge_value(
                &metrics,
                "transponder_relays_configured",
                &[("type", "clearnet")]
            ),
            3.0
        );
        assert_eq!(
            gauge_value(
                &metrics,
                "transponder_relays_configured",
                &[("type", "onion")]
            ),
            2.0
        );
        assert_eq!(
            gauge_value(
                &metrics,
                "transponder_relays_connected",
                &[("type", "clearnet")]
            ),
            2.0
        );
        assert_eq!(
            gauge_value(
                &metrics,
                "transponder_relays_connected",
                &[("type", "onion")]
            ),
            1.0
        );
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_relay_notifications_lagged_total",
                &[]
            ),
            1.0
        );
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_relay_notifications_dropped_total",
                &[]
            ),
            4.0
        );
    }

    #[test]
    fn test_server_info() {
        let metrics = Metrics::new().unwrap();

        metrics.init_server_info("0.1.0");

        assert!(gauge_value(&metrics, "transponder_server_start_time_seconds", &[]) > 0.0);
        assert_eq!(
            gauge_value(&metrics, "transponder_server_info", &[("version", "0.1.0")]),
            1.0
        );
    }

    #[test]
    fn test_dedup_cache_metrics() {
        let metrics = Metrics::new().unwrap();

        metrics.set_dedup_cache_size(50000);
        metrics.record_dedup_evictions(100);

        assert_eq!(
            gauge_value(&metrics, "transponder_dedup_cache_size", &[]),
            50_000.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_dedup_cache_evictions_total", &[]),
            100.0
        );
    }

    #[test]
    fn test_token_metrics() {
        let metrics = Metrics::new().unwrap();

        metrics.record_token_decrypted();
        metrics.record_token_decryption_failed();
        metrics.observe_token_decrypt_duration(OperationOutcome::Success, 0.0005);
        metrics.observe_token_decrypt_duration(OperationOutcome::Failed, 0.0007);

        assert_eq!(
            counter_value(&metrics, "transponder_tokens_decrypted_total", &[]),
            1.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_tokens_decryption_failed_total", &[]),
            1.0
        );
        assert_eq!(
            histogram_sample_count(
                &metrics,
                "transponder_token_decrypt_duration_seconds",
                &[("outcome", OperationOutcome::Success.as_str())],
            ),
            1
        );
        assert_eq!(
            histogram_sample_count(
                &metrics,
                "transponder_token_decrypt_duration_seconds",
                &[("outcome", OperationOutcome::Failed.as_str())],
            ),
            1
        );
    }

    #[test]
    fn test_rate_limit_metrics_creation() {
        let metrics = Metrics::new().unwrap();

        // Verify rate limit metrics exist by exercising them
        metrics.record_rate_limited("encrypted_token", Some("minute"));
        metrics.record_rate_limited("device_token", Some("hour"));

        let families = metrics.registry.gather();
        let rate_limit_metric = families
            .iter()
            .find(|f| f.name() == "transponder_tokens_rate_limited_total");
        assert!(rate_limit_metric.is_some());
    }

    #[test]
    fn test_record_rate_limited() {
        let metrics = Metrics::new().unwrap();

        metrics.record_rate_limited("encrypted_token", Some("minute"));
        metrics.record_rate_limited("encrypted_token", Some("minute"));
        metrics.record_rate_limited("encrypted_token", Some("hour"));
        metrics.record_rate_limited("device_token", Some("minute"));
        metrics.record_rate_limited("device_token", None);

        // Verify counters incremented correctly
        let encrypted_minute = metrics
            .tokens_rate_limited_total
            .with_label_values(&["encrypted_token", "minute"])
            .get();
        let encrypted_hour = metrics
            .tokens_rate_limited_total
            .with_label_values(&["encrypted_token", "hour"])
            .get();
        let device_minute = metrics
            .tokens_rate_limited_total
            .with_label_values(&["device_token", "minute"])
            .get();
        let device_unknown = metrics
            .tokens_rate_limited_total
            .with_label_values(&["device_token", "unknown"])
            .get();

        assert_eq!(encrypted_minute, 2);
        assert_eq!(encrypted_hour, 1);
        assert_eq!(device_minute, 1);
        assert_eq!(device_unknown, 1);
    }

    #[test]
    fn test_set_rate_limit_cache_size() {
        let metrics = Metrics::new().unwrap();

        metrics.set_rate_limit_cache_size("encrypted_token", 5000);
        metrics.set_rate_limit_cache_size("device_token", 3000);

        let encrypted_size = metrics
            .rate_limit_cache_size
            .with_label_values(&["encrypted_token"])
            .get();
        let device_size = metrics
            .rate_limit_cache_size
            .with_label_values(&["device_token"])
            .get();

        assert_eq!(encrypted_size, 5000);
        assert_eq!(device_size, 3000);
    }

    #[test]
    fn test_record_rate_limit_evictions() {
        let metrics = Metrics::new().unwrap();

        metrics.record_rate_limit_evictions("encrypted_token", 100);
        metrics.record_rate_limit_evictions("device_token", 50);
        metrics.record_rate_limit_evictions("encrypted_token", 25);

        let encrypted_evictions = metrics
            .rate_limit_evictions_total
            .with_label_values(&["encrypted_token"])
            .get();
        let device_evictions = metrics
            .rate_limit_evictions_total
            .with_label_values(&["device_token"])
            .get();

        assert_eq!(encrypted_evictions, 125);
        assert_eq!(device_evictions, 50);
    }
}

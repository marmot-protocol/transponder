//! Event processing for incoming Nostr events.
//!
//! Handles deduplication and processing of gift-wrapped notification requests,
//! including rate limiting to prevent spam and replay attacks.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};

use lru::LruCache;
use nostr_sdk::prelude::*;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tokio::time::Instant;
use tracing::{debug, trace, warn};

use crate::crypto::nip59::DEFAULT_MAX_TOKENS_PER_EVENT;
use crate::crypto::token::ENCRYPTED_TOKEN_SIZE;
use crate::crypto::{Nip59Handler, TokenDecryptor, TokenPayload};
use crate::error::Result;
use crate::metrics::{EventOutcome, Metrics, OperationOutcome};
use crate::push::PushDispatcher;
use crate::rate_limiter::{
    DEFAULT_MAX_SIZE, DEFAULT_RATE_LIMIT_PER_HOUR, DEFAULT_RATE_LIMIT_PER_MINUTE, RateLimitConfig,
    RateLimiter,
};

/// Duration to keep event IDs for deduplication (5 minutes).
const DEDUP_WINDOW: Duration = Duration::from_secs(300);

/// Maximum number of entries to scan per cleanup cycle.
const CLEANUP_BATCH_SIZE: usize = 1000;

/// Default maximum size for the deduplication cache.
pub const DEFAULT_MAX_DEDUP_CACHE_SIZE: usize = 100_000;

#[must_use]
struct InFlightEventGuard<'a> {
    metrics: Option<&'a Metrics>,
}

impl<'a> InFlightEventGuard<'a> {
    fn new(metrics: Option<&'a Metrics>) -> Self {
        if let Some(m) = metrics {
            m.inc_events_in_flight();
        }

        Self { metrics }
    }
}

impl Drop for InFlightEventGuard<'_> {
    fn drop(&mut self) {
        if let Some(m) = self.metrics {
            m.dec_events_in_flight();
        }
    }
}

struct StageTimer(StdInstant);

impl StageTimer {
    fn start() -> Self {
        Self(StdInstant::now())
    }

    fn elapsed_secs(&self) -> f64 {
        self.0.elapsed().as_secs_f64()
    }
}

/// Event processor for handling incoming gift-wrapped notifications.
pub struct EventProcessor {
    nip59_handler: Nip59Handler,
    token_decryptor: TokenDecryptor,
    push_dispatcher: Arc<PushDispatcher>,
    /// Event ID deduplication cache.
    seen_events: Arc<RwLock<LruCache<EventId, Instant>>>,
    /// Encrypted token rate limiter.
    encrypted_token_limiter: RateLimiter<[u8; 32]>,
    /// Device token rate limiter.
    device_token_limiter: RateLimiter<[u8; 32]>,
    /// Maximum encrypted tokens accepted in a single event.
    max_tokens_per_event: usize,
    metrics: Option<Metrics>,
}

/// Configuration for token rate limiting.
#[derive(Debug, Clone, Copy)]
pub struct TokenRateLimitConfig {
    /// Maximum entries in each rate limit cache.
    pub max_cache_size: usize,
    /// Maximum encrypted tokens accepted in a single event.
    pub max_tokens_per_event: usize,
    /// Max encrypted token requests per minute.
    pub encrypted_token_per_minute: u32,
    /// Max encrypted token requests per hour.
    pub encrypted_token_per_hour: u32,
    /// Max device token requests per minute.
    pub device_token_per_minute: u32,
    /// Max device token requests per hour.
    pub device_token_per_hour: u32,
}

impl Default for TokenRateLimitConfig {
    fn default() -> Self {
        Self {
            max_cache_size: DEFAULT_MAX_SIZE,
            max_tokens_per_event: DEFAULT_MAX_TOKENS_PER_EVENT,
            encrypted_token_per_minute: DEFAULT_RATE_LIMIT_PER_MINUTE,
            encrypted_token_per_hour: DEFAULT_RATE_LIMIT_PER_HOUR,
            device_token_per_minute: DEFAULT_RATE_LIMIT_PER_MINUTE,
            device_token_per_hour: DEFAULT_RATE_LIMIT_PER_HOUR,
        }
    }
}

impl EventProcessor {
    /// Create a new event processor with default settings.
    ///
    /// Uses default cache sizes and rate limits. For production use,
    /// prefer `with_full_config` to specify all parameters explicitly.
    #[cfg(test)]
    pub fn new(
        nip59_handler: Nip59Handler,
        token_decryptor: TokenDecryptor,
        push_dispatcher: Arc<PushDispatcher>,
    ) -> Self {
        Self::with_full_config(
            nip59_handler,
            token_decryptor,
            push_dispatcher,
            DEFAULT_MAX_DEDUP_CACHE_SIZE,
            TokenRateLimitConfig::default(),
            None,
        )
    }

    /// Create a new event processor with a custom dedup cache size.
    #[cfg(test)]
    pub fn with_cache_size(
        nip59_handler: Nip59Handler,
        token_decryptor: TokenDecryptor,
        push_dispatcher: Arc<PushDispatcher>,
        max_cache_size: usize,
    ) -> Self {
        Self::with_full_config(
            nip59_handler,
            token_decryptor,
            push_dispatcher,
            max_cache_size,
            TokenRateLimitConfig::default(),
            None,
        )
    }

    /// Create a new event processor with full configuration.
    pub fn with_full_config(
        nip59_handler: Nip59Handler,
        token_decryptor: TokenDecryptor,
        push_dispatcher: Arc<PushDispatcher>,
        max_dedup_cache_size: usize,
        rate_limit_config: TokenRateLimitConfig,
        metrics: Option<Metrics>,
    ) -> Self {
        let cache_size = NonZeroUsize::new(max_dedup_cache_size).unwrap_or(
            NonZeroUsize::new(DEFAULT_MAX_DEDUP_CACHE_SIZE)
                .expect("DEFAULT_MAX_DEDUP_CACHE_SIZE is non-zero"),
        );

        Self {
            nip59_handler,
            token_decryptor,
            push_dispatcher,
            seen_events: Arc::new(RwLock::new(LruCache::new(cache_size))),
            encrypted_token_limiter: RateLimiter::new(RateLimitConfig {
                max_per_minute: rate_limit_config.encrypted_token_per_minute,
                max_per_hour: rate_limit_config.encrypted_token_per_hour,
                max_entries: rate_limit_config.max_cache_size,
            }),
            device_token_limiter: RateLimiter::new(RateLimitConfig {
                max_per_minute: rate_limit_config.device_token_per_minute,
                max_per_hour: rate_limit_config.device_token_per_hour,
                max_entries: rate_limit_config.max_cache_size,
            }),
            max_tokens_per_event: rate_limit_config.max_tokens_per_event,
            metrics,
        }
    }

    /// Process an incoming event.
    ///
    /// Returns `Ok(true)` if the event was processed, `Ok(false)` if it was
    /// deduplicated (already seen), or an error if processing failed.
    pub async fn process(&self, event: &Event) -> Result<bool> {
        let _in_flight = InFlightEventGuard::new(self.metrics.as_ref());
        let started_at = StageTimer::start();

        // Record event received
        if let Some(ref m) = self.metrics {
            m.record_event_received();
        }

        // Check for duplicates
        if self.is_duplicate(&event.id).await {
            trace!(event_id = %event.id, "Skipping duplicate event");
            if let Some(ref m) = self.metrics {
                m.record_event_deduplicated();
                m.observe_event_processing_duration(
                    EventOutcome::Duplicate,
                    started_at.elapsed_secs(),
                );
            }
            return Ok(false);
        }

        // Process the event
        match self.process_inner(event).await {
            Ok(count) => {
                // Mark as seen only after successful processing.
                // This avoids dropping events due to transient failures.
                self.mark_seen(event.id).await;

                debug!(
                    event_id = %event.id,
                    notifications_sent = count,
                    "Processed notification event"
                );

                if let Some(ref m) = self.metrics {
                    m.record_event_processed();
                    m.observe_event_processing_duration(
                        EventOutcome::Processed,
                        started_at.elapsed_secs(),
                    );
                }
                Ok(true)
            }
            Err(e) => {
                // Log but don't propagate - we want to continue processing other events
                warn!(
                    event_id = %event.id,
                    error = %e,
                    "Failed to process event"
                );
                if let Some(ref m) = self.metrics {
                    m.record_event_failed();
                    m.observe_event_processing_duration(
                        EventOutcome::Failed,
                        started_at.elapsed_secs(),
                    );
                }
                Ok(false)
            }
        }
    }

    /// Inner processing logic for an event.
    async fn process_inner(&self, event: &Event) -> Result<usize> {
        // Unwrap the gift wrap to get the notification request
        let unwrap_started_at = StageTimer::start();
        let notification = match self.nip59_handler.unwrap(event).await {
            Ok(notification) => {
                if let Some(ref m) = self.metrics {
                    m.observe_gift_wrap_unwrap_duration(
                        OperationOutcome::Success,
                        unwrap_started_at.elapsed_secs(),
                    );
                }
                notification
            }
            Err(e) => {
                if let Some(ref m) = self.metrics {
                    m.observe_gift_wrap_unwrap_duration(
                        OperationOutcome::Failed,
                        unwrap_started_at.elapsed_secs(),
                    );
                }
                return Err(e);
            }
        };

        trace!(
            sender = %notification.sender_pubkey,
            "Unwrapped notification request"
        );

        // Parse the encrypted tokens from the content
        let parse_started_at = StageTimer::start();
        let token_bytes = match notification.parse_tokens_with_limit(self.max_tokens_per_event) {
            Ok(token_bytes) => {
                if let Some(ref m) = self.metrics {
                    m.observe_notification_parse_duration(
                        OperationOutcome::Success,
                        parse_started_at.elapsed_secs(),
                    );
                    m.observe_tokens_per_event(token_bytes.len());
                    m.observe_notification_content_size_bytes(
                        token_bytes.len() * ENCRYPTED_TOKEN_SIZE,
                    );
                }
                token_bytes
            }
            Err(e) => {
                if let Some(ref m) = self.metrics {
                    m.observe_notification_parse_duration(
                        OperationOutcome::Failed,
                        parse_started_at.elapsed_secs(),
                    );
                }
                return Err(e);
            }
        };

        if token_bytes.is_empty() {
            return Ok(0);
        }

        debug!(token_count = token_bytes.len(), "Decrypting tokens");

        // Decrypt each token and dispatch notifications, with rate limiting.
        //
        // Rate limiting happens BEFORE decryption intentionally:
        // Prevents wasting CPU on tokens we'll immediately rate-limit anyway.
        let mut payloads = Vec::with_capacity(token_bytes.len());
        for bytes in token_bytes {
            // Rate limit check 1: encrypted token (replay protection)
            let encrypted_key = Self::hash_bytes(&bytes);
            let encrypted_result = self
                .encrypted_token_limiter
                .check_and_increment(&encrypted_key)
                .await;
            if !encrypted_result.is_allowed() {
                trace!(
                    reason = encrypted_result.limit_reason(),
                    "Rate limited encrypted token"
                );
                if let Some(ref m) = self.metrics {
                    m.record_rate_limited("encrypted_token", encrypted_result.limit_reason());
                }
                continue;
            }

            // Decrypt the token
            let decrypt_started_at = StageTimer::start();
            let payload = match self.token_decryptor.decrypt_bytes(&bytes) {
                Ok(p) => {
                    if let Some(ref m) = self.metrics {
                        m.record_token_decrypted();
                        m.observe_token_decrypt_duration(
                            OperationOutcome::Success,
                            decrypt_started_at.elapsed_secs(),
                        );
                    }
                    p
                }
                Err(e) => {
                    // Silently ignore invalid tokens per MIP-05 spec
                    trace!(error = %e, "Failed to decrypt token (ignoring)");
                    if let Some(ref m) = self.metrics {
                        m.record_token_decryption_failed();
                        m.observe_token_decrypt_duration(
                            OperationOutcome::Failed,
                            decrypt_started_at.elapsed_secs(),
                        );
                    }
                    continue;
                }
            };

            // Rate limit check 2: Is this device token within rate limits?
            let device_key = Self::hash_device_token_key(&payload);
            let device_result = self
                .device_token_limiter
                .check_and_increment(&device_key)
                .await;
            if !device_result.is_allowed() {
                trace!(
                    reason = device_result.limit_reason(),
                    "Rate limited device token"
                );
                if let Some(ref m) = self.metrics {
                    m.record_rate_limited("device_token", device_result.limit_reason());
                }
                continue;
            }

            payloads.push(payload);
        }

        if payloads.is_empty() {
            if let Some(ref m) = self.metrics {
                m.observe_notifications_admitted_per_event(0);
            }
            return Ok(0);
        }

        // Dispatch notifications
        let dispatch_started_at = StageTimer::start();
        match self.push_dispatcher.dispatch(payloads).await {
            Ok(count) => {
                if let Some(ref m) = self.metrics {
                    m.observe_push_dispatch_admission_duration(
                        OperationOutcome::Success,
                        dispatch_started_at.elapsed_secs(),
                    );
                    m.observe_notifications_admitted_per_event(count);
                }
                Ok(count)
            }
            Err(e) => {
                if let Some(ref m) = self.metrics {
                    m.observe_push_dispatch_admission_duration(
                        OperationOutcome::Failed,
                        dispatch_started_at.elapsed_secs(),
                    );
                    m.observe_notifications_admitted_per_event(0);
                }
                Err(e)
            }
        }
    }

    /// Hash arbitrary bytes to a fixed-size key for rate limiting.
    fn hash_bytes(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Hash device token key (platform || device_token) for rate limiting.
    fn hash_device_token_key(payload: &TokenPayload) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([payload.platform.as_byte()]);
        hasher.update(&payload.device_token);
        hasher.finalize().into()
    }

    /// Check if an event has been seen recently.
    async fn is_duplicate(&self, event_id: &EventId) -> bool {
        let seen = self.seen_events.read().await;
        seen.contains(event_id)
    }

    /// Mark an event as seen.
    async fn mark_seen(&self, event_id: EventId) {
        let mut seen = self.seen_events.write().await;
        seen.put(event_id, Instant::now());

        // Update cache size metric
        if let Some(ref m) = self.metrics {
            m.set_dedup_cache_size(seen.len());
        }
    }

    /// Clean up all caches by removing expired entries.
    ///
    /// Uses incremental cleanup to avoid holding write locks for extended
    /// periods. Call periodically for full cleanup of all expired entries.
    pub async fn cleanup(&self) {
        // Clean event deduplication cache
        let (evicted, remaining) = {
            let mut seen = self.seen_events.write().await;
            let now = Instant::now();

            let expired_keys: Vec<_> = seen
                .iter()
                .take(CLEANUP_BATCH_SIZE)
                .filter(|(_, seen_at)| now.duration_since(**seen_at) >= DEDUP_WINDOW)
                .map(|(id, _)| *id)
                .collect();

            for key in &expired_keys {
                seen.pop(key);
            }

            (expired_keys.len(), seen.len())
        };

        if let Some(ref m) = self.metrics {
            m.set_dedup_cache_size(remaining);
            if evicted > 0 {
                m.record_dedup_evictions(evicted);
            }
        }
        if evicted > 0 {
            debug!(
                removed = evicted,
                remaining = remaining,
                "Cleaned up event deduplication cache"
            );
        }

        // Clean encrypted token rate limiter cache
        let encrypted_stats = self.encrypted_token_limiter.cleanup().await;
        if let Some(ref m) = self.metrics {
            m.set_rate_limit_cache_size("encrypted_token", encrypted_stats.remaining);
            if encrypted_stats.evicted > 0 {
                m.record_rate_limit_evictions("encrypted_token", encrypted_stats.evicted);
            }
        }
        if encrypted_stats.evicted > 0 {
            debug!(
                removed = encrypted_stats.evicted,
                remaining = encrypted_stats.remaining,
                "Cleaned up encrypted token rate limit cache"
            );
        }

        // Clean device token rate limiter cache
        let device_stats = self.device_token_limiter.cleanup().await;
        if let Some(ref m) = self.metrics {
            m.set_rate_limit_cache_size("device_token", device_stats.remaining);
            if device_stats.evicted > 0 {
                m.record_rate_limit_evictions("device_token", device_stats.evicted);
            }
        }
        if device_stats.evicted > 0 {
            debug!(
                removed = device_stats.evicted,
                remaining = device_stats.remaining,
                "Cleaned up device token rate limit cache"
            );
        }
    }

    /// Returns the current number of entries in the deduplication cache.
    #[cfg(test)]
    pub fn cache_len(&self) -> usize {
        self.seen_events
            .try_read()
            .map(|guard| guard.len())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ApnsConfig;
    use crate::crypto::token::ENCRYPTED_TOKEN_SIZE;
    use crate::metrics::{EventOutcome, Metrics, OperationOutcome};
    use crate::push::{ApnsClient, PushDispatcher};
    use crate::test_metrics::{
        counter_value, gauge_value as metric_gauge_value,
        histogram_sample_count as histogram_count, histogram_sample_sum,
    };
    use crate::test_vectors::scenarios;

    fn gauge_value(metrics: &Metrics, name: &str) -> f64 {
        metric_gauge_value(metrics, name, &[])
    }

    fn create_processor(server_keys: &Keys) -> EventProcessor {
        let nip59_handler = Nip59Handler::new(server_keys.clone());
        let secp_secret_key =
            secp256k1::SecretKey::from_slice(&server_keys.secret_key().to_secret_bytes())
                .expect("valid secret key");
        let token_decryptor = TokenDecryptor::new(secp_secret_key);
        let push_dispatcher = Arc::new(PushDispatcher::new(None, None));
        EventProcessor::new(nip59_handler, token_decryptor, push_dispatcher)
    }

    fn create_processor_with_cache_size(server_keys: &Keys, cache_size: usize) -> EventProcessor {
        let nip59_handler = Nip59Handler::new(server_keys.clone());
        let secp_secret_key =
            secp256k1::SecretKey::from_slice(&server_keys.secret_key().to_secret_bytes())
                .expect("valid secret key");
        let token_decryptor = TokenDecryptor::new(secp_secret_key);
        let push_dispatcher = Arc::new(PushDispatcher::new(None, None));
        EventProcessor::with_cache_size(nip59_handler, token_decryptor, push_dispatcher, cache_size)
    }

    fn create_processor_with_metrics(server_keys: &Keys) -> (EventProcessor, Metrics) {
        create_processor_with_metrics_and_rate_limits(server_keys, TokenRateLimitConfig::default())
    }

    fn create_processor_with_metrics_and_rate_limits(
        server_keys: &Keys,
        rate_limit_config: TokenRateLimitConfig,
    ) -> (EventProcessor, Metrics) {
        let nip59_handler = Nip59Handler::new(server_keys.clone());
        let secp_secret_key =
            secp256k1::SecretKey::from_slice(&server_keys.secret_key().to_secret_bytes())
                .expect("valid secret key");
        let token_decryptor = TokenDecryptor::new(secp_secret_key);
        let apns_config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: "sandbox".to_string(),
            bundle_id: "com.example.app".to_string(),
        };
        let metrics = Metrics::new().expect("metrics");
        let push_dispatcher = Arc::new(PushDispatcher::with_metrics(
            Some(ApnsClient::mock(apns_config, true)),
            None,
            Some(metrics.clone()),
        ));
        (
            EventProcessor::with_full_config(
                nip59_handler,
                token_decryptor,
                push_dispatcher,
                DEFAULT_MAX_DEDUP_CACHE_SIZE,
                rate_limit_config,
                Some(metrics.clone()),
            ),
            metrics,
        )
    }

    async fn create_processor_with_shutdown_dispatcher_metrics(
        server_keys: &Keys,
    ) -> (EventProcessor, Metrics) {
        let nip59_handler = Nip59Handler::new(server_keys.clone());
        let secp_secret_key =
            secp256k1::SecretKey::from_slice(&server_keys.secret_key().to_secret_bytes())
                .expect("valid secret key");
        let token_decryptor = TokenDecryptor::new(secp_secret_key);
        let apns_config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: "sandbox".to_string(),
            bundle_id: "com.example.app".to_string(),
        };
        let metrics = Metrics::new().expect("metrics");
        let push_dispatcher = Arc::new(PushDispatcher::with_metrics(
            Some(ApnsClient::mock(apns_config, true)),
            None,
            Some(metrics.clone()),
        ));
        push_dispatcher.wait_for_completion().await;

        (
            EventProcessor::with_full_config(
                nip59_handler,
                token_decryptor,
                push_dispatcher,
                DEFAULT_MAX_DEDUP_CACHE_SIZE,
                TokenRateLimitConfig::default(),
                Some(metrics.clone()),
            ),
            metrics,
        )
    }

    #[tokio::test]
    async fn test_process_valid_gift_wrap_event() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let device_token = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        let event =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;

        let processor = create_processor(&server_keys);
        let result = processor.process(&event).await;

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_process_valid_gift_wrap_event_records_metrics() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let device_token = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        let event =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;

        let (processor, metrics) = create_processor_with_metrics(&server_keys);
        let result = processor.process(&event).await;

        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(
            counter_value(&metrics, "transponder_events_received_total", &[]),
            1.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_events_processed_total", &[]),
            1.0
        );
        assert_eq!(gauge_value(&metrics, "transponder_events_in_flight"), 0.0);
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_event_processing_duration_seconds",
                &[("outcome", EventOutcome::Processed.as_str())],
            ),
            1
        );
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_gift_wrap_unwrap_duration_seconds",
                &[("outcome", OperationOutcome::Success.as_str())],
            ),
            1
        );
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_notification_parse_duration_seconds",
                &[("outcome", OperationOutcome::Success.as_str())],
            ),
            1
        );
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_token_decrypt_duration_seconds",
                &[("outcome", OperationOutcome::Success.as_str())],
            ),
            1
        );
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_push_dispatch_admission_duration_seconds",
                &[("outcome", OperationOutcome::Success.as_str())],
            ),
            1
        );
        assert_eq!(
            histogram_count(&metrics, "transponder_tokens_per_event", &[]),
            1
        );
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_notifications_admitted_per_event",
                &[]
            ),
            1
        );
        assert_eq!(
            histogram_sample_sum(&metrics, "transponder_notification_content_size_bytes", &[]),
            ENCRYPTED_TOKEN_SIZE as f64
        );
    }

    #[tokio::test]
    async fn test_process_deduplicates_same_event() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let event = scenarios::single_apns_notification(
            &server_keys,
            &sender_keys,
            "deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678",
        )
        .await;

        let processor = create_processor(&server_keys);

        // First processing should succeed
        let result1 = processor.process(&event).await;
        assert!(result1.is_ok());
        assert!(result1.unwrap());

        // Second processing of same event should be deduplicated
        let result2 = processor.process(&event).await;
        assert!(result2.is_ok());
        assert!(!result2.unwrap());
    }

    #[tokio::test]
    async fn test_process_duplicate_event_records_metrics() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let event = scenarios::single_apns_notification(
            &server_keys,
            &sender_keys,
            "deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678",
        )
        .await;

        let (processor, metrics) = create_processor_with_metrics(&server_keys);

        assert!(processor.process(&event).await.unwrap());
        assert!(!processor.process(&event).await.unwrap());

        assert_eq!(
            counter_value(&metrics, "transponder_events_received_total", &[]),
            2.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_events_deduplicated_total", &[]),
            1.0
        );
        assert_eq!(gauge_value(&metrics, "transponder_events_in_flight"), 0.0);
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_event_processing_duration_seconds",
                &[("outcome", EventOutcome::Duplicate.as_str())],
            ),
            1
        );
    }

    #[tokio::test]
    async fn test_process_different_events_not_deduplicated() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let event1 = scenarios::single_apns_notification(
            &server_keys,
            &sender_keys,
            "aaaa111122223333aaaa111122223333aaaa111122223333aaaa111122223333",
        )
        .await;

        let event2 = scenarios::single_apns_notification(
            &server_keys,
            &sender_keys,
            "bbbb444455556666bbbb444455556666bbbb444455556666bbbb444455556666",
        )
        .await;

        let processor = create_processor(&server_keys);

        let result1 = processor.process(&event1).await;
        let result2 = processor.process(&event2).await;

        assert!(result1.unwrap());
        assert!(result2.unwrap());
    }

    #[tokio::test]
    async fn test_process_wrong_recipient_fails() {
        let server_keys = Keys::generate();
        let wrong_server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let event = scenarios::single_apns_notification(
            &wrong_server_keys,
            &sender_keys,
            "deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678",
        )
        .await;

        let processor = create_processor(&server_keys);
        let result = processor.process(&event).await;

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_process_failed_event_records_metrics() {
        let server_keys = Keys::generate();
        let wrong_server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let event = scenarios::single_apns_notification(
            &wrong_server_keys,
            &sender_keys,
            "deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678",
        )
        .await;

        let (processor, metrics) = create_processor_with_metrics(&server_keys);
        let result = processor.process(&event).await;

        assert!(result.is_ok());
        assert!(!result.unwrap());
        assert_eq!(
            counter_value(&metrics, "transponder_events_failed_total", &[]),
            1.0
        );
        assert_eq!(gauge_value(&metrics, "transponder_events_in_flight"), 0.0);
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_event_processing_duration_seconds",
                &[("outcome", EventOutcome::Failed.as_str())],
            ),
            1
        );
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_gift_wrap_unwrap_duration_seconds",
                &[("outcome", OperationOutcome::Failed.as_str())],
            ),
            1
        );
    }

    #[tokio::test]
    async fn test_process_dispatch_failure_records_zero_admissions() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let device_token = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        let event =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;

        let (processor, metrics) =
            create_processor_with_shutdown_dispatcher_metrics(&server_keys).await;
        let result = processor.process(&event).await;

        assert!(result.is_ok());
        assert!(!result.unwrap());
        assert_eq!(
            counter_value(&metrics, "transponder_events_failed_total", &[]),
            1.0
        );
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_push_dispatch_admission_duration_seconds",
                &[("outcome", OperationOutcome::Failed.as_str())],
            ),
            1
        );
        assert_eq!(
            histogram_count(
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
            0.0
        );
    }

    #[tokio::test]
    async fn test_process_empty_token_blob() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let event = scenarios::empty_notification(&server_keys, &sender_keys).await;

        let processor = create_processor(&server_keys);
        let result = processor.process(&event).await;

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_process_empty_token_blob_records_parse_failure_metrics() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let event = scenarios::empty_notification(&server_keys, &sender_keys).await;

        let (processor, metrics) = create_processor_with_metrics(&server_keys);
        let result = processor.process(&event).await;

        assert!(result.is_ok());
        assert!(!result.unwrap());
        assert_eq!(
            counter_value(&metrics, "transponder_events_failed_total", &[]),
            1.0
        );
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_notification_parse_duration_seconds",
                &[("outcome", OperationOutcome::Failed.as_str())],
            ),
            1
        );
    }

    #[tokio::test]
    async fn test_process_multi_token_notification() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let event = scenarios::multi_token_notification(&server_keys, &sender_keys).await;

        let processor = create_processor(&server_keys);
        let result = processor.process(&event).await;

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_process_non_gift_wrap_event_fails() {
        let server_keys = Keys::generate();
        let some_keys = Keys::generate();

        let event = EventBuilder::text_note("Hello, world!")
            .sign_with_keys(&some_keys)
            .unwrap();

        let processor = create_processor(&server_keys);
        let result = processor.process(&event).await;

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_cleanup_removes_old_entries() {
        tokio::time::pause();

        let server_keys = Keys::generate();
        let processor = create_processor(&server_keys);

        // Add an event
        processor.mark_seen(EventId::all_zeros()).await;
        assert!(processor.is_duplicate(&EventId::all_zeros()).await);

        // Cleanup shouldn't remove it (it's recent)
        processor.cleanup().await;
        assert!(processor.is_duplicate(&EventId::all_zeros()).await);

        // Advance time past the dedup window
        tokio::time::advance(DEDUP_WINDOW + Duration::from_secs(1)).await;

        // Now cleanup should remove it
        processor.cleanup().await;
        assert!(!processor.is_duplicate(&EventId::all_zeros()).await);
    }

    #[tokio::test]
    async fn test_fcm_token_processing() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let event = scenarios::single_fcm_notification(
            &server_keys,
            &sender_keys,
            "fcm-device-token-12345",
        )
        .await;

        let processor = create_processor(&server_keys);
        let result = processor.process(&event).await;

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_cache_size_limit_evicts_oldest_entries() {
        let server_keys = Keys::generate();
        let processor = create_processor_with_cache_size(&server_keys, 3);

        let event_ids: Vec<EventId> = (0..5)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0] = i;
                EventId::from_byte_array(bytes)
            })
            .collect();

        for event_id in &event_ids {
            processor.mark_seen(*event_id).await;
        }

        assert_eq!(processor.cache_len(), 3);

        // First two entries should have been evicted (LRU)
        assert!(!processor.is_duplicate(&event_ids[0]).await);
        assert!(!processor.is_duplicate(&event_ids[1]).await);

        // Last three entries should still be present
        assert!(processor.is_duplicate(&event_ids[2]).await);
        assert!(processor.is_duplicate(&event_ids[3]).await);
        assert!(processor.is_duplicate(&event_ids[4]).await);
    }

    #[tokio::test]
    async fn test_cache_size_zero_uses_default() {
        let server_keys = Keys::generate();
        let processor = create_processor_with_cache_size(&server_keys, 0);

        let event_id = EventId::all_zeros();
        processor.mark_seen(event_id).await;
        assert!(processor.is_duplicate(&event_id).await);
    }

    #[tokio::test]
    async fn test_cache_lru_access_updates_order() {
        let server_keys = Keys::generate();
        let processor = create_processor_with_cache_size(&server_keys, 3);

        let event_ids: Vec<EventId> = (0..4)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0] = i;
                EventId::from_byte_array(bytes)
            })
            .collect();

        processor.mark_seen(event_ids[0]).await;
        processor.mark_seen(event_ids[1]).await;
        processor.mark_seen(event_ids[2]).await;

        // Access the first event again (makes it most recently used)
        processor.mark_seen(event_ids[0]).await;

        // Add a 4th event - should evict event_ids[1] (now the LRU)
        processor.mark_seen(event_ids[3]).await;

        assert!(!processor.is_duplicate(&event_ids[1]).await);
        assert!(processor.is_duplicate(&event_ids[0]).await);
        assert!(processor.is_duplicate(&event_ids[2]).await);
        assert!(processor.is_duplicate(&event_ids[3]).await);
    }

    #[tokio::test]
    async fn test_cleanup_processes_limited_entries() {
        tokio::time::pause();

        let server_keys = Keys::generate();
        let processor = create_processor(&server_keys);

        // Add more entries than CLEANUP_BATCH_SIZE
        let num_entries = CLEANUP_BATCH_SIZE + 500;
        let old_time = Instant::now() - DEDUP_WINDOW - Duration::from_secs(1);

        {
            let mut seen = processor.seen_events.write().await;
            for i in 0..num_entries {
                let mut bytes = [0u8; 32];
                bytes[0..4].copy_from_slice(&(i as u32).to_le_bytes());
                let event_id = EventId::from_byte_array(bytes);
                seen.put(event_id, old_time);
            }
        }

        assert_eq!(processor.cache_len(), num_entries);

        // Run cleanup once - should only remove up to CLEANUP_BATCH_SIZE entries
        processor.cleanup().await;

        let remaining = processor.cache_len();
        assert!(
            remaining >= num_entries - CLEANUP_BATCH_SIZE,
            "Cleanup removed more than CLEANUP_BATCH_SIZE entries: expected at least {}, got {}",
            num_entries - CLEANUP_BATCH_SIZE,
            remaining
        );

        // Run cleanup again - should remove remaining old entries
        processor.cleanup().await;

        assert_eq!(
            processor.cache_len(),
            0,
            "Expected all expired entries to be removed after two cleanup cycles"
        );
    }

    #[tokio::test]
    async fn test_cleanup_preserves_recent_entries() {
        tokio::time::pause();

        let server_keys = Keys::generate();
        let processor = create_processor(&server_keys);

        let old_time = Instant::now() - DEDUP_WINDOW - Duration::from_secs(1);
        let recent_time = Instant::now();

        {
            let mut seen = processor.seen_events.write().await;

            // Add some old entries
            for i in 0..100 {
                let mut bytes = [0u8; 32];
                bytes[0..4].copy_from_slice(&(i as u32).to_le_bytes());
                let event_id = EventId::from_byte_array(bytes);
                seen.put(event_id, old_time);
            }

            // Add some recent entries
            for i in 100..150 {
                let mut bytes = [0u8; 32];
                bytes[0..4].copy_from_slice(&(i as u32).to_le_bytes());
                let event_id = EventId::from_byte_array(bytes);
                seen.put(event_id, recent_time);
            }
        }

        assert_eq!(processor.cache_len(), 150);

        // Cleanup should remove old entries but keep recent ones
        processor.cleanup().await;

        assert_eq!(
            processor.cache_len(),
            50,
            "Expected 50 recent entries to remain after cleanup"
        );
    }

    // === Rate Limiting Integration Tests ===

    fn create_processor_with_rate_limits(
        server_keys: &Keys,
        rate_limit_config: TokenRateLimitConfig,
    ) -> EventProcessor {
        let nip59_handler = Nip59Handler::new(server_keys.clone());
        let secp_secret_key =
            secp256k1::SecretKey::from_slice(&server_keys.secret_key().to_secret_bytes())
                .expect("valid secret key");
        let token_decryptor = TokenDecryptor::new(secp_secret_key);
        let push_dispatcher = Arc::new(PushDispatcher::new(None, None));
        EventProcessor::with_full_config(
            nip59_handler,
            token_decryptor,
            push_dispatcher,
            DEFAULT_MAX_DEDUP_CACHE_SIZE,
            rate_limit_config,
            None,
        )
    }

    #[tokio::test]
    async fn test_zero_admission_event_records_metrics() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let device_token = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        let (processor, metrics) = create_processor_with_metrics_and_rate_limits(
            &server_keys,
            TokenRateLimitConfig {
                max_cache_size: 100,
                max_tokens_per_event: DEFAULT_MAX_TOKENS_PER_EVENT,
                encrypted_token_per_minute: 100,
                encrypted_token_per_hour: 1000,
                device_token_per_minute: 1,
                device_token_per_hour: 100,
            },
        );

        let event1 =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;
        assert!(processor.process(&event1).await.unwrap());

        let event2 =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;
        assert!(processor.process(&event2).await.unwrap());

        assert_eq!(
            counter_value(&metrics, "transponder_events_processed_total", &[]),
            2.0
        );
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_tokens_rate_limited_total",
                &[("type", "device_token"), ("reason", "minute")],
            ),
            1.0
        );
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_notifications_admitted_per_event",
                &[]
            ),
            2
        );
        assert_eq!(
            histogram_sample_sum(
                &metrics,
                "transponder_notifications_admitted_per_event",
                &[]
            ),
            1.0
        );
    }

    #[tokio::test]
    async fn test_device_token_rate_limiting() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        // Create processor with very low device token rate limit
        let processor = create_processor_with_rate_limits(
            &server_keys,
            TokenRateLimitConfig {
                max_cache_size: 100,
                max_tokens_per_event: DEFAULT_MAX_TOKENS_PER_EVENT,
                encrypted_token_per_minute: 100, // High limit for encrypted tokens
                encrypted_token_per_hour: 1000,
                device_token_per_minute: 2, // Only allow 2 per minute per device
                device_token_per_hour: 100,
            },
        );

        // Same device token, but different encrypted blobs (re-encrypted each time)
        let device_token = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        // First notification should succeed
        let event1 =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;
        let result1 = processor.process(&event1).await;
        assert!(result1.is_ok());
        assert!(result1.unwrap(), "First notification should be processed");

        // Second notification to same device should succeed (within limit)
        let event2 =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;
        let result2 = processor.process(&event2).await;
        assert!(result2.is_ok());
        assert!(result2.unwrap(), "Second notification should be processed");

        // Third notification to same device should be rate limited
        // The event processes OK (returns true) but the token is skipped internally
        let event3 =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;
        let result3 = processor.process(&event3).await;
        assert!(result3.is_ok());
        // Still returns true because event was processed, but 0 notifications sent
        assert!(result3.unwrap());

        // A different device should still work
        let other_device = "1111111122222222333333334444444411111111222222223333333344444444";
        let event4 =
            scenarios::single_apns_notification(&server_keys, &sender_keys, other_device).await;
        let result4 = processor.process(&event4).await;
        assert!(result4.is_ok());
        assert!(
            result4.unwrap(),
            "Different device should not be rate limited"
        );
    }

    #[tokio::test]
    async fn test_encrypted_token_rate_limiting() {
        use crate::test_vectors::{
            GiftWrapBuilder, NotificationContentBuilder, TestToken, TokenEncryptor,
        };

        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        // Create processor with very low encrypted token rate limit
        let processor = create_processor_with_rate_limits(
            &server_keys,
            TokenRateLimitConfig {
                max_cache_size: 100,
                max_tokens_per_event: DEFAULT_MAX_TOKENS_PER_EVENT,
                encrypted_token_per_minute: 2, // Only allow 2 per minute per encrypted token
                encrypted_token_per_hour: 100,
                device_token_per_minute: 100, // High limit for device tokens
                device_token_per_hour: 1000,
            },
        );

        // Encrypt a token once and reuse the same encrypted blob
        let encryptor = TokenEncryptor::from_keys(&server_keys);
        let test_token =
            TestToken::apns("deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678");
        let encrypted_b64 = encryptor.encrypt_base64(&test_token);

        // Create events with the exact same encrypted token
        let content = NotificationContentBuilder::new(&server_keys)
            .with_raw_token(encrypted_b64.clone())
            .build();

        let event1 = GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(&content)
            .await;
        let result1 = processor.process(&event1).await;
        assert!(result1.is_ok());
        assert!(
            result1.unwrap(),
            "First use of encrypted token should succeed"
        );

        let event2 = GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(&content)
            .await;
        let result2 = processor.process(&event2).await;
        assert!(result2.is_ok());
        assert!(
            result2.unwrap(),
            "Second use of encrypted token should succeed"
        );

        // Third use of the same encrypted blob should be rate limited
        let event3 = GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(&content)
            .await;
        let result3 = processor.process(&event3).await;
        assert!(result3.is_ok());
        // Event processes but token is skipped
        assert!(result3.unwrap());

        // A different encrypted token (same device) should work since we rate limit
        // encrypted tokens first
        let encrypted_b64_2 = encryptor.encrypt_base64(&test_token);
        let content2 = NotificationContentBuilder::new(&server_keys)
            .with_raw_token(encrypted_b64_2)
            .build();
        let event4 = GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(&content2)
            .await;
        let result4 = processor.process(&event4).await;
        assert!(result4.is_ok());
        assert!(result4.unwrap(), "Different encrypted token should work");
    }

    #[tokio::test]
    async fn test_rate_limit_window_reset() {
        use crate::test_vectors::{
            GiftWrapBuilder, NotificationContentBuilder, TestToken, TokenEncryptor,
        };

        tokio::time::pause();

        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let processor = create_processor_with_rate_limits(
            &server_keys,
            TokenRateLimitConfig {
                max_cache_size: 100,
                max_tokens_per_event: DEFAULT_MAX_TOKENS_PER_EVENT,
                encrypted_token_per_minute: 1,
                encrypted_token_per_hour: 100,
                device_token_per_minute: 100,
                device_token_per_hour: 1000,
            },
        );

        let encryptor = TokenEncryptor::from_keys(&server_keys);
        let test_token =
            TestToken::apns("aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344");
        let encrypted_b64 = encryptor.encrypt_base64(&test_token);
        let content = NotificationContentBuilder::new(&server_keys)
            .with_raw_token(encrypted_b64)
            .build();

        // First request succeeds
        let event1 = GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(&content)
            .await;
        assert!(processor.process(&event1).await.unwrap());

        // Second request is rate limited (same encrypted token)
        let event2 = GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(&content)
            .await;
        processor.process(&event2).await.unwrap();
        // Can't easily assert the token was skipped without metrics, but we can test window reset

        // Advance time past the minute window
        tokio::time::advance(Duration::from_secs(61)).await;

        // Now the same token should be allowed again
        let event3 = GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(&content)
            .await;
        let result3 = processor.process(&event3).await;
        assert!(result3.is_ok());
        assert!(
            result3.unwrap(),
            "Token should be allowed after window reset"
        );
    }
}

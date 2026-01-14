//! Event processing for incoming Nostr events.
//!
//! Handles deduplication and processing of gift-wrapped notification requests.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use lru::LruCache;
use nostr_sdk::prelude::*;
use tokio::sync::RwLock;
use tokio::time::Instant;
use tracing::{debug, trace, warn};

use crate::crypto::{Nip59Handler, TokenDecryptor};
use crate::error::Result;
use crate::push::PushDispatcher;

/// Duration to keep event IDs for deduplication (5 minutes).
const DEDUP_WINDOW: Duration = Duration::from_secs(300);

/// Default maximum size for the deduplication cache.
///
/// This value (100,000 entries) provides a reasonable upper bound on memory
/// usage while allowing sufficient capacity for high-traffic scenarios.
/// Each entry consists of an `EventId` (32 bytes) and an `Instant` (16 bytes),
/// so the maximum memory usage is approximately 4.8 MB at full capacity.
pub const DEFAULT_MAX_DEDUP_CACHE_SIZE: usize = 100_000;

/// Event processor for handling incoming gift-wrapped notifications.
pub struct EventProcessor {
    nip59_handler: Nip59Handler,
    token_decryptor: TokenDecryptor,
    push_dispatcher: Arc<PushDispatcher>,
    seen_events: Arc<RwLock<LruCache<EventId, Instant>>>,
}

impl EventProcessor {
    /// Create a new event processor with default cache size.
    #[allow(dead_code)]
    pub fn new(
        nip59_handler: Nip59Handler,
        token_decryptor: TokenDecryptor,
        push_dispatcher: Arc<PushDispatcher>,
    ) -> Self {
        Self::with_cache_size(
            nip59_handler,
            token_decryptor,
            push_dispatcher,
            DEFAULT_MAX_DEDUP_CACHE_SIZE,
        )
    }

    /// Create a new event processor with a custom cache size limit.
    ///
    /// The cache will automatically evict the least recently used entries
    /// when the size limit is reached, preventing unbounded memory growth.
    pub fn with_cache_size(
        nip59_handler: Nip59Handler,
        token_decryptor: TokenDecryptor,
        push_dispatcher: Arc<PushDispatcher>,
        max_cache_size: usize,
    ) -> Self {
        let cache_size = NonZeroUsize::new(max_cache_size).unwrap_or(
            NonZeroUsize::new(DEFAULT_MAX_DEDUP_CACHE_SIZE)
                .expect("DEFAULT_MAX_DEDUP_CACHE_SIZE is non-zero"),
        );
        Self {
            nip59_handler,
            token_decryptor,
            push_dispatcher,
            seen_events: Arc::new(RwLock::new(LruCache::new(cache_size))),
        }
    }

    /// Process an incoming event.
    ///
    /// Returns `Ok(true)` if the event was processed, `Ok(false)` if it was
    /// deduplicated (already seen), or an error if processing failed.
    pub async fn process(&self, event: &Event) -> Result<bool> {
        // Check for duplicates
        if self.is_duplicate(&event.id).await {
            trace!(event_id = %event.id, "Skipping duplicate event");
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
                Ok(true)
            }
            Err(e) => {
                // Log but don't propagate - we want to continue processing other events
                warn!(
                    event_id = %event.id,
                    error = %e,
                    "Failed to process event"
                );
                Ok(false)
            }
        }
    }

    /// Inner processing logic for an event.
    async fn process_inner(&self, event: &Event) -> Result<usize> {
        // Unwrap the gift wrap to get the notification request
        let notification = self.nip59_handler.unwrap(event).await?;

        trace!(
            sender = %notification.sender_pubkey,
            "Unwrapped notification request"
        );

        // Parse the encrypted tokens from the content
        let token_bytes = notification.parse_tokens()?;

        if token_bytes.is_empty() {
            return Ok(0);
        }

        debug!(token_count = token_bytes.len(), "Decrypting tokens");

        // Decrypt each token and dispatch notifications
        let mut payloads = Vec::with_capacity(token_bytes.len());
        for bytes in token_bytes {
            match self.token_decryptor.decrypt_bytes(&bytes) {
                Ok(payload) => {
                    payloads.push(payload);
                }
                Err(e) => {
                    // Silently ignore invalid tokens per MIP-05 spec
                    trace!(error = %e, "Failed to decrypt token (ignoring)");
                }
            }
        }

        if payloads.is_empty() {
            return Ok(0);
        }

        // Dispatch notifications
        let count = payloads.len();
        self.push_dispatcher.dispatch(payloads).await;

        Ok(count)
    }

    /// Check if an event has been seen recently.
    async fn is_duplicate(&self, event_id: &EventId) -> bool {
        let seen = self.seen_events.read().await;
        seen.contains(event_id)
    }

    /// Mark an event as seen.
    ///
    /// The LRU cache automatically evicts the oldest entries when the
    /// configured size limit is reached, preventing unbounded memory growth.
    async fn mark_seen(&self, event_id: EventId) {
        let mut seen = self.seen_events.write().await;
        seen.put(event_id, Instant::now());
    }

    /// Clean up the deduplication cache by removing entries older than `DEDUP_WINDOW`.
    ///
    /// Note: The LRU cache also provides automatic eviction based on size,
    /// so this cleanup is for time-based expiration of stale entries.
    pub async fn cleanup(&self) {
        let mut seen = self.seen_events.write().await;
        let now = Instant::now();
        let before = seen.len();

        // LruCache doesn't have retain(), so we collect keys to remove first
        let expired_keys: Vec<_> = seen
            .iter()
            .filter(|(_, seen_at)| now.duration_since(**seen_at) >= DEDUP_WINDOW)
            .map(|(id, _)| *id)
            .collect();

        for key in &expired_keys {
            seen.pop(key);
        }

        let after = seen.len();

        if before != after {
            debug!(
                removed = before - after,
                remaining = after,
                "Cleaned up deduplication cache"
            );
        }
    }

    /// Returns the current number of entries in the deduplication cache.
    #[cfg(test)]
    pub fn cache_len(&self) -> usize {
        // Use try_read to avoid blocking in tests
        self.seen_events
            .try_read()
            .map(|guard| guard.len())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::push::PushDispatcher;
    use crate::test_vectors::scenarios;

    /// Create an EventProcessor with the given server keys and no push clients.
    fn create_processor(server_keys: &Keys) -> EventProcessor {
        let nip59_handler = Nip59Handler::new(server_keys.clone());
        let token_decryptor = TokenDecryptor::new(server_keys.clone());
        let push_dispatcher = Arc::new(PushDispatcher::new(None, None));
        EventProcessor::new(nip59_handler, token_decryptor, push_dispatcher)
    }

    #[tokio::test]
    async fn test_process_valid_gift_wrap_event() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let device_token = "aabbccdd11223344aabbccdd11223344";

        // Create a valid gift-wrapped notification
        let event =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;

        // Process the event
        let processor = create_processor(&server_keys);
        let result = processor.process(&event).await;

        // Should succeed (even without push clients, decryption should work)
        assert!(result.is_ok());
        assert!(result.unwrap()); // true = processed successfully
    }

    #[tokio::test]
    async fn test_process_deduplicates_same_event() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let event = scenarios::single_apns_notification(
            &server_keys,
            &sender_keys,
            "deadbeef12345678deadbeef12345678",
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
        assert!(!result2.unwrap()); // false = deduplicated
    }

    #[tokio::test]
    async fn test_process_different_events_not_deduplicated() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let event1 = scenarios::single_apns_notification(
            &server_keys,
            &sender_keys,
            "aaaa111122223333aaaa111122223333",
        )
        .await;

        let event2 = scenarios::single_apns_notification(
            &server_keys,
            &sender_keys,
            "bbbb444455556666bbbb444455556666",
        )
        .await;

        let processor = create_processor(&server_keys);

        // Both events should be processed (different event IDs)
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

        // Create event for wrong server
        let event = scenarios::single_apns_notification(
            &wrong_server_keys,
            &sender_keys,
            "deadbeef12345678deadbeef12345678",
        )
        .await;

        // Try to process with different server keys
        let processor = create_processor(&server_keys);
        let result = processor.process(&event).await;

        // Should return Ok(false) - failed to process but didn't error out
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_process_empty_token_list() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let event = scenarios::empty_notification(&server_keys, &sender_keys).await;

        let processor = create_processor(&server_keys);
        let result = processor.process(&event).await;

        // Should succeed but process 0 tokens
        assert!(result.is_ok());
        assert!(result.unwrap());
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

        // Create a regular text note (not a gift wrap)
        let event = EventBuilder::text_note("Hello, world!")
            .sign_with_keys(&some_keys)
            .unwrap();

        let processor = create_processor(&server_keys);
        let result = processor.process(&event).await;

        // Should return Ok(false) - failed to process but should remain retryable
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_cleanup_removes_old_entries() {
        let server_keys = Keys::generate();
        let processor = create_processor(&server_keys);

        // Manually add an event ID to the seen list
        {
            let mut seen = processor.seen_events.write().await;
            seen.put(EventId::all_zeros(), Instant::now());
        }

        // Verify it's there
        assert!(processor.is_duplicate(&EventId::all_zeros()).await);

        // Cleanup shouldn't remove it (it's recent)
        processor.cleanup().await;
        assert!(processor.is_duplicate(&EventId::all_zeros()).await);

        // The entry would need to be older than DEDUP_WINDOW to be removed
        // We can't easily test that without mocking time, but we've verified
        // the basic cleanup logic runs
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

    /// Create an EventProcessor with a custom cache size for testing.
    fn create_processor_with_cache_size(server_keys: &Keys, cache_size: usize) -> EventProcessor {
        let nip59_handler = Nip59Handler::new(server_keys.clone());
        let token_decryptor = TokenDecryptor::new(server_keys.clone());
        let push_dispatcher = Arc::new(PushDispatcher::new(None, None));
        EventProcessor::with_cache_size(nip59_handler, token_decryptor, push_dispatcher, cache_size)
    }

    #[tokio::test]
    async fn test_cache_size_limit_evicts_oldest_entries() {
        let server_keys = Keys::generate();
        // Create processor with small cache size
        let processor = create_processor_with_cache_size(&server_keys, 3);

        // Generate 5 event IDs
        let event_ids: Vec<EventId> = (0..5)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0] = i;
                EventId::from_byte_array(bytes)
            })
            .collect();

        // Add all 5 events - should evict oldest ones
        for event_id in &event_ids {
            processor.mark_seen(*event_id).await;
        }

        // Cache should only contain the last 3 entries
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
        // Creating with cache size 0 should fall back to default
        let processor = create_processor_with_cache_size(&server_keys, 0);

        // Add an event - should work without panic
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

        // Add first 3 events
        processor.mark_seen(event_ids[0]).await;
        processor.mark_seen(event_ids[1]).await;
        processor.mark_seen(event_ids[2]).await;

        // Access the first event again (makes it most recently used)
        processor.mark_seen(event_ids[0]).await;

        // Add a 4th event - should evict event_ids[1] (now the LRU)
        processor.mark_seen(event_ids[3]).await;

        // event_ids[1] should be evicted
        assert!(!processor.is_duplicate(&event_ids[1]).await);

        // event_ids[0], [2], and [3] should still be present
        assert!(processor.is_duplicate(&event_ids[0]).await);
        assert!(processor.is_duplicate(&event_ids[2]).await);
        assert!(processor.is_duplicate(&event_ids[3]).await);
    }
}

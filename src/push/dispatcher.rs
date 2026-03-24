//! Push notification dispatcher.
//!
//! Routes decrypted tokens to the appropriate push service (APNs or FCM)
//! with bounded queue and semaphore-based concurrency control.
//!
//! # Bounded Queue Pattern
//!
//! To prevent unbounded task spawning (a potential DoS vector), the dispatcher
//! uses a bounded channel. When the queue is full, new notifications are dropped
//! and logged as warnings. This provides backpressure and protects against OOM
//! conditions during traffic spikes.
//!
//! # Security
//!
//! Device tokens are wrapped in `Zeroizing<String>` to ensure they are zeroed
//! from memory when no longer needed, preventing sensitive data from lingering.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};
use zeroize::Zeroizing;

use crate::crypto::{Platform, TokenPayload};
use crate::error::{Error, Result};
use crate::metrics::Metrics;
use crate::push::{ApnsClient, FcmClient};

/// Maximum concurrent outbound push requests.
const MAX_CONCURRENT_PUSHES: usize = 100;

/// Maximum number of pending notifications in the queue.
///
/// This bounds the memory used by waiting tasks. When this limit is reached,
/// new notifications will be dropped to protect against DoS attacks.
const MAX_PENDING_QUEUE_SIZE: usize = 10_000;

/// Number of worker tasks processing the queue.
const NUM_WORKERS: usize = 4;

/// Internal message for the push queue.
///
/// # Security
///
/// The token field is wrapped in `Zeroizing<String>` to ensure device tokens
/// are zeroed from memory when the message is dropped.
enum PushMessage {
    /// Send a notification to the given platform with the given token.
    Send {
        platform: Platform,
        token: Zeroizing<String>,
    },
    /// Shutdown signal for workers.
    Shutdown,
}

struct QueuedPushMessage {
    platform: Platform,
    token: Zeroizing<String>,
}

/// Push notification dispatcher.
pub struct PushDispatcher {
    apns_client: Option<Arc<ApnsClient>>,
    fcm_client: Option<Arc<FcmClient>>,
    semaphore: Arc<Semaphore>,
    sender: mpsc::Sender<PushMessage>,
    shutting_down: Arc<AtomicBool>,
    worker_handles: tokio::sync::Mutex<Vec<JoinHandle<()>>>,
    metrics: Option<Metrics>,
}

impl PushDispatcher {
    /// Create a new push dispatcher.
    ///
    /// This spawns worker tasks that process the bounded queue of notifications.
    #[allow(dead_code)]
    pub fn new(apns_client: Option<ApnsClient>, fcm_client: Option<FcmClient>) -> Self {
        Self::with_metrics(apns_client, fcm_client, None)
    }

    /// Create a new push dispatcher with metrics.
    ///
    /// This spawns worker tasks that process the bounded queue of notifications.
    pub fn with_metrics(
        apns_client: Option<ApnsClient>,
        fcm_client: Option<FcmClient>,
        metrics: Option<Metrics>,
    ) -> Self {
        let apns_client = apns_client.map(Arc::new);
        let fcm_client = fcm_client.map(Arc::new);
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_PUSHES));
        let (sender, receiver) = mpsc::channel(MAX_PENDING_QUEUE_SIZE);
        let shutting_down = Arc::new(AtomicBool::new(false));

        // Initialize semaphore metric
        if let Some(ref m) = metrics {
            m.set_push_semaphore_available(MAX_CONCURRENT_PUSHES);
        }

        // Spawn worker tasks
        let worker_handles = Self::spawn_workers(
            receiver,
            apns_client.clone(),
            fcm_client.clone(),
            semaphore.clone(),
            metrics.clone(),
        );

        Self {
            apns_client,
            fcm_client,
            semaphore,
            sender,
            shutting_down,
            worker_handles: tokio::sync::Mutex::new(worker_handles),
            metrics,
        }
    }

    /// Spawn worker tasks that process the push queue.
    fn spawn_workers(
        receiver: mpsc::Receiver<PushMessage>,
        apns_client: Option<Arc<ApnsClient>>,
        fcm_client: Option<Arc<FcmClient>>,
        semaphore: Arc<Semaphore>,
        metrics: Option<Metrics>,
    ) -> Vec<JoinHandle<()>> {
        // Wrap receiver in Arc<Mutex> so workers can share it
        let receiver = Arc::new(tokio::sync::Mutex::new(receiver));
        let mut worker_handles = Vec::with_capacity(NUM_WORKERS);

        for worker_id in 0..NUM_WORKERS {
            let receiver = receiver.clone();
            let apns_client = apns_client.clone();
            let fcm_client = fcm_client.clone();
            let semaphore = semaphore.clone();
            let metrics = metrics.clone();

            worker_handles.push(tokio::spawn(async move {
                loop {
                    // Get next message from the shared queue
                    let msg = {
                        let mut rx = receiver.lock().await;
                        rx.recv().await
                    };

                    match msg {
                        Some(PushMessage::Send { platform, token }) => {
                            // Acquire semaphore permit before sending
                            let permit = match semaphore.acquire().await {
                                Ok(p) => p,
                                Err(_) => {
                                    debug!(worker_id, "Semaphore closed, worker exiting");
                                    // Token is automatically zeroed when dropped here
                                    break;
                                }
                            };

                            // Update semaphore metric after acquiring permit
                            if let Some(ref m) = metrics {
                                m.set_push_semaphore_available(semaphore.available_permits());
                            }

                            let platform_str = match platform {
                                Platform::Apns => "apns",
                                Platform::Fcm => "fcm",
                            };

                            match platform {
                                Platform::Apns => {
                                    if let Some(ref client) = apns_client {
                                        match client.send(token.as_str()).await {
                                            Ok(true) => {
                                                trace!("APNs notification sent");
                                                if let Some(ref m) = metrics {
                                                    m.record_push_success(platform_str);
                                                }
                                            }
                                            Ok(false) => {
                                                trace!("APNs notification failed (invalid token)");
                                                if let Some(ref m) = metrics {
                                                    m.record_push_failed(
                                                        platform_str,
                                                        "invalid_token",
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                debug!(error = %e, "APNs send error");
                                                if let Some(ref m) = metrics {
                                                    m.record_push_failed(platform_str, "error");
                                                }
                                            }
                                        }
                                    }
                                }
                                Platform::Fcm => {
                                    if let Some(ref client) = fcm_client {
                                        match client.send(token.as_str()).await {
                                            Ok(true) => {
                                                trace!("FCM notification sent");
                                                if let Some(ref m) = metrics {
                                                    m.record_push_success(platform_str);
                                                }
                                            }
                                            Ok(false) => {
                                                trace!("FCM notification failed (invalid token)");
                                                if let Some(ref m) = metrics {
                                                    m.record_push_failed(
                                                        platform_str,
                                                        "invalid_token",
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                debug!(error = %e, "FCM send error");
                                                if let Some(ref m) = metrics {
                                                    m.record_push_failed(platform_str, "error");
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            // Token is automatically zeroed when dropped here

                            drop(permit);

                            // Update semaphore metric after releasing permit
                            if let Some(ref m) = metrics {
                                m.set_push_semaphore_available(semaphore.available_permits());
                            }
                        }
                        Some(PushMessage::Shutdown) => {
                            debug!(worker_id, "Worker received shutdown signal");
                            break;
                        }
                        None => {
                            // Channel closed
                            debug!(worker_id, "Push queue channel closed, worker exiting");
                            break;
                        }
                    }
                }
            }));
        }

        worker_handles
    }

    /// Dispatch push notifications for all payloads.
    ///
    /// This queues notifications for processing by worker tasks. The batch is
    /// only accepted if enough queue capacity exists for all notifications, so
    /// callers can safely treat a successful return as "all notifications were
    /// admitted locally". Invalid tokens are silently ignored per MIP-05 spec.
    pub async fn dispatch(&self, payloads: Vec<TokenPayload>) -> Result<usize> {
        if self.shutting_down.load(Ordering::SeqCst) {
            debug!("Dispatcher shutting down, ignoring dispatch request");
            return Err(Error::Dispatch("Dispatcher is shutting down".to_string()));
        }

        let mut messages = Vec::with_capacity(payloads.len());

        for payload in payloads {
            // Extract token as Zeroizing<String> for automatic cleanup
            let (platform, token): (Platform, Zeroizing<String>) = match payload.platform {
                Platform::Apns => {
                    if self.apns_client.is_none() {
                        trace!("APNs not configured, skipping notification");
                        continue;
                    }
                    (Platform::Apns, Zeroizing::new(payload.device_token_hex()))
                }
                Platform::Fcm => {
                    if self.fcm_client.is_none() {
                        trace!("FCM not configured, skipping notification");
                        continue;
                    }
                    match payload.device_token_string() {
                        Some(t) => (Platform::Fcm, Zeroizing::new(t)),
                        None => {
                            trace!("Invalid FCM token (not UTF-8)");
                            continue;
                        }
                    }
                }
            };
            // Note: payload (TokenPayload) is automatically zeroed when dropped here
            // due to its ZeroizeOnDrop implementation

            messages.push(QueuedPushMessage { platform, token });
        }

        if messages.is_empty() {
            return Ok(0);
        }

        let message_count = messages.len();
        let mut permits =
            self.sender
                .try_reserve_many(message_count)
                .map_err(|error| match error {
                    mpsc::error::TrySendError::Full(_) => {
                        warn!(
                            requested = message_count,
                            available = self.sender.capacity(),
                            "Push queue full, rejecting notification batch"
                        );
                        Error::Dispatch(format!(
                            "Push queue full: unable to queue {message_count} notifications"
                        ))
                    }
                    mpsc::error::TrySendError::Closed(_) => {
                        warn!("Push queue closed, rejecting notification batch");
                        Error::Dispatch("Push queue closed".to_string())
                    }
                })?;

        for message in messages {
            let platform_str = match message.platform {
                Platform::Apns => "apns",
                Platform::Fcm => "fcm",
            };

            let permit = permits
                .next()
                .expect("reserved permits should match queued message count");
            permit.send(PushMessage::Send {
                platform: message.platform,
                token: message.token,
            });

            if let Some(ref m) = self.metrics {
                m.record_push_dispatched(platform_str);
            }
        }

        if let Some(ref m) = self.metrics {
            // Update queue size after the full batch is admitted.
            m.set_push_queue_size(MAX_PENDING_QUEUE_SIZE - self.sender.capacity());
        }

        Ok(message_count)
    }

    /// Check if APNs is configured and ready.
    #[must_use]
    pub fn has_apns(&self) -> bool {
        self.apns_client
            .as_ref()
            .map(|c| c.is_configured())
            .unwrap_or(false)
    }

    /// Check if FCM is configured and ready.
    #[must_use]
    pub fn has_fcm(&self) -> bool {
        self.fcm_client
            .as_ref()
            .map(|c| c.is_configured())
            .unwrap_or(false)
    }

    /// Check if at least one push service is configured.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.has_apns() || self.has_fcm()
    }

    /// Wait for all in-flight push notifications to complete.
    ///
    /// This is used during graceful shutdown. It stops accepting new dispatches,
    /// enqueues one shutdown message per worker behind any queued notifications,
    /// and then waits for all worker tasks to exit. This guarantees queued work
    /// is drained before shutdown completes.
    pub async fn wait_for_completion(&self) {
        // Mark as shutting down to prevent new dispatches.
        self.shutting_down.store(true, Ordering::SeqCst);

        // Enqueue shutdown signals after any already-queued notifications.
        for _ in 0..NUM_WORKERS {
            if self.sender.send(PushMessage::Shutdown).await.is_err() {
                break;
            }
        }

        let worker_handles = {
            let mut handles = self.worker_handles.lock().await;
            std::mem::take(&mut *handles)
        };

        for handle in worker_handles {
            if let Err(error) = handle.await {
                warn!(error = %error, "Push worker exited unexpectedly during shutdown");
            }
        }

        if let Some(ref m) = self.metrics {
            m.set_push_queue_size(0);
            m.set_push_semaphore_available(self.semaphore.available_permits());
        }

        debug!("All queued push notifications drained");
    }

    /// Returns the current queue capacity available.
    ///
    /// This is useful for monitoring and testing.
    #[cfg(test)]
    #[must_use]
    pub fn queue_capacity(&self) -> usize {
        self.sender.capacity()
    }

    /// Returns the maximum queue size.
    #[cfg(test)]
    #[must_use]
    pub fn max_queue_size(&self) -> usize {
        MAX_PENDING_QUEUE_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_dispatcher_no_clients() {
        let dispatcher = PushDispatcher::new(None, None);
        assert!(!dispatcher.has_apns());
        assert!(!dispatcher.has_fcm());
        assert!(!dispatcher.is_ready());
    }

    #[tokio::test]
    async fn test_dispatch_empty_payloads() {
        let dispatcher = PushDispatcher::new(None, None);

        // Should not panic with empty payloads
        assert_eq!(dispatcher.dispatch(vec![]).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_dispatch_without_clients() {
        let dispatcher = PushDispatcher::new(None, None);

        let payloads = vec![
            TokenPayload {
                platform: Platform::Apns,
                device_token: vec![0xaa, 0xbb, 0xcc],
            },
            TokenPayload {
                platform: Platform::Fcm,
                device_token: b"fcm-token-123".to_vec(),
            },
        ];

        // Should not panic - just skips notifications
        assert_eq!(dispatcher.dispatch(payloads).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_wait_for_completion() {
        let dispatcher = PushDispatcher::new(None, None);

        // Should complete immediately when no pushes in flight
        let result =
            tokio::time::timeout(Duration::from_secs(1), dispatcher.wait_for_completion()).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_has_apns_with_configured_client() {
        use crate::config::ApnsConfig;
        use crate::push::ApnsClient;

        let config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: "sandbox".to_string(),
            bundle_id: "com.example.app".to_string(),
        };

        let apns_client = ApnsClient::mock(config, true);
        let dispatcher = PushDispatcher::new(Some(apns_client), None);

        assert!(dispatcher.has_apns());
        assert!(!dispatcher.has_fcm());
        assert!(dispatcher.is_ready());
    }

    #[tokio::test]
    async fn test_has_fcm_with_configured_client() {
        use crate::config::FcmConfig;
        use crate::push::FcmClient;

        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };

        let fcm_client = FcmClient::mock(config, true);
        let dispatcher = PushDispatcher::new(None, Some(fcm_client));

        assert!(!dispatcher.has_apns());
        assert!(dispatcher.has_fcm());
        assert!(dispatcher.is_ready());
    }

    #[tokio::test]
    async fn test_dispatch_apns_without_apns_client() {
        use crate::config::FcmConfig;
        use crate::push::FcmClient;

        // Only FCM client configured
        let fcm_config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };
        let fcm_client = FcmClient::mock(fcm_config, true);
        let dispatcher = PushDispatcher::new(None, Some(fcm_client));

        // Try to dispatch an APNs payload - should be skipped
        let payloads = vec![TokenPayload {
            platform: Platform::Apns,
            device_token: vec![0xaa, 0xbb, 0xcc],
        }];

        assert_eq!(dispatcher.dispatch(payloads).await.unwrap(), 0);
        // Should not panic, just skip the notification
    }

    #[tokio::test]
    async fn test_dispatch_fcm_without_fcm_client() {
        use crate::config::ApnsConfig;
        use crate::push::ApnsClient;

        // Only APNs client configured
        let apns_config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: "sandbox".to_string(),
            bundle_id: "com.example.app".to_string(),
        };
        let apns_client = ApnsClient::mock(apns_config, true);
        let dispatcher = PushDispatcher::new(Some(apns_client), None);

        // Try to dispatch an FCM payload - should be skipped
        let payloads = vec![TokenPayload {
            platform: Platform::Fcm,
            device_token: b"fcm-token-123".to_vec(),
        }];

        assert_eq!(dispatcher.dispatch(payloads).await.unwrap(), 0);
        // Should not panic, just skip the notification
    }

    #[tokio::test]
    async fn test_dispatch_fcm_invalid_utf8_token() {
        use crate::config::FcmConfig;
        use crate::push::FcmClient;

        let fcm_config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };
        let fcm_client = FcmClient::mock(fcm_config, true);
        let dispatcher = PushDispatcher::new(None, Some(fcm_client));

        // Invalid UTF-8 FCM token - should be skipped
        let payloads = vec![TokenPayload {
            platform: Platform::Fcm,
            device_token: vec![0xff, 0xfe, 0x00, 0x01], // Invalid UTF-8
        }];

        assert_eq!(dispatcher.dispatch(payloads).await.unwrap(), 0);
        // Should not panic, just skip the notification
    }

    #[tokio::test]
    async fn test_dispatch_both_platforms() {
        use crate::config::{ApnsConfig, FcmConfig};
        use crate::metrics::Metrics;
        use crate::push::{ApnsClient, FcmClient};

        let apns_config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: "sandbox".to_string(),
            bundle_id: "com.example.app".to_string(),
        };
        let apns_client = ApnsClient::mock(apns_config, true);

        let fcm_config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };
        let fcm_client = FcmClient::mock(fcm_config, true);

        let metrics = Metrics::default();
        let dispatcher = PushDispatcher::with_metrics(
            Some(apns_client),
            Some(fcm_client),
            Some(metrics.clone()),
        );

        // Dispatch both APNs and FCM payloads
        let payloads = vec![
            TokenPayload {
                platform: Platform::Apns,
                device_token: vec![0xaa, 0xbb, 0xcc],
            },
            TokenPayload {
                platform: Platform::Fcm,
                device_token: b"fcm-token-123".to_vec(),
            },
        ];

        assert_eq!(dispatcher.dispatch(payloads).await.unwrap(), 2);
        // Tasks are spawned - give them time to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify metrics
        let families = metrics.gather();
        let mut apns_dispatched = false;
        let mut fcm_dispatched = false;

        for family in families {
            if family.name() == "transponder_push_dispatched_total" {
                for metric in family.get_metric() {
                    for label in metric.get_label() {
                        if label.name() == "platform" {
                            if label.value() == "apns" {
                                assert_eq!(metric.get_counter().value, Some(1.0));
                                apns_dispatched = true;
                            } else if label.value() == "fcm" {
                                assert_eq!(metric.get_counter().value, Some(1.0));
                                fcm_dispatched = true;
                            }
                        }
                    }
                }
            }
        }

        assert!(apns_dispatched, "APNs dispatch metric missing");
        assert!(fcm_dispatched, "FCM dispatch metric missing");
    }

    #[tokio::test]
    async fn test_is_ready_both_clients() {
        use crate::config::{ApnsConfig, FcmConfig};
        use crate::push::{ApnsClient, FcmClient};

        let apns_config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: "sandbox".to_string(),
            bundle_id: "com.example.app".to_string(),
        };
        let apns_client = ApnsClient::mock(apns_config, true);

        let fcm_config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };
        let fcm_client = FcmClient::mock(fcm_config, true);

        let dispatcher = PushDispatcher::new(Some(apns_client), Some(fcm_client));

        assert!(dispatcher.has_apns());
        assert!(dispatcher.has_fcm());
        assert!(dispatcher.is_ready());
    }

    #[tokio::test]
    async fn test_has_apns_unconfigured_client() {
        use crate::config::ApnsConfig;
        use crate::push::ApnsClient;

        // APNs client that is not properly configured
        let apns_config = ApnsConfig {
            enabled: false, // Disabled
            key_id: String::new(),
            team_id: String::new(),
            private_key_path: String::new(),
            environment: "sandbox".to_string(),
            bundle_id: String::new(),
        };
        let apns_client = ApnsClient::mock(apns_config, false);
        let dispatcher = PushDispatcher::new(Some(apns_client), None);

        assert!(!dispatcher.has_apns()); // Client exists but not configured
        assert!(!dispatcher.is_ready());
    }

    #[tokio::test]
    async fn test_has_fcm_unconfigured_client() {
        use crate::config::FcmConfig;
        use crate::push::FcmClient;

        // FCM client that is not properly configured
        let fcm_config = FcmConfig {
            enabled: false, // Disabled
            service_account_path: String::new(),
            project_id: String::new(),
        };
        let fcm_client = FcmClient::mock(fcm_config, false);
        let dispatcher = PushDispatcher::new(None, Some(fcm_client));

        assert!(!dispatcher.has_fcm()); // Client exists but not configured
        assert!(!dispatcher.is_ready());
    }

    #[tokio::test]
    async fn test_queue_capacity() {
        let dispatcher = PushDispatcher::new(None, None);

        // Queue should have capacity available
        assert!(dispatcher.queue_capacity() > 0);
        assert_eq!(dispatcher.max_queue_size(), MAX_PENDING_QUEUE_SIZE);
    }

    #[tokio::test]
    async fn test_dispatch_after_shutdown() {
        let dispatcher = PushDispatcher::new(None, None);

        // Shutdown the dispatcher
        dispatcher.wait_for_completion().await;

        // Dispatch should be ignored after shutdown
        let payloads = vec![TokenPayload {
            platform: Platform::Apns,
            device_token: vec![0xaa, 0xbb, 0xcc],
        }];

        let error = dispatcher.dispatch(payloads).await.unwrap_err();
        assert!(matches!(error, Error::Dispatch(_)));
    }

    #[tokio::test]
    async fn test_bounded_queue_prevents_unbounded_growth() {
        use crate::config::ApnsConfig;
        use crate::push::ApnsClient;

        // Create a dispatcher with a mock client
        let apns_config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: "sandbox".to_string(),
            bundle_id: "com.example.app".to_string(),
        };
        let apns_client = ApnsClient::mock(apns_config, true);
        let dispatcher = PushDispatcher::new(Some(apns_client), None);

        // The queue should be bounded
        assert!(dispatcher.queue_capacity() <= MAX_PENDING_QUEUE_SIZE);
        assert_eq!(dispatcher.max_queue_size(), MAX_PENDING_QUEUE_SIZE);
    }

    #[tokio::test]
    async fn test_wait_for_completion_drains_backlog_before_returning() {
        use crate::config::ApnsConfig;
        use crate::push::ApnsClient;

        let apns_config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: "sandbox".to_string(),
            bundle_id: "com.example.app".to_string(),
        };
        let dispatcher = Arc::new(PushDispatcher::new(
            Some(ApnsClient::mock(apns_config, true)),
            None,
        ));

        let permits = dispatcher
            .semaphore
            .acquire_many(MAX_CONCURRENT_PUSHES as u32)
            .await
            .unwrap();

        let payloads = vec![
            TokenPayload {
                platform: Platform::Apns,
                device_token: vec![0xaa, 0xbb, 0xcc],
            };
            NUM_WORKERS + 2
        ];
        assert_eq!(
            dispatcher.dispatch(payloads).await.unwrap(),
            NUM_WORKERS + 2
        );

        let shutdown_dispatcher = dispatcher.clone();
        let shutdown_handle = tokio::spawn(async move {
            shutdown_dispatcher.wait_for_completion().await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(permits);

        tokio::time::timeout(Duration::from_secs(1), shutdown_handle)
            .await
            .expect("shutdown should complete")
            .expect("shutdown task should not panic");

        assert_eq!(dispatcher.queue_capacity(), MAX_PENDING_QUEUE_SIZE);
    }

    #[tokio::test]
    async fn test_dispatch_rejects_batch_larger_than_queue() {
        use crate::config::ApnsConfig;
        use crate::push::ApnsClient;

        let apns_config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: "sandbox".to_string(),
            bundle_id: "com.example.app".to_string(),
        };
        let apns_client = ApnsClient::mock(apns_config, true);
        let dispatcher = PushDispatcher::new(Some(apns_client), None);

        let payloads = vec![
            TokenPayload {
                platform: Platform::Apns,
                device_token: vec![0xaa, 0xbb, 0xcc],
            };
            MAX_PENDING_QUEUE_SIZE + 1
        ];

        let error = dispatcher.dispatch(payloads).await.unwrap_err();

        assert!(matches!(error, Error::Dispatch(message) if message.contains("Push queue full")));
    }
}

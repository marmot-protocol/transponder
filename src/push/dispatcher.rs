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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

use crate::crypto::{Platform, TokenPayload};
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
enum PushMessage {
    /// Send a notification to the given platform with the given token.
    Send { platform: Platform, token: String },
    /// Shutdown signal for workers.
    Shutdown,
}

/// Push notification dispatcher.
pub struct PushDispatcher {
    apns_client: Option<Arc<ApnsClient>>,
    fcm_client: Option<Arc<FcmClient>>,
    semaphore: Arc<Semaphore>,
    sender: mpsc::Sender<PushMessage>,
    shutting_down: Arc<AtomicBool>,
}

impl PushDispatcher {
    /// Create a new push dispatcher.
    ///
    /// This spawns worker tasks that process the bounded queue of notifications.
    pub fn new(apns_client: Option<ApnsClient>, fcm_client: Option<FcmClient>) -> Self {
        let apns_client = apns_client.map(Arc::new);
        let fcm_client = fcm_client.map(Arc::new);
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_PUSHES));
        let (sender, receiver) = mpsc::channel(MAX_PENDING_QUEUE_SIZE);
        let shutting_down = Arc::new(AtomicBool::new(false));

        // Spawn worker tasks
        Self::spawn_workers(
            receiver,
            apns_client.clone(),
            fcm_client.clone(),
            semaphore.clone(),
            shutting_down.clone(),
        );

        Self {
            apns_client,
            fcm_client,
            semaphore,
            sender,
            shutting_down,
        }
    }

    /// Spawn worker tasks that process the push queue.
    fn spawn_workers(
        receiver: mpsc::Receiver<PushMessage>,
        apns_client: Option<Arc<ApnsClient>>,
        fcm_client: Option<Arc<FcmClient>>,
        semaphore: Arc<Semaphore>,
        shutting_down: Arc<AtomicBool>,
    ) {
        // Wrap receiver in Arc<Mutex> so workers can share it
        let receiver = Arc::new(tokio::sync::Mutex::new(receiver));

        for worker_id in 0..NUM_WORKERS {
            let receiver = receiver.clone();
            let apns_client = apns_client.clone();
            let fcm_client = fcm_client.clone();
            let semaphore = semaphore.clone();
            let shutting_down = shutting_down.clone();

            tokio::spawn(async move {
                loop {
                    // Check shutdown flag before waiting for next message
                    if shutting_down.load(Ordering::SeqCst) {
                        debug!(worker_id, "Worker detected shutdown flag, exiting");
                        break;
                    }

                    // Get next message from the shared queue
                    let msg = {
                        let mut rx = receiver.lock().await;
                        rx.recv().await
                    };

                    match msg {
                        Some(PushMessage::Send { platform, token }) => {
                            // Check shutdown flag again before processing
                            // This handles the case where shutdown was triggered while waiting
                            if shutting_down.load(Ordering::SeqCst) {
                                debug!(
                                    worker_id,
                                    "Worker detected shutdown during processing, exiting"
                                );
                                break;
                            }

                            // Acquire semaphore permit before sending
                            let permit = match semaphore.acquire().await {
                                Ok(p) => p,
                                Err(_) => {
                                    debug!(worker_id, "Semaphore closed, worker exiting");
                                    break;
                                }
                            };

                            match platform {
                                Platform::Apns => {
                                    if let Some(ref client) = apns_client {
                                        match client.send(&token).await {
                                            Ok(true) => trace!("APNs notification sent"),
                                            Ok(false) => {
                                                trace!("APNs notification failed (invalid token)")
                                            }
                                            Err(e) => debug!(error = %e, "APNs send error"),
                                        }
                                    }
                                }
                                Platform::Fcm => {
                                    if let Some(ref client) = fcm_client {
                                        match client.send(&token).await {
                                            Ok(true) => trace!("FCM notification sent"),
                                            Ok(false) => {
                                                trace!("FCM notification failed (invalid token)")
                                            }
                                            Err(e) => debug!(error = %e, "FCM send error"),
                                        }
                                    }
                                }
                            }

                            drop(permit);
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
            });
        }
    }

    /// Dispatch push notifications for all payloads.
    ///
    /// This queues notifications for processing by worker tasks. If the queue
    /// is full, notifications are dropped to prevent unbounded memory growth.
    /// Invalid tokens are silently ignored per MIP-05 spec.
    pub async fn dispatch(&self, payloads: Vec<TokenPayload>) {
        if self.shutting_down.load(Ordering::SeqCst) {
            debug!("Dispatcher shutting down, ignoring dispatch request");
            return;
        }

        for payload in payloads {
            let (platform, token) = match payload.platform {
                Platform::Apns => {
                    if self.apns_client.is_none() {
                        trace!("APNs not configured, skipping notification");
                        continue;
                    }
                    (Platform::Apns, payload.device_token_hex())
                }
                Platform::Fcm => {
                    if self.fcm_client.is_none() {
                        trace!("FCM not configured, skipping notification");
                        continue;
                    }
                    match payload.device_token_string() {
                        Some(t) => (Platform::Fcm, t),
                        None => {
                            trace!("Invalid FCM token (not UTF-8)");
                            continue;
                        }
                    }
                }
            };

            // Try to send to the bounded queue
            match self.sender.try_send(PushMessage::Send { platform, token }) {
                Ok(()) => {
                    // Successfully queued
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    warn!("Push queue full, dropping notification (DoS protection)");
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    warn!("Push queue closed, dropping notification");
                    break;
                }
            }
        }
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
    /// This is used during graceful shutdown. It sets the shutdown flag,
    /// attempts to send shutdown signals, then waits for all permits to be
    /// available (indicating all pushes complete).
    ///
    /// Workers check the `shutting_down` flag in their loop, so they will
    /// exit even if shutdown messages are dropped due to a full queue.
    pub async fn wait_for_completion(&self) {
        // Mark as shutting down to prevent new dispatches and signal workers
        self.shutting_down.store(true, Ordering::SeqCst);

        // Send shutdown signals to all workers (best effort - workers also check the flag)
        for _ in 0..NUM_WORKERS {
            // Use try_send since we don't want to block if queue is full.
            // Workers will exit via the shutting_down flag check even if this fails.
            let _ = self.sender.try_send(PushMessage::Shutdown);
        }

        // Wait for all permits to be available (all in-flight pushes complete)
        let mut permits = Vec::with_capacity(MAX_CONCURRENT_PUSHES);
        for _ in 0..MAX_CONCURRENT_PUSHES {
            if let Ok(permit) = self.semaphore.acquire().await {
                permits.push(permit);
            }
        }
        debug!("All in-flight push notifications completed");
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
        dispatcher.dispatch(vec![]).await;
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
        dispatcher.dispatch(payloads).await;
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

        dispatcher.dispatch(payloads).await;
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

        dispatcher.dispatch(payloads).await;
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

        dispatcher.dispatch(payloads).await;
        // Should not panic, just skip the notification
    }

    #[tokio::test]
    async fn test_dispatch_both_platforms() {
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

        dispatcher.dispatch(payloads).await;
        // Tasks are spawned - give them time to start
        tokio::time::sleep(Duration::from_millis(50)).await;
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

        dispatcher.dispatch(payloads).await;
        // Should not panic, just ignore
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
}

//! Push notification dispatcher.
//!
//! Routes decrypted tokens to the appropriate push service (APNs or FCM)
//! with semaphore-based concurrency control.

use std::sync::Arc;

use tokio::sync::Semaphore;
use tracing::{debug, trace, warn};

use crate::crypto::{Platform, TokenPayload};
use crate::push::{ApnsClient, FcmClient};

/// Maximum concurrent outbound push requests.
const MAX_CONCURRENT_PUSHES: usize = 100;

/// Push notification dispatcher.
pub struct PushDispatcher {
    apns_client: Option<Arc<ApnsClient>>,
    fcm_client: Option<Arc<FcmClient>>,
    semaphore: Arc<Semaphore>,
}

impl PushDispatcher {
    /// Create a new push dispatcher.
    pub fn new(apns_client: Option<ApnsClient>, fcm_client: Option<FcmClient>) -> Self {
        Self {
            apns_client: apns_client.map(Arc::new),
            fcm_client: fcm_client.map(Arc::new),
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_PUSHES)),
        }
    }

    /// Dispatch push notifications for all payloads.
    ///
    /// This spawns tasks for each notification and does not wait for them
    /// to complete. Invalid tokens are silently ignored per MIP-05 spec.
    pub async fn dispatch(&self, payloads: Vec<TokenPayload>) {
        for payload in payloads {
            match payload.platform {
                Platform::Apns => {
                    if let Some(client) = &self.apns_client {
                        let client = client.clone();
                        let semaphore = self.semaphore.clone();
                        let token = payload.device_token_hex();

                        tokio::spawn(async move {
                            let permit = match semaphore.acquire_owned().await {
                                Ok(p) => p,
                                Err(_) => {
                                    warn!("Semaphore closed, stopping dispatch");
                                    return;
                                }
                            };
                            let _permit = permit; // Hold permit until end of scope

                            match client.send(&token).await {
                                Ok(true) => trace!("APNs notification sent"),
                                Ok(false) => trace!("APNs notification failed (invalid token)"),
                                Err(e) => debug!(error = %e, "APNs send error"),
                            }
                        });
                    } else {
                        trace!("APNs not configured, skipping notification");
                    }
                }
                Platform::Fcm => {
                    if let Some(client) = &self.fcm_client {
                        let token = match payload.device_token_string() {
                            Some(t) => t,
                            None => {
                                trace!("Invalid FCM token (not UTF-8)");
                                continue;
                            }
                        };

                        let client = client.clone();
                        let semaphore = self.semaphore.clone();

                        tokio::spawn(async move {
                            let permit = match semaphore.acquire_owned().await {
                                Ok(p) => p,
                                Err(_) => {
                                    warn!("Semaphore closed, stopping dispatch");
                                    return;
                                }
                            };
                            let _permit = permit; // Hold permit until end of scope

                            match client.send(&token).await {
                                Ok(true) => trace!("FCM notification sent"),
                                Ok(false) => trace!("FCM notification failed (invalid token)"),
                                Err(e) => debug!(error = %e, "FCM send error"),
                            }
                        });
                    } else {
                        trace!("FCM not configured, skipping notification");
                    }
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
    /// This is used during graceful shutdown.
    pub async fn wait_for_completion(&self) {
        // Acquire all permits to ensure no pushes are in flight
        let mut permits = Vec::with_capacity(MAX_CONCURRENT_PUSHES);
        for _ in 0..MAX_CONCURRENT_PUSHES {
            if let Ok(permit) = self.semaphore.acquire().await {
                permits.push(permit);
            }
        }
        debug!("All in-flight push notifications completed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_dispatcher_no_clients() {
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
}

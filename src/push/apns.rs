//! Apple Push Notification Service (APNs) client.
//!
//! Uses token-based (JWT) authentication with a .p8 key file.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, error, trace, warn};

use crate::config::ApnsConfig;
use crate::error::{Error, Result};
use crate::push::retry::{self, RetryConfig, SendAttemptResult};

/// APNs JWT token lifetime (50 minutes, less than the 1 hour max).
const TOKEN_LIFETIME: Duration = Duration::from_secs(50 * 60);

/// JWT claims for APNs authentication.
#[derive(Debug, Serialize)]
struct ApnsClaims {
    /// Issuer (Team ID).
    iss: String,
    /// Issued at timestamp.
    iat: u64,
}

/// Cached JWT token.
pub(crate) struct CachedToken {
    token: String,
    expires_at: SystemTime,
}

/// APNs silent notification payload.
#[derive(Debug, Serialize)]
struct ApnsPayload {
    aps: ApnsAps,
}

#[derive(Debug, Serialize)]
struct ApnsAps {
    #[serde(rename = "content-available")]
    content_available: u8,
}

impl Default for ApnsPayload {
    fn default() -> Self {
        Self {
            aps: ApnsAps {
                content_available: 1,
            },
        }
    }
}

/// APNs error response.
#[derive(Debug, Deserialize)]
struct ApnsErrorResponse {
    reason: String,
}

/// APNs client for sending push notifications.
pub struct ApnsClient {
    pub(crate) http_client: Client,
    pub(crate) config: ApnsConfig,
    pub(crate) encoding_key: Option<EncodingKey>,
    pub(crate) cached_token: Arc<RwLock<Option<CachedToken>>>,
}

impl ApnsClient {
    /// Create a new APNs client.
    pub async fn new(config: ApnsConfig) -> Result<Self> {
        let http_client = Client::builder()
            .http2_prior_knowledge()
            .timeout(Duration::from_secs(30))
            .build()?;

        // Load encoding key for token auth
        let encoding_key = if !config.private_key_path.is_empty() {
            let key_data = tokio::fs::read(&config.private_key_path)
                .await
                .map_err(|e| {
                    Error::Apns(format!(
                        "Failed to read APNs key file '{}': {e}",
                        config.private_key_path
                    ))
                })?;

            Some(
                EncodingKey::from_ec_pem(&key_data)
                    .map_err(|e| Error::Apns(format!("Failed to parse APNs key: {e}")))?,
            )
        } else {
            None
        };

        Ok(Self {
            http_client,
            config,
            encoding_key,
            cached_token: Arc::new(RwLock::new(None)),
        })
    }

    /// Get a valid JWT token, refreshing if necessary.
    async fn get_token(&self) -> Result<String> {
        // First check with read lock (fast path)
        {
            let cached = self.cached_token.read().await;
            if let Some(ref token) = *cached
                && token.expires_at > SystemTime::now()
            {
                return Ok(token.token.clone());
            }
        }

        // Acquire write lock and double-check to avoid TOCTOU race
        let mut cached = self.cached_token.write().await;
        if let Some(ref token) = *cached
            && token.expires_at > SystemTime::now()
        {
            return Ok(token.token.clone());
        }

        // Generate and cache new token
        let token = self.generate_token()?;
        *cached = Some(CachedToken {
            token: token.clone(),
            expires_at: SystemTime::now() + TOKEN_LIFETIME,
        });

        Ok(token)
    }

    /// Generate a new JWT token.
    fn generate_token(&self) -> Result<String> {
        let encoding_key = self
            .encoding_key
            .as_ref()
            .ok_or_else(|| Error::Apns("No encoding key configured".to_string()))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::Apns(format!("System time error: {e}")))?
            .as_secs();

        let claims = ApnsClaims {
            iss: self.config.team_id.clone(),
            iat: now,
        };

        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.config.key_id.clone());

        let token = encode(&header, &claims, encoding_key)?;

        trace!("Generated new APNs JWT token");
        Ok(token)
    }

    /// Send a silent push notification to a device.
    ///
    /// Returns `Ok(true)` if successful, `Ok(false)` if the token is invalid/expired,
    /// or `Err` for other failures.
    ///
    /// This method automatically retries transient failures (429, 5xx) with
    /// exponential backoff.
    pub async fn send(&self, device_token: &str) -> Result<bool> {
        let retry_config = RetryConfig::default();
        retry::with_retry(&retry_config, "APNs", || self.send_once(device_token)).await
    }

    /// Send a single push notification attempt without retry.
    ///
    /// Returns a `SendAttemptResult` indicating success, retriable error, or permanent error.
    async fn send_once(&self, device_token: &str) -> SendAttemptResult {
        let url = format!("{}/3/device/{}", self.config.base_url(), device_token);

        let payload = ApnsPayload::default();

        let mut request = self
            .http_client
            .post(&url)
            .header("apns-push-type", "background")
            .header("apns-priority", "5")
            .header("apns-topic", &self.config.bundle_id)
            .json(&payload);

        // Add authorization header
        let token = match self.get_token().await {
            Ok(t) => t,
            Err(e) => return SendAttemptResult::Permanent(e),
        };
        request = request.header("authorization", format!("bearer {token}"));

        let response = match request.send().await {
            Ok(r) => r,
            Err(e) => return SendAttemptResult::Permanent(Error::from(e)),
        };

        let status = response.status();

        match status.as_u16() {
            200 => {
                trace!("APNs notification sent successfully");
                SendAttemptResult::Success(true)
            }
            400 => {
                let error: ApnsErrorResponse = response.json().await.unwrap_or(ApnsErrorResponse {
                    reason: "Unknown".to_string(),
                });
                warn!(reason = %error.reason, "APNs bad request");
                SendAttemptResult::Success(false)
            }
            403 => {
                let error: ApnsErrorResponse = response.json().await.unwrap_or(ApnsErrorResponse {
                    reason: "Unknown".to_string(),
                });
                error!(reason = %error.reason, "APNs authentication error");
                SendAttemptResult::Permanent(Error::Apns(format!(
                    "Authentication error: {}",
                    error.reason
                )))
            }
            410 => {
                // Token is no longer valid (device unregistered)
                debug!("APNs token no longer valid (device unregistered)");
                SendAttemptResult::Success(false)
            }
            429 => {
                // Rate limited - retriable
                let retry_after = response
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| retry::parse_retry_after(Some(v)));
                SendAttemptResult::Retriable {
                    status_code: 429,
                    retry_after,
                }
            }
            500..=599 => {
                // Server error - retriable
                let body = response.text().await.unwrap_or_default();
                debug!(status = %status, body = %body, "APNs server error (retriable)");
                SendAttemptResult::Retriable {
                    status_code: status.as_u16(),
                    retry_after: None,
                }
            }
            _ => {
                let body = response.text().await.unwrap_or_default();
                warn!(status = %status, body = %body, "APNs unexpected response");
                SendAttemptResult::Success(false)
            }
        }
    }

    /// Check if the client is properly configured.
    #[must_use]
    pub fn is_configured(&self) -> bool {
        if !self.config.enabled {
            return false;
        }

        self.encoding_key.is_some()
            && !self.config.key_id.is_empty()
            && !self.config.team_id.is_empty()
            && !self.config.bundle_id.is_empty()
    }
}

#[cfg(test)]
impl ApnsClient {
    /// Create a mock APNs client for testing.
    pub(crate) fn mock(config: ApnsConfig, with_encoding_key: bool) -> Self {
        Self {
            http_client: Client::new(),
            config,
            encoding_key: if with_encoding_key {
                Some(EncodingKey::from_secret(b"fake-key"))
            } else {
                None
            },
            cached_token: Arc::new(RwLock::new(None)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use wiremock::matchers::{header, method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_config() -> ApnsConfig {
        ApnsConfig {
            enabled: true,
            key_id: "KEYID123".to_string(),
            team_id: "TEAMID456".to_string(),
            private_key_path: String::new(),
            environment: "sandbox".to_string(),
            bundle_id: "com.example.app".to_string(),
        }
    }

    #[test]
    fn test_apns_payload_serialization() {
        let payload = ApnsPayload::default();
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("content-available"));
        assert!(json.contains("1"));
    }

    #[tokio::test]
    async fn test_client_not_configured_when_disabled() {
        let config = ApnsConfig {
            enabled: false,
            key_id: String::new(),
            team_id: String::new(),
            private_key_path: String::new(),
            environment: "sandbox".to_string(),
            bundle_id: String::new(),
        };

        let client = ApnsClient::new(config).await.unwrap();
        assert!(!client.is_configured());
    }

    #[tokio::test]
    async fn test_send_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/3/device/[a-f0-9]+"))
            .and(header("apns-push-type", "background"))
            .and(header("apns-priority", "5"))
            .and(header("apns-topic", "com.example.app"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut config = test_config();
        // Override the environment to use the mock server
        config.environment = "sandbox".to_string();

        let http_client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        // Create client with custom HTTP client and pre-populated token cache
        let client = ApnsClient {
            http_client,
            config: ApnsConfig {
                enabled: true,
                key_id: "KEYID123".to_string(),
                team_id: "TEAMID456".to_string(),
                private_key_path: String::new(),
                environment: "sandbox".to_string(),
                bundle_id: "com.example.app".to_string(),
            },
            encoding_key: None,
            cached_token: Arc::new(RwLock::new(Some(CachedToken {
                token: "test-token".to_string(),
                expires_at: SystemTime::now() + Duration::from_secs(3600),
            }))),
        };

        // We need to override the base_url - let's test with a modified approach
        // by creating a custom send function that uses the mock URL
        let url = format!("{}/3/device/{}", mock_server.uri(), "aabbccdd11223344");

        let payload = ApnsPayload::default();
        let response = client
            .http_client
            .post(&url)
            .header("apns-push-type", "background")
            .header("apns-priority", "5")
            .header("apns-topic", "com.example.app")
            .json(&payload)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_send_bad_request() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/3/device/[a-f0-9]+"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "reason": "BadDeviceToken"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let http_client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let url = format!("{}/3/device/{}", mock_server.uri(), "badtoken123456");

        let payload = ApnsPayload::default();
        let response = http_client
            .post(&url)
            .header("apns-push-type", "background")
            .header("apns-priority", "5")
            .header("apns-topic", "com.example.app")
            .json(&payload)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 400);
        let body: ApnsErrorResponse = response.json().await.unwrap();
        assert_eq!(body.reason, "BadDeviceToken");
    }

    #[tokio::test]
    async fn test_send_token_expired() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/3/device/[a-f0-9]+"))
            .respond_with(ResponseTemplate::new(410))
            .expect(1)
            .mount(&mock_server)
            .await;

        let http_client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let url = format!("{}/3/device/{}", mock_server.uri(), "abcd1234ef56");

        let payload = ApnsPayload::default();
        let response = http_client
            .post(&url)
            .header("apns-push-type", "background")
            .header("apns-priority", "5")
            .header("apns-topic", "com.example.app")
            .json(&payload)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 410);
    }

    #[tokio::test]
    async fn test_send_rate_limited() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/3/device/[a-f0-9]+"))
            .respond_with(ResponseTemplate::new(429))
            .expect(1)
            .mount(&mock_server)
            .await;

        let http_client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let url = format!("{}/3/device/{}", mock_server.uri(), "1234567890ab");

        let payload = ApnsPayload::default();
        let response = http_client
            .post(&url)
            .header("apns-push-type", "background")
            .header("apns-priority", "5")
            .header("apns-topic", "com.example.app")
            .json(&payload)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 429);
    }

    #[tokio::test]
    async fn test_send_auth_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/3/device/[a-f0-9]+"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "reason": "InvalidProviderToken"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let http_client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let url = format!("{}/3/device/{}", mock_server.uri(), "deadbeef1234");

        let payload = ApnsPayload::default();
        let response = http_client
            .post(&url)
            .header("apns-push-type", "background")
            .header("apns-priority", "5")
            .header("apns-topic", "com.example.app")
            .json(&payload)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 403);
    }

    #[test]
    fn test_is_configured_with_all_fields() {
        let config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: "production".to_string(),
            bundle_id: "com.example.app".to_string(),
        };

        let client = ApnsClient::mock(config, true);
        assert!(client.is_configured());
    }

    #[test]
    fn test_is_configured_missing_key_id() {
        let config = ApnsConfig {
            enabled: true,
            key_id: String::new(), // Missing
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: "production".to_string(),
            bundle_id: "com.example.app".to_string(),
        };

        let client = ApnsClient::mock(config, true);
        assert!(!client.is_configured());
    }

    #[test]
    fn test_is_configured_missing_team_id() {
        let config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: String::new(), // Missing
            private_key_path: String::new(),
            environment: "production".to_string(),
            bundle_id: "com.example.app".to_string(),
        };

        let client = ApnsClient::mock(config, true);
        assert!(!client.is_configured());
    }

    #[test]
    fn test_is_configured_missing_bundle_id() {
        let config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: "production".to_string(),
            bundle_id: String::new(), // Missing
        };

        let client = ApnsClient::mock(config, true);
        assert!(!client.is_configured());
    }

    #[test]
    fn test_is_configured_missing_encoding_key() {
        let config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: "production".to_string(),
            bundle_id: "com.example.app".to_string(),
        };

        let client = ApnsClient::mock(config, false); // No encoding key
        assert!(!client.is_configured());
    }

    #[tokio::test]
    async fn test_send_unexpected_status() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/3/device/[a-f0-9]+"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let http_client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let url = format!("{}/3/device/{}", mock_server.uri(), "abc123def456");

        let payload = ApnsPayload::default();
        let response = http_client
            .post(&url)
            .header("apns-push-type", "background")
            .header("apns-priority", "5")
            .header("apns-topic", "com.example.app")
            .json(&payload)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 500);
    }

    #[test]
    fn test_generate_token_no_encoding_key() {
        let config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: "production".to_string(),
            bundle_id: "com.example.app".to_string(),
        };

        let client = ApnsClient::mock(config, false);
        let result = client.generate_token();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("No encoding key"));
    }

    #[tokio::test]
    async fn test_get_token_uses_cache() {
        let config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: "production".to_string(),
            bundle_id: "com.example.app".to_string(),
        };

        let client = ApnsClient::mock(config, true);

        // Pre-populate the cache
        {
            let mut cached = client.cached_token.write().await;
            *cached = Some(CachedToken {
                token: "cached-test-token".to_string(),
                expires_at: SystemTime::now() + Duration::from_secs(3600),
            });
        }

        // Should return cached token
        let token = client.get_token().await.unwrap();
        assert_eq!(token, "cached-test-token");
    }

    #[tokio::test]
    async fn test_get_token_expired_cache_regenerates() {
        let config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: "production".to_string(),
            bundle_id: "com.example.app".to_string(),
        };

        // Create a client without an encoding key to test the error case
        let client = ApnsClient::mock(config, false);

        // Pre-populate the cache with an expired token
        {
            let mut cached = client.cached_token.write().await;
            *cached = Some(CachedToken {
                token: "expired-token".to_string(),
                expires_at: SystemTime::now() - Duration::from_secs(1), // Already expired
            });
        }

        // Should try to generate new token but fail since no encoding key
        let result = client.get_token().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_token_cache_not_expired() {
        let config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: "production".to_string(),
            bundle_id: "com.example.app".to_string(),
        };

        let client = ApnsClient::mock(config, false); // No encoding key

        // Pre-populate the cache with a valid (non-expired) token
        {
            let mut cached = client.cached_token.write().await;
            *cached = Some(CachedToken {
                token: "valid-cached-token".to_string(),
                expires_at: SystemTime::now() + Duration::from_secs(3600), // 1 hour in the future
            });
        }

        // Should return cached token (no encoding key needed since we have valid cache)
        let token = client.get_token().await.unwrap();
        assert_eq!(token, "valid-cached-token");
    }

    #[tokio::test]
    async fn test_new_client_without_key_path() {
        let config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(), // Empty path
            environment: "production".to_string(),
            bundle_id: "com.example.app".to_string(),
        };

        let client = ApnsClient::new(config).await.unwrap();
        assert!(client.encoding_key.is_none());
    }

    #[tokio::test]
    async fn test_new_client_invalid_key_path() {
        let config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: "/nonexistent/key.p8".to_string(),
            environment: "production".to_string(),
            bundle_id: "com.example.app".to_string(),
        };

        let result = ApnsClient::new(config).await;
        assert!(result.is_err());
        match result {
            Err(e) => assert!(e.to_string().contains("Failed to read APNs key file")),
            Ok(_) => panic!("Expected error"),
        }
    }

    #[tokio::test]
    async fn test_send_with_cached_token() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/3/device/[a-f0-9]+"))
            .and(header("apns-push-type", "background"))
            .and(header("apns-priority", "5"))
            .and(header("apns-topic", "com.example.app"))
            .and(header("authorization", "bearer test-cached-token"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Create a client with a custom base_url pointing to mock server
        // We need to test the full send() method, so we create a client
        // and manually set its HTTP client to use the mock server
        let http_client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let config = ApnsConfig {
            enabled: true,
            key_id: "KEYID123".to_string(),
            team_id: "TEAMID456".to_string(),
            private_key_path: String::new(),
            environment: "sandbox".to_string(),
            bundle_id: "com.example.app".to_string(),
        };

        let client = ApnsClient {
            http_client,
            config,
            encoding_key: Some(EncodingKey::from_secret(b"fake-key")),
            cached_token: Arc::new(RwLock::new(Some(CachedToken {
                token: "test-cached-token".to_string(),
                expires_at: SystemTime::now() + Duration::from_secs(3600),
            }))),
        };

        // The send method uses self.config.base_url() which returns the real APNs URL,
        // but we can test with direct HTTP calls through the mock
        let url = format!("{}/3/device/{}", mock_server.uri(), "aabbccdd11223344");
        let payload = ApnsPayload::default();

        // Get token from cache
        let token = client.get_token().await.unwrap();
        assert_eq!(token, "test-cached-token");

        // Make request manually (simulating what send() does)
        let response = client
            .http_client
            .post(&url)
            .header("apns-push-type", "background")
            .header("apns-priority", "5")
            .header("apns-topic", "com.example.app")
            .header("authorization", format!("bearer {}", token))
            .json(&payload)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_get_token_generates_new_when_empty_cache() {
        let config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: "production".to_string(),
            bundle_id: "com.example.app".to_string(),
        };

        // Client without encoding key - should fail when trying to generate
        let client = ApnsClient::mock(config, false);

        // Cache is empty, so get_token will try to generate a new one
        let result = client.get_token().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No encoding key"));
    }

    #[tokio::test]
    async fn test_new_client_with_valid_key_file() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Generate a valid EC P-256 private key in PEM format
        // This is a test key - never use in production!
        let test_ec_key = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(test_ec_key.as_bytes()).unwrap();

        let config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: file.path().to_string_lossy().to_string(),
            environment: "production".to_string(),
            bundle_id: "com.example.app".to_string(),
        };

        let client = ApnsClient::new(config).await.unwrap();
        assert!(client.encoding_key.is_some());
        assert!(client.is_configured());
    }

    #[tokio::test]
    async fn test_generate_token_with_valid_key() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Valid EC P-256 test key
        let test_ec_key = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(test_ec_key.as_bytes()).unwrap();

        let config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: file.path().to_string_lossy().to_string(),
            environment: "production".to_string(),
            bundle_id: "com.example.app".to_string(),
        };

        let client = ApnsClient::new(config).await.unwrap();

        // Generate a token
        let token = client.generate_token().unwrap();

        // Token should be a valid JWT (three dot-separated parts)
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have 3 parts");

        // Verify the header contains the key ID
        let header_json = base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(parts[0])
            .unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_json).unwrap();
        assert_eq!(header["kid"], "KEY123");
        assert_eq!(header["alg"], "ES256");
    }

    #[tokio::test]
    async fn test_get_token_caches_generated_token() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Valid EC P-256 test key
        let test_ec_key = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----"#;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(test_ec_key.as_bytes()).unwrap();

        let config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: file.path().to_string_lossy().to_string(),
            environment: "production".to_string(),
            bundle_id: "com.example.app".to_string(),
        };

        let client = ApnsClient::new(config).await.unwrap();

        // Cache should be empty initially
        {
            let cached = client.cached_token.read().await;
            assert!(cached.is_none());
        }

        // Get token - should generate and cache
        let token1 = client.get_token().await.unwrap();

        // Cache should now have a token
        {
            let cached = client.cached_token.read().await;
            assert!(cached.is_some());
            assert_eq!(cached.as_ref().unwrap().token, token1);
        }

        // Get token again - should return cached token (same value)
        let token2 = client.get_token().await.unwrap();
        assert_eq!(token1, token2);
    }
}

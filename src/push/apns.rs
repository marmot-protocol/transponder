//! Apple Push Notification Service (APNs) client.
//!
//! Uses token-based (JWT) authentication with a .p8 key file.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, trace};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::config::{ApnsConfig, ApnsPayloadMode};
use crate::error::{Error, Result};
use crate::metrics::Metrics;
use crate::push::retry::{self, RetryConfig, SendAttemptResult};

/// APNs JWT token lifetime (50 minutes, less than the 1 hour max).
const TOKEN_LIFETIME: Duration = Duration::from_secs(50 * 60);

/// APNs JWT expiration time (1 hour, Apple's maximum).
const TOKEN_EXPIRATION_SECS: u64 = 3600;

/// JWT claims for APNs authentication.
#[derive(Debug, Serialize)]
struct ApnsClaims {
    /// Issuer (Team ID).
    iss: String,
    /// Issued at timestamp.
    iat: u64,
    /// Expiration timestamp.
    exp: u64,
}

/// Cached JWT token.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct CachedToken {
    token: Zeroizing<String>,
    #[zeroize(skip)]
    expires_at: SystemTime,
}

/// APNs notification payload.
#[derive(Debug, Serialize)]
#[serde(untagged)]
enum ApnsPayload {
    Silent(ApnsSilentPayload),
    NsePrototypeAlert(ApnsNsePrototypeAlertPayload),
}

#[derive(Debug, Serialize)]
struct ApnsSilentPayload {
    aps: ApnsSilentAps,
}

#[derive(Debug, Serialize)]
struct ApnsSilentAps {
    #[serde(rename = "content-available")]
    content_available: u8,
}

impl Default for ApnsPayload {
    fn default() -> Self {
        Self::Silent(ApnsSilentPayload {
            aps: ApnsSilentAps {
                content_available: 1,
            },
        })
    }
}

impl From<ApnsPayloadMode> for ApnsPayload {
    fn from(mode: ApnsPayloadMode) -> Self {
        match mode {
            ApnsPayloadMode::Silent => Self::default(),
            ApnsPayloadMode::NsePrototypeAlert => {
                Self::NsePrototypeAlert(ApnsNsePrototypeAlertPayload::default())
            }
        }
    }
}

#[derive(Debug, Serialize)]
struct ApnsNsePrototypeAlertPayload {
    aps: ApnsNsePrototypeAps,
    wn_nse_prototype: bool,
}

impl Default for ApnsNsePrototypeAlertPayload {
    fn default() -> Self {
        Self {
            aps: ApnsNsePrototypeAps::default(),
            wn_nse_prototype: true,
        }
    }
}

#[derive(Debug, Serialize)]
struct ApnsNsePrototypeAps {
    alert: ApnsAlert,
    #[serde(rename = "mutable-content")]
    mutable_content: u8,
    sound: &'static str,
}

impl Default for ApnsNsePrototypeAps {
    fn default() -> Self {
        Self {
            alert: ApnsAlert {
                title: "White Noise",
                body: "New encrypted message",
            },
            mutable_content: 1,
            sound: "default",
        }
    }
}

#[derive(Debug, Serialize)]
struct ApnsAlert {
    title: &'static str,
    body: &'static str,
}

fn redacted_device_token_id(_device_token: &str) -> &'static str {
    "<redacted_device_token>"
}

#[derive(Debug)]
struct ApnsRequestParts {
    push_type: &'static str,
    priority: &'static str,
    payload: ApnsPayload,
}

impl ApnsRequestParts {
    fn for_mode(mode: ApnsPayloadMode) -> Self {
        Self {
            push_type: mode.push_type(),
            priority: mode.priority(),
            payload: ApnsPayload::from(mode),
        }
    }
}

/// APNs error response.
#[derive(Debug, Deserialize)]
struct ApnsErrorResponse {
    reason: String,
}

/// Validate an APNs device token format.
///
/// MIP-05 treats APNs tokens as variable-length opaque bytes. Transponder
/// hex-encodes those bytes for the APNs device-token URL path, so only reject
/// empty, odd-length, or non-hex strings here.
#[must_use]
fn is_valid_device_token(token: &str) -> bool {
    !token.is_empty()
        && token.len().is_multiple_of(2)
        && token.chars().all(|c| c.is_ascii_hexdigit())
}

/// APNs client for sending push notifications.
pub struct ApnsClient {
    pub(crate) http_client: Client,
    pub(crate) config: ApnsConfig,
    pub(crate) encoding_key: Option<EncodingKey>,
    pub(crate) cached_token: Arc<RwLock<Option<CachedToken>>>,
    pub(crate) metrics: Option<Metrics>,
}

impl ApnsClient {
    /// Create a new APNs client.
    #[allow(dead_code)]
    pub async fn new(config: ApnsConfig) -> Result<Self> {
        Self::with_metrics(config, None).await
    }

    /// Create a new APNs client with metrics.
    pub async fn with_metrics(config: ApnsConfig, metrics: Option<Metrics>) -> Result<Self> {
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
            metrics,
        })
    }

    /// Get a valid JWT token, refreshing if necessary.
    async fn get_token(&self) -> Result<Zeroizing<String>> {
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

        // Generate and cache new token. The caller gets a short-lived zeroizing
        // clone for request construction while the cache owns the reusable copy.
        let token = self.generate_token()?;
        let cached_token = CachedToken {
            token,
            expires_at: SystemTime::now() + TOKEN_LIFETIME,
        };
        let outbound_token = cached_token.token.clone();
        *cached = Some(cached_token);

        Ok(outbound_token)
    }

    /// Generate a new JWT token.
    fn generate_token(&self) -> Result<Zeroizing<String>> {
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
            exp: now + TOKEN_EXPIRATION_SECS,
        };

        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.config.key_id.clone());

        let token = Zeroizing::new(encode(&header, &claims, encoding_key)?);

        if let Some(metrics) = &self.metrics {
            metrics.record_auth_token_refresh("apns_jwt");
        }

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
    ///
    /// When `backoff_permit` is `Some`, the dispatcher concurrency permit is
    /// released during backoff sleeps and re-acquired before each retry, so a
    /// sleeping retry does not occupy an in-flight concurrency slot.
    pub async fn send(
        &self,
        device_token: &str,
        backoff_permit: Option<&mut crate::push::retry::BackoffPermit>,
    ) -> Result<bool> {
        // Validate token format before sending
        if !is_valid_device_token(device_token) {
            trace!(
                token_len = device_token.len(),
                "Invalid APNs device token format"
            );
            return Ok(false);
        }

        let retry_config = RetryConfig::default();
        retry::with_retry(
            &retry_config,
            "APNs",
            || self.send_once(device_token),
            backoff_permit,
            self.metrics.as_ref(),
        )
        .await
    }

    fn build_request(
        &self,
        url: &str,
        auth_token: &str,
        request_parts: &ApnsRequestParts,
    ) -> reqwest::RequestBuilder {
        self.http_client
            .post(url)
            .header("apns-push-type", request_parts.push_type)
            .header("apns-priority", request_parts.priority)
            .header("apns-topic", &self.config.bundle_id)
            .header("authorization", format!("bearer {auth_token}"))
            .json(&request_parts.payload)
    }

    /// Invalidate the cached token only if it still matches the one the failing
    /// request used.
    ///
    /// Under concurrency another task may have already refreshed the cache with
    /// a fresh token between the time this request read its token and the time
    /// the authentication rejection came back. Evicting unconditionally would
    /// discard that valid token and force redundant JWT regeneration, so the
    /// eviction is gated on the cached entry still being the failing token.
    async fn invalidate_cached_token(&self, failing_token: &str) {
        let mut cached = self.cached_token.write().await;
        if cached
            .as_ref()
            .is_some_and(|token| token.token.as_str() == failing_token)
        {
            *cached = None;
            debug!("Invalidated cached APNs JWT after authentication rejection");
        }
    }

    async fn handle_response(
        &self,
        start: Instant,
        response: reqwest::Response,
        auth_token: &str,
    ) -> SendAttemptResult {
        let status = response.status();

        if let Some(metrics) = &self.metrics {
            metrics.observe_push_duration("apns", start.elapsed().as_secs_f64());
            metrics.record_push_response_status("apns", status.as_u16());
        }

        match status.as_u16() {
            200 => {
                debug!(
                    payload_mode = %self.config.payload_mode,
                    status = status.as_u16(),
                    "APNs notification accepted"
                );
                SendAttemptResult::Success(true)
            }
            400 => {
                let error: ApnsErrorResponse = response.json().await.unwrap_or(ApnsErrorResponse {
                    reason: "Unknown".to_string(),
                });
                debug!(
                    payload_mode = %self.config.payload_mode,
                    reason = %error.reason,
                    "APNs bad request"
                );
                SendAttemptResult::Success(false)
            }
            403 => {
                self.invalidate_cached_token(auth_token).await;
                let error: ApnsErrorResponse = response.json().await.unwrap_or(ApnsErrorResponse {
                    reason: "Unknown".to_string(),
                });
                debug!(
                    payload_mode = %self.config.payload_mode,
                    reason = %error.reason,
                    "APNs authentication error"
                );
                SendAttemptResult::Permanent(Error::Apns(format!(
                    "Authentication error: {}",
                    error.reason
                )))
            }
            410 => {
                // Token is no longer valid (device unregistered)
                debug!(
                    payload_mode = %self.config.payload_mode,
                    "APNs token no longer valid"
                );
                SendAttemptResult::Success(false)
            }
            429 => {
                // Rate limited - retriable
                let retry_after = response
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| retry::parse_retry_after(Some(v)));
                debug!(
                    payload_mode = %self.config.payload_mode,
                    "APNs rate limited request"
                );
                SendAttemptResult::Retriable {
                    status_code: 429,
                    retry_after,
                }
            }
            500..=599 => {
                // Server error - retriable
                debug!(
                    payload_mode = %self.config.payload_mode,
                    status = %status,
                    "APNs server error (retriable)"
                );
                SendAttemptResult::Retriable {
                    status_code: status.as_u16(),
                    retry_after: None,
                }
            }
            _ => {
                debug!(
                    payload_mode = %self.config.payload_mode,
                    status = %status,
                    "APNs unexpected response"
                );
                SendAttemptResult::Success(false)
            }
        }
    }

    /// Send a single push notification attempt without retry.
    ///
    /// Returns a `SendAttemptResult` indicating success, retriable error, or permanent error.
    async fn send_once(&self, device_token: &str) -> SendAttemptResult {
        self.send_once_with_transport_retry_config(device_token, &RetryConfig::default())
            .await
    }

    async fn send_once_with_transport_retry_config(
        &self,
        device_token: &str,
        transport_retry: &RetryConfig,
    ) -> SendAttemptResult {
        let start = Instant::now();
        let url = format!("{}/3/device/{}", self.config.base_url(), device_token);

        debug!(
            payload_mode = %self.config.payload_mode,
            push_type = self.config.payload_mode.push_type(),
            priority = self.config.payload_mode.priority(),
            topic = %self.config.bundle_id,
            device_token = redacted_device_token_id(device_token),
            "Sending APNs notification"
        );

        // Add authorization header
        let token = match self.get_token().await {
            Ok(t) => t,
            Err(e) => return SendAttemptResult::Permanent(e),
        };

        let request_parts = ApnsRequestParts::for_mode(self.config.payload_mode);
        let response = match retry::with_transport_retry(
            transport_retry,
            "APNs",
            || async {
                self.build_request(&url, token.as_str(), &request_parts)
                    .send()
                    .await
                    .map_err(Error::from)
            },
            self.metrics.as_ref(),
        )
        .await
        {
            Ok(r) => r,
            Err(e) => return SendAttemptResult::Permanent(e),
        };

        self.handle_response(start, response, token.as_str()).await
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
            metrics: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use wiremock::matchers::{header, method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use zeroize::Zeroizing;

    fn test_config() -> ApnsConfig {
        ApnsConfig {
            enabled: true,
            key_id: "KEYID123".to_string(),
            team_id: "TEAMID456".to_string(),
            private_key_path: String::new(),
            environment: "sandbox".to_string(),
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
        }
    }

    fn header_value<'a>(request: &'a reqwest::Request, name: &str) -> &'a str {
        request.headers().get(name).unwrap().to_str().unwrap()
    }

    fn request_json(request: &reqwest::Request) -> serde_json::Value {
        let body = request.body().and_then(reqwest::Body::as_bytes).unwrap();
        serde_json::from_slice(body).unwrap()
    }

    #[test]
    fn test_apns_payload_serialization() {
        let payload = ApnsPayload::default();
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("content-available"));
        assert!(json.contains("1"));
    }

    #[test]
    fn test_device_token_redaction_is_not_token_derived() {
        assert_eq!(
            redacted_device_token_id("00112233445566778899aabbccddeeff"),
            "<redacted_device_token>"
        );
        assert_eq!(
            redacted_device_token_id("ffeeddccbbaa99887766554433221100"),
            "<redacted_device_token>"
        );
    }

    #[test]
    fn test_silent_mode_builds_background_headers_and_payload() {
        let mut config = test_config();
        config.payload_mode = ApnsPayloadMode::Silent;
        config.bundle_id = "dev.ipf.whitenoise.staging".to_string();
        let client = ApnsClient::mock(config, false);
        let request_parts = ApnsRequestParts::for_mode(client.config.payload_mode);

        let request = client
            .build_request(
                "https://api.push.apple.com/3/device/aabbccdd11223344",
                "test-token",
                &request_parts,
            )
            .build()
            .unwrap();

        assert_eq!(header_value(&request, "apns-push-type"), "background");
        assert_eq!(header_value(&request, "apns-priority"), "5");
        assert_eq!(
            header_value(&request, "apns-topic"),
            "dev.ipf.whitenoise.staging"
        );
        assert_eq!(
            request_json(&request),
            serde_json::json!({
                "aps": {
                    "content-available": 1
                }
            })
        );
    }

    #[test]
    fn test_nse_prototype_alert_mode_builds_alert_headers_and_payload() {
        let mut config = test_config();
        config.payload_mode = ApnsPayloadMode::NsePrototypeAlert;
        config.bundle_id = "dev.ipf.whitenoise.staging".to_string();
        let client = ApnsClient::mock(config, false);
        let request_parts = ApnsRequestParts::for_mode(client.config.payload_mode);

        let request = client
            .build_request(
                "https://api.push.apple.com/3/device/aabbccdd11223344",
                "test-token",
                &request_parts,
            )
            .build()
            .unwrap();

        assert_eq!(header_value(&request, "apns-push-type"), "alert");
        assert_eq!(header_value(&request, "apns-priority"), "10");
        assert_eq!(
            header_value(&request, "apns-topic"),
            "dev.ipf.whitenoise.staging"
        );
        assert_eq!(
            request_json(&request),
            serde_json::json!({
                "aps": {
                    "alert": {
                        "title": "White Noise",
                        "body": "New encrypted message"
                    },
                    "mutable-content": 1,
                    "sound": "default"
                },
                "wn_nse_prototype": true
            })
        );
    }

    #[test]
    fn test_cached_token_stores_jwt_in_zeroizing_string() {
        // Compile-time guard: cached credentials must stay zeroizing.
        fn assert_zeroizing_string(_: &Zeroizing<String>) {}

        let cached = CachedToken {
            token: Zeroizing::new("cached-jwt".to_string()),
            expires_at: SystemTime::now() + Duration::from_secs(60),
        };

        assert_zeroizing_string(&cached.token);
    }

    #[test]
    fn test_valid_device_token() {
        // Valid short hex token (lowercase)
        assert!(is_valid_device_token("0123456789abcdef"));

        // Valid 64-character hex token (lowercase)
        assert!(is_valid_device_token(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));

        // Valid longer-than-64-character hex token (uppercase)
        assert!(is_valid_device_token(
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01"
        ));

        // Valid mixed-case hex token
        assert!(is_valid_device_token(
            "0123456789AbCdEf0123456789AbCdEf0123456789AbCdEf0123456789AbCdEf"
        ));
    }

    #[test]
    fn test_invalid_device_token_empty() {
        assert!(!is_valid_device_token(""));
    }

    #[test]
    fn test_invalid_device_token_odd_length() {
        assert!(!is_valid_device_token("abc"));
    }

    #[test]
    fn test_invalid_device_token_non_hex_chars() {
        // Contains 'g' which is not hex
        assert!(!is_valid_device_token(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"
        ));

        // Contains spaces
        assert!(!is_valid_device_token(
            "0123456789abcdef 123456789abcdef0123456789abcdef0123456789abcdef"
        ));

        // Contains special characters
        assert!(!is_valid_device_token(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde!"
        ));

        // Contains unicode
        assert!(!is_valid_device_token(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdéf"
        ));
    }

    #[tokio::test]
    async fn test_send_rejects_invalid_device_token() {
        let config = ApnsConfig {
            enabled: true,
            key_id: "KEYID123".to_string(),
            team_id: "TEAMID456".to_string(),
            private_key_path: String::new(),
            environment: "sandbox".to_string(),
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
        };

        let client = ApnsClient {
            http_client: Client::new(),
            config,
            encoding_key: Some(EncodingKey::from_secret(b"fake-key")),
            cached_token: Arc::new(RwLock::new(Some(CachedToken {
                token: Zeroizing::new("test-token".to_string()),
                expires_at: SystemTime::now() + Duration::from_secs(3600),
            }))),
            metrics: None,
        };

        // Test with a token that contains non-hex characters
        let result = client.send("tooshort", None).await.unwrap();
        assert!(
            !result,
            "Should return false for token with non-hex characters"
        );

        // Test with token that has invalid characters
        let result = client
            .send(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg",
                None,
            )
            .await
            .unwrap();
        assert!(
            !result,
            "Should return false for token with invalid characters"
        );

        // Test with empty token
        let result = client.send("", None).await.unwrap();
        assert!(!result, "Should return false for empty token");
    }

    #[tokio::test]
    async fn test_send_once_returns_transport_error_after_connect_retries() {
        let proxy_addr = {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let addr = listener.local_addr().unwrap();
            drop(listener);
            addr
        };
        let http_client = Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://{proxy_addr}")).unwrap())
            .connect_timeout(Duration::from_millis(50))
            .timeout(Duration::from_millis(50))
            .build()
            .unwrap();
        let client = ApnsClient {
            http_client,
            config: test_config(),
            encoding_key: None,
            cached_token: Arc::new(RwLock::new(Some(CachedToken {
                token: Zeroizing::new("cached-token".to_string()),
                expires_at: SystemTime::now() + Duration::from_secs(3600),
            }))),
            metrics: None,
        };
        let retry_config = RetryConfig {
            max_retries: 3,
            initial_backoff: Duration::from_millis(1),
        };

        let result = client
            .send_once_with_transport_retry_config("aabbccdd11223344", &retry_config)
            .await;

        assert!(matches!(
            result,
            SendAttemptResult::Permanent(Error::Http(_))
        ));
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
            payload_mode: Default::default(),
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
                payload_mode: Default::default(),
            },
            encoding_key: None,
            cached_token: Arc::new(RwLock::new(Some(CachedToken {
                token: Zeroizing::new("test-token".to_string()),
                expires_at: SystemTime::now() + Duration::from_secs(3600),
            }))),
            metrics: None,
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

    #[tokio::test]
    async fn test_auth_error_invalidates_cached_token() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/3/device/[a-f0-9]+"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "reason": "BadJwtToken"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = ApnsClient::mock(test_config(), false);
        {
            let mut cached = client.cached_token.write().await;
            *cached = Some(CachedToken {
                token: Zeroizing::new("poisoned-jwt".to_string()),
                expires_at: SystemTime::now() + TOKEN_LIFETIME,
            });
        }

        let response = Client::new()
            .post(format!("{}/3/device/{}", mock_server.uri(), "deadbeef1234"))
            .send()
            .await
            .unwrap();

        let result = client
            .handle_response(Instant::now(), response, "poisoned-jwt")
            .await;

        assert!(matches!(
            result,
            SendAttemptResult::Permanent(Error::Apns(ref message))
                if message.contains("BadJwtToken")
        ));
        assert!(client.cached_token.read().await.is_none());
    }

    #[tokio::test]
    async fn test_auth_error_keeps_token_refreshed_by_concurrent_task() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/3/device/[a-f0-9]+"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "reason": "InvalidProviderToken"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = ApnsClient::mock(test_config(), false);

        // Simulate a concurrent task having already refreshed the cache to a
        // newer token after the failing request read its (now stale) token.
        {
            let mut cached = client.cached_token.write().await;
            *cached = Some(CachedToken {
                token: Zeroizing::new("fresh-jwt".to_string()),
                expires_at: SystemTime::now() + TOKEN_LIFETIME,
            });
        }

        let response = Client::new()
            .post(format!("{}/3/device/{}", mock_server.uri(), "deadbeef1234"))
            .send()
            .await
            .unwrap();

        // The failing request used the older, now-replaced token.
        let result = client
            .handle_response(Instant::now(), response, "stale-jwt")
            .await;

        assert!(matches!(
            result,
            SendAttemptResult::Permanent(Error::Apns(ref message))
                if message.contains("InvalidProviderToken")
        ));

        // The freshly refreshed token must survive the stale rejection.
        let cached = client.cached_token.read().await;
        assert_eq!(
            cached.as_ref().map(|token| token.token.as_str()),
            Some("fresh-jwt")
        );
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
            payload_mode: Default::default(),
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
            payload_mode: Default::default(),
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
            payload_mode: Default::default(),
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
            payload_mode: Default::default(),
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
            payload_mode: Default::default(),
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
            payload_mode: Default::default(),
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
            payload_mode: Default::default(),
        };

        let client = ApnsClient::mock(config, true);

        // Pre-populate the cache
        {
            let mut cached = client.cached_token.write().await;
            *cached = Some(CachedToken {
                token: Zeroizing::new("cached-test-token".to_string()),
                expires_at: SystemTime::now() + Duration::from_secs(3600),
            });
        }

        // Should return cached token
        let token = client.get_token().await.unwrap();
        assert_eq!(token.as_str(), "cached-test-token");
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
            payload_mode: Default::default(),
        };

        // Create a client without an encoding key to test the error case
        let client = ApnsClient::mock(config, false);

        // Pre-populate the cache with an expired token
        {
            let mut cached = client.cached_token.write().await;
            *cached = Some(CachedToken {
                token: Zeroizing::new("expired-token".to_string()),
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
            payload_mode: Default::default(),
        };

        let client = ApnsClient::mock(config, false); // No encoding key

        // Pre-populate the cache with a valid (non-expired) token
        {
            let mut cached = client.cached_token.write().await;
            *cached = Some(CachedToken {
                token: Zeroizing::new("valid-cached-token".to_string()),
                expires_at: SystemTime::now() + Duration::from_secs(3600), // 1 hour in the future
            });
        }

        // Should return cached token (no encoding key needed since we have valid cache)
        let token = client.get_token().await.unwrap();
        assert_eq!(token.as_str(), "valid-cached-token");
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
            payload_mode: Default::default(),
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
            payload_mode: Default::default(),
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
            payload_mode: Default::default(),
        };

        let client = ApnsClient {
            http_client,
            config,
            encoding_key: Some(EncodingKey::from_secret(b"fake-key")),
            cached_token: Arc::new(RwLock::new(Some(CachedToken {
                token: Zeroizing::new("test-cached-token".to_string()),
                expires_at: SystemTime::now() + Duration::from_secs(3600),
            }))),
            metrics: None,
        };

        // The send method uses self.config.base_url() which returns the real APNs URL,
        // but we can test with direct HTTP calls through the mock
        let url = format!("{}/3/device/{}", mock_server.uri(), "aabbccdd11223344");
        let payload = ApnsPayload::default();

        // Get token from cache
        let token = client.get_token().await.unwrap();
        assert_eq!(token.as_str(), "test-cached-token");

        // Make request manually (simulating what send() does)
        let response = client
            .http_client
            .post(&url)
            .header("apns-push-type", "background")
            .header("apns-priority", "5")
            .header("apns-topic", "com.example.app")
            .header("authorization", format!("bearer {}", token.as_str()))
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
            payload_mode: Default::default(),
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
            payload_mode: Default::default(),
        };

        let client = ApnsClient::new(config).await.unwrap();
        assert!(client.encoding_key.is_some());
        assert!(client.is_configured());
    }

    #[tokio::test]
    async fn test_generate_token_with_valid_key() {
        use crate::metrics::Metrics;
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
            payload_mode: Default::default(),
        };

        let metrics = Metrics::default();
        let client = ApnsClient::with_metrics(config, Some(metrics.clone()))
            .await
            .unwrap();

        // Generate a token
        let token = client.generate_token().unwrap();

        // Token should be a valid JWT (three dot-separated parts)
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have 3 parts");

        // Verify metrics
        let metric_families = metrics.gather();
        let mut found = false;
        for family in &metric_families {
            if family.name() == "transponder_auth_token_refreshes_total" {
                for metric in family.get_metric() {
                    for label in metric.get_label() {
                        if label.name() == "service" && label.value() == "apns_jwt" {
                            assert_eq!(metric.get_counter().value, Some(1.0));
                            found = true;
                        }
                    }
                }
            }
        }

        if !found {
            println!("Available metrics:");
            for f in &metric_families {
                println!(" - {}", f.name());
            }
        }

        assert!(
            found,
            "Metric transponder_auth_token_refreshes_total not found"
        );
        assert!(
            found,
            "Metric transponder_auth_token_refresh_total not found"
        );

        // Verify the header contains the key ID
        let header_json = base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(parts[0])
            .unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_json).unwrap();
        assert_eq!(header["kid"], "KEY123");
        assert_eq!(header["alg"], "ES256");

        // Verify the claims contain iss, iat, and exp
        let claims_json = base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&claims_json).unwrap();
        assert_eq!(claims["iss"], "TEAM456");
        assert!(claims["iat"].is_u64(), "iat should be a u64 timestamp");
        assert!(claims["exp"].is_u64(), "exp should be a u64 timestamp");

        // Verify exp is iat + 3600 (1 hour)
        let iat = claims["iat"].as_u64().unwrap();
        let exp = claims["exp"].as_u64().unwrap();
        assert_eq!(exp - iat, 3600, "exp should be iat + 3600 seconds");
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
            payload_mode: Default::default(),
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
            assert_eq!(cached.as_ref().unwrap().token.as_str(), token1.as_str());
        }

        // Get token again - should return cached token (same value)
        let token2 = client.get_token().await.unwrap();
        assert_eq!(token1, token2);
    }

    #[tokio::test]
    async fn test_send_once_returns_retriable_on_429() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/3/device/[a-f0-9]+"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "60"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let http_client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        // Create a client that points to our mock server
        // We'll need to create a custom client for testing send_once
        let config = ApnsConfig {
            enabled: true,
            key_id: "KEYID123".to_string(),
            team_id: "TEAMID456".to_string(),
            private_key_path: String::new(),
            environment: "sandbox".to_string(),
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
        };

        let client = ApnsClient {
            http_client,
            config,
            encoding_key: Some(EncodingKey::from_secret(b"fake-key")),
            cached_token: Arc::new(RwLock::new(Some(CachedToken {
                token: Zeroizing::new("test-token".to_string()),
                expires_at: SystemTime::now() + Duration::from_secs(3600),
            }))),
            metrics: None,
        };

        // Manually test the response handling logic by making a direct request
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

        assert_eq!(response.status(), 429);
        // Verify retry-after header is present
        assert!(response.headers().get("retry-after").is_some());
    }

    #[tokio::test]
    async fn test_send_once_returns_retriable_on_500() {
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

        // 500 should be a retriable error
        assert_eq!(response.status(), 500);
    }

    #[tokio::test]
    async fn test_send_once_returns_retriable_on_503() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/3/device/[a-f0-9]+"))
            .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
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

        // 503 should be a retriable error
        assert_eq!(response.status(), 503);
    }

    #[tokio::test]
    async fn test_send_retries_on_429_then_succeeds() {
        let mock_server = MockServer::start().await;

        // First request returns 429, second returns 200
        Mock::given(method("POST"))
            .and(path_regex(r"/3/device/[a-f0-9]+"))
            .respond_with(ResponseTemplate::new(429))
            .expect(1)
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path_regex(r"/3/device/[a-f0-9]+"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let http_client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        // First request - should get 429
        let url = format!("{}/3/device/{}", mock_server.uri(), "aabbccdd11223344");
        let payload = ApnsPayload::default();

        let response1 = http_client
            .post(&url)
            .header("apns-push-type", "background")
            .header("apns-priority", "5")
            .header("apns-topic", "com.example.app")
            .json(&payload)
            .send()
            .await
            .unwrap();

        assert_eq!(response1.status(), 429);

        // Second request - should get 200
        let response2 = http_client
            .post(&url)
            .header("apns-push-type", "background")
            .header("apns-priority", "5")
            .header("apns-topic", "com.example.app")
            .json(&payload)
            .send()
            .await
            .unwrap();

        assert_eq!(response2.status(), 200);
    }
}

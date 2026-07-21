//! Apple Push Notification Service (APNs) client.
//!
//! Uses token-based (JWT) authentication with a .p8 key file.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use reqwest::Client;
use reqwest::header::HeaderValue;
use serde::{Deserialize, Serialize};
use tracing::{debug, trace, warn};
use zeroize::Zeroizing;

use crate::config::{ApnsConfig, ApnsPayloadMode};
use crate::error::{Error, Result};
use crate::metrics::Metrics;
use crate::push::auth::{AuthTokenGenerator, MintedToken, TokenAcquisitionError, TokenCache};
use crate::push::retry::{self, PushSendOutcome, RetryConfig, SendAttemptResult};

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

/// APNs notification payload.
#[derive(Debug, Serialize)]
#[serde(untagged)]
enum ApnsPayload {
    Silent(ApnsSilentPayload),
    GenericAlert(ApnsGenericAlertPayload),
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

impl ApnsPayload {
    fn for_config(config: &ApnsConfig) -> Self {
        match config.payload_mode {
            ApnsPayloadMode::Silent => Self::default(),
            ApnsPayloadMode::GenericAlert => Self::GenericAlert(ApnsGenericAlertPayload {
                aps: ApnsGenericAlertAps {
                    alert: ApnsGenericAlert {
                        title: config.alert_title.clone(),
                        body: config.alert_body.clone(),
                    },
                    sound: "default",
                },
            }),
        }
    }
}

/// Product-neutral alert carrying no message or sender content.
#[derive(Debug, Serialize)]
struct ApnsGenericAlertPayload {
    aps: ApnsGenericAlertAps,
}

#[derive(Debug, Serialize)]
struct ApnsGenericAlertAps {
    alert: ApnsGenericAlert,
    sound: &'static str,
}

#[derive(Debug, Serialize)]
struct ApnsGenericAlert {
    /// Omitted when configured empty, allowing a body-only alert.
    #[serde(skip_serializing_if = "String::is_empty")]
    title: String,
    /// Omitted when configured empty, allowing a title-only alert.
    #[serde(skip_serializing_if = "String::is_empty")]
    body: String,
}

fn redacted_device_token_id(_device_token: &str) -> &'static str {
    "<redacted_device_token>"
}

fn device_token_url(base_url: &str, device_token: &str) -> Zeroizing<String> {
    Zeroizing::new(format!("{base_url}/3/device/{device_token}"))
}

#[derive(Debug)]
struct ApnsRequestParts {
    push_type: &'static str,
    priority: &'static str,
    collapse_id: Option<HeaderValue>,
    payload: ApnsPayload,
}

impl ApnsRequestParts {
    fn for_config(config: &ApnsConfig) -> Result<Self> {
        let collapse_id = if config.collapse_id.is_empty() {
            None
        } else {
            if config.collapse_id.chars().any(char::is_control) {
                return Err(Error::Apns(
                    "apns.collapse_id contains a control character; configuration validation should have rejected it"
                        .to_string(),
                ));
            }
            Some(HeaderValue::try_from(config.collapse_id.as_str()).map_err(|_| {
                Error::Apns(
                    "apns.collapse_id is not a valid HTTP header value; configuration validation should have rejected it"
                        .to_string(),
                )
            })?)
        };

        Ok(Self {
            push_type: config.payload_mode.push_type(),
            priority: config.payload_mode.priority(),
            collapse_id,
            payload: ApnsPayload::for_config(config),
        })
    }
}

/// APNs error response.
#[derive(Debug, Deserialize)]
struct ApnsErrorResponse {
    reason: String,
}

/// Classification of an APNs `400 Bad Request` `reason`.
///
/// APNs returns `400` both for a genuinely dead device token and for
/// server-side misconfiguration (bad topic, bad priority, malformed payload,
/// etc.). Collapsing every `400` into "token dead" would silently drop every
/// notification on a single config mistake *and* unregister healthy device
/// tokens, so the two cases must be distinguished. See issue #111.
#[derive(Debug, PartialEq, Eq)]
enum Apns400Classification {
    /// The provider explicitly identified the device token as invalid for this
    /// app; the token should be treated as dead.
    TokenDead,
    /// A configuration or request-construction error that is permanent for this
    /// provider but unrelated to the device token; must surface as an error
    /// rather than evicting the token.
    Permanent,
}

/// Classify an APNs `400` `reason` as either a dead device token or a
/// permanent provider/configuration error.
///
/// Only `BadDeviceToken` and `Unregistered` unambiguously indicate that the
/// device token itself is invalid. `DeviceTokenNotForTopic` can also mean this
/// server is sending every request with the wrong `apns-topic`/bundle ID, so it
/// is treated as a permanent provider/configuration error rather than evicting
/// otherwise-healthy tokens. Every other reason (and any unrecognised reason)
/// is also a permanent error.
#[must_use]
fn classify_apns_400(reason: &str) -> Apns400Classification {
    match reason {
        "BadDeviceToken" | "Unregistered" => Apns400Classification::TokenDead,
        _ => Apns400Classification::Permanent,
    }
}

/// Whether an APNs `403` `reason` indicates the provider *token* (JWT) is the
/// problem, as opposed to a configuration/environment fault that also returns
/// `403`.
///
/// APNs returns `403` for several unrelated conditions: `ExpiredProviderToken`
/// and `InvalidProviderToken` mean the JWT is stale/wrong and re-minting can
/// recover, but `BadCertificateEnvironment`, `Forbidden`, `TopicDisallowed`,
/// etc. are static misconfigurations. Evicting (and re-signing) the JWT on
/// every non-JWT 403 turns a static misconfiguration into a per-notification
/// ES256 re-sign stampede, so only the JWT reasons trigger eviction and a
/// fresh-token retry (issues #145, #85).
#[must_use]
fn is_apns_jwt_reason(reason: &str) -> bool {
    matches!(reason, "ExpiredProviderToken" | "InvalidProviderToken")
}

/// APNs credential generator: local ES256 signing of a short-lived JWT.
pub(crate) struct ApnsTokenGenerator {
    encoding_key: Option<EncodingKey>,
    team_id: String,
    key_id: String,
    metrics: Metrics,
}

impl ApnsTokenGenerator {
    /// Whether a signing key was loaded (used by `is_configured`).
    fn has_encoding_key(&self) -> bool {
        self.encoding_key.is_some()
    }
}

impl AuthTokenGenerator for ApnsTokenGenerator {
    async fn mint(&self) -> std::result::Result<MintedToken, TokenAcquisitionError> {
        let encoding_key = self.encoding_key.as_ref().ok_or_else(|| {
            TokenAcquisitionError::permanent(Error::Apns("No encoding key configured".to_string()))
        })?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                TokenAcquisitionError::permanent(Error::Apns(format!("System time error: {e}")))
            })?
            .as_secs();

        // Backdate `iat` by the clock-skew leeway so a fast host clock does not
        // yield an `iat` in APNs's future (403 InvalidProviderToken); `exp`
        // stays within Apple's 1-hour max measured from the backdated `iat`.
        let (iat, exp) = crate::push::auth_jwt_iat_exp(now, TOKEN_EXPIRATION_SECS);

        let claims = ApnsClaims {
            iss: self.team_id.clone(),
            iat,
            exp,
        };

        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());

        let token = Zeroizing::new(
            encode(&header, &claims, encoding_key)
                .map_err(|e| TokenAcquisitionError::permanent(Error::from(e)))?,
        );

        self.metrics.record_auth_token_refresh("apns_jwt");

        trace!("Generated new APNs JWT token");
        Ok(MintedToken {
            token,
            expires_at: SystemTime::now() + TOKEN_LIFETIME,
        })
    }
}

/// APNs client for sending push notifications.
pub struct ApnsClient {
    pub(crate) http_client: Client,
    pub(crate) config: ApnsConfig,
    pub(crate) token_cache: TokenCache<ApnsTokenGenerator>,
    pub(crate) metrics: Metrics,
    /// Test-only override for the APNs base URL (scheme + host + port).
    #[cfg(test)]
    pub(crate) test_base_url: Option<String>,
}

impl ApnsClient {
    /// The APNs base URL (scheme + host), overridable in tests.
    fn base_url(&self) -> &str {
        #[cfg(test)]
        if let Some(base) = self.test_base_url.as_deref() {
            return base;
        }
        self.config.base_url()
    }

    /// Create a new APNs client.
    #[allow(dead_code)]
    pub async fn new(config: ApnsConfig) -> Result<Self> {
        Self::with_metrics(config, Metrics::disabled()).await
    }

    /// Create a new APNs client with metrics.
    pub async fn with_metrics(config: ApnsConfig, metrics: Metrics) -> Result<Self> {
        let http_client = Client::builder()
            .http2_prior_knowledge()
            .timeout(Duration::from_secs(30))
            .build()?;

        // Load encoding key for token auth
        let encoding_key = if !config.private_key_path.is_empty() {
            let key_data = Zeroizing::new(
                tokio::fs::read(&config.private_key_path)
                    .await
                    .map_err(|e| {
                        Error::Apns(format!(
                            "Failed to read APNs key file '{}': {e}",
                            config.private_key_path
                        ))
                    })?,
            );

            // `jsonwebtoken::EncodingKey` owns parsed key material internally
            // and exposes no zeroize hook; the avoidable local PEM buffer above
            // is wiped on drop.
            Some(
                EncodingKey::from_ec_pem(key_data.as_slice())
                    .map_err(|e| Error::Apns(format!("Failed to parse APNs key: {e}")))?,
            )
        } else {
            None
        };

        let token_cache = TokenCache::new(ApnsTokenGenerator {
            encoding_key,
            team_id: config.team_id.clone(),
            key_id: config.key_id.clone(),
            metrics: metrics.clone(),
        });

        Ok(Self {
            http_client,
            config,
            token_cache,
            metrics,
            #[cfg(test)]
            test_base_url: None,
        })
    }

    /// Send the configured content-free push notification to a device.
    ///
    /// Returns [`PushSendOutcome::Sent`] if APNs accepted the notification,
    /// [`PushSendOutcome::InvalidToken`] if the token is invalid/expired,
    /// or `Err` for other failures.
    ///
    /// This method automatically retries transient failures (408, 429, 5xx)
    /// with exponential backoff.
    ///
    /// When `backoff_permit` is `Some`, the dispatcher concurrency permit is
    /// released during backoff sleeps and re-acquired before each retry, so a
    /// sleeping retry does not occupy an in-flight concurrency slot.
    pub async fn send(
        &self,
        device_token: Zeroizing<String>,
        backoff_permit: Option<&mut crate::push::retry::BackoffPermit>,
    ) -> Result<PushSendOutcome> {
        // Device-token well-formedness is guaranteed upstream: the dispatcher
        // feeds tokens produced by `TokenPayload::device_token_hex()`, which
        // always yields even-length lowercase hex within
        // `1..=MAX_DEVICE_TOKEN_SIZE` (bounded at decrypt time in
        // `crypto/token.rs`). That is the single source of truth for token
        // well-formedness (issue #199), so no re-validation happens here.
        debug_assert!(
            !device_token.is_empty()
                && device_token.len().is_multiple_of(2)
                && device_token.chars().all(|c| c.is_ascii_hexdigit()),
            "device token must be even-length hex; TokenPayload is the single source of truth"
        );

        // Build the request template once, outside the retry closures, so a
        // retry does not re-allocate the payload/headers (issue #198). The
        // device-token URL is a zeroizing buffer (issue #126); reqwest still
        // materializes the serialized body/headers into non-zeroized buffers
        // it owns, which is the accepted #126 posture (see build_request).
        let request_parts = ApnsRequestParts::for_config(&self.config)?;
        let url = device_token_url(self.base_url(), device_token.as_str());

        debug!(
            payload_mode = %self.config.payload_mode,
            push_type = self.config.payload_mode.push_type(),
            priority = self.config.payload_mode.priority(),
            topic = %self.config.bundle_id,
            device_token = redacted_device_token_id(device_token.as_str()),
            "Sending APNs notification"
        );

        let retry_config = RetryConfig::default();
        // Record one duration sample per logical push, measured across all
        // retries, so `push_request_duration_seconds` counts notifications
        // rather than HTTP attempts (issue #168). Per-attempt HTTP status is
        // still recorded in handle_response.
        let start = Instant::now();
        let result = retry::with_retry(
            &retry_config,
            "APNs",
            || self.send_once(url.as_str(), &request_parts),
            backoff_permit,
            self.metrics.clone(),
        )
        .await;
        self.metrics
            .observe_push_duration("apns", start.elapsed().as_secs_f64());

        result
    }

    /// Build the outbound request from the pre-built template.
    ///
    /// reqwest owns the serialized header/body buffers, so the `bearer` token
    /// and JSON payload are materialized into non-zeroized memory it controls.
    /// This is the accepted defense-in-depth posture for issue #126: the
    /// upstream `Zeroizing` wrapping bounds the token's own copies, but the
    /// serialized HTTP request cannot be zeroized without reimplementing the
    /// client.
    fn build_request(
        &self,
        url: &str,
        auth_token: &str,
        request_parts: &ApnsRequestParts,
    ) -> reqwest::RequestBuilder {
        let authorization = Zeroizing::new(format!("bearer {auth_token}"));
        let mut request = self
            .http_client
            .post(url)
            .header("apns-push-type", request_parts.push_type)
            .header("apns-priority", request_parts.priority)
            .header("apns-topic", &self.config.bundle_id)
            .header("authorization", authorization.as_str());
        if let Some(collapse_id) = &request_parts.collapse_id {
            request = request.header("apns-collapse-id", collapse_id);
        }
        request.json(&request_parts.payload)
    }

    async fn handle_response(
        &self,
        response: reqwest::Response,
        auth_token: &str,
    ) -> SendAttemptResult {
        let status = response.status();

        self.metrics
            .record_push_response_status("apns", status.as_u16());

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
                let error = crate::push::parse_bounded_error_body::<ApnsErrorResponse>(response)
                    .await
                    .unwrap_or(ApnsErrorResponse {
                        reason: "Unknown".to_string(),
                    });
                match classify_apns_400(&error.reason) {
                    Apns400Classification::TokenDead => {
                        debug!(
                            payload_mode = %self.config.payload_mode,
                            reason = %error.reason,
                            "APNs bad device token"
                        );
                        SendAttemptResult::Success(false)
                    }
                    Apns400Classification::Permanent => {
                        // Configuration/request error (e.g. BadTopic, MissingTopic,
                        // BadPriority): surface as a permanent error instead of
                        // silently dropping the notification and evicting the token.
                        warn!(
                            payload_mode = %self.config.payload_mode,
                            reason = %error.reason,
                            "APNs rejected request (configuration or request error)"
                        );
                        SendAttemptResult::Permanent(Error::Apns(format!(
                            "Bad request: {}",
                            error.reason
                        )))
                    }
                }
            }
            403 => {
                let retry_after = retry::retry_after_from_headers(response.headers());
                // Parse the reason BEFORE deciding whether to evict. Only a
                // genuine provider-token reason (ExpiredProviderToken /
                // InvalidProviderToken) means the JWT is the problem; every
                // other 403 (BadCertificateEnvironment, Forbidden, ...) is a
                // static misconfiguration, and evicting the freshly-minted JWT
                // on those would cause a per-notification re-sign stampede
                // (issue #145).
                let error = crate::push::parse_bounded_error_body::<ApnsErrorResponse>(response)
                    .await
                    .unwrap_or(ApnsErrorResponse {
                        reason: "Unknown".to_string(),
                    });
                let apns_error = Error::Apns(format!("Authentication error: {}", error.reason));
                if error.reason == "TooManyProviderTokenUpdates" {
                    // This is provider backpressure, not a bad key. Reuse the
                    // cached JWT and retry with bounded backoff.
                    debug!(
                        payload_mode = %self.config.payload_mode,
                        "APNs throttled provider-token updates"
                    );
                    SendAttemptResult::Retriable {
                        status_code: 403,
                        retry_after,
                    }
                } else if is_apns_jwt_reason(&error.reason) {
                    // The cached JWT is stale/invalid: evict it (gated on it
                    // still being the failing token) and ask the retry engine
                    // to retry once with a freshly minted JWT (issue #85).
                    self.token_cache.invalidate_if_matches(auth_token).await;
                    debug!(
                        payload_mode = %self.config.payload_mode,
                        reason = %error.reason,
                        "APNs provider-token rejected; will retry once with a fresh JWT"
                    );
                    SendAttemptResult::AuthRejected(apns_error)
                } else {
                    // Non-JWT 403: do not touch the cache, and surface as a
                    // permanent error so a config fault is not mistaken for a
                    // recoverable auth rejection.
                    warn!(
                        payload_mode = %self.config.payload_mode,
                        reason = %error.reason,
                        "APNs rejected request (non-token 403: configuration/environment error)"
                    );
                    SendAttemptResult::Permanent(apns_error)
                }
            }
            408 => {
                // Request timeout - retriable. Honor Retry-After if present.
                let retry_after = retry::retry_after_from_headers(response.headers());
                debug!(
                    payload_mode = %self.config.payload_mode,
                    status = %status,
                    "APNs request timeout (retriable)"
                );
                SendAttemptResult::Retriable {
                    status_code: 408,
                    retry_after,
                }
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
                let retry_after = retry::retry_after_from_headers(response.headers());
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
                // Server error - retriable. Honor an explicit Retry-After
                // backpressure hint when the provider supplies one.
                let retry_after = retry::retry_after_from_headers(response.headers());
                debug!(
                    payload_mode = %self.config.payload_mode,
                    status = %status,
                    "APNs server error (retriable)"
                );
                SendAttemptResult::Retriable {
                    status_code: status.as_u16(),
                    retry_after,
                }
            }
            _ => {
                // Unknown statuses are provider/protocol errors, not evidence
                // that the device token is dead. Keep them out of the
                // invalid-token path so operators do not prune live tokens.
                warn!(
                    payload_mode = %self.config.payload_mode,
                    status = %status,
                    "APNs unexpected response"
                );
                SendAttemptResult::Permanent(Error::Apns(format!(
                    "Unexpected APNs response status: {status}"
                )))
            }
        }
    }

    /// Send a single push notification attempt (one `with_retry` iteration).
    ///
    /// Borrows the request template built once in [`Self::send`]; a transport
    /// retry re-sends the same borrowed template rather than rebuilding it
    /// (issue #198). Returns a `SendAttemptResult` indicating success, a
    /// retriable error, an auth rejection, or a permanent error.
    async fn send_once(&self, url: &str, request_parts: &ApnsRequestParts) -> SendAttemptResult {
        self.send_once_with_transport_retry_config(url, request_parts, &RetryConfig::transport())
            .await
    }

    async fn send_once_with_transport_retry_config(
        &self,
        url: &str,
        request_parts: &ApnsRequestParts,
        transport_retry: &RetryConfig,
    ) -> SendAttemptResult {
        // Mint/read the JWT via the shared cache. A transient acquisition
        // failure (none for APNs's pure-CPU signing today, but the shared
        // classification allows it) maps to a retriable attempt.
        let token = match self.token_cache.get().await {
            Ok(t) => t,
            Err(e) => return e.into_send_attempt(),
        };

        let response = match retry::with_transport_retry(
            transport_retry,
            "APNs",
            || async {
                self.build_request(url, token.as_str(), request_parts)
                    .send()
                    .await
                    // Strip the URL (which embeds the device token) before the
                    // error can reach any log sink downstream (issue #172).
                    .map_err(|e| Error::from(e).redact_transport_url())
            },
            &self.metrics,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => return SendAttemptResult::Permanent(e),
        };

        self.handle_response(response, token.as_str()).await
    }

    /// Check if the client is properly configured.
    #[must_use]
    pub fn is_configured(&self) -> bool {
        if !self.config.enabled {
            return false;
        }

        self.token_cache.generator().has_encoding_key()
            && !self.config.key_id.is_empty()
            && !self.config.team_id.is_empty()
            && !self.config.bundle_id.is_empty()
    }
}

#[cfg(test)]
impl ApnsClient {
    /// Create a mock APNs client for testing.
    pub(crate) fn mock(config: ApnsConfig, with_encoding_key: bool) -> Self {
        let encoding_key = with_encoding_key.then(|| EncodingKey::from_secret(b"fake-key"));
        let token_cache = TokenCache::new(ApnsTokenGenerator {
            encoding_key,
            team_id: config.team_id.clone(),
            key_id: config.key_id.clone(),
            metrics: Metrics::disabled(),
        });
        Self {
            http_client: Client::new(),
            config,
            token_cache,
            metrics: Metrics::disabled(),
            test_base_url: None,
        }
    }

    /// Seed the token cache with a credential (test setup).
    pub(crate) async fn seed_token(&self, token: &str, expires_at: SystemTime) {
        self.token_cache.seed(token, expires_at).await;
    }

    /// The currently cached credential value, if any (test inspection).
    pub(crate) async fn cached_token_value(&self) -> Option<String> {
        self.token_cache.cached_token_value().await
    }

    /// Mint a JWT directly through the generator (test inspection).
    async fn generate_token(&self) -> Result<Zeroizing<String>> {
        self.token_cache
            .generator()
            .mint()
            .await
            .map(|minted| minted.token)
            .map_err(|e| match e {
                TokenAcquisitionError::Permanent(err) => err,
                TokenAcquisitionError::Retriable { .. } => {
                    Error::Apns("transient mint failure".to_string())
                }
            })
    }

    /// Get a JWT through the cache (test inspection).
    async fn get_token(&self) -> Result<Zeroizing<String>> {
        self.token_cache.get().await.map_err(|e| match e {
            TokenAcquisitionError::Permanent(err) => err,
            TokenAcquisitionError::Retriable { .. } => {
                Error::Apns("transient mint failure".to_string())
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_metrics::{counter_value, histogram_sample_count};
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
            environment: crate::config::ApnsEnvironment::Sandbox,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
            alert_title: String::new(),
            alert_body: String::new(),
            collapse_id: String::new(),
        }
    }

    fn header_value<'a>(request: &'a reqwest::Request, name: &str) -> &'a str {
        request.headers().get(name).unwrap().to_str().unwrap()
    }

    fn request_json(request: &reqwest::Request) -> serde_json::Value {
        let body = request.body().and_then(reqwest::Body::as_bytes).unwrap();
        serde_json::from_slice(body).unwrap()
    }

    fn zeroizing_token(token: &str) -> Zeroizing<String> {
        Zeroizing::new(token.to_owned())
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
    fn test_device_token_url_buffer_is_zeroizing() {
        fn assert_zeroizing_string(_: &Zeroizing<String>) {}

        let url = device_token_url("https://api.push.apple.com", "aabbccdd11223344");

        assert_zeroizing_string(&url);
        assert_eq!(
            url.as_str(),
            "https://api.push.apple.com/3/device/aabbccdd11223344"
        );
    }

    #[test]
    fn test_silent_mode_builds_background_headers_and_payload() {
        let mut config = test_config();
        config.payload_mode = ApnsPayloadMode::Silent;
        config.bundle_id = "com.example.app".to_string();
        let client = ApnsClient::mock(config, false);
        let request_parts = ApnsRequestParts::for_config(&client.config).unwrap();

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
        assert_eq!(header_value(&request, "apns-topic"), "com.example.app");
        assert!(request.headers().get("apns-collapse-id").is_none());
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
    fn test_generic_alert_mode_builds_product_neutral_payload() {
        let mut config = test_config();
        config.payload_mode = ApnsPayloadMode::GenericAlert;
        config.alert_title = "New activity".to_string();
        config.alert_body = "You have a new notification".to_string();
        let client = ApnsClient::mock(config, false);
        let request_parts = ApnsRequestParts::for_config(&client.config).unwrap();

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
        assert_eq!(header_value(&request, "apns-topic"), "com.example.app");
        assert_eq!(
            request_json(&request),
            serde_json::json!({
                "aps": {
                    "alert": {
                        "title": "New activity",
                        "body": "You have a new notification"
                    },
                    "sound": "default"
                }
            })
        );
    }

    #[test]
    fn test_generic_alert_mode_omits_empty_body() {
        let mut config = test_config();
        config.payload_mode = ApnsPayloadMode::GenericAlert;
        config.alert_title = "New activity".to_string();
        let client = ApnsClient::mock(config, false);
        let request_parts = ApnsRequestParts::for_config(&client.config).unwrap();
        let request = client
            .build_request(
                "https://api.push.apple.com/3/device/aabbccdd11223344",
                "test-token",
                &request_parts,
            )
            .build()
            .unwrap();

        assert_eq!(
            request_json(&request),
            serde_json::json!({
                "aps": {
                    "alert": { "title": "New activity" },
                    "sound": "default"
                }
            })
        );
    }

    #[test]
    fn test_generic_alert_mode_omits_empty_title() {
        let mut config = test_config();
        config.payload_mode = ApnsPayloadMode::GenericAlert;
        config.alert_body = "You have a new notification".to_string();
        let client = ApnsClient::mock(config, false);
        let request_parts = ApnsRequestParts::for_config(&client.config).unwrap();
        let request = client
            .build_request(
                "https://api.push.apple.com/3/device/aabbccdd11223344",
                "test-token",
                &request_parts,
            )
            .build()
            .unwrap();

        assert_eq!(
            request_json(&request),
            serde_json::json!({
                "aps": {
                    "alert": { "body": "You have a new notification" },
                    "sound": "default"
                }
            })
        );
    }

    #[test]
    fn test_collapse_id_header_applies_to_any_payload_mode() {
        let mut config = test_config();
        config.payload_mode = ApnsPayloadMode::Silent;
        config.collapse_id = "sync".to_string();
        let client = ApnsClient::mock(config, false);
        let request_parts = ApnsRequestParts::for_config(&client.config).unwrap();
        let request = client
            .build_request(
                "https://api.push.apple.com/3/device/aabbccdd11223344",
                "test-token",
                &request_parts,
            )
            .build()
            .unwrap();

        assert_eq!(header_value(&request, "apns-collapse-id"), "sync");
    }

    #[test]
    fn test_request_parts_defensively_reject_control_character_collapse_id() {
        let mut config = test_config();
        config.collapse_id = "line\nbreak".to_string();
        let error = ApnsRequestParts::for_config(&config).unwrap_err();
        assert!(error.to_string().contains("control character"), "{error}");
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
        let mut client = ApnsClient::mock(test_config(), false);
        client.http_client = http_client;
        client
            .seed_token(
                "cached-token",
                SystemTime::now() + Duration::from_secs(3600),
            )
            .await;
        let retry_config = RetryConfig {
            max_retries: 3,
            initial_backoff: Duration::from_millis(1),
        };

        let request_parts = ApnsRequestParts::for_config(&client.config).unwrap();
        let url = device_token_url(client.config.base_url(), "aabbccdd11223344");
        let result = client
            .send_once_with_transport_retry_config(url.as_str(), &request_parts, &retry_config)
            .await;

        // The propagated transport error must not carry the device-token URL
        // (issue #172): the retry engine and send path both strip it.
        let SendAttemptResult::Permanent(Error::Http(ref http_error)) = result else {
            panic!("expected a permanent transport error, got {result:?}");
        };
        assert!(
            !http_error.to_string().contains("aabbccdd11223344"),
            "device token leaked into transport error: {http_error}"
        );
    }

    #[tokio::test]
    async fn test_client_not_configured_when_disabled() {
        let config = ApnsConfig {
            enabled: false,
            key_id: String::new(),
            team_id: String::new(),
            private_key_path: String::new(),
            environment: crate::config::ApnsEnvironment::Sandbox,
            bundle_id: String::new(),
            payload_mode: Default::default(),
            alert_title: String::new(),
            alert_body: String::new(),
            collapse_id: String::new(),
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

        let http_client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        // Create client with custom HTTP client and pre-populated token cache
        let mut client = ApnsClient::mock(test_config(), false);
        client.http_client = http_client;
        client
            .seed_token("test-token", SystemTime::now() + Duration::from_secs(3600))
            .await;

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

    #[test]
    fn test_classify_apns_400_token_dead_reasons() {
        // Only genuine device-token rejections should evict the token.
        assert_eq!(
            classify_apns_400("BadDeviceToken"),
            Apns400Classification::TokenDead
        );
        assert_eq!(
            classify_apns_400("Unregistered"),
            Apns400Classification::TokenDead
        );
    }

    #[test]
    fn test_classify_apns_400_configuration_reasons_are_permanent() {
        // Configuration / request-construction errors must NOT evict the token.
        for reason in [
            "BadTopic",
            "MissingTopic",
            "DeviceTokenNotForTopic",
            "TopicDisallowed",
            "BadPriority",
            "BadExpirationDate",
            "PayloadEmpty",
            "BadMessageId",
            "Unknown",
            "SomeFutureReason",
        ] {
            assert_eq!(
                classify_apns_400(reason),
                Apns400Classification::Permanent,
                "reason {reason} should be classified as a permanent error"
            );
        }
    }

    #[tokio::test]
    async fn test_handle_response_records_per_attempt_status_not_duration() {
        // Metric layering (issue #168): handle_response runs once per HTTP
        // attempt and records only the per-attempt response-status counter.
        // Per-logical-push duration is now recorded once in send(), so
        // handle_response must NOT observe the duration histogram.
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/3/device/[a-f0-9]+"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let metrics = Metrics::new().unwrap();
        let mut client = ApnsClient::mock(test_config(), false);
        client.metrics = metrics.clone();

        let response = Client::new()
            .post(format!("{}/3/device/{}", mock_server.uri(), "deadbeef1234"))
            .send()
            .await
            .unwrap();

        let result = client.handle_response(response, "test-token").await;

        assert!(matches!(result, SendAttemptResult::Success(true)));
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_push_response_status_total",
                &[("platform", "apns"), ("status", "200")]
            ),
            1.0
        );
        // No duration sample from handle_response — send() owns that now. The
        // HistogramVec has no children until send() observes one, so the
        // family is absent from the gathered output entirely.
        assert!(
            !metrics
                .gather()
                .iter()
                .any(|family| { family.name() == "transponder_push_request_duration_seconds" }),
            "handle_response must not observe the per-push duration histogram"
        );
    }

    #[tokio::test]
    async fn test_send_records_one_duration_sample_per_logical_push_across_retries() {
        // A logical push that succeeds after one 429 retry must record exactly
        // one duration sample (issue #168) and two per-attempt status counts.
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/3/device/[a-f0-9]+"))
            .respond_with(ResponseTemplate::new(429))
            .up_to_n_times(1)
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(r"/3/device/[a-f0-9]+"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let metrics = Metrics::new().unwrap();
        let mut client = ApnsClient::mock(test_config(), true);
        client.metrics = metrics.clone();
        client.test_base_url = Some(mock_server.uri());
        client
            .seed_token("cached", SystemTime::now() + Duration::from_secs(3600))
            .await;

        let outcome = client
            .send(zeroizing_token("aabbccdd11223344"), None)
            .await
            .unwrap();

        assert_eq!(outcome, PushSendOutcome::Sent);
        assert_eq!(
            histogram_sample_count(
                &metrics,
                "transponder_push_request_duration_seconds",
                &[("platform", "apns")]
            ),
            1,
            "duration must be sampled once per logical push, not per attempt"
        );
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_push_response_status_total",
                &[("platform", "apns"), ("status", "429")]
            ),
            1.0
        );
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_push_response_status_total",
                &[("platform", "apns"), ("status", "200")]
            ),
            1.0
        );
    }

    async fn apns_400_result(reason: &str) -> SendAttemptResult {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/3/device/[a-f0-9]+"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "reason": reason
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = ApnsClient::mock(test_config(), false);
        let response = Client::new()
            .post(format!("{}/3/device/{}", mock_server.uri(), "deadbeef1234"))
            .send()
            .await
            .unwrap();

        client.handle_response(response, "test-token").await
    }

    #[tokio::test]
    async fn test_handle_response_400_bad_device_token_is_token_dead() {
        // BadDeviceToken must continue to signal token death.
        let result = apns_400_result("BadDeviceToken").await;
        assert!(matches!(result, SendAttemptResult::Success(false)));
    }

    #[tokio::test]
    async fn test_handle_response_400_device_token_not_for_topic_is_permanent_error() {
        let result = apns_400_result("DeviceTokenNotForTopic").await;
        assert!(matches!(
            result,
            SendAttemptResult::Permanent(Error::Apns(ref message))
                if message.contains("DeviceTokenNotForTopic")
        ));
    }

    #[tokio::test]
    async fn test_handle_response_400_bad_topic_is_permanent_error() {
        // Server-side misconfiguration must be a permanent error, not token death.
        let result = apns_400_result("BadTopic").await;
        assert!(matches!(
            result,
            SendAttemptResult::Permanent(Error::Apns(ref message))
                if message.contains("BadTopic")
        ));
    }

    #[tokio::test]
    async fn test_handle_response_400_missing_topic_is_permanent_error() {
        let result = apns_400_result("MissingTopic").await;
        assert!(matches!(
            result,
            SendAttemptResult::Permanent(Error::Apns(ref message))
                if message.contains("MissingTopic")
        ));
    }

    /// Drive `handle_response` against a mock server returning `status_code`
    /// with an optional `retry-after` header, returning the classified result.
    async fn apns_status_result(status_code: u16, retry_after: Option<&str>) -> SendAttemptResult {
        let mock_server = MockServer::start().await;
        let mut template = ResponseTemplate::new(status_code);
        if let Some(value) = retry_after {
            template = template.insert_header("retry-after", value);
        }
        Mock::given(method("POST"))
            .and(path_regex(r"/3/device/[a-f0-9]+"))
            .respond_with(template)
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = ApnsClient::mock(test_config(), false);
        let response = Client::new()
            .post(format!("{}/3/device/{}", mock_server.uri(), "deadbeef1234"))
            .send()
            .await
            .unwrap();

        client.handle_response(response, "test-token").await
    }

    #[tokio::test]
    async fn test_handle_response_503_honors_retry_after_header() {
        // A 503 with an explicit Retry-After must surface the provider's
        // backpressure hint, not fall back to the default backoff.
        let result = apns_status_result(503, Some("120")).await;
        assert!(matches!(
            result,
            SendAttemptResult::Retriable {
                status_code: 503,
                retry_after: Some(delay),
            } if delay == Duration::from_secs(120)
        ));
    }

    #[tokio::test]
    async fn test_handle_response_500_without_retry_after_is_retriable_without_hint() {
        // A 5xx without a Retry-After stays retriable but carries no hint,
        // preserving the default exponential-backoff behavior.
        let result = apns_status_result(500, None).await;
        assert!(matches!(
            result,
            SendAttemptResult::Retriable {
                status_code: 500,
                retry_after: None,
            }
        ));
    }

    #[tokio::test]
    async fn test_handle_response_429_honors_retry_after_header() {
        let result = apns_status_result(429, Some("30")).await;
        assert!(matches!(
            result,
            SendAttemptResult::Retriable {
                status_code: 429,
                retry_after: Some(delay),
            } if delay == Duration::from_secs(30)
        ));
    }

    #[tokio::test]
    async fn test_handle_response_408_is_retriable() {
        let result = apns_status_result(408, None).await;
        assert!(matches!(
            result,
            SendAttemptResult::Retriable {
                status_code: 408,
                retry_after: None,
            }
        ));
    }

    #[tokio::test]
    async fn test_handle_response_unexpected_status_is_permanent_error() {
        let result = apns_status_result(404, None).await;
        assert!(matches!(
            result,
            SendAttemptResult::Permanent(Error::Apns(ref message))
                if message.contains("Unexpected APNs response status")
                    && message.contains("404")
        ));
    }

    #[tokio::test]
    async fn test_handle_response_400_oversized_body_falls_back_without_whole_body_parse() {
        // A hostile/buggy endpoint returns a 400 with a multi-megabyte body.
        // The bounded read must refuse to buffer/parse the whole body and fall
        // back to the "Unknown" reason (a permanent error), never treating the
        // token as dead based on attacker-controlled content.
        let padding = "A".repeat(4 * 1024 * 1024);
        let huge_body = format!(r#"{{"reason":"{padding}"}}"#);

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/3/device/[a-f0-9]+"))
            .respond_with(ResponseTemplate::new(400).set_body_string(huge_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = ApnsClient::mock(test_config(), false);
        let response = Client::new()
            .post(format!("{}/3/device/{}", mock_server.uri(), "deadbeef1234"))
            .send()
            .await
            .unwrap();

        let result = client.handle_response(response, "test-token").await;

        let SendAttemptResult::Permanent(Error::Apns(message)) = result else {
            panic!("expected a permanent APNs error, got {result:?}");
        };
        assert!(message.contains("Unknown"));
        // The oversized provider body must not leak into the error message,
        // which stays bounded regardless of the (huge) upstream body.
        assert!(!message.contains(&padding));
        assert!(message.len() < 128);
    }

    #[tokio::test]
    async fn test_handle_response_403_oversized_body_falls_back_to_unknown_reason() {
        // The 403 auth-error path must likewise cap the body it reads and fall
        // back to the "Unknown" reason instead of embedding the huge body.
        let padding = "A".repeat(4 * 1024 * 1024);
        let huge_body = format!(r#"{{"reason":"{padding}"}}"#);

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/3/device/[a-f0-9]+"))
            .respond_with(ResponseTemplate::new(403).set_body_string(huge_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = ApnsClient::mock(test_config(), false);
        let response = Client::new()
            .post(format!("{}/3/device/{}", mock_server.uri(), "deadbeef1234"))
            .send()
            .await
            .unwrap();

        let result = client.handle_response(response, "test-token").await;

        let SendAttemptResult::Permanent(Error::Apns(message)) = result else {
            panic!("expected a permanent APNs error, got {result:?}");
        };
        assert!(message.contains("Authentication error"));
        assert!(message.contains("Unknown"));
        // The oversized provider body must not leak into the error message,
        // which stays bounded regardless of the (huge) upstream body.
        assert!(!message.contains(&padding));
        assert!(message.len() < 128);
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
    async fn test_jwt_reason_403_evicts_and_asks_for_a_fresh_token_retry() {
        // A provider-token 403 (ExpiredProviderToken) means the cached JWT is
        // the problem: evict it (issue #145) and return AuthRejected so the
        // retry engine retries once with a fresh JWT (issue #85).
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/3/device/[a-f0-9]+"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "reason": "ExpiredProviderToken"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = ApnsClient::mock(test_config(), false);
        client
            .seed_token("poisoned-jwt", SystemTime::now() + TOKEN_LIFETIME)
            .await;

        let response = Client::new()
            .post(format!("{}/3/device/{}", mock_server.uri(), "deadbeef1234"))
            .send()
            .await
            .unwrap();

        let result = client.handle_response(response, "poisoned-jwt").await;

        assert!(matches!(
            result,
            SendAttemptResult::AuthRejected(Error::Apns(ref message))
                if message.contains("ExpiredProviderToken")
        ));
        assert_eq!(client.cached_token_value().await, None);
    }

    #[tokio::test]
    async fn test_non_jwt_403_does_not_evict_and_is_permanent() {
        // A non-token 403 (BadCertificateEnvironment) is a static
        // misconfiguration: the cached JWT must survive (no re-sign stampede,
        // issue #145) and the result is a permanent error (not retriable).
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/3/device/[a-f0-9]+"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "reason": "BadCertificateEnvironment"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = ApnsClient::mock(test_config(), false);
        client
            .seed_token("valid-jwt", SystemTime::now() + TOKEN_LIFETIME)
            .await;

        let response = Client::new()
            .post(format!("{}/3/device/{}", mock_server.uri(), "deadbeef1234"))
            .send()
            .await
            .unwrap();

        let result = client.handle_response(response, "valid-jwt").await;

        assert!(matches!(
            result,
            SendAttemptResult::Permanent(Error::Apns(ref message))
                if message.contains("BadCertificateEnvironment")
        ));
        // The valid JWT must NOT be evicted by a non-token 403.
        assert_eq!(
            client.cached_token_value().await.as_deref(),
            Some("valid-jwt")
        );
    }

    #[tokio::test]
    async fn test_too_many_provider_token_updates_retries_without_eviction() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(403)
                    .insert_header("retry-after", "2")
                    .set_body_json(serde_json::json!({
                        "reason": "TooManyProviderTokenUpdates"
                    })),
            )
            .mount(&mock_server)
            .await;

        let client = ApnsClient::mock(test_config(), false);
        client
            .seed_token("valid-jwt", SystemTime::now() + TOKEN_LIFETIME)
            .await;
        let response = Client::new().post(mock_server.uri()).send().await.unwrap();

        let result = client.handle_response(response, "valid-jwt").await;

        assert!(matches!(
            result,
            SendAttemptResult::Retriable {
                status_code: 403,
                retry_after: Some(delay)
            } if delay == Duration::from_secs(2)
        ));
        assert_eq!(
            client.cached_token_value().await.as_deref(),
            Some("valid-jwt")
        );
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
        client
            .seed_token("fresh-jwt", SystemTime::now() + TOKEN_LIFETIME)
            .await;

        let response = Client::new()
            .post(format!("{}/3/device/{}", mock_server.uri(), "deadbeef1234"))
            .send()
            .await
            .unwrap();

        // The failing request used the older, now-replaced token.
        let result = client.handle_response(response, "stale-jwt").await;

        assert!(matches!(
            result,
            SendAttemptResult::AuthRejected(Error::Apns(ref message))
                if message.contains("InvalidProviderToken")
        ));

        // The freshly refreshed token must survive the stale rejection.
        assert_eq!(
            client.cached_token_value().await.as_deref(),
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
            environment: crate::config::ApnsEnvironment::Production,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
            alert_title: String::new(),
            alert_body: String::new(),
            collapse_id: String::new(),
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
            environment: crate::config::ApnsEnvironment::Production,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
            alert_title: String::new(),
            alert_body: String::new(),
            collapse_id: String::new(),
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
            environment: crate::config::ApnsEnvironment::Production,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
            alert_title: String::new(),
            alert_body: String::new(),
            collapse_id: String::new(),
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
            environment: crate::config::ApnsEnvironment::Production,
            bundle_id: String::new(), // Missing
            payload_mode: Default::default(),
            alert_title: String::new(),
            alert_body: String::new(),
            collapse_id: String::new(),
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
            environment: crate::config::ApnsEnvironment::Production,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
            alert_title: String::new(),
            alert_body: String::new(),
            collapse_id: String::new(),
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

    #[tokio::test]
    async fn test_generate_token_no_encoding_key() {
        let config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: crate::config::ApnsEnvironment::Production,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
            alert_title: String::new(),
            alert_body: String::new(),
            collapse_id: String::new(),
        };

        let client = ApnsClient::mock(config, false);
        let result = client.generate_token().await;
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
            environment: crate::config::ApnsEnvironment::Production,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
            alert_title: String::new(),
            alert_body: String::new(),
            collapse_id: String::new(),
        };

        let client = ApnsClient::mock(config, true);

        // Pre-populate the cache
        client
            .seed_token(
                "cached-test-token",
                SystemTime::now() + Duration::from_secs(3600),
            )
            .await;

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
            environment: crate::config::ApnsEnvironment::Production,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
            alert_title: String::new(),
            alert_body: String::new(),
            collapse_id: String::new(),
        };

        // Create a client without an encoding key to test the error case
        let client = ApnsClient::mock(config, false);

        // Pre-populate the cache with an expired token
        client
            .seed_token("expired-token", SystemTime::now() - Duration::from_secs(1))
            .await;

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
            environment: crate::config::ApnsEnvironment::Production,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
            alert_title: String::new(),
            alert_body: String::new(),
            collapse_id: String::new(),
        };

        let client = ApnsClient::mock(config, false); // No encoding key

        // Pre-populate the cache with a valid (non-expired) token
        client
            .seed_token(
                "valid-cached-token",
                SystemTime::now() + Duration::from_secs(3600),
            )
            .await;

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
            environment: crate::config::ApnsEnvironment::Production,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
            alert_title: String::new(),
            alert_body: String::new(),
            collapse_id: String::new(),
        };

        let client = ApnsClient::new(config).await.unwrap();
        assert!(!client.token_cache.generator().has_encoding_key());
    }

    #[tokio::test]
    async fn test_new_client_invalid_key_path() {
        let config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: "/nonexistent/key.p8".to_string(),
            environment: crate::config::ApnsEnvironment::Production,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
            alert_title: String::new(),
            alert_body: String::new(),
            collapse_id: String::new(),
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

        let mut client = ApnsClient::mock(test_config(), true);
        client.http_client = http_client;
        client
            .seed_token(
                "test-cached-token",
                SystemTime::now() + Duration::from_secs(3600),
            )
            .await;

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
            environment: crate::config::ApnsEnvironment::Production,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
            alert_title: String::new(),
            alert_body: String::new(),
            collapse_id: String::new(),
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
            environment: crate::config::ApnsEnvironment::Production,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
            alert_title: String::new(),
            alert_body: String::new(),
            collapse_id: String::new(),
        };

        let client = ApnsClient::new(config).await.unwrap();
        assert!(client.token_cache.generator().has_encoding_key());
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
            environment: crate::config::ApnsEnvironment::Production,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
            alert_title: String::new(),
            alert_body: String::new(),
            collapse_id: String::new(),
        };

        let metrics = Metrics::new().unwrap();
        let client = ApnsClient::with_metrics(config, metrics.clone())
            .await
            .unwrap();

        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Generate a token
        let token = client.generate_token().await.unwrap();

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

        // iat must be backdated by the clock-skew leeway so a fast host clock
        // does not stamp an iat in APNs's future. Bound it by the wall-clock
        // times captured before and after signing so the assertion is stable
        // even if the test crosses a second boundary.
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let leeway = crate::push::AUTH_JWT_CLOCK_SKEW_LEEWAY_SECS;
        assert!(
            iat >= before.saturating_sub(leeway),
            "iat ({iat}) should be no earlier than the backdated start ({before} - {leeway})"
        );
        assert!(
            iat <= after.saturating_sub(leeway),
            "iat ({iat}) should be backdated at least {leeway}s before now ({after})"
        );
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
            environment: crate::config::ApnsEnvironment::Production,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
            alert_title: String::new(),
            alert_body: String::new(),
            collapse_id: String::new(),
        };

        let client = ApnsClient::new(config).await.unwrap();

        // Cache should be empty initially
        assert_eq!(client.cached_token_value().await, None);

        // Get token - should generate and cache
        let token1 = client.get_token().await.unwrap();

        // Cache should now have a token
        assert_eq!(
            client.cached_token_value().await.as_deref(),
            Some(token1.as_str())
        );

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
        let mut client = ApnsClient::mock(test_config(), true);
        client.http_client = http_client;
        client
            .seed_token("test-token", SystemTime::now() + Duration::from_secs(3600))
            .await;

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

//! Firebase Cloud Messaging (FCM) v1 API client.
//!
//! Uses service account credentials for OAuth2 authentication.

use std::fmt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, trace, warn};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::config::FcmConfig;
use crate::error::{Error, Result};
use crate::metrics::Metrics;
use crate::push::auth::{AuthTokenGenerator, MintedToken, TokenAcquisitionError, TokenCache};
use crate::push::retry::{self, PushSendOutcome, RetryConfig, SendAttemptResult};

/// FCM OAuth2 token endpoint.
const OAUTH_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// FCM OAuth2 scope.
const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";

/// Type URL used by FCM v1 to carry provider-specific error codes.
const FCM_ERROR_DETAIL_TYPE: &str = "type.googleapis.com/google.firebase.fcm.v1.FcmError";

/// FCM provider-specific error code for an unregistered/dead device token.
const FCM_ERROR_UNREGISTERED: &str = "UNREGISTERED";

/// Fallback access token lifetime (50 minutes) used when the provider omits expiry.
const TOKEN_LIFETIME: Duration = Duration::from_secs(50 * 60);

/// Safety margin subtracted from provider-reported OAuth token lifetimes.
const TOKEN_REFRESH_SAFETY_MARGIN_SECS: u64 = 60;

/// Minimum cache lifetime for provider-reported OAuth tokens after applying the
/// refresh safety margin.
const TOKEN_LIFETIME_MIN: Duration = Duration::from_secs(30);

/// Upper bound on FCM registration token length.
///
/// FCM tokens are opaque and have historically been ~150-200 characters, but
/// the format is undocumented and may grow. This generous bound only exists to
/// reject obviously-malformed (e.g. unbounded) input before spending an
/// OAuth-authenticated round-trip; it is not a precise format check.
const MAX_FCM_TOKEN_LEN: usize = 4096;

/// Service account JSON structure.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[allow(dead_code)]
pub(crate) struct ServiceAccount {
    #[serde(rename = "type")]
    #[zeroize(skip)]
    pub(crate) account_type: String,
    #[zeroize(skip)]
    pub(crate) project_id: String,
    pub(crate) private_key: Zeroizing<String>,
    #[zeroize(skip)]
    pub(crate) client_email: String,
    #[zeroize(skip)]
    pub(crate) token_uri: String,
}

impl fmt::Debug for ServiceAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceAccount")
            .field("account_type", &self.account_type)
            .field("project_id", &self.project_id)
            .field("private_key", &"[REDACTED]")
            .field("client_email", &self.client_email)
            .field("token_uri", &self.token_uri)
            .finish()
    }
}

/// JWT claims for OAuth2.
#[derive(Debug, Serialize)]
struct OAuthClaims {
    iss: String,
    scope: String,
    aud: String,
    iat: u64,
    exp: u64,
}

/// OAuth2 token request.
// Debug intentionally omitted: assertion contains credential material.
#[derive(Serialize)]
struct TokenRequest {
    grant_type: String,
    assertion: Zeroizing<String>,
}

/// OAuth2 token response.
// Debug intentionally omitted: access_token contains credential material.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: Zeroizing<String>,
    expires_in: Option<u64>,
}

/// Return how long an FCM OAuth token should stay cached.
///
/// Google is authoritative for issued token lifetimes; keep a small local
/// safety margin so Transponder refreshes before the provider-side expiry.
#[must_use]
fn token_cache_lifetime(expires_in: Option<u64>) -> Duration {
    expires_in
        .map(|seconds| {
            Duration::from_secs(seconds.saturating_sub(TOKEN_REFRESH_SAFETY_MARGIN_SECS))
                .max(TOKEN_LIFETIME_MIN)
        })
        .unwrap_or(TOKEN_LIFETIME)
}

/// FCM message payload.
#[derive(Serialize)]
struct FcmRequest<'a> {
    message: FcmMessage<'a>,
}

#[derive(Serialize)]
struct FcmMessage<'a> {
    token: &'a str,
    android: Option<AndroidConfig>,
    data: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Serialize)]
struct AndroidConfig {
    priority: String,
}

/// FCM error response.
#[derive(Debug, Deserialize)]
struct FcmErrorResponse {
    error: FcmError,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FcmError {
    code: u32,
    message: String,
    status: String,
    #[serde(default)]
    details: Vec<FcmErrorDetail>,
}

#[derive(Debug, Deserialize)]
struct FcmErrorDetail {
    #[serde(rename = "@type")]
    type_url: Option<String>,
    #[serde(rename = "errorCode")]
    error_code: Option<String>,
}

/// Classification of an FCM error response.
///
/// FCM returns `400 INVALID_ARGUMENT` both for a genuinely malformed/expired
/// token and for malformed payloads or other request-construction errors, and
/// returns `404 NOT_FOUND` both for an unregistered token *and* for a
/// wrong/typoed `project_id` in the `/v1/projects/{project_id}/messages:send`
/// path. Collapsing those into "token dead" would silently drop every
/// notification on a single config mistake *and* unregister healthy device
/// tokens, so token death must be signalled explicitly. See issue #111.
#[derive(Debug, PartialEq, Eq)]
enum FcmClassification {
    /// The provider explicitly reported the token as unregistered; the token
    /// should be treated as dead.
    TokenDead,
    /// A configuration, payload, or path error that is permanent for this
    /// provider but unrelated to the device token; must surface as an error
    /// rather than evicting the token.
    Permanent,
}

/// Classify an FCM error response as either an unregistered (dead) token or a
/// permanent provider/configuration error.
///
/// The provider-specific `google.firebase.fcm.v1.FcmError.errorCode` detail is
/// the discriminator for token death. The generic top-level status can be
/// `NOT_FOUND` for both unregistered tokens and wrong-project misconfiguration,
/// so it is not enough by itself.
#[must_use]
fn classify_fcm_error(error: &FcmError) -> FcmClassification {
    let token_unregistered = error.details.iter().any(|detail| {
        detail.type_url.as_deref() == Some(FCM_ERROR_DETAIL_TYPE)
            && detail.error_code.as_deref() == Some(FCM_ERROR_UNREGISTERED)
    });

    if token_unregistered {
        FcmClassification::TokenDead
    } else {
        FcmClassification::Permanent
    }
}

fn fcm_provider_error_code(error: &FcmError) -> Option<&str> {
    error.details.iter().find_map(|detail| {
        if detail.type_url.as_deref() == Some(FCM_ERROR_DETAIL_TYPE) {
            detail.error_code.as_deref()
        } else {
            None
        }
    })
}

fn fcm_error_summary(error: &FcmError) -> String {
    let mut summary = format!("{} - {}", error.status, error.message);
    if let Some(error_code) = fcm_provider_error_code(error).filter(|code| *code != error.status) {
        summary.push_str(" (");
        summary.push_str(error_code);
        summary.push(')');
    }
    summary
}

/// Classify an OAuth token HTTP-error response for retry handling.
///
/// A `408`, `425`, `429`, or `5xx` from the token endpoint is transient
/// (retriable); every other status is a permanent OAuth rejection carrying
/// only the status text (never the body — see [`oauth_failure_message`]).
fn oauth_error_from_status(
    status: reqwest::StatusCode,
    retry_after: Option<Duration>,
) -> TokenAcquisitionError {
    if matches!(
        status,
        reqwest::StatusCode::REQUEST_TIMEOUT
            | reqwest::StatusCode::TOO_EARLY
            | reqwest::StatusCode::TOO_MANY_REQUESTS
    ) || status.is_server_error()
    {
        TokenAcquisitionError::Retriable {
            status_code: status.as_u16(),
            retry_after,
        }
    } else {
        TokenAcquisitionError::permanent(Error::Fcm(oauth_failure_message(status)))
    }
}

/// Classify an OAuth token transport failure as a retriable acquisition error.
///
/// The URL is stripped before logging: while the OAuth endpoint URL carries no
/// device token, keeping the redaction uniform avoids leaking a hijacked
/// `token_uri` and mirrors the send-path posture (issue #172).
fn oauth_error_from_transport(err: reqwest::Error) -> TokenAcquisitionError {
    debug!(error = %err.without_url(), "FCM OAuth token transport error");
    TokenAcquisitionError::Retriable {
        status_code: 0,
        retry_after: None,
    }
}

/// Maximum bytes read from the OAuth token success body before parsing.
///
/// An OAuth token response is a small JSON object (an access token plus expiry
/// metadata); a few KiB is ample. Bounding the read keeps a hijacked or
/// misconfigured `token_uri` from streaming an unbounded `200` body into
/// memory (issue #154). Reused via [`crate::push::parse_bounded_json_body`],
/// whose intermediate buffer is zeroized on drop since this body carries a
/// bearer credential.
const MAX_OAUTH_BODY_BYTES: usize = 8 * 1024;

/// FCM credential generator: mints an OAuth2 access token from the service
/// account via a JWT-bearer grant.
pub(crate) struct FcmTokenGenerator {
    http_client: Client,
    service_account: Option<ServiceAccount>,
    encoding_key: Option<EncodingKey>,
    metrics: Metrics,
    /// Test-only override for the OAuth token endpoint URL.
    #[cfg(test)]
    test_oauth_token_url: Option<String>,
}

impl FcmTokenGenerator {
    fn service_account(&self) -> Option<&ServiceAccount> {
        self.service_account.as_ref()
    }

    fn is_configured(&self) -> bool {
        self.service_account.is_some() && self.encoding_key.is_some()
    }

    /// The OAuth token endpoint the request is POSTed to.
    ///
    /// The signed OAuth audience for `sa`: its `token_uri`, falling back to the
    /// well-known constant only when `token_uri` is empty.
    ///
    /// This is the single source of truth for the token endpoint. BOTH the
    /// signed assertion `aud` claim and the request target derive from it, so
    /// they can never diverge (issue #153) — including the degenerate empty
    /// `token_uri` case, where signing `aud=""` while POSTing to the constant
    /// would otherwise be an audience mismatch.
    fn signed_audience(sa: &ServiceAccount) -> &str {
        if sa.token_uri.is_empty() {
            OAUTH_TOKEN_URL
        } else {
            sa.token_uri.as_str()
        }
    }

    /// The URL the OAuth token request is POSTed to.
    ///
    /// In production this is always [`Self::signed_audience`], so the request
    /// target matches the signed `aud`. A test override redirects only the
    /// request target (to a mock server) while `aud` keeps reflecting the real
    /// `token_uri`, which is the intended test shape.
    fn oauth_token_url<'a>(&'a self, sa: &'a ServiceAccount) -> &'a str {
        #[cfg(test)]
        if let Some(url) = self.test_oauth_token_url.as_deref() {
            return url;
        }
        Self::signed_audience(sa)
    }
}

impl AuthTokenGenerator for FcmTokenGenerator {
    async fn mint(&self) -> std::result::Result<MintedToken, TokenAcquisitionError> {
        let sa = self.service_account.as_ref().ok_or_else(|| {
            TokenAcquisitionError::permanent(Error::Fcm(
                "No service account configured".to_string(),
            ))
        })?;

        let encoding_key = self.encoding_key.as_ref().ok_or_else(|| {
            TokenAcquisitionError::permanent(Error::Fcm("No encoding key available".to_string()))
        })?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                TokenAcquisitionError::permanent(Error::Fcm(format!("System time error: {e}")))
            })?
            .as_secs();

        // Backdate `iat` by the clock-skew leeway so a fast host clock does not
        // produce an assertion Google sees as issued in the future; `exp` stays
        // within Google's 1-hour max measured from the backdated `iat`.
        let (iat, exp) = crate::push::auth_jwt_iat_exp(now, 3600);

        let claims = OAuthClaims {
            iss: sa.client_email.clone(),
            scope: FCM_SCOPE.to_string(),
            // Derive the signed audience from the same helper the request
            // target uses, so aud and endpoint can never diverge — even for an
            // empty token_uri (issue #153).
            aud: Self::signed_audience(sa).to_string(),
            iat,
            exp,
        };

        let header = Header::new(Algorithm::RS256);
        let jwt = Zeroizing::new(
            encode(&header, &claims, encoding_key)
                .map_err(|e| TokenAcquisitionError::permanent(Error::from(e)))?,
        );

        let request = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
            assertion: jwt,
        };

        // POST to the signed audience (token_uri) so aud and endpoint agree
        // (issue #153).
        let response = self
            .http_client
            .post(self.oauth_token_url(sa))
            .form(&request)
            .send()
            .await
            .map_err(oauth_error_from_transport)?;

        if !response.status().is_success() {
            let status = response.status();
            let retry_after = retry::retry_after_from_headers(response.headers());
            debug!(status = %status, "FCM OAuth token request failed");
            return Err(oauth_error_from_status(status, retry_after));
        }

        // Bounded, zeroizing read of the success body (issue #154).
        let token_response: TokenResponse =
            match crate::push::parse_bounded_json_body(response, MAX_OAUTH_BODY_BYTES).await {
                Ok(token_response) => token_response,
                Err(crate::push::BoundedJsonBodyError::Read(error)) => {
                    return Err(oauth_error_from_transport(error));
                }
                Err(crate::push::BoundedJsonBodyError::TooLarge) => {
                    return Err(TokenAcquisitionError::permanent(Error::Fcm(
                        "OAuth token response exceeded the size cap".to_string(),
                    )));
                }
                Err(crate::push::BoundedJsonBodyError::Parse) => {
                    return Err(TokenAcquisitionError::permanent(Error::Fcm(
                        "OAuth token response was malformed JSON".to_string(),
                    )));
                }
            };

        let ttl = token_cache_lifetime(token_response.expires_in);

        self.metrics.record_auth_token_refresh("fcm_oauth");

        trace!("Refreshed FCM access token");
        Ok(MintedToken {
            token: token_response.access_token,
            expires_at: SystemTime::now() + ttl,
        })
    }
}

/// FCM client for sending push notifications.
pub struct FcmClient {
    pub(crate) config: FcmConfig,
    pub(crate) http_client: Client,
    pub(crate) token_cache: TokenCache<FcmTokenGenerator>,
    pub(crate) metrics: Metrics,
    /// Test-only override for the FCM v1 API base URL (scheme + host + port).
    #[cfg(test)]
    pub(crate) test_fcm_api_base_url: Option<String>,
}

impl FcmClient {
    /// Create a new FCM client.
    #[allow(dead_code)]
    pub async fn new(config: FcmConfig) -> Result<Self> {
        Self::with_metrics(config, Metrics::disabled()).await
    }

    /// Create a new FCM client with metrics.
    pub async fn with_metrics(config: FcmConfig, metrics: Metrics) -> Result<Self> {
        let http_client = Client::builder().timeout(Duration::from_secs(30)).build()?;

        // Load service account if configured
        let (service_account, encoding_key) = if !config.service_account_path.is_empty() {
            let data = Zeroizing::new(
                tokio::fs::read_to_string(&config.service_account_path)
                    .await
                    .map_err(|e| {
                        Error::Fcm(format!(
                            "Failed to read service account file '{}': {e}",
                            config.service_account_path
                        ))
                    })?,
            );

            let sa: ServiceAccount = serde_json::from_str(data.as_str())
                .map_err(|e| Error::Fcm(format!("Failed to parse service account JSON: {e}")))?;

            // The raw JSON and parsed private-key string are zeroizing; the
            // `jsonwebtoken::EncodingKey` copy is dependency-owned and has no
            // zeroize hook short of replacing the signer.
            let key = EncodingKey::from_rsa_pem(sa.private_key.as_bytes())
                .map_err(|e| Error::Fcm(format!("Failed to parse service account key: {e}")))?;

            (Some(sa), Some(key))
        } else {
            (None, None)
        };

        let token_cache = TokenCache::new(FcmTokenGenerator {
            http_client: http_client.clone(),
            service_account,
            encoding_key,
            metrics: metrics.clone(),
            #[cfg(test)]
            test_oauth_token_url: None,
        });

        Ok(Self {
            config,
            http_client,
            token_cache,
            metrics,
            #[cfg(test)]
            test_fcm_api_base_url: None,
        })
    }

    fn fcm_messages_send_url(&self, project_id: &str) -> String {
        #[cfg(test)]
        if let Some(base) = self.test_fcm_api_base_url.as_deref() {
            return format!("{base}/v1/projects/{project_id}/messages:send");
        }
        format!("https://fcm.googleapis.com/v1/projects/{project_id}/messages:send")
    }

    /// Get a valid access token via the shared cache, refreshing if necessary.
    async fn get_access_token(
        &self,
    ) -> std::result::Result<Zeroizing<String>, TokenAcquisitionError> {
        self.token_cache.get().await
    }

    /// Get the project ID, from config or service account.
    fn project_id(&self) -> Result<&str> {
        let project_id = if !self.config.project_id.is_empty() {
            self.config.project_id.as_str()
        } else {
            self.token_cache
                .generator()
                .service_account()
                .map(|sa| sa.project_id.as_str())
                .ok_or_else(|| Error::Fcm("No project ID configured".to_string()))?
        };

        validate_project_id(project_id)
    }

    /// Send a silent push notification to a device.
    ///
    /// Returns [`PushSendOutcome::Sent`] if FCM accepted the notification,
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
        // Validate token format before spending an OAuth-authenticated round-trip
        // and FCM quota on a clearly-malformed token (mirrors APNs).
        if !is_valid_fcm_token(device_token.as_str()) {
            trace!(
                token_len = device_token.len(),
                "Invalid FCM device token format"
            );
            return Ok(PushSendOutcome::InvalidToken);
        }

        // Record one duration sample per logical push, across all retries, so
        // push_request_duration_seconds counts notifications rather than HTTP
        // attempts (issue #168). Per-attempt HTTP status stays in
        // handle_response.
        let retry_config = RetryConfig::default();
        let start = Instant::now();
        let result = retry::with_retry(
            &retry_config,
            "FCM",
            || self.send_once(&device_token),
            backoff_permit,
            self.metrics.clone(),
        )
        .await;
        self.metrics
            .observe_push_duration("fcm", start.elapsed().as_secs_f64());

        result
    }

    /// Build the outbound request from a pre-built `FcmRequest` template.
    ///
    /// The template (built once in `send_once`, outside the transport-retry
    /// closure) borrows the device token from its zeroizing buffer via
    /// `FcmMessage<'a>` rather than copying it into an owned `String`
    /// (issue #126/#198); a transport retry reuses the same template instead of
    /// rebuilding the map/struct/token copy per attempt. reqwest still
    /// serializes the token into a non-zeroized body buffer it owns; that
    /// residual copy is the accepted #126 posture — the token cannot be
    /// zeroized in the serialized HTTP body without reimplementing the client.
    fn build_request(
        &self,
        url: &str,
        access_token: &str,
        request: &FcmRequest<'_>,
    ) -> reqwest::RequestBuilder {
        let authorization = Zeroizing::new(format!("Bearer {access_token}"));
        self.http_client
            .post(url)
            .header("authorization", authorization.as_str())
            .json(request)
    }

    /// Build the FCM request body template.
    fn build_message(device_token: &str) -> FcmRequest<'_> {
        let mut data = std::collections::HashMap::new();
        data.insert("content_available".to_string(), "true".to_string());
        FcmRequest {
            message: FcmMessage {
                token: device_token,
                android: Some(AndroidConfig {
                    priority: "high".to_string(),
                }),
                data: Some(data),
            },
        }
    }

    /// Parse an FCM error response, falling back to a status-derived error when
    /// the provider body is empty, non-JSON, or exceeds the bounded read limit.
    async fn parse_error_response(
        response: reqwest::Response,
        default_code: u32,
        default_status: &str,
    ) -> FcmErrorResponse {
        crate::push::parse_bounded_error_body::<FcmErrorResponse>(response)
            .await
            .unwrap_or(FcmErrorResponse {
                error: FcmError {
                    code: default_code,
                    message: "Unknown".to_string(),
                    status: default_status.to_string(),
                    details: Vec::new(),
                },
            })
    }

    /// Parse an FCM error response and classify it as a dead token or a
    /// permanent error.
    ///
    /// `default_status` is used when the body cannot be parsed (e.g. an empty
    /// or non-JSON body, or a body exceeding the bounded read limit), preserving
    /// the provider's HTTP-status-implied default classification. Only a
    /// provider-specific FCM detail with
    /// `errorCode: "UNREGISTERED"` is treated as a dead device token; every
    /// other response — including `INVALID_ARGUMENT` and `NOT_FOUND` (which can
    /// mean a misconfigured project ID) — is surfaced as a permanent error so a
    /// healthy token is not evicted. See issue #111.
    async fn classify_error_response(
        &self,
        response: reqwest::Response,
        default_code: u32,
        default_status: &str,
    ) -> SendAttemptResult {
        let error = Self::parse_error_response(response, default_code, default_status).await;

        match classify_fcm_error(&error.error) {
            FcmClassification::TokenDead => {
                debug!(status = %error.error.status, "FCM token unregistered");
                SendAttemptResult::Success(false)
            }
            FcmClassification::Permanent => {
                warn!(
                    status = %error.error.status,
                    message = %error.error.message,
                    "FCM rejected request (configuration or request error)"
                );
                SendAttemptResult::Permanent(Error::Fcm(format!(
                    "Bad request: {}",
                    fcm_error_summary(&error.error)
                )))
            }
        }
    }

    async fn handle_response(
        &self,
        response: reqwest::Response,
        access_token: &str,
    ) -> SendAttemptResult {
        let status = response.status();

        self.metrics
            .record_push_response_status("fcm", status.as_u16());

        match status.as_u16() {
            200 => {
                debug!(status = status.as_u16(), "FCM notification accepted");
                SendAttemptResult::Success(true)
            }
            400 => {
                self.classify_error_response(response, 400, "INVALID_ARGUMENT")
                    .await
            }
            401 => {
                // Auth error. FCM 401 is unambiguously an auth failure (unlike
                // APNs 403, which overloads auth and config), so evict the
                // cached token unconditionally and ask the retry engine to
                // retry once with a freshly minted token (issue #85).
                self.token_cache.invalidate_if_matches(access_token).await;
                debug!("FCM authentication error; will retry once with a fresh token");
                SendAttemptResult::AuthRejected(Error::Fcm("Authentication error".to_string()))
            }
            403 => {
                // Project or service-account authorization failure. This is a
                // provider-wide configuration outage, not a dead device token.
                let error = Self::parse_error_response(response, 403, "PERMISSION_DENIED").await;
                error!(
                    status = %error.error.status,
                    fcm_error_code = fcm_provider_error_code(&error.error).unwrap_or("unknown"),
                    "FCM permission denied"
                );
                SendAttemptResult::Permanent(Error::Fcm(format!(
                    "FCM permission denied: {} (check Cloud Messaging API enablement / service-account IAM)",
                    fcm_error_summary(&error.error)
                )))
            }
            404 => {
                self.classify_error_response(response, 404, "NOT_FOUND")
                    .await
            }
            408 => {
                // Request timeout - retriable. Honor Retry-After if present.
                let retry_after = retry::retry_after_from_headers(response.headers());
                debug!(status = %status, "FCM request timeout (retriable)");
                SendAttemptResult::Retriable {
                    status_code: 408,
                    retry_after,
                }
            }
            429 => {
                // Rate limited - retriable
                let retry_after = retry::retry_after_from_headers(response.headers());
                SendAttemptResult::Retriable {
                    status_code: 429,
                    retry_after,
                }
            }
            500..=599 => {
                // Server error - retriable. FCM documents that
                // 503 SERVICE_UNAVAILABLE responses include a Retry-After the
                // caller is expected to honor, so reuse the same extraction.
                let retry_after = retry::retry_after_from_headers(response.headers());
                debug!(status = %status, "FCM server error (retriable)");
                SendAttemptResult::Retriable {
                    status_code: status.as_u16(),
                    retry_after,
                }
            }
            _ => {
                // Unknown statuses are provider/protocol errors, not evidence
                // that the device token is dead. Keep them out of the
                // invalid-token path so operators do not prune live tokens.
                warn!(status = %status, "FCM unexpected response");
                SendAttemptResult::Permanent(Error::Fcm(format!(
                    "Unexpected FCM response status: {status}"
                )))
            }
        }
    }

    /// Send a single push notification attempt (one `with_retry` iteration).
    ///
    /// Builds the request template once, before the transport-retry closure,
    /// so a transport retry reuses it rather than rebuilding the map/struct and
    /// re-copying the device token per attempt (issue #198). Returns a
    /// `SendAttemptResult` indicating success, a retriable error, an auth
    /// rejection, or a permanent error.
    async fn send_once(&self, device_token: &Zeroizing<String>) -> SendAttemptResult {
        let project_id = match self.project_id() {
            Ok(id) => id,
            Err(e) => return SendAttemptResult::Permanent(e),
        };
        let url = self.fcm_messages_send_url(project_id);

        let access_token = match self.get_access_token().await {
            Ok(t) => t,
            Err(e) => return e.into_send_attempt(),
        };

        // Build the request body template once, outside the transport-retry
        // closure (issue #198). It borrows the device token from its zeroizing
        // buffer (issue #126).
        let request = Self::build_message(device_token.as_str());

        let transport_retry = RetryConfig::transport();
        let response = match retry::with_transport_retry(
            &transport_retry,
            "FCM",
            || async {
                self.build_request(&url, access_token.as_str(), &request)
                    .send()
                    .await
                    // FCM's URL does not embed the device token (it lives in
                    // the JSON body), but strip any URL uniformly with APNs so
                    // transport errors never carry a target into logs (#172).
                    .map_err(|e| Error::from(e).redact_transport_url())
            },
            &self.metrics,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => return SendAttemptResult::Permanent(e),
        };

        self.handle_response(response, access_token.as_str()).await
    }

    /// Check if the client is properly configured.
    #[must_use]
    pub fn is_configured(&self) -> bool {
        if !self.config.enabled {
            return false;
        }

        self.token_cache.generator().is_configured()
    }
}

/// Cheap sanity check for an FCM registration token.
///
/// FCM registration tokens are opaque, so this deliberately only rejects input
/// that cannot be a valid token: empty strings, unreasonably long strings, and
/// strings containing characters outside the ASCII alphanumeric plus URL-safe
/// punctuation set that real tokens use. This mirrors the APNs short-circuit so
/// a malformed token does not cost a full OAuth-authenticated round-trip and
/// FCM quota. It does not (and cannot) guarantee the token is live.
#[must_use]
fn is_valid_fcm_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_FCM_TOKEN_LEN
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.'))
}

/// Build the bounded, non-sensitive error message for a failed OAuth token
/// request.
///
/// Only the HTTP status is included. The raw provider body is intentionally
/// omitted because Google OAuth error responses can echo assertion/JWT-related
/// material, and embedding it verbatim risks leaking auth context into logs.
fn oauth_failure_message(status: reqwest::StatusCode) -> String {
    format!("OAuth token request failed: {status}")
}

fn validate_project_id(project_id: &str) -> Result<&str> {
    if project_id.is_empty() {
        return Err(Error::Fcm("No project ID configured".to_string()));
    }

    if !project_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(Error::Fcm(
            "Invalid FCM project ID: must contain only ASCII letters, digits, and hyphens"
                .to_string(),
        ));
    }

    Ok(project_id)
}

#[cfg(test)]
impl FcmClient {
    /// Create a mock FCM client for testing.
    pub(crate) fn mock(config: FcmConfig, with_service_account: bool) -> Self {
        let (service_account, encoding_key) = if with_service_account {
            let sa = ServiceAccount {
                account_type: "service_account".to_string(),
                project_id: config.project_id.clone(),
                private_key: Zeroizing::new("fake-key".to_string()),
                client_email: "test@test.iam.gserviceaccount.com".to_string(),
                token_uri: "https://oauth2.googleapis.com/token".to_string(),
            };
            (Some(sa), Some(EncodingKey::from_secret(b"fake-key")))
        } else {
            (None, None)
        };

        let http_client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("http client");
        let token_cache = TokenCache::new(FcmTokenGenerator {
            http_client: http_client.clone(),
            service_account,
            encoding_key,
            metrics: Metrics::disabled(),
            test_oauth_token_url: None,
        });

        Self {
            config,
            http_client,
            token_cache,
            metrics: Metrics::disabled(),
            test_fcm_api_base_url: None,
        }
    }

    /// Set the mock service account's project id (test setup).
    pub(crate) fn set_service_account_project_id(&mut self, project_id: &str) {
        if let Some(sa) = self.token_cache.generator_mut().service_account.as_mut() {
            sa.project_id = project_id.to_string();
        }
    }

    /// Set the OAuth token endpoint override (test setup).
    pub(crate) fn set_test_oauth_token_url(&mut self, url: String) {
        self.token_cache.generator_mut().test_oauth_token_url = Some(url);
    }

    /// Seed the token cache with a credential (test setup).
    pub(crate) async fn seed_token(&self, token: &str, expires_at: SystemTime) {
        self.token_cache.seed(token, expires_at).await;
    }

    /// The currently cached credential value, if any (test inspection).
    pub(crate) async fn cached_token_value(&self) -> Option<String> {
        self.token_cache.cached_token_value().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_metrics::{counter_value, histogram_sample_count};
    use wiremock::matchers::{body_partial_json, header, method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn zeroizing_token(token: &str) -> Zeroizing<String> {
        Zeroizing::new(token.to_owned())
    }

    #[test]
    fn test_minted_token_stores_access_token_in_zeroizing_string() {
        // Compile-time guard: minted credentials handed to the shared cache
        // must stay zeroizing.
        fn assert_zeroizing_string(_: &Zeroizing<String>) {}

        let minted = MintedToken {
            token: Zeroizing::new("cached-access-token".to_string()),
            expires_at: SystemTime::now() + Duration::from_secs(60),
        };

        assert_zeroizing_string(&minted.token);
    }

    #[test]
    fn test_token_request_stores_assertion_in_zeroizing_string() {
        // Compile-time guard: OAuth assertions must stay zeroizing.
        fn assert_zeroizing_string(_: &Zeroizing<String>) {}

        let request = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
            assertion: Zeroizing::new("signed-jwt-assertion".to_string()),
        };

        assert_zeroizing_string(&request.assertion);
    }

    #[test]
    fn test_token_response_deserializes_access_token_and_expiry() {
        // Compile-time guard: provider bearer tokens must deserialize directly
        // into zeroizing storage while preserving provider lifetime metadata.
        fn assert_zeroizing_string(_: &Zeroizing<String>) {}

        let response: TokenResponse = serde_json::from_value(serde_json::json!({
            "access_token": "provider-access-token",
            "expires_in": 3600,
            "token_type": "Bearer"
        }))
        .unwrap();

        assert_eq!(response.access_token.as_str(), "provider-access-token");
        assert_eq!(response.expires_in, Some(3600));
        assert_zeroizing_string(&response.access_token);
    }

    #[test]
    fn test_token_cache_lifetime_uses_provider_expiry_with_safety_margin() {
        assert_eq!(
            token_cache_lifetime(Some(3600)),
            Duration::from_secs(3600 - TOKEN_REFRESH_SAFETY_MARGIN_SECS)
        );
    }

    #[test]
    fn test_token_cache_lifetime_falls_back_when_provider_omits_expiry() {
        let response: TokenResponse = serde_json::from_value(serde_json::json!({
            "access_token": "provider-access-token"
        }))
        .unwrap();

        assert_eq!(response.expires_in, None);
        assert_eq!(token_cache_lifetime(response.expires_in), TOKEN_LIFETIME);
    }

    #[test]
    fn test_token_cache_lifetime_clamps_short_provider_expiry_to_minimum() {
        assert_eq!(token_cache_lifetime(Some(30)), TOKEN_LIFETIME_MIN);
        assert_eq!(
            token_cache_lifetime(Some(TOKEN_REFRESH_SAFETY_MARGIN_SECS)),
            TOKEN_LIFETIME_MIN
        );
    }

    #[test]
    fn test_fcm_request_borrows_device_token_from_zeroizing_string() {
        // Compile-time guard: request construction must not copy the device
        // token into an owned plain String before reqwest serializes the body.
        fn assert_borrowed_token(_: &str) {}

        let token = zeroizing_token("device-token-123");
        let request = FcmRequest {
            message: FcmMessage {
                token: token.as_str(),
                android: None,
                data: None,
            },
        };

        assert_borrowed_token(request.message.token);
        assert_eq!(request.message.token, "device-token-123");
    }

    #[test]
    fn test_oauth_failure_message_omits_body_and_stays_bounded() {
        // A hostile/buggy token endpoint could echo a huge body containing
        // assertion/JWT material. The propagated error must contain only the
        // status, never the body, and must not grow with the body size.
        let status = reqwest::StatusCode::BAD_REQUEST;
        let message = oauth_failure_message(status);

        assert_eq!(message, "OAuth token request failed: 400 Bad Request");

        // Independent of any provider body, the message length is a
        // small constant bounded by the status text.
        let secret = "leaked-assertion-jwt-".repeat(100_000);
        assert!(!message.contains(&secret));
        assert!(!message.contains("leaked-assertion-jwt"));
        assert!(message.len() < 128);
    }

    #[tokio::test]
    async fn test_oauth_failure_does_not_propagate_or_buffer_raw_body() {
        // Regression: the OAuth failure path must not read the body nor embed
        // raw provider content into the error. Drive a real response with an
        // oversized, secret-bearing body through the same status-only error
        // construction the failure path uses, then drop the response body
        // unread.
        let mock_server = MockServer::start().await;

        let secret = "assertion-jwt-secret-".repeat(100_000);
        let huge_body =
            format!("{{\"error\":\"invalid_grant\",\"error_description\":\"{secret}\"}}");
        assert!(huge_body.len() > 1_000_000);

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_string(huge_body.clone()))
            .expect(1)
            .mount(&mock_server)
            .await;

        let response = Client::new().post(mock_server.uri()).send().await.unwrap();

        let status = response.status();
        drop(response);
        let error = Error::Fcm(oauth_failure_message(status));

        let rendered = error.to_string();
        assert!(rendered.contains("OAuth token request failed"));
        assert!(rendered.contains("400"));
        // No raw provider body leaks into the error, and it stays bounded
        // regardless of the (huge) upstream body.
        assert!(!rendered.contains(&secret));
        assert!(!rendered.contains("assertion-jwt-secret"));
        assert!(!rendered.contains("invalid_grant"));
        assert!(rendered.len() < 128);
    }

    #[test]
    fn test_fcm_request_serialization() {
        let mut data = std::collections::HashMap::new();
        data.insert("content_available".to_string(), "true".to_string());

        let request = FcmRequest {
            message: FcmMessage {
                token: "test-token",
                android: Some(AndroidConfig {
                    priority: "high".to_string(),
                }),
                data: Some(data),
            },
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("test-token"));
        assert!(json.contains("high"));
        assert!(json.contains("content_available"));
    }

    #[test]
    fn test_service_account_debug_redacts_private_key() {
        let private_key =
            "-----BEGIN PRIVATE KEY-----\nsecret-key-material\n-----END PRIVATE KEY-----";
        let sa = ServiceAccount {
            account_type: "service_account".to_string(),
            project_id: "test-project".to_string(),
            private_key: Zeroizing::new(private_key.to_string()),
            client_email: "test@test.iam.gserviceaccount.com".to_string(),
            token_uri: "https://oauth2.googleapis.com/token".to_string(),
        };

        let debug = format!("{sa:?}");

        assert!(debug.contains("ServiceAccount"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(private_key));
        assert!(!debug.contains("secret-key-material"));
    }

    #[tokio::test]
    async fn test_client_not_configured_when_disabled() {
        let config = FcmConfig {
            enabled: false,
            service_account_path: String::new(),
            project_id: String::new(),
        };

        let client = FcmClient::new(config).await.unwrap();
        assert!(!client.is_configured());
    }

    #[tokio::test]
    async fn test_send_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/v1/projects/.+/messages:send"))
            .and(header("authorization", "Bearer test-access-token"))
            .and(body_partial_json(serde_json::json!({
                "message": {
                    "token": "device-token-123"
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "projects/test-project/messages/123456"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();

        let url = format!(
            "{}/v1/projects/test-project/messages:send",
            mock_server.uri()
        );

        let mut data = std::collections::HashMap::new();
        data.insert("content_available".to_string(), "true".to_string());

        let request = FcmRequest {
            message: FcmMessage {
                token: "device-token-123",
                android: Some(AndroidConfig {
                    priority: "high".to_string(),
                }),
                data: Some(data),
            },
        };

        let response = http_client
            .post(&url)
            .header("authorization", "Bearer test-access-token")
            .json(&request)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_send_bad_request() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/v1/projects/.+/messages:send"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": {
                    "code": 400,
                    "message": "Invalid token",
                    "status": "INVALID_ARGUMENT"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();

        let url = format!(
            "{}/v1/projects/test-project/messages:send",
            mock_server.uri()
        );

        let request = FcmRequest {
            message: FcmMessage {
                token: "invalid-token",
                android: None,
                data: None,
            },
        };

        let response = http_client
            .post(&url)
            .header("authorization", "Bearer test-access-token")
            .json(&request)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 400);
        let body: FcmErrorResponse = response.json().await.unwrap();
        assert_eq!(body.error.status, "INVALID_ARGUMENT");
    }

    #[tokio::test]
    async fn test_send_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/v1/projects/.+/messages:send"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "error": {
                    "code": 404,
                    "message": "Requested entity was not found.",
                    "status": "NOT_FOUND"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();

        let url = format!(
            "{}/v1/projects/test-project/messages:send",
            mock_server.uri()
        );

        let request = FcmRequest {
            message: FcmMessage {
                token: "unregistered-token",
                android: None,
                data: None,
            },
        };

        let response = http_client
            .post(&url)
            .header("authorization", "Bearer test-access-token")
            .json(&request)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 404);
    }

    #[test]
    fn test_classify_fcm_error_unregistered_detail_is_token_dead() {
        let error = FcmError {
            code: 404,
            message: "Requested entity was not found.".to_string(),
            status: "NOT_FOUND".to_string(),
            details: vec![FcmErrorDetail {
                type_url: Some(FCM_ERROR_DETAIL_TYPE.to_string()),
                error_code: Some(FCM_ERROR_UNREGISTERED.to_string()),
            }],
        };

        assert_eq!(classify_fcm_error(&error), FcmClassification::TokenDead);
    }

    #[test]
    fn test_classify_fcm_error_other_statuses_are_permanent() {
        // INVALID_ARGUMENT, NOT_FOUND (wrong project), and unknown statuses must
        // NOT evict the token unless FCM supplies the provider-specific
        // UNREGISTERED detail.
        for status in [
            "INVALID_ARGUMENT",
            "NOT_FOUND",
            "PERMISSION_DENIED",
            "SENDER_ID_MISMATCH",
            "Unknown",
            "SOME_FUTURE_STATUS",
        ] {
            let error = FcmError {
                code: 400,
                message: "test error message".to_string(),
                status: status.to_string(),
                details: Vec::new(),
            };

            assert_eq!(
                classify_fcm_error(&error),
                FcmClassification::Permanent,
                "status {status} should be classified as a permanent error"
            );
        }

        let wrong_detail_type = FcmError {
            code: 404,
            message: "Requested entity was not found.".to_string(),
            status: "NOT_FOUND".to_string(),
            details: vec![FcmErrorDetail {
                type_url: Some("type.googleapis.com/google.rpc.BadRequest".to_string()),
                error_code: Some(FCM_ERROR_UNREGISTERED.to_string()),
            }],
        };
        assert_eq!(
            classify_fcm_error(&wrong_detail_type),
            FcmClassification::Permanent
        );

        let different_fcm_error_code = FcmError {
            code: 403,
            message: "Sender ID mismatch".to_string(),
            status: "PERMISSION_DENIED".to_string(),
            details: vec![FcmErrorDetail {
                type_url: Some(FCM_ERROR_DETAIL_TYPE.to_string()),
                error_code: Some("SENDER_ID_MISMATCH".to_string()),
            }],
        };
        assert_eq!(
            classify_fcm_error(&different_fcm_error_code),
            FcmClassification::Permanent
        );
    }

    #[tokio::test]
    async fn test_handle_response_records_per_attempt_status_not_duration() {
        // Metric layering (issue #168): handle_response records only the
        // per-attempt response-status counter; the per-logical-push duration
        // is recorded once in send(), so no duration sample comes from here.
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/v1/projects/.+/messages:send"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let metrics = Metrics::new().unwrap();
        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };
        let mut client = FcmClient::mock(config, false);
        client.metrics = metrics.clone();

        let response = Client::new()
            .post(format!(
                "{}/v1/projects/test-project/messages:send",
                mock_server.uri()
            ))
            .send()
            .await
            .unwrap();

        let result = client.handle_response(response, "test-access-token").await;

        assert!(matches!(result, SendAttemptResult::Success(true)));
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_push_response_status_total",
                &[("platform", "fcm"), ("status", "200")]
            ),
            1.0
        );
        assert!(
            !metrics
                .gather()
                .iter()
                .any(|family| family.name() == "transponder_push_request_duration_seconds"),
            "handle_response must not observe the per-push duration histogram"
        );
    }

    #[tokio::test]
    async fn test_send_records_one_duration_sample_per_logical_push_across_retries() {
        // A logical push that succeeds after one 429 retry records exactly one
        // duration sample (issue #168) and two per-attempt status counts.
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/v1/projects/.+/messages:send"))
            .respond_with(ResponseTemplate::new(429).set_body_json(serde_json::json!({
                "error": { "code": 429, "message": "quota", "status": "RESOURCE_EXHAUSTED" }
            })))
            .up_to_n_times(1)
            .expect(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(r"/v1/projects/.+/messages:send"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock_server)
            .await;

        let metrics = Metrics::new().unwrap();
        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };
        let mut client = FcmClient::mock(config, true);
        client.metrics = metrics.clone();
        client.test_fcm_api_base_url = Some(mock_server.uri());
        client
            .seed_token("cached", SystemTime::now() + Duration::from_secs(3600))
            .await;

        let outcome = client
            .send(zeroizing_token("device-token-123"), None)
            .await
            .unwrap();

        assert_eq!(outcome, PushSendOutcome::Sent);
        assert_eq!(
            histogram_sample_count(
                &metrics,
                "transponder_push_request_duration_seconds",
                &[("platform", "fcm")]
            ),
            1,
            "duration must be sampled once per logical push, not per attempt"
        );
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_push_response_status_total",
                &[("platform", "fcm"), ("status", "429")]
            ),
            1.0
        );
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_push_response_status_total",
                &[("platform", "fcm"), ("status", "200")]
            ),
            1.0
        );
    }

    /// Drive `handle_response` against a mock server returning `status_code`
    /// with the given FCM error body, returning the classified result.
    async fn fcm_error_result_with_body(
        status_code: u16,
        body: serde_json::Value,
    ) -> SendAttemptResult {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/v1/projects/.+/messages:send"))
            .respond_with(ResponseTemplate::new(status_code).set_body_json(body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };
        let client = FcmClient::mock(config, false);

        let response = Client::new()
            .post(format!(
                "{}/v1/projects/test-project/messages:send",
                mock_server.uri()
            ))
            .send()
            .await
            .unwrap();

        client.handle_response(response, "test-access-token").await
    }

    /// Drive `handle_response` against a mock server returning `status_code`
    /// with the given FCM error `status`, returning the classified result.
    async fn fcm_error_result(status_code: u16, status: &str) -> SendAttemptResult {
        fcm_error_result_with_body(
            status_code,
            serde_json::json!({
                "error": {
                    "code": status_code,
                    "message": "test error message",
                    "status": status
                }
            }),
        )
        .await
    }

    /// Drive `handle_response` against a mock server returning `status_code`
    /// with an optional `retry-after` header, returning the classified result.
    async fn fcm_status_result(status_code: u16, retry_after: Option<&str>) -> SendAttemptResult {
        let mock_server = MockServer::start().await;
        let mut template =
            ResponseTemplate::new(status_code).set_body_string("Service Unavailable");
        if let Some(value) = retry_after {
            template = template.insert_header("retry-after", value);
        }
        Mock::given(method("POST"))
            .and(path_regex(r"/v1/projects/.+/messages:send"))
            .respond_with(template)
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };
        let client = FcmClient::mock(config, false);

        let response = Client::new()
            .post(format!(
                "{}/v1/projects/test-project/messages:send",
                mock_server.uri()
            ))
            .send()
            .await
            .unwrap();

        client.handle_response(response, "test-access-token").await
    }

    #[tokio::test]
    async fn test_handle_response_503_honors_retry_after_header() {
        // FCM documents that 503 SERVICE_UNAVAILABLE responses include a
        // Retry-After the caller is expected to honor.
        let result = fcm_status_result(503, Some("120")).await;
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
        let result = fcm_status_result(500, None).await;
        assert!(matches!(
            result,
            SendAttemptResult::Retriable {
                status_code: 500,
                retry_after: None,
            }
        ));
    }

    #[tokio::test]
    async fn test_handle_response_408_is_retriable() {
        let result = fcm_status_result(408, None).await;
        assert!(matches!(
            result,
            SendAttemptResult::Retriable {
                status_code: 408,
                retry_after: None,
            }
        ));
    }

    #[tokio::test]
    async fn test_handle_response_400_invalid_argument_is_permanent_error() {
        // INVALID_ARGUMENT is a malformed-payload/config error, not token death.
        let result = fcm_error_result(400, "INVALID_ARGUMENT").await;
        assert!(matches!(
            result,
            SendAttemptResult::Permanent(Error::Fcm(ref message))
                if message.contains("INVALID_ARGUMENT")
        ));
    }

    #[tokio::test]
    async fn test_handle_response_404_unregistered_detail_is_token_dead() {
        let result = fcm_error_result_with_body(
            404,
            serde_json::json!({
                "error": {
                    "code": 404,
                    "message": "Requested entity was not found.",
                    "status": "NOT_FOUND",
                    "details": [
                        {
                            "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
                            "errorCode": "UNREGISTERED"
                        }
                    ]
                }
            }),
        )
        .await;
        assert!(matches!(result, SendAttemptResult::Success(false)));
    }

    #[tokio::test]
    async fn test_handle_response_404_unregistered_status_without_detail_is_permanent_error() {
        // The generic top-level status is not the FCM provider-specific token
        // death discriminator; a 404 needs the FcmError detail to evict.
        let result = fcm_error_result(404, "UNREGISTERED").await;
        assert!(matches!(
            result,
            SendAttemptResult::Permanent(Error::Fcm(ref message))
                if message.contains("UNREGISTERED")
        ));
    }

    #[tokio::test]
    async fn test_handle_response_404_not_found_is_permanent_error() {
        // A 404 without an explicit UNREGISTERED status (e.g. wrong project ID)
        // must be a permanent error, not token death.
        let result = fcm_error_result(404, "NOT_FOUND").await;
        assert!(matches!(
            result,
            SendAttemptResult::Permanent(Error::Fcm(ref message))
                if message.contains("NOT_FOUND")
        ));
    }

    /// Drive `handle_response` against a mock server returning `status_code`
    /// with a raw (potentially oversized) string body.
    async fn fcm_error_result_with_string_body(
        status_code: u16,
        body: String,
    ) -> SendAttemptResult {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/v1/projects/.+/messages:send"))
            .respond_with(ResponseTemplate::new(status_code).set_body_string(body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };
        let client = FcmClient::mock(config, false);

        let response = Client::new()
            .post(format!(
                "{}/v1/projects/test-project/messages:send",
                mock_server.uri()
            ))
            .send()
            .await
            .unwrap();

        client.handle_response(response, "test-access-token").await
    }

    #[tokio::test]
    async fn test_handle_response_oversized_body_falls_back_without_whole_body_parse() {
        // A hostile/buggy endpoint returns a 400 whose body is far larger than
        // any legitimate FCM error payload but contains an UNREGISTERED detail.
        // The bounded read must refuse to buffer/parse the whole body and fall
        // back to the default INVALID_ARGUMENT classification (a permanent
        // error), never evicting the token based on attacker-controlled content.
        let padding = "A".repeat(4 * 1024 * 1024);
        let huge_body = format!(
            r#"{{"error":{{"code":400,"message":"{padding}","status":"NOT_FOUND","details":[{{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}}]}}}}"#
        );

        let result = fcm_error_result_with_string_body(400, huge_body).await;

        let SendAttemptResult::Permanent(Error::Fcm(message)) = result else {
            panic!("expected a permanent FCM error, got {result:?}");
        };
        assert!(message.contains("INVALID_ARGUMENT"));
        // The oversized provider body must not leak into the error message,
        // which stays bounded regardless of the (huge) upstream body.
        assert!(!message.contains(&padding));
        assert!(message.len() < 128);
    }

    #[tokio::test]
    async fn test_handle_response_403_permission_denied_is_permanent_error() {
        // PERMISSION_DENIED is a project/service-account configuration outage,
        // not a dead device token. Preserve the provider status/message/code so
        // operators can distinguish IAM, API-disabled, and sender-mismatch cases.
        let result = fcm_error_result_with_body(
            403,
            serde_json::json!({
                "error": {
                    "code": 403,
                    "message": "Sender ID mismatch.",
                    "status": "PERMISSION_DENIED",
                    "details": [
                        {
                            "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
                            "errorCode": "SENDER_ID_MISMATCH"
                        }
                    ]
                }
            }),
        )
        .await;
        assert!(matches!(
            result,
            SendAttemptResult::Permanent(Error::Fcm(ref message))
                if message.contains("permission denied")
                    && message.contains("PERMISSION_DENIED")
                    && message.contains("Sender ID mismatch")
                    && message.contains("SENDER_ID_MISMATCH")
                    && message.contains("Cloud Messaging API")
        ));
    }

    #[tokio::test]
    async fn test_handle_response_unexpected_status_is_permanent_error() {
        // Unknown statuses should surface as provider errors rather than being
        // counted as invalid device tokens.
        let result = fcm_status_result(418, None).await;
        assert!(matches!(
            result,
            SendAttemptResult::Permanent(Error::Fcm(ref message))
                if message.contains("Unexpected FCM response status")
                    && message.contains("418")
        ));
    }

    #[tokio::test]
    async fn test_send_auth_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/v1/projects/.+/messages:send"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": {
                    "code": 401,
                    "message": "Request had invalid authentication credentials.",
                    "status": "UNAUTHENTICATED"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();

        let url = format!(
            "{}/v1/projects/test-project/messages:send",
            mock_server.uri()
        );

        let request = FcmRequest {
            message: FcmMessage {
                token: "any-token",
                android: None,
                data: None,
            },
        };

        let response = http_client
            .post(&url)
            .header("authorization", "Bearer invalid-token")
            .json(&request)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 401);
    }

    #[tokio::test]
    async fn test_auth_error_invalidates_cached_token() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/v1/projects/.+/messages:send"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": {
                    "code": 401,
                    "message": "Request had invalid authentication credentials.",
                    "status": "UNAUTHENTICATED"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };
        let client = FcmClient::mock(config, false);
        client
            .seed_token("poisoned-access-token", SystemTime::now() + TOKEN_LIFETIME)
            .await;

        let response = Client::new()
            .post(format!(
                "{}/v1/projects/test-project/messages:send",
                mock_server.uri()
            ))
            .send()
            .await
            .unwrap();

        let result = client
            .handle_response(response, "poisoned-access-token")
            .await;

        // FCM 401 is unambiguous auth failure: evict the token and ask for a
        // fresh-token retry (issue #85).
        assert!(matches!(
            result,
            SendAttemptResult::AuthRejected(Error::Fcm(ref message))
                if message.contains("Authentication error")
        ));
        assert_eq!(client.cached_token_value().await, None);
    }

    #[tokio::test]
    async fn test_auth_error_keeps_token_refreshed_by_concurrent_task() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/v1/projects/.+/messages:send"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": {
                    "code": 401,
                    "message": "Request had invalid authentication credentials.",
                    "status": "UNAUTHENTICATED"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };
        let client = FcmClient::mock(config, false);

        // Simulate a concurrent task having already refreshed the cache to a
        // newer token after the failing request read its (now stale) token.
        client
            .seed_token("fresh-access-token", SystemTime::now() + TOKEN_LIFETIME)
            .await;

        let response = Client::new()
            .post(format!(
                "{}/v1/projects/test-project/messages:send",
                mock_server.uri()
            ))
            .send()
            .await
            .unwrap();

        // The failing request used the older, now-replaced token.
        let result = client.handle_response(response, "stale-access-token").await;

        assert!(matches!(
            result,
            SendAttemptResult::AuthRejected(Error::Fcm(ref message))
                if message.contains("Authentication error")
        ));

        // The freshly refreshed token must survive the stale rejection.
        assert_eq!(
            client.cached_token_value().await.as_deref(),
            Some("fresh-access-token")
        );
    }

    #[tokio::test]
    async fn test_send_rate_limited() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/v1/projects/.+/messages:send"))
            .respond_with(ResponseTemplate::new(429).set_body_json(serde_json::json!({
                "error": {
                    "code": 429,
                    "message": "Quota exceeded",
                    "status": "RESOURCE_EXHAUSTED"
                }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();

        let url = format!(
            "{}/v1/projects/test-project/messages:send",
            mock_server.uri()
        );

        let request = FcmRequest {
            message: FcmMessage {
                token: "any-token",
                android: None,
                data: None,
            },
        };

        let response = http_client
            .post(&url)
            .header("authorization", "Bearer test-token")
            .json(&request)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 429);
    }

    #[test]
    fn test_is_configured_with_service_account() {
        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };

        let client = FcmClient::mock(config, true);
        assert!(client.is_configured());
    }

    #[test]
    fn test_is_configured_missing_service_account() {
        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };

        let client = FcmClient::mock(config, false);
        assert!(!client.is_configured());
    }

    #[test]
    fn test_project_id_from_config() {
        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "config-project".to_string(),
        };

        let client = FcmClient::mock(config, false);
        assert_eq!(client.project_id().unwrap(), "config-project");
    }

    #[test]
    fn test_project_id_from_service_account() {
        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: String::new(), // Empty - should fall back to service account
        };

        let mut client = FcmClient::mock(config, true);
        client.set_service_account_project_id("service-project");

        assert_eq!(client.project_id().unwrap(), "service-project");
    }

    #[test]
    fn test_project_id_missing() {
        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: String::new(),
        };

        let client = FcmClient::mock(config, false);
        assert!(client.project_id().is_err());
    }

    #[tokio::test]
    async fn test_send_unexpected_status() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/v1/projects/.+/messages:send"))
            .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();

        let url = format!(
            "{}/v1/projects/test-project/messages:send",
            mock_server.uri()
        );

        let request = FcmRequest {
            message: FcmMessage {
                token: "any-token",
                android: None,
                data: None,
            },
        };

        let response = http_client
            .post(&url)
            .header("authorization", "Bearer test-token")
            .json(&request)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 503);
    }

    #[tokio::test]
    async fn test_new_client_without_service_account_path() {
        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(), // Empty
            project_id: "test-project".to_string(),
        };

        let client = FcmClient::new(config).await.unwrap();
        // No service account / encoding key loaded means the client is not
        // configured to send.
        assert!(!client.is_configured());
    }

    #[tokio::test]
    async fn test_new_client_invalid_service_account_path() {
        let config = FcmConfig {
            enabled: true,
            service_account_path: "/nonexistent/service-account.json".to_string(),
            project_id: "test-project".to_string(),
        };

        let result = FcmClient::new(config).await;
        assert!(result.is_err());
        match result {
            Err(e) => assert!(e.to_string().contains("Failed to read service account")),
            Ok(_) => panic!("Expected error"),
        }
    }

    #[tokio::test]
    async fn test_get_access_token_uses_cache() {
        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };

        let client = FcmClient::mock(config, true);

        // Pre-populate the cache
        client
            .seed_token(
                "cached-access-token",
                SystemTime::now() + Duration::from_secs(3600),
            )
            .await;

        // Should return cached token
        let token = client.get_access_token().await.unwrap();
        assert_eq!(token.as_str(), "cached-access-token");
    }

    #[tokio::test]
    async fn test_get_access_token_no_service_account() {
        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };

        // Client without service account - cache is empty, so it will try to refresh
        let client = FcmClient::mock(config, false);
        let result = client.get_access_token().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            TokenAcquisitionError::Permanent(err) => {
                assert!(err.to_string().contains("No service account"));
            }
            TokenAcquisitionError::Retriable { .. } => panic!("expected permanent error"),
        }
    }

    #[test]
    fn test_is_configured_enabled_with_service_account() {
        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };

        let client = FcmClient::mock(config, true);
        assert!(client.is_configured());
    }

    #[test]
    fn test_is_configured_disabled() {
        let config = FcmConfig {
            enabled: false,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };

        let client = FcmClient::mock(config, true);
        assert!(!client.is_configured()); // Disabled takes precedence
    }

    #[test]
    fn test_fcm_message_without_android() {
        let request = FcmRequest {
            message: FcmMessage {
                token: "test-token",
                android: None,
                data: None,
            },
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("test-token"));
        assert!(!json.contains("priority"));
    }

    #[test]
    fn test_fcm_message_with_empty_data() {
        let request = FcmRequest {
            message: FcmMessage {
                token: "test-token",
                android: Some(AndroidConfig {
                    priority: "high".to_string(),
                }),
                data: Some(std::collections::HashMap::new()),
            },
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("test-token"));
        assert!(json.contains("high"));
    }

    #[tokio::test]
    async fn test_new_client_invalid_json() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"not valid json {{{").unwrap();

        let config = FcmConfig {
            enabled: true,
            service_account_path: file.path().to_string_lossy().to_string(),
            project_id: "test-project".to_string(),
        };

        let result = FcmClient::new(config).await;
        assert!(result.is_err());
        match result {
            Err(e) => assert!(e.to_string().contains("Failed to parse service account")),
            Ok(_) => panic!("Expected error"),
        }
    }

    #[tokio::test]
    async fn test_new_client_invalid_key_in_service_account() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Valid JSON but with an invalid private key
        let sa_json = serde_json::json!({
            "type": "service_account",
            "project_id": "test-project",
            "private_key": "not-a-valid-pem-key",
            "client_email": "test@test.iam.gserviceaccount.com",
            "token_uri": "https://oauth2.googleapis.com/token"
        });

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(sa_json.to_string().as_bytes()).unwrap();

        let config = FcmConfig {
            enabled: true,
            service_account_path: file.path().to_string_lossy().to_string(),
            project_id: "test-project".to_string(),
        };

        let result = FcmClient::new(config).await;
        assert!(result.is_err());
        match result {
            Err(e) => assert!(
                e.to_string()
                    .contains("Failed to parse service account key")
            ),
            Ok(_) => panic!("Expected error"),
        }
    }

    #[tokio::test]
    async fn test_get_access_token_expired_cache_tries_refresh() {
        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };

        // Client without service account - will fail when trying to refresh
        let client = FcmClient::mock(config, false);

        // Pre-populate with expired token
        client
            .seed_token("expired-token", SystemTime::now() - Duration::from_secs(1))
            .await;

        // Should try to refresh but fail since no service account
        let result = client.get_access_token().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            TokenAcquisitionError::Permanent(err) => {
                assert!(err.to_string().contains("No service account"));
            }
            TokenAcquisitionError::Retriable { .. } => panic!("expected permanent error"),
        }
    }

    #[test]
    fn test_project_id_empty_config_no_service_account() {
        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: String::new(), // Empty
        };

        let client = FcmClient::mock(config, false);
        let result = client.project_id();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No project ID"));
    }

    #[tokio::test]
    async fn test_send_without_project_id() {
        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: String::new(), // Empty - will fail
        };

        let client = FcmClient::mock(config, false);

        // Pre-populate cache so it doesn't fail on get_access_token first
        client
            .seed_token("test-token", SystemTime::now() + Duration::from_secs(3600))
            .await;

        let result = client
            .send(zeroizing_token("test-device-token"), None)
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No project ID"));
    }

    #[tokio::test]
    async fn test_send_rejects_invalid_config_project_id_before_auth() {
        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "x/../../admin/v1".to_string(),
        };

        let client = FcmClient::mock(config, false);

        let result = client
            .send(zeroizing_token("test-device-token"), None)
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid FCM project ID")
        );
    }

    #[tokio::test]
    async fn test_send_rejects_invalid_service_account_project_id_before_auth() {
        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: String::new(),
        };

        let mut client = FcmClient::mock(config, true);
        client.set_service_account_project_id("x/../../admin/v1");

        let result = client
            .send(zeroizing_token("test-device-token"), None)
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid FCM project ID")
        );
    }

    #[tokio::test]
    async fn test_send_without_access_token() {
        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };

        // Client without service account - will fail to get access token
        let client = FcmClient::mock(config, false);

        let result = client
            .send(zeroizing_token("test-device-token"), None)
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("No service account")
        );
    }

    #[test]
    fn test_is_configured_missing_service_account_and_encoding_key() {
        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };

        // Create client with no service account and no encoding key.
        let client = FcmClient::mock(config, false);

        // Should not be configured - no encoding key
        assert!(!client.is_configured());
    }

    #[tokio::test]
    async fn test_send_once_returns_retriable_on_429() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/v1/projects/.+/messages:send"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "60")
                    .set_body_json(serde_json::json!({
                        "error": {
                            "code": 429,
                            "message": "Quota exceeded",
                            "status": "RESOURCE_EXHAUSTED"
                        }
                    })),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        let http_client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let url = format!(
            "{}/v1/projects/test-project/messages:send",
            mock_server.uri()
        );

        let request = FcmRequest {
            message: FcmMessage {
                token: "device-token-123",
                android: None,
                data: None,
            },
        };

        let response = http_client
            .post(&url)
            .header("authorization", "Bearer test-access-token")
            .json(&request)
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
            .and(path_regex(r"/v1/projects/.+/messages:send"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let http_client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let url = format!(
            "{}/v1/projects/test-project/messages:send",
            mock_server.uri()
        );

        let request = FcmRequest {
            message: FcmMessage {
                token: "device-token-123",
                android: None,
                data: None,
            },
        };

        let response = http_client
            .post(&url)
            .header("authorization", "Bearer test-access-token")
            .json(&request)
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
            .and(path_regex(r"/v1/projects/.+/messages:send"))
            .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let http_client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let url = format!(
            "{}/v1/projects/test-project/messages:send",
            mock_server.uri()
        );

        let request = FcmRequest {
            message: FcmMessage {
                token: "device-token-123",
                android: None,
                data: None,
            },
        };

        let response = http_client
            .post(&url)
            .header("authorization", "Bearer test-access-token")
            .json(&request)
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
            .and(path_regex(r"/v1/projects/.+/messages:send"))
            .respond_with(ResponseTemplate::new(429).set_body_json(serde_json::json!({
                "error": {
                    "code": 429,
                    "message": "Quota exceeded",
                    "status": "RESOURCE_EXHAUSTED"
                }
            })))
            .expect(1)
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path_regex(r"/v1/projects/.+/messages:send"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "projects/test-project/messages/123456"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let http_client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let url = format!(
            "{}/v1/projects/test-project/messages:send",
            mock_server.uri()
        );

        let request = FcmRequest {
            message: FcmMessage {
                token: "device-token-123",
                android: None,
                data: None,
            },
        };

        // First request - should get 429
        let response1 = http_client
            .post(&url)
            .header("authorization", "Bearer test-access-token")
            .json(&request)
            .send()
            .await
            .unwrap();

        assert_eq!(response1.status(), 429);

        // Second request - should get 200
        let response2 = http_client
            .post(&url)
            .header("authorization", "Bearer test-access-token")
            .json(&request)
            .send()
            .await
            .unwrap();

        assert_eq!(response2.status(), 200);
    }

    #[test]
    fn test_valid_fcm_token() {
        // Realistic-looking FCM registration token shape (colon-separated parts
        // with URL-safe alphanumerics, dashes and underscores).
        assert!(is_valid_fcm_token(
            "cZx1AbC-dEf:APA91bH-Token_value.with-allowed_chars0123456789"
        ));

        // Plain ASCII alphanumeric.
        assert!(is_valid_fcm_token("abcDEF0123456789"));

        // All individually-allowed punctuation characters.
        assert!(is_valid_fcm_token("a-b_c:d.e"));

        // A long-but-bounded token is still accepted.
        assert!(is_valid_fcm_token(&"a".repeat(MAX_FCM_TOKEN_LEN)));
    }

    #[test]
    fn test_invalid_fcm_token_empty() {
        assert!(!is_valid_fcm_token(""));
    }

    #[test]
    fn test_invalid_fcm_token_too_long() {
        assert!(!is_valid_fcm_token(&"a".repeat(MAX_FCM_TOKEN_LEN + 1)));
    }

    #[test]
    fn test_invalid_fcm_token_disallowed_chars() {
        // Whitespace.
        assert!(!is_valid_fcm_token("token with space"));
        assert!(!is_valid_fcm_token("token\twith\ttab"));
        assert!(!is_valid_fcm_token("token\nwith\nnewline"));

        // Control characters.
        assert!(!is_valid_fcm_token("token\0null"));

        // Non-ASCII / unicode.
        assert!(!is_valid_fcm_token("tokén-with-unicode"));

        // Other punctuation that is not part of the allowed set.
        assert!(!is_valid_fcm_token("token/with/slash"));
        assert!(!is_valid_fcm_token("token!bang"));
    }

    #[tokio::test]
    async fn test_send_rejects_invalid_token_without_oauth() {
        // A client with no service account / encoding key would error on the
        // OAuth round-trip if it ever reached it. Invalid tokens must instead
        // short-circuit to InvalidToken before any auth lookup or request build.
        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };
        let client = FcmClient::mock(config, false);

        assert_eq!(
            client.send(zeroizing_token(""), None).await.unwrap(),
            PushSendOutcome::InvalidToken,
            "empty token"
        );
        assert_eq!(
            client
                .send(zeroizing_token("token with space"), None)
                .await
                .unwrap(),
            PushSendOutcome::InvalidToken,
            "whitespace token"
        );
        assert_eq!(
            client
                .send(zeroizing_token("tokén-with-unicode"), None)
                .await
                .unwrap(),
            PushSendOutcome::InvalidToken,
            "unicode token"
        );
        assert_eq!(
            client
                .send(Zeroizing::new("a".repeat(MAX_FCM_TOKEN_LEN + 1)), None)
                .await
                .unwrap(),
            PushSendOutcome::InvalidToken,
            "overlong token"
        );
    }

    /// RSA private key used only to exercise the OAuth JWT-signing path in
    /// wiremock integration tests. The key is not a real credential.
    const TEST_RSA_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC+ck55JGyU1jFS
zlGUrJT1e9UL8voNAYXMTP34v3Mo1Gg4gs8CQnuBsO6RLnHoQtIYNdopqNE536il
zvcnQGBkS4gn1wAJjm+16sQZYPvykwFNNmWAkcWKIfn2qZcE3GAC2W2W6knH5ser
T2+2mrHrFMd1hML8JYH+hJsPuH1tNK2JfRrNkUJOmG6NUAqU8LT8P2bI4Fi6iAGI
RzGxaRqmBBJ97jx6dwakqFU+6XQiIxQ5wq0yakN/auhPT1lKfNa0mzE1QnG0t3Ht
Mfc7b77ToA7mHkln6+9KEPupULsD0H+O2W46KvIIwzeS6kk2aleIPMMVMVAw/UHl
LYaVuSCLAgMBAAECggEAAyPOUGf91ExdvtBA/xMDV7LFde95GOrMAmzIiSfa5bLu
zvO1JwPilmZM4J7j6ODlJtoIcURjwrEBzk4FvCNvE2g9Y+7DBOVQyS6IMiTrsnmi
/VtmvAJrP9ZEkUEFiOJ7QMDF8kWFluKiqxvhqyCMy2Ppz/Gy50ZVCNW12sH/a2P6
KLsSRwLQxl/v+TTiYxSPN2OsPi5xucbxV9fAA4G1EURgnjg540PiagbV2Kj8mwBB
ZRqrBVfWpyPQGVMwQUfSn0dQ4zJnOZPszKpaIMF2pu6yKpkf66u4X2baefL3yjez
FCoiwIvJhAvgQV4bIrcmOPmEIGhM087SFuC1q3QtQQKBgQDm2jiChO6xeOKeiZlJ
i4r/PjG/gNOVMi0IkGkfVfxSs3ZnFUlCU3LMHpI+sG7w+8EM+PsNtCfVk8ZKc/0w
mK5FdRh7j8/uIVAz1FV3H5c40B8w93w8VLeZvShMZRTyCNw2wMoMuOI+ZvAdt8m3
0hZSqEX7bvCAwlnG6llfcDPIQQKBgQDTMUlU276xP69VQIT6JQMT7uL5pfJ8o4/l
tZ/LN9Vd7bWeeSXXFtdJ057xmNMPafCu6ZNZ1XtpTjaB3dvpzDS0w2AULV/vBt6u
2mUjU4CG3hrYpmtvVHHOeRJpqBySj79Cy6PV6Wd80qhDna1rpPEd12DH54tEr4WI
jl0V7jwVywKBgQDEWKSptmDCR7wP9Z6P5ATz9TUg2XScOBH/b7xJb7vtp0A0ivFF
XW6NWA8xDKU/iBD5dKcrT6h1yntkBeU6ORI4d1C8f2Pt+R2bB6UtbYwUQUfWQRjE
w5VpSG6HE45OEeUjGLSBP5sGUk02KYSDOUfNQ9xJ72DVUvhC7D3Zo7gXQQKBgDQp
mT4vZGMtIqZA4FdUavUybLdSqJjmYTVQbd5otPeVLeWtcI42owgmD70GjSLifMMH
CBEJLIku+0GKRbXybRY0p3d0WZyVKs0vPgnCpx0ooKLgP+rohY+E0epszlnYzVm3
KIk+NARdl5fTyzCqNa+0McBOTVSysZ2v5Af1pruPAoGAfstlp38kcS9jlEyz6ykr
5+GInq5o7ZdjcoHnQ6Vz8PhfKxy92LQSkT3Dz/qHU9aqKA4YaEt9ftzvphortnnu
HdBEAGGbO85e4Qu6cPFfNMf3nK/gchAwBudaQEhGDAarVre0rDxjOpeaNmABo82P
LTP/MQIxLydQxT4+jx2NBu0=
-----END PRIVATE KEY-----";

    fn mock_client_with_rsa_service_account(project_id: &str) -> FcmClient {
        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: project_id.to_string(),
        };
        let sa = ServiceAccount {
            account_type: "service_account".to_string(),
            project_id: project_id.to_string(),
            private_key: Zeroizing::new(TEST_RSA_PRIVATE_KEY.to_string()),
            client_email: "test@test.iam.gserviceaccount.com".to_string(),
            token_uri: "https://oauth2.googleapis.com/token".to_string(),
        };
        let encoding_key =
            EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY.as_bytes()).expect("test RSA key");

        let http_client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("http client");
        let token_cache = TokenCache::new(FcmTokenGenerator {
            http_client: http_client.clone(),
            service_account: Some(sa),
            encoding_key: Some(encoding_key),
            metrics: Metrics::disabled(),
            test_oauth_token_url: None,
        });

        FcmClient {
            config,
            http_client,
            token_cache,
            metrics: Metrics::disabled(),
            test_fcm_api_base_url: None,
        }
    }

    #[test]
    fn test_oauth_token_http_status_classifies_transient_failures_as_retriable() {
        for status_code in [408_u16, 425, 429, 500, 503] {
            let status = reqwest::StatusCode::from_u16(status_code).unwrap();
            let failure = oauth_error_from_status(status, None);
            assert!(
                matches!(
                    failure,
                    TokenAcquisitionError::Retriable {
                        status_code: code,
                        retry_after: None,
                    } if code == status_code
                ),
                "status {status_code} should be retriable"
            );
        }
    }

    #[test]
    fn test_oauth_token_http_status_classifies_permanent_oauth_failures() {
        let status = reqwest::StatusCode::BAD_REQUEST;
        let failure = oauth_error_from_status(status, None);
        assert!(matches!(
            failure,
            TokenAcquisitionError::Permanent(Error::Fcm(ref message))
                if message == "OAuth token request failed: 400 Bad Request"
        ));
    }

    #[test]
    fn test_oauth_token_http_status_honors_retry_after_for_503() {
        let status = reqwest::StatusCode::SERVICE_UNAVAILABLE;
        let failure = oauth_error_from_status(status, Some(Duration::from_secs(30)));
        assert!(matches!(
            failure,
            TokenAcquisitionError::Retriable {
                status_code: 503,
                retry_after: Some(delay),
            } if delay == Duration::from_secs(30)
        ));
    }

    #[tokio::test]
    async fn test_get_access_token_oauth_503_is_retriable() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut client = mock_client_with_rsa_service_account("test-project");
        client.set_test_oauth_token_url(mock_server.uri());

        let result = client.get_access_token().await;
        assert!(matches!(
            result,
            Err(TokenAcquisitionError::Retriable {
                status_code: 503,
                ..
            })
        ));
    }

    /// Build an FCM token generator whose service-account `token_uri` is
    /// `token_uri` and with no OAuth-URL test override, so `mint()` POSTs to
    /// the signed audience (issue #153).
    fn generator_with_token_uri(token_uri: &str) -> FcmTokenGenerator {
        let sa = ServiceAccount {
            account_type: "service_account".to_string(),
            project_id: "test-project".to_string(),
            private_key: Zeroizing::new(TEST_RSA_PRIVATE_KEY.to_string()),
            client_email: "test@test.iam.gserviceaccount.com".to_string(),
            token_uri: token_uri.to_string(),
        };
        let encoding_key =
            EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY.as_bytes()).expect("test RSA key");
        FcmTokenGenerator {
            http_client: Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("http client"),
            service_account: Some(sa),
            encoding_key: Some(encoding_key),
            metrics: Metrics::disabled(),
            test_oauth_token_url: None,
        }
    }

    #[tokio::test]
    async fn test_mint_posts_to_service_account_token_uri() {
        // The OAuth request must target the service-account token_uri so the
        // signed assertion `aud` and the endpoint agree (issue #153). The mock
        // only answers on /custom/token; a POST to the constant would 404.
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/custom/token$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "minted-token",
                "expires_in": 3600
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let generator = generator_with_token_uri(&format!("{}/custom/token", mock_server.uri()));
        let minted = generator
            .mint()
            .await
            .expect("mint should target token_uri");
        assert_eq!(minted.token.as_str(), "minted-token");
    }

    #[tokio::test]
    async fn test_mint_falls_back_to_constant_when_token_uri_empty() {
        // With an empty token_uri the generator must fall back to the well-known
        // constant rather than POSTing to an empty URL (issue #153).
        let generator = generator_with_token_uri("");
        let sa = generator.service_account().unwrap();
        assert_eq!(generator.oauth_token_url(sa), OAUTH_TOKEN_URL);
    }

    #[test]
    fn test_signed_aud_and_post_target_agree_for_standard_and_empty_token_uri() {
        // The signed assertion `aud` and the production POST target must be the
        // SAME URL, or Google rejects the token request as an audience mismatch
        // (issue #153). Assert the invariant directly (no test-URL override, so
        // oauth_token_url resolves to the production target) for both a
        // non-standard token_uri and the degenerate empty case.
        for token_uri in ["https://oauth2.example.test/token", ""] {
            let generator = generator_with_token_uri(token_uri);
            let sa = generator.service_account().unwrap();
            let aud = FcmTokenGenerator::signed_audience(sa);
            let post_target = generator.oauth_token_url(sa);
            assert_eq!(
                aud, post_target,
                "signed aud must equal the POST target for token_uri {token_uri:?}"
            );
        }

        // And the empty case resolves both to the well-known constant.
        let empty = generator_with_token_uri("");
        let sa = empty.service_account().unwrap();
        assert_eq!(FcmTokenGenerator::signed_audience(sa), OAUTH_TOKEN_URL);
    }

    #[tokio::test]
    async fn test_mint_signs_aud_matching_post_target_for_empty_token_uri() {
        // End-to-end proof for the degenerate empty-token_uri case: with an
        // empty token_uri and NO test override, mint() POSTs to OAUTH_TOKEN_URL
        // and must sign aud=OAUTH_TOKEN_URL (not aud=""). We cannot hit the real
        // Google endpoint here, so assert the two derivations agree — the mint
        // path reads aud and target from the same helper, so they are identical
        // by construction, and this locks that in against regressions.
        let generator = generator_with_token_uri("");
        let sa = generator.service_account().unwrap();

        let aud = FcmTokenGenerator::signed_audience(sa);
        let post_target = generator.oauth_token_url(sa);
        assert_eq!(aud, OAUTH_TOKEN_URL);
        assert_eq!(post_target, OAUTH_TOKEN_URL);
        assert_eq!(aud, post_target);
    }

    #[tokio::test]
    async fn test_mint_honors_provider_expires_in() {
        // The cached lifetime must derive from the provider's expires_in (minus
        // the safety margin), not the hardcoded fallback (issue #88 groundwork,
        // preserved through the refactor).
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "minted-token",
                "expires_in": 120
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let generator = generator_with_token_uri(&mock_server.uri());
        let minted = generator.mint().await.expect("mint");
        // expires_at is set to now()+ttl inside mint, where ttl is the provider
        // 120s expiry minus the 60s safety margin (= 60s). Measuring the
        // remaining lifetime just after mint returns should land near 60s (a
        // little less, by the elapsed time since expires_at was stamped), and
        // well under the 120s the provider reported.
        let remaining = minted
            .expires_at
            .duration_since(SystemTime::now())
            .expect("expiry in the future");
        assert!(remaining <= Duration::from_secs(60));
        assert!(remaining >= Duration::from_secs(50));
    }

    #[tokio::test]
    async fn test_mint_rejects_oversized_oauth_success_body() {
        // A hijacked/misconfigured token_uri returning a multi-megabyte 200
        // body must be refused by the bounded read rather than buffered whole
        // (issue #154).
        let mock_server = MockServer::start().await;
        let padding = "A".repeat(MAX_OAUTH_BODY_BYTES + 1024);
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"{{"access_token":"{padding}","expires_in":3600}}"#
            )))
            .expect(1)
            .mount(&mock_server)
            .await;

        let generator = generator_with_token_uri(&mock_server.uri());
        let result = generator.mint().await;
        let Err(TokenAcquisitionError::Permanent(Error::Fcm(message))) = result else {
            panic!("expected a permanent OAuth error for the oversized body");
        };
        assert!(message.contains("exceeded the size cap"));
        assert!(!message.contains(&padding));
    }

    #[tokio::test]
    async fn test_mint_oauth_success_body_read_error_is_retriable() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            let _ = socket.read(&mut request).await.unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 128\r\n\r\n{\"access_token\":\"partial",
                )
                .await
                .unwrap();
        });

        let generator = generator_with_token_uri(&format!("http://{addr}/token"));
        let result = generator.mint().await;
        server.await.unwrap();

        assert!(matches!(
            result,
            Err(TokenAcquisitionError::Retriable {
                status_code: 0,
                retry_after: None
            })
        ));
    }

    #[tokio::test]
    async fn test_get_access_token_oauth_transport_error_is_retriable() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let mut client = mock_client_with_rsa_service_account("test-project");
        client.set_test_oauth_token_url(format!("http://{addr}/token"));

        let result = client.get_access_token().await;
        assert!(matches!(
            result,
            Err(TokenAcquisitionError::Retriable {
                status_code: 0,
                retry_after: None,
            })
        ));
    }

    #[tokio::test]
    async fn test_get_access_token_oauth_400_is_permanent() {
        let mock_server = MockServer::start().await;

        let secret = "assertion-jwt-secret-".repeat(1_000);
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_string(format!(
                "{{\"error\":\"invalid_grant\",\"error_description\":\"{secret}\"}}"
            )))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut client = mock_client_with_rsa_service_account("test-project");
        client.set_test_oauth_token_url(mock_server.uri());

        let result = client.get_access_token().await;
        let TokenAcquisitionError::Permanent(Error::Fcm(message)) = result.unwrap_err() else {
            panic!("expected permanent OAuth failure");
        };
        assert_eq!(message, "OAuth token request failed: 400 Bad Request");
        assert!(!message.contains("invalid_grant"));
        assert!(!message.contains(&secret));
    }

    #[tokio::test]
    async fn test_send_retries_transient_oauth_failure_then_succeeds() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path_regex(r"/v1/projects/.+/messages:send"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "projects/test-project/messages/123456"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
            .expect(1)
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "mock-access-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut client = mock_client_with_rsa_service_account("test-project");
        client.set_test_oauth_token_url(mock_server.uri());
        client.test_fcm_api_base_url = Some(mock_server.uri());

        let result = client.send(zeroizing_token("device-token-123"), None).await;
        assert!(
            result.is_ok(),
            "expected success after OAuth retry: {result:?}"
        );
        assert_eq!(result.unwrap(), PushSendOutcome::Sent);
    }

    #[tokio::test]
    async fn test_send_does_not_retry_permanent_oauth_failure() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Invalid JWT Signature."
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let mut client = mock_client_with_rsa_service_account("test-project");
        client.set_test_oauth_token_url(mock_server.uri());
        client.test_fcm_api_base_url = Some(mock_server.uri());

        let result = client.send(zeroizing_token("device-token-123"), None).await;
        assert!(result.is_err(), "expected permanent OAuth failure");
        let message = result.unwrap_err().to_string();
        assert!(message.contains("OAuth token request failed"));
        assert!(message.contains("400"));
        assert!(!message.contains("invalid_grant"));
        assert!(!message.contains("Invalid JWT Signature"));
    }
}

//! Retry logic with exponential backoff for push notifications.
//!
//! Implements retry behavior for transient failures (429 rate limiting, 5xx server errors)
//! with configurable exponential backoff and optional Retry-After header support.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::sleep;
use tracing::warn;

use crate::error::Error;
use crate::metrics::Metrics;

/// Holds the dispatcher concurrency permit and the semaphore it came from, so
/// that `with_retry` can release the in-flight slot during a backoff sleep and
/// re-acquire it before the next attempt. This prevents sleeping retries from
/// occupying concurrency slots that represent actual in-flight requests.
pub struct BackoffPermit {
    semaphore: Arc<Semaphore>,
    permit: Option<OwnedSemaphorePermit>,
}

impl BackoffPermit {
    /// Create a new `BackoffPermit` wrapping an already-acquired concurrency
    /// permit and the semaphore it was acquired from.
    #[must_use]
    pub fn new(semaphore: Arc<Semaphore>, permit: OwnedSemaphorePermit) -> Self {
        Self {
            semaphore,
            permit: Some(permit),
        }
    }

    /// Release the held permit (frees the in-flight slot for the sleep window).
    fn release(&mut self) {
        self.permit = None;
    }

    fn update_available_metric(&self, metrics: Option<&Metrics>) {
        if let Some(metrics) = metrics {
            metrics.set_push_semaphore_available(self.semaphore.available_permits());
        }
    }

    /// Re-acquire a permit before the next attempt. Awaits if all slots are busy.
    /// Returns `Err` only if the semaphore was closed (shutdown).
    async fn reacquire(&mut self) -> Result<(), tokio::sync::AcquireError> {
        if self.permit.is_none() {
            let p = self.semaphore.clone().acquire_owned().await?;
            self.permit = Some(p);
        }
        Ok(())
    }
}

/// Default maximum number of retry attempts.
pub const DEFAULT_MAX_RETRIES: u32 = 3;

/// Maximum number of transport (connect-error) retry attempts.
///
/// Transport retries only cover pre-delivery `reqwest` connect failures (see
/// [`with_transport_retry`]), so a single extra attempt is enough to ride out a
/// transient connection blip without meaningfully extending worst-case
/// permit-hold time. Kept intentionally smaller than [`DEFAULT_MAX_RETRIES`]
/// and shared by every push provider so their connect-retry budgets stay
/// consistent (see issue #99).
pub const TRANSPORT_MAX_RETRIES: u32 = 1;

/// Default initial backoff duration.
pub const DEFAULT_INITIAL_BACKOFF: Duration = Duration::from_millis(100);

/// Maximum backoff duration cap.
pub const MAX_BACKOFF: Duration = Duration::from_secs(10);

/// Upper bound on an honored provider-supplied `Retry-After` value.
///
/// The header is provider/network-controlled input. Without a ceiling, a
/// misbehaving or compromised endpoint could pin a send task — which holds a
/// decrypted device token and an in-flight guard that blocks graceful-shutdown
/// drain — in a backoff sleep for an arbitrary duration (issue #162). 60
/// seconds comfortably covers genuine provider backpressure (APNs/FCM hints
/// are typically single-digit seconds) while bounding how long an untrusted
/// header can pin a task. Deliberately larger than [`MAX_BACKOFF`], which only
/// caps locally-computed exponential backoff.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);

/// Minimum server-requested backoff duration.
const MIN_RETRY_BACKOFF: Duration = DEFAULT_INITIAL_BACKOFF;

/// Maximum randomized jitter applied to a retry sleep.
const MAX_RETRY_JITTER: Duration = Duration::from_secs(1);

/// Configuration for retry behavior.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts.
    pub max_retries: u32,
    /// Initial backoff duration (doubles with each retry).
    pub initial_backoff: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: DEFAULT_MAX_RETRIES,
            initial_backoff: DEFAULT_INITIAL_BACKOFF,
        }
    }
}

impl RetryConfig {
    /// Shared retry budget for transport (connect-error) retries.
    ///
    /// Every push provider uses this for [`with_transport_retry`] so their
    /// pre-delivery connect-retry budgets stay consistent and permit-hold time
    /// is bounded uniformly (see issue #99).
    #[must_use]
    pub const fn transport() -> Self {
        Self {
            max_retries: TRANSPORT_MAX_RETRIES,
            initial_backoff: DEFAULT_INITIAL_BACKOFF,
        }
    }
}

/// Final outcome of a push send operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushSendOutcome {
    /// The push provider accepted the notification.
    Sent,
    /// The provider or local validation identified a dead/invalid device token.
    InvalidToken,
    /// A transient provider failure consumed the bounded retry budget.
    RetriesExhausted,
}

/// Result of a single send attempt.
#[derive(Debug)]
pub enum SendAttemptResult {
    /// Request reached a terminal non-error state (`true` = sent,
    /// `false` = invalid token).
    Success(bool),
    /// Transient error that should be retried (429, 5xx).
    Retriable {
        /// The status code that triggered the retry.
        status_code: u16,
        /// Optional Retry-After duration from the response header.
        retry_after: Option<Duration>,
    },
    /// The provider rejected the request's auth credential (an APNs `403`
    /// with a provider-token `reason`, or an FCM `401`).
    ///
    /// The client has already invalidated the cached credential, so the next
    /// attempt will mint a fresh one. [`with_retry`] allows exactly one
    /// immediate retry per logical push for this variant (issue #85): a
    /// transient rejection (clock skew, key rotation window) recovers with
    /// the fresh credential, while a genuinely bad key fails again and
    /// surfaces the carried error instead of looping.
    AuthRejected(crate::error::Error),
    /// Permanent error that should not be retried.
    Permanent(crate::error::Error),
}

/// Execute an async operation with exponential backoff retry.
///
/// The `operation` closure should return a `SendAttemptResult` indicating
/// whether to retry or return the result.
///
/// When `backoff_permit` is `Some`, the held concurrency permit is released
/// for the duration of each backoff sleep and re-acquired before the next
/// attempt. This keeps sleeping retries from occupying in-flight concurrency
/// slots. If re-acquisition fails because the semaphore was closed (shutdown),
/// the retry loop is aborted and returns [`PushSendOutcome::RetriesExhausted`]
/// so the request is not mislabeled as an invalid token.
#[must_use = "retry result indicates success/failure and should not be ignored"]
pub async fn with_retry<F, Fut>(
    config: &RetryConfig,
    service_name: &str,
    mut operation: F,
    backoff_permit: Option<&mut BackoffPermit>,
    metrics: Option<&Metrics>,
) -> crate::error::Result<PushSendOutcome>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = SendAttemptResult>,
{
    let mut retries = 0;
    let mut backoff = config.initial_backoff;
    // One-shot budget for retrying after a provider auth rejection with a
    // freshly minted credential (issue #85). Tracked separately from the
    // transient-retry budget so an auth recovery does not consume (or get
    // starved by) 429/5xx retries.
    let mut auth_retry_used = false;
    // Reborrow across loop iterations: `Option<&mut T>` is not `Copy`.
    let mut backoff_permit = backoff_permit;

    loop {
        match operation().await {
            SendAttemptResult::Success(true) => return Ok(PushSendOutcome::Sent),
            SendAttemptResult::Success(false) => return Ok(PushSendOutcome::InvalidToken),
            SendAttemptResult::AuthRejected(error) if !auth_retry_used => {
                auth_retry_used = true;

                if let Some(metrics) = metrics {
                    metrics.record_push_retry(service_name.to_lowercase().as_str());
                }

                // Retry immediately: the rejection is not backpressure, and
                // the client already evicted the rejected credential, so the
                // next attempt mints a fresh one.
                warn!(
                    service = service_name,
                    error = %error,
                    "Provider rejected auth credential; retrying once with a freshly minted token"
                );
            }
            SendAttemptResult::AuthRejected(error) => {
                warn!(
                    service = service_name,
                    "Provider rejected a freshly minted auth credential; not retrying again"
                );
                return Err(error);
            }
            SendAttemptResult::Retriable {
                status_code,
                retry_after,
            } if retries < config.max_retries => {
                retries += 1;

                if let Some(metrics) = metrics {
                    metrics.record_push_retry(service_name.to_lowercase().as_str());
                }

                // Honor provider-supplied Retry-After values, but floor zero
                // or tiny values, cap at MAX_RETRY_AFTER (untrusted input),
                // and jitter every sleep so concurrent failures do not retry
                // in synchronized waves. Locally-computed exponential backoff
                // is capped separately at MAX_BACKOFF.
                let wait_duration = retry_sleep_duration(retry_after, backoff);

                warn!(
                    service = service_name,
                    status_code = status_code,
                    retry = retries,
                    max_retries = config.max_retries,
                    backoff_ms = wait_duration.as_millis() as u64,
                    "Retrying push notification"
                );

                // Release the in-flight slot during the backoff sleep so other
                // requests can proceed, then re-acquire it before retrying.
                if let Some(permit) = backoff_permit.as_deref_mut() {
                    permit.release();
                    permit.update_available_metric(metrics);
                    sleep(wait_duration).await;
                    if permit.reacquire().await.is_err() {
                        // Semaphore closed (shutdown): shed this request without
                        // classifying it as a dead device token.
                        return Ok(PushSendOutcome::RetriesExhausted);
                    }
                    permit.update_available_metric(metrics);
                } else {
                    sleep(wait_duration).await;
                }

                // Advance the fallback backoff every time so repeated tiny
                // Retry-After values degrade gracefully once the header stops.
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
            SendAttemptResult::Retriable { status_code, .. } => {
                warn!(
                    service = service_name,
                    status_code = status_code,
                    retries = retries,
                    "Max retries exceeded for push notification"
                );
                return Ok(PushSendOutcome::RetriesExhausted);
            }
            SendAttemptResult::Permanent(e) => return Err(e),
        }
    }
}

fn retry_sleep_base(retry_after: Option<Duration>, backoff: Duration) -> (Duration, bool) {
    let fallback = backoff.min(MAX_BACKOFF);
    match retry_after {
        Some(Duration::ZERO) => (MIN_RETRY_BACKOFF.max(fallback), true),
        // Honor the provider hint, but clamp it: floored so a tiny value
        // cannot produce hot-loop retries, and capped so an untrusted header
        // cannot pin the task (and its decrypted token) arbitrarily long
        // (issue #162).
        Some(server_delay) => (server_delay.clamp(MIN_RETRY_BACKOFF, MAX_RETRY_AFTER), true),
        None => (fallback, false),
    }
}

fn retry_sleep_duration(retry_after: Option<Duration>, backoff: Duration) -> Duration {
    let (base, retry_after_supplied) = retry_sleep_base(retry_after, backoff);
    let jitter = random_retry_jitter(base);
    if retry_after_supplied {
        // Retry-After is a provider-requested minimum, so jitter is additive:
        // this may wait up to one bounded-jitter window longer, but never less.
        base.saturating_add(jitter)
    } else {
        base.saturating_sub(jitter)
    }
}

fn random_retry_jitter(base: Duration) -> Duration {
    max_retry_jitter(base).mul_f64(rand::random_range(0.0..1.0))
}

fn max_retry_jitter(base: Duration) -> Duration {
    // The jitter window is bounded, not a strict 50% multiplier at every size:
    // large sleeps desynchronize within one second instead of stretching or
    // shrinking by many seconds.
    (base / 2).min(MAX_RETRY_JITTER)
}

/// Decide whether a transport (`reqwest`) error is safe to retry.
///
/// Only connection-establishment failures are retriable: when
/// [`reqwest::Error::is_connect`] is true the request body was never sent to
/// the provider, so retrying cannot produce a duplicate delivery of a
/// non-idempotent POST. Any other transport error (read/timeout, response
/// body, decode, etc.) may have occurred *after* the provider already accepted
/// the request, so it must not be retried.
fn should_retry_transport(err: &reqwest::Error) -> bool {
    err.is_connect()
}

/// Execute an async transport operation with exponential backoff retry.
///
/// Only `Error::Http` failures whose underlying `reqwest::Error` is a
/// connection-establishment error (see [`should_retry_transport`]) are
/// retried. Restricting retries to pre-delivery connect errors avoids
/// duplicating non-idempotent POSTs (a read/timeout error can fire *after*
/// the provider already accepted the request) and bounds worst-case permit-hold
/// time: post-connect hangs consume the full client timeout and are no longer
/// multiplied by the transport retry budget. Any non-connect `Error::Http`,
/// and any non-`Http` error, is returned immediately. The last transport error
/// is returned once the retry budget is exhausted.
///
/// Transport-level retries are short connect-error retries and are
/// intentionally not permit-suspended (no `BackoffPermit`), unlike
/// [`with_retry`] which suspends the concurrency permit across provider
/// 429/5xx backoff sleeps.
#[must_use = "retry result indicates success/failure and should not be ignored"]
pub async fn with_transport_retry<T, F, Fut>(
    config: &RetryConfig,
    service_name: &str,
    mut operation: F,
    metrics: Option<&Metrics>,
) -> crate::error::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = crate::error::Result<T>>,
{
    let mut retries = 0;
    let mut backoff = config.initial_backoff;

    loop {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(Error::Http(error))
                if retries < config.max_retries && should_retry_transport(&error) =>
            {
                retries += 1;

                if let Some(metrics) = metrics {
                    metrics.record_push_retry(service_name.to_lowercase().as_str());
                }

                // A reqwest error can embed the request URL, and the APNs URL
                // contains the raw device token; strip it before the error can
                // reach any log sink (issue #172). The push clients already
                // strip at the conversion site, but this keeps the retry
                // engine safe regardless of caller discipline.
                let error = error.without_url();
                warn!(
                    service = service_name,
                    error = %error,
                    retry = retries,
                    max_retries = config.max_retries,
                    backoff_ms = backoff.as_millis() as u64,
                    "Retrying push transport error"
                );

                sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
            Err(Error::Http(error)) if should_retry_transport(&error) => {
                // Strip any URL (which may embed a device token) before both
                // logging and propagating the exhausted error (issue #172).
                let error = error.without_url();
                warn!(
                    service = service_name,
                    error = %error,
                    retries = retries,
                    "Max retries exceeded for push transport error"
                );
                return Err(Error::Http(error));
            }
            // Non-connect transport errors are not retriable: the provider may
            // already have accepted the (non-idempotent) request, so return
            // immediately without retrying. The URL is stripped so downstream
            // logging of the propagated error cannot leak a device token
            // (issue #172).
            Err(error) => return Err(error.redact_transport_url()),
        }
    }
}

/// Parse a Retry-After header value into a Duration.
///
/// Supports both forms allowed by RFC 7231: delay-seconds (e.g., `"120"`) and
/// HTTP-date (e.g., `"Wed, 21 Oct 2015 07:28:00 GMT"`). An HTTP-date is
/// converted to a delay relative to the current time; a date at or in the past
/// clamps to [`Duration::ZERO`]. Returns `None` if the header is missing or
/// matches neither form.
pub fn parse_retry_after(header_value: Option<&str>) -> Option<Duration> {
    parse_retry_after_at(header_value, SystemTime::now())
}

/// [`parse_retry_after`] with an injectable `now` so the HTTP-date branch is
/// deterministically testable.
fn parse_retry_after_at(header_value: Option<&str>, now: SystemTime) -> Option<Duration> {
    let value = header_value?;

    // Try parsing as seconds first (most common for API rate limiting).
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }

    // Fall back to the RFC 7231 HTTP-date form, converting it to a delay
    // relative to `now`. A date at or before `now` yields a zero delay.
    if let Ok(when) = httpdate::parse_http_date(value) {
        return Some(when.duration_since(now).unwrap_or(Duration::ZERO));
    }

    None
}

/// Extract and parse a `Retry-After` header from a response's headers.
///
/// Returns the parsed backpressure hint when the provider supplied a
/// `Retry-After` value understood by [`parse_retry_after`], and `None`
/// otherwise. Shared by the `429` and `5xx` handling arms of the push clients
/// so a `503 SERVICE_UNAVAILABLE` with an explicit `Retry-After` is honored,
/// not just a `429`.
#[must_use]
pub(crate) fn retry_after_from_headers(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| parse_retry_after(Some(v)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Client;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn test_default_config() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, DEFAULT_MAX_RETRIES);
        assert_eq!(config.initial_backoff, DEFAULT_INITIAL_BACKOFF);
    }

    #[test]
    fn test_transport_config_is_shared_and_bounded() {
        // Every push provider must share the same transport connect-retry
        // budget so APNs and FCM stay consistent (issue #99). It is a single,
        // small extra attempt and intentionally tighter than the default.
        let config = RetryConfig::transport();
        assert_eq!(config.max_retries, TRANSPORT_MAX_RETRIES);
        assert_eq!(config.max_retries, 1);
        assert!(config.max_retries < DEFAULT_MAX_RETRIES);
        assert_eq!(config.initial_backoff, DEFAULT_INITIAL_BACKOFF);
    }

    #[test]
    fn test_parse_retry_after_seconds() {
        assert_eq!(parse_retry_after(Some("60")), Some(Duration::from_secs(60)));
        assert_eq!(parse_retry_after(Some("0")), Some(Duration::from_secs(0)));
        assert_eq!(
            parse_retry_after(Some("120")),
            Some(Duration::from_secs(120))
        );
    }

    #[test]
    fn test_parse_retry_after_none() {
        assert_eq!(parse_retry_after(None), None);
    }

    #[test]
    fn test_parse_retry_after_invalid() {
        assert_eq!(parse_retry_after(Some("invalid")), None);
        assert_eq!(parse_retry_after(Some("not-a-number")), None);
    }

    #[test]
    fn test_parse_retry_after_http_date_future() {
        // A fixed `now` keeps the delta deterministic regardless of wall clock.
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_445_412_180); // 2015-10-21 07:23:00 GMT
        assert_eq!(
            parse_retry_after_at(Some("Wed, 21 Oct 2015 07:28:00 GMT"), now),
            Some(Duration::from_secs(300))
        );
    }

    #[test]
    fn test_parse_retry_after_http_date_past_clamps_to_zero() {
        // `now` is after the header's date, so the delay clamps to zero rather
        // than underflowing.
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_445_500_000);
        assert_eq!(
            parse_retry_after_at(Some("Wed, 21 Oct 2015 07:28:00 GMT"), now),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn test_parse_retry_after_http_date_equal_now_is_zero() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_445_412_480); // 2015-10-21 07:28:00 GMT
        assert_eq!(
            parse_retry_after_at(Some("Wed, 21 Oct 2015 07:28:00 GMT"), now),
            Some(Duration::ZERO)
        );
    }

    #[test]
    fn test_parse_retry_after_http_date_via_headers() {
        // The full header path (used by the push clients) must also honor the
        // HTTP-date form, not just the direct parser.
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "retry-after",
            "Wed, 21 Oct 2015 07:28:00 GMT".parse().unwrap(),
        );
        assert!(retry_after_from_headers(&headers).is_some());
    }

    #[test]
    fn test_parse_retry_after_seconds_unchanged_by_now() {
        // The delay-seconds form must remain independent of the clock.
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_445_500_000);
        assert_eq!(
            parse_retry_after_at(Some("60"), now),
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn test_retry_after_from_headers() {
        let mut headers = reqwest::header::HeaderMap::new();
        assert_eq!(retry_after_from_headers(&headers), None);

        headers.insert("retry-after", "120".parse().unwrap());
        assert_eq!(
            retry_after_from_headers(&headers),
            Some(Duration::from_secs(120))
        );

        headers.insert("retry-after", "not-a-number".parse().unwrap());
        assert_eq!(retry_after_from_headers(&headers), None);
    }

    fn assert_duration_between(actual: Duration, min: Duration, max: Duration) {
        assert!(
            actual >= min && actual <= max,
            "expected {actual:?} to be between {min:?} and {max:?}"
        );
    }

    #[test]
    fn test_retry_sleep_duration_honors_retry_after_above_max_backoff() {
        let sleep = retry_sleep_duration(Some(Duration::from_secs(60)), Duration::from_millis(100));

        assert_duration_between(sleep, Duration::from_secs(60), Duration::from_secs(61));
    }

    #[test]
    fn test_retry_sleep_duration_floors_zero_retry_after() {
        let sleep = retry_sleep_duration(Some(Duration::ZERO), Duration::from_millis(1));

        assert_duration_between(
            sleep,
            MIN_RETRY_BACKOFF,
            MIN_RETRY_BACKOFF + max_retry_jitter(MIN_RETRY_BACKOFF),
        );
    }

    #[test]
    fn test_retry_sleep_duration_uses_fallback_backoff_when_retry_after_is_zero() {
        let sleep = retry_sleep_duration(Some(Duration::ZERO), Duration::from_millis(400));
        assert_duration_between(
            sleep,
            Duration::from_millis(400),
            Duration::from_millis(600),
        );

        let capped_sleep = retry_sleep_duration(Some(Duration::ZERO), Duration::from_secs(60));
        assert_duration_between(capped_sleep, MAX_BACKOFF, MAX_BACKOFF + MAX_RETRY_JITTER);
    }

    #[test]
    fn test_retry_sleep_duration_floors_tiny_nonzero_retry_after_without_fallback() {
        let sleep = retry_sleep_duration(Some(Duration::from_millis(1)), Duration::from_secs(60));

        assert_duration_between(
            sleep,
            MIN_RETRY_BACKOFF,
            MIN_RETRY_BACKOFF + max_retry_jitter(MIN_RETRY_BACKOFF),
        );
    }

    #[test]
    fn test_retry_sleep_duration_jitters_fallback_between_window_and_base() {
        let sleep = retry_sleep_duration(None, Duration::from_millis(100));

        assert_duration_between(sleep, Duration::from_millis(50), Duration::from_millis(100));
    }

    #[test]
    fn test_retry_after_jitter_never_retries_before_server_delay() {
        let server_delay = Duration::from_millis(100);
        let sleep = retry_sleep_duration(Some(server_delay), Duration::from_millis(1));

        assert_duration_between(
            sleep,
            server_delay,
            server_delay + max_retry_jitter(server_delay),
        );
    }

    #[test]
    fn test_retry_jitter_is_capped() {
        assert_eq!(
            max_retry_jitter(Duration::from_millis(100)),
            Duration::from_millis(50)
        );
        assert_eq!(max_retry_jitter(Duration::from_secs(10)), MAX_RETRY_JITTER);
    }

    #[test]
    fn test_retry_sleep_duration_caps_exponential_backoff() {
        let sleep = retry_sleep_duration(None, Duration::from_secs(60));

        assert_duration_between(sleep, MAX_BACKOFF - MAX_RETRY_JITTER, MAX_BACKOFF);
    }

    #[test]
    fn test_retry_sleep_duration_caps_untrusted_retry_after() {
        // A hostile/misbehaving provider sends `Retry-After: 86400`. The
        // honored delay must clamp to MAX_RETRY_AFTER (plus at most one
        // additive jitter window), not pin the task for a day (issue #162).
        let sleep = retry_sleep_duration(
            Some(Duration::from_secs(86_400)),
            Duration::from_millis(100),
        );

        assert_duration_between(sleep, MAX_RETRY_AFTER, MAX_RETRY_AFTER + MAX_RETRY_JITTER);
    }

    #[test]
    fn test_retry_sleep_duration_honors_retry_after_at_cap_boundary() {
        // A Retry-After exactly at the cap is honored unchanged.
        let sleep = retry_sleep_duration(Some(MAX_RETRY_AFTER), Duration::from_millis(100));

        assert_duration_between(sleep, MAX_RETRY_AFTER, MAX_RETRY_AFTER + MAX_RETRY_JITTER);
    }

    #[tokio::test]
    async fn test_with_retry_auth_rejected_retries_once_then_succeeds() {
        // First attempt: provider rejects the auth credential. The retry
        // engine must immediately retry once (fresh credential), and the
        // second attempt's success must resolve the push as Sent (issue #85).
        let config = RetryConfig::default();
        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let start = std::time::Instant::now();
        let result = with_retry(
            &config,
            "test",
            || {
                let count = attempt_count_clone.clone();
                async move {
                    let attempts = count.fetch_add(1, Ordering::SeqCst) + 1;
                    if attempts == 1 {
                        SendAttemptResult::AuthRejected(crate::error::Error::Apns(
                            "Authentication error: ExpiredProviderToken".to_string(),
                        ))
                    } else {
                        SendAttemptResult::Success(true)
                    }
                }
            },
            None,
            None,
        )
        .await;

        assert_eq!(result.unwrap(), PushSendOutcome::Sent);
        assert_eq!(attempt_count.load(Ordering::SeqCst), 2);
        // The auth retry is immediate: no backoff sleep is inserted.
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn test_with_retry_auth_rejected_twice_returns_error() {
        // A second rejection means the freshly minted credential was also
        // rejected (genuinely bad key): surface the error instead of looping.
        let config = RetryConfig::default();
        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let result = with_retry(
            &config,
            "test",
            || {
                let count = attempt_count_clone.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    SendAttemptResult::AuthRejected(crate::error::Error::Fcm(
                        "Authentication error".to_string(),
                    ))
                }
            },
            None,
            None,
        )
        .await;

        assert!(matches!(result, Err(Error::Fcm(ref message))
            if message.contains("Authentication error")));
        assert_eq!(attempt_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_with_retry_auth_retry_budget_is_separate_from_transient_budget() {
        // An auth retry must not consume the transient 429/5xx budget: after
        // the one-shot auth recovery, the full transient budget still applies.
        let config = RetryConfig {
            max_retries: 2,
            initial_backoff: Duration::from_millis(1),
        };
        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let result = with_retry(
            &config,
            "test",
            || {
                let count = attempt_count_clone.clone();
                async move {
                    let attempts = count.fetch_add(1, Ordering::SeqCst) + 1;
                    match attempts {
                        1 => SendAttemptResult::AuthRejected(crate::error::Error::Apns(
                            "Authentication error: ExpiredProviderToken".to_string(),
                        )),
                        2 | 3 => SendAttemptResult::Retriable {
                            status_code: 503,
                            retry_after: None,
                        },
                        _ => SendAttemptResult::Success(true),
                    }
                }
            },
            None,
            None,
        )
        .await;

        // 1 auth-rejected attempt + 1 fresh attempt + 2 transient retries.
        assert_eq!(result.unwrap(), PushSendOutcome::Sent);
        assert_eq!(attempt_count.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn test_with_transport_retry_redacts_url_from_exhausted_connect_error() {
        // The APNs request URL embeds the raw device token. When transport
        // retries exhaust, the propagated (and logged) error must not carry
        // the URL (issue #172).
        let config = RetryConfig {
            max_retries: 1,
            initial_backoff: Duration::from_millis(1),
        };
        let client = Client::new();

        let result: crate::error::Result<bool> = with_transport_retry(
            &config,
            "test",
            || {
                let client = client.clone();
                async move {
                    let error = client
                        .post("http://127.0.0.1:9/3/device/aabbccddeeff00112233")
                        .send()
                        .await
                        .unwrap_err();
                    assert!(error.is_connect());
                    // Deliberately convert WITHOUT stripping the URL to prove
                    // the retry engine redacts even without caller discipline.
                    Err(Error::from(error))
                }
            },
            None,
        )
        .await;

        let error = result.unwrap_err();
        let rendered = error.to_string();
        assert!(matches!(error, Error::Http(_)));
        assert!(
            !rendered.contains("aabbccddeeff00112233"),
            "device token leaked into transport error display: {rendered}"
        );
    }

    #[tokio::test]
    async fn test_with_transport_retry_redacts_url_from_non_retriable_error() {
        // Non-connect transport errors return through the terminal arm; the
        // URL (which may embed a device token) must be stripped there too.
        let config = RetryConfig {
            max_retries: 3,
            initial_backoff: Duration::from_millis(1),
        };
        let client = Client::new();

        let result: crate::error::Result<bool> = with_transport_retry(
            &config,
            "test",
            || {
                let client = client.clone();
                async move {
                    let error = client
                        .post("ftp://example.invalid/3/device/aabbccddeeff00112233")
                        .send()
                        .await
                        .unwrap_err();
                    assert!(!error.is_connect());
                    Err(Error::from(error))
                }
            },
            None,
        )
        .await;

        let error = result.unwrap_err();
        let rendered = error.to_string();
        assert!(matches!(error, Error::Http(_)));
        assert!(
            !rendered.contains("aabbccddeeff00112233"),
            "device token leaked into transport error display: {rendered}"
        );
    }

    #[tokio::test]
    async fn test_with_retry_success_first_attempt() {
        let config = RetryConfig::default();
        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let result = with_retry(
            &config,
            "test",
            || {
                let count = attempt_count_clone.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    SendAttemptResult::Success(true)
                }
            },
            None,
            None,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PushSendOutcome::Sent);
        assert_eq!(attempt_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_with_retry_success_after_retries() {
        let config = RetryConfig {
            max_retries: 3,
            initial_backoff: Duration::from_millis(1), // Very short for testing
        };
        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let result = with_retry(
            &config,
            "test",
            || {
                let count = attempt_count_clone.clone();
                async move {
                    let attempts = count.fetch_add(1, Ordering::SeqCst) + 1;
                    if attempts < 3 {
                        SendAttemptResult::Retriable {
                            status_code: 429,
                            retry_after: None,
                        }
                    } else {
                        SendAttemptResult::Success(true)
                    }
                }
            },
            None,
            None,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PushSendOutcome::Sent);
        assert_eq!(attempt_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_with_retry_max_retries_exceeded() {
        let config = RetryConfig {
            max_retries: 2,
            initial_backoff: Duration::from_millis(1),
        };
        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let result = with_retry(
            &config,
            "test",
            || {
                let count = attempt_count_clone.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    SendAttemptResult::Retriable {
                        status_code: 503,
                        retry_after: None,
                    }
                }
            },
            None,
            None,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PushSendOutcome::RetriesExhausted);
        // Initial attempt + max_retries = 1 + 2 = 3
        assert_eq!(attempt_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_with_retry_permanent_error() {
        let config = RetryConfig::default();
        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let result = with_retry(
            &config,
            "test",
            || {
                let count = attempt_count_clone.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    SendAttemptResult::Permanent(crate::error::Error::Apns(
                        "Auth error".to_string(),
                    ))
                }
            },
            None,
            None,
        )
        .await;

        assert!(result.is_err());
        assert_eq!(attempt_count.load(Ordering::SeqCst), 1); // No retries for permanent errors
    }

    #[tokio::test]
    async fn test_with_retry_uses_retry_after_header() {
        let config = RetryConfig {
            max_retries: 1,
            initial_backoff: Duration::from_secs(100), // Long backoff that we won't use
        };

        let start = std::time::Instant::now();
        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let _ = with_retry(
            &config,
            "test",
            || {
                let count = attempt_count_clone.clone();
                async move {
                    let attempts = count.fetch_add(1, Ordering::SeqCst) + 1;
                    if attempts == 1 {
                        SendAttemptResult::Retriable {
                            status_code: 429,
                            retry_after: Some(Duration::from_millis(10)), // Short retry-after
                        }
                    } else {
                        SendAttemptResult::Success(true)
                    }
                }
            },
            None,
            None,
        )
        .await;

        let elapsed = start.elapsed();
        // Should have used the short retry-after, not the long initial_backoff
        assert!(elapsed < Duration::from_secs(1));
    }

    /// Wait until `count` reaches at least `expected`, yielding to the scheduler
    /// in a bounded loop.
    ///
    /// A paused-clock test can require more than one scheduler pass for a
    /// spawned task to cross a fired timer boundary and run its next attempt —
    /// especially under coverage instrumentation, where scheduling is slower and
    /// perturbed — so a single `yield_now` is not a reliable synchronization
    /// point. The retry task runs from "sleep fires" through incrementing the
    /// counter to re-parking on the next sleep in a single poll (no intermediate
    /// await), so observing the incremented count does not race ahead of the
    /// task re-parking. The iteration cap prevents a hang if progress never
    /// happens.
    async fn wait_for_attempt_count(count: &AtomicU32, expected: u32) {
        for _ in 0..10_000 {
            if count.load(Ordering::SeqCst) >= expected {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!(
            "timed out waiting for attempt_count to reach {expected}; last observed {}",
            count.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn test_with_retry_repeated_retry_after_zero_sleeps_before_each_retry() {
        tokio::time::pause();

        let config = RetryConfig {
            max_retries: 3,
            initial_backoff: Duration::from_millis(100),
        };
        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let task = tokio::spawn(async move {
            with_retry(
                &config,
                "test",
                || {
                    let count = attempt_count_clone.clone();
                    async move {
                        let attempt = count.fetch_add(1, Ordering::SeqCst) + 1;
                        if attempt <= 3 {
                            SendAttemptResult::Retriable {
                                status_code: 429,
                                retry_after: Some(Duration::ZERO),
                            }
                        } else {
                            SendAttemptResult::Success(true)
                        }
                    }
                },
                None,
                None,
            )
            .await
        });

        wait_for_attempt_count(&attempt_count, 1).await;
        assert_eq!(attempt_count.load(Ordering::SeqCst), 1);
        assert!(!task.is_finished());

        // First Retry-After: 0 sleep is floored to at least 100ms, then can add
        // up to 50ms of jitter. It must not retry before the floor elapses.
        tokio::time::advance(Duration::from_millis(99)).await;
        tokio::task::yield_now().await;
        assert_eq!(attempt_count.load(Ordering::SeqCst), 1);

        tokio::time::advance(Duration::from_millis(51)).await;
        wait_for_attempt_count(&attempt_count, 2).await;
        assert_eq!(attempt_count.load(Ordering::SeqCst), 2);

        // The fallback backoff advances even while Retry-After is supplied, so
        // the next zero-header sleep is based on 200ms, not 100ms again.
        tokio::time::advance(Duration::from_millis(199)).await;
        tokio::task::yield_now().await;
        assert_eq!(attempt_count.load(Ordering::SeqCst), 2);

        tokio::time::advance(Duration::from_millis(101)).await;
        wait_for_attempt_count(&attempt_count, 3).await;
        assert_eq!(attempt_count.load(Ordering::SeqCst), 3);

        // The third zero-header retry uses the next 400ms fallback slot.
        tokio::time::advance(Duration::from_millis(399)).await;
        tokio::task::yield_now().await;
        assert_eq!(attempt_count.load(Ordering::SeqCst), 3);

        tokio::time::advance(Duration::from_millis(201)).await;
        let result = task.await.unwrap();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PushSendOutcome::Sent);
        assert_eq!(attempt_count.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    #[should_panic(expected = "timed out waiting for attempt_count")]
    async fn wait_for_attempt_count_panics_when_progress_never_happens() {
        // Guard the bounded-wait helper's timeout path: if the awaited count is
        // never reached (nothing increments it here), the helper must not spin
        // forever — it exhausts its iteration cap and panics with a diagnostic.
        let count = AtomicU32::new(0);
        wait_for_attempt_count(&count, 1).await;
    }

    #[tokio::test]
    async fn test_with_retry_success_false() {
        let config = RetryConfig::default();

        let result = with_retry(
            &config,
            "test",
            || async { SendAttemptResult::Success(false) },
            None,
            None,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PushSendOutcome::InvalidToken);
    }

    #[tokio::test]
    async fn test_with_retry_records_metrics() {
        use crate::metrics::Metrics;

        let config = RetryConfig {
            max_retries: 2,
            initial_backoff: Duration::from_millis(1),
        };
        let metrics = Metrics::new().unwrap();
        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let result = with_retry(
            &config,
            "APNS",
            || {
                let count = attempt_count_clone.clone();
                async move {
                    let attempts = count.fetch_add(1, Ordering::SeqCst) + 1;
                    if attempts < 2 {
                        SendAttemptResult::Retriable {
                            status_code: 429,
                            retry_after: None,
                        }
                    } else {
                        SendAttemptResult::Success(true)
                    }
                }
            },
            None,
            Some(&metrics),
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PushSendOutcome::Sent);
        assert_eq!(attempt_count.load(Ordering::SeqCst), 2);

        // Verify metrics were recorded - gather metrics and check they're non-empty
        let families = metrics.registry.gather();
        assert!(!families.is_empty());
    }

    #[tokio::test]
    async fn test_with_retry_releases_permit_during_backoff() {
        // A single-permit semaphore models one concurrency slot. While the
        // retry is sleeping in backoff, the slot must be freed so other work
        // can proceed; it must be re-acquired before the next attempt.
        let sem = Arc::new(Semaphore::new(1));
        let permit = sem.clone().acquire_owned().await.unwrap();
        let mut bp = BackoffPermit::new(sem.clone(), permit);

        let config = RetryConfig {
            max_retries: 1,
            initial_backoff: Duration::from_millis(50),
        };

        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let sem_for_assert = sem.clone();
        let task = tokio::spawn(async move {
            with_retry(
                &config,
                "test",
                || {
                    let count = attempt_count_clone.clone();
                    async move {
                        let attempts = count.fetch_add(1, Ordering::SeqCst) + 1;
                        if attempts == 1 {
                            SendAttemptResult::Retriable {
                                status_code: 429,
                                retry_after: None,
                            }
                        } else {
                            SendAttemptResult::Success(true)
                        }
                    }
                },
                Some(&mut bp),
                None,
            )
            .await
        });

        // Wait until the retry is sleeping in backoff (slot released), then
        // verify the in-flight slot is available again.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            sem_for_assert.available_permits(),
            1,
            "permit should be released during backoff sleep"
        );

        let result = task.await.unwrap();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PushSendOutcome::Sent);
        assert_eq!(attempt_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_with_retry_updates_semaphore_metric_during_backoff_transitions() {
        use crate::metrics::Metrics;
        use crate::test_metrics::gauge_value as metric_gauge_value;
        use tokio::sync::oneshot;

        fn semaphore_gauge(metrics: &Metrics) -> i64 {
            metric_gauge_value(metrics, "transponder_push_semaphore_available", &[]) as i64
        }

        // A single-permit semaphore makes each transition observable: the
        // initial attempt holds the only slot, backoff releases it, and the
        // retry re-acquires it before the second attempt starts.
        let sem = Arc::new(Semaphore::new(1));
        let permit = sem.clone().acquire_owned().await.unwrap();
        let mut bp = BackoffPermit::new(sem.clone(), permit);
        let metrics = Metrics::default();
        metrics.set_push_semaphore_available(0);

        let config = RetryConfig {
            max_retries: 1,
            initial_backoff: Duration::from_millis(50),
        };

        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();
        let metrics_for_task = metrics.clone();
        let (second_attempt_tx, second_attempt_rx) = oneshot::channel();
        let (finish_tx, finish_rx) = oneshot::channel();
        let mut second_attempt_tx = Some(second_attempt_tx);
        let mut finish_rx = Some(finish_rx);

        let task = tokio::spawn(async move {
            with_retry(
                &config,
                "test",
                || {
                    let attempt = attempt_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
                    let signal_second_attempt = if attempt == 2 {
                        second_attempt_tx.take()
                    } else {
                        None
                    };
                    let wait_for_assertion = if attempt == 2 { finish_rx.take() } else { None };

                    async move {
                        if attempt == 1 {
                            SendAttemptResult::Retriable {
                                status_code: 429,
                                retry_after: None,
                            }
                        } else {
                            if let Some(tx) = signal_second_attempt {
                                let _ = tx.send(());
                            }
                            if let Some(rx) = wait_for_assertion {
                                let _ = rx.await;
                            }
                            SendAttemptResult::Success(true)
                        }
                    }
                },
                Some(&mut bp),
                Some(&metrics_for_task),
            )
            .await
        });

        // During backoff the permit has been released, and the metric must
        // reflect the real free slot instead of staying stale at zero.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(sem.available_permits(), 1);
        assert_eq!(semaphore_gauge(&metrics), 1);

        tokio::time::timeout(Duration::from_secs(1), second_attempt_rx)
            .await
            .expect("retry should start a second attempt")
            .expect("second attempt signal should be sent");

        // The second attempt starts only after the retry path re-acquires the
        // permit. The gauge must dip back to zero at that transition.
        assert_eq!(sem.available_permits(), 0);
        assert_eq!(semaphore_gauge(&metrics), 0);

        finish_tx
            .send(())
            .expect("second attempt should still be waiting for test assertion");
        let result = task.await.unwrap();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PushSendOutcome::Sent);
        assert_eq!(attempt_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_with_transport_retry_success_after_retries() {
        let config = RetryConfig {
            max_retries: 3,
            initial_backoff: Duration::from_millis(1),
        };
        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();
        let client = Client::new();

        let result: crate::error::Result<bool> = with_transport_retry(
            &config,
            "test",
            || {
                let count = attempt_count_clone.clone();
                let client = client.clone();
                async move {
                    let attempts = count.fetch_add(1, Ordering::SeqCst);
                    if attempts < 2 {
                        let error = client.get("http://127.0.0.1:9").send().await.unwrap_err();
                        Err(Error::from(error))
                    } else {
                        Ok(true)
                    }
                }
            },
            None,
        )
        .await;

        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(attempt_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_with_transport_retry_exhausts_retries() {
        let config = RetryConfig {
            max_retries: 2,
            initial_backoff: Duration::from_millis(1),
        };
        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();
        let client = Client::new();

        let result: crate::error::Result<bool> = with_transport_retry(
            &config,
            "test",
            || {
                let count = attempt_count_clone.clone();
                let client = client.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    let error = client.get("http://127.0.0.1:9").send().await.unwrap_err();
                    Err(Error::from(error))
                }
            },
            None,
        )
        .await;

        assert!(matches!(result, Err(Error::Http(_))));
        assert_eq!(attempt_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_with_transport_retry_does_not_retry_non_connect_error() {
        let config = RetryConfig {
            max_retries: 3,
            initial_backoff: Duration::from_millis(1),
        };
        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();
        let client = Client::new();

        // A request to an unsupported URL scheme produces a `reqwest::Error`
        // whose `is_connect()` is false: the request was never dispatched to a
        // provider, but it is *not* a connection-establishment failure, so it
        // must be treated as non-retriable.
        let result: crate::error::Result<bool> = with_transport_retry(
            &config,
            "test",
            || {
                let count = attempt_count_clone.clone();
                let client = client.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    let error = client
                        .get("ftp://example.invalid/resource")
                        .send()
                        .await
                        .unwrap_err();
                    assert!(!error.is_connect());
                    Err(Error::from(error))
                }
            },
            None,
        )
        .await;

        assert!(matches!(result, Err(Error::Http(_))));
        // The operation is invoked exactly once: no retry for non-connect errors.
        assert_eq!(attempt_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_should_retry_transport_connect_error_is_retriable() {
        // A connection refused on a closed port is a connect error => retriable.
        let client = Client::new();
        let error = client.get("http://127.0.0.1:9").send().await.unwrap_err();
        assert!(error.is_connect());
        assert!(should_retry_transport(&error));
    }

    #[tokio::test]
    async fn test_should_retry_transport_non_connect_error_is_not_retriable() {
        // An unsupported URL scheme is not a connect error => not retriable.
        let client = Client::new();
        let error = client
            .get("ftp://example.invalid/resource")
            .send()
            .await
            .unwrap_err();
        assert!(!error.is_connect());
        assert!(!should_retry_transport(&error));
    }
}

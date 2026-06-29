//! Retry logic with exponential backoff for push notifications.
//!
//! Implements retry behavior for transient failures (429 rate limiting, 5xx server errors)
//! with configurable exponential backoff and optional Retry-After header support.

use std::sync::Arc;
use std::time::Duration;

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

/// Default initial backoff duration.
pub const DEFAULT_INITIAL_BACKOFF: Duration = Duration::from_millis(100);

/// Maximum backoff duration cap.
pub const MAX_BACKOFF: Duration = Duration::from_secs(10);

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

/// Result of a single send attempt.
#[derive(Debug)]
pub enum SendAttemptResult {
    /// Request succeeded.
    Success(bool),
    /// Transient error that should be retried (429, 5xx).
    Retriable {
        /// The status code that triggered the retry.
        status_code: u16,
        /// Optional Retry-After duration from the response header.
        retry_after: Option<Duration>,
    },
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
/// the retry loop is aborted and `Ok(false)` is returned (the request is shed).
#[must_use = "retry result indicates success/failure and should not be ignored"]
pub async fn with_retry<F, Fut>(
    config: &RetryConfig,
    service_name: &str,
    mut operation: F,
    backoff_permit: Option<&mut BackoffPermit>,
    metrics: Option<&Metrics>,
) -> crate::error::Result<bool>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = SendAttemptResult>,
{
    let mut retries = 0;
    let mut backoff = config.initial_backoff;
    // Reborrow across loop iterations: `Option<&mut T>` is not `Copy`.
    let mut backoff_permit = backoff_permit;

    loop {
        match operation().await {
            SendAttemptResult::Success(result) => return Ok(result),
            SendAttemptResult::Retriable {
                status_code,
                retry_after,
            } if retries < config.max_retries => {
                retries += 1;

                if let Some(metrics) = metrics {
                    metrics.record_push_retry(service_name.to_lowercase().as_str());
                }

                // Honor Retry-After exactly when the provider supplies one. Only cap
                // locally-computed exponential backoff to avoid runaway delays.
                let wait_duration = retry_wait_duration(retry_after, backoff);

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
                    sleep(wait_duration).await;
                    if permit.reacquire().await.is_err() {
                        // Semaphore closed (shutdown): shed this request.
                        return Ok(false);
                    }
                } else {
                    sleep(wait_duration).await;
                }

                // Exponential backoff for next iteration (if not using Retry-After)
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
            SendAttemptResult::Retriable { status_code, .. } => {
                warn!(
                    service = service_name,
                    status_code = status_code,
                    retries = retries,
                    "Max retries exceeded for push notification"
                );
                return Ok(false);
            }
            SendAttemptResult::Permanent(e) => return Err(e),
        }
    }
}

fn retry_wait_duration(retry_after: Option<Duration>, backoff: Duration) -> Duration {
    match retry_after {
        Some(server_delay) => server_delay,
        None => backoff.min(MAX_BACKOFF),
    }
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
            // immediately without retrying.
            Err(error) => return Err(error),
        }
    }
}

/// Parse a Retry-After header value into a Duration.
///
/// Supports both delay-seconds format (e.g., "120") and HTTP-date format.
/// Returns None if the header is missing or cannot be parsed.
pub fn parse_retry_after(header_value: Option<&str>) -> Option<Duration> {
    let value = header_value?;

    // Try parsing as seconds first (most common for API rate limiting)
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }

    // TODO: Could add HTTP-date parsing here if needed
    // For now, just return None for date formats

    None
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
    fn test_retry_wait_duration_honors_retry_after_above_max_backoff() {
        assert_eq!(
            retry_wait_duration(Some(Duration::from_secs(60)), Duration::from_millis(100)),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn test_retry_wait_duration_caps_exponential_backoff() {
        assert_eq!(
            retry_wait_duration(None, Duration::from_secs(60)),
            MAX_BACKOFF
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
        assert!(result.unwrap());
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
        assert!(result.unwrap());
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
        assert!(!result.unwrap()); // Returns false when max retries exceeded
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
        assert!(!result.unwrap());
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
        assert!(result.unwrap());
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
        assert!(result.unwrap());
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

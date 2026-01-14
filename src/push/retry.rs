//! Retry logic with exponential backoff for push notifications.
//!
//! Implements retry behavior for transient failures (429 rate limiting, 5xx server errors)
//! with configurable exponential backoff and optional Retry-After header support.

use std::time::Duration;

use tokio::time::sleep;
use tracing::warn;

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
pub async fn with_retry<F, Fut>(
    config: &RetryConfig,
    service_name: &str,
    mut operation: F,
) -> crate::error::Result<bool>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = SendAttemptResult>,
{
    let mut retries = 0;
    let mut backoff = config.initial_backoff;

    loop {
        match operation().await {
            SendAttemptResult::Success(result) => return Ok(result),
            SendAttemptResult::Retriable {
                status_code,
                retry_after,
            } if retries < config.max_retries => {
                retries += 1;

                // Use Retry-After header if provided, otherwise use exponential backoff
                let wait_duration = retry_after.unwrap_or(backoff).min(MAX_BACKOFF);

                warn!(
                    service = service_name,
                    status_code = status_code,
                    retry = retries,
                    max_retries = config.max_retries,
                    backoff_ms = wait_duration.as_millis() as u64,
                    "Retrying push notification"
                );

                sleep(wait_duration).await;

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

    #[tokio::test]
    async fn test_with_retry_success_first_attempt() {
        let config = RetryConfig::default();
        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let result = with_retry(&config, "test", || {
            let count = attempt_count_clone.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                SendAttemptResult::Success(true)
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
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

        let result = with_retry(&config, "test", || {
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
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
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

        let result = with_retry(&config, "test", || {
            let count = attempt_count_clone.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                SendAttemptResult::Retriable {
                    status_code: 503,
                    retry_after: None,
                }
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false); // Returns false when max retries exceeded
        // Initial attempt + max_retries = 1 + 2 = 3
        assert_eq!(attempt_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_with_retry_permanent_error() {
        let config = RetryConfig::default();
        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let result = with_retry(&config, "test", || {
            let count = attempt_count_clone.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                SendAttemptResult::Permanent(crate::error::Error::Apns("Auth error".to_string()))
            }
        })
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

        let _ = with_retry(&config, "test", || {
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
        })
        .await;

        let elapsed = start.elapsed();
        // Should have used the short retry-after, not the long initial_backoff
        assert!(elapsed < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn test_with_retry_success_false() {
        let config = RetryConfig::default();

        let result = with_retry(&config, "test", || async {
            SendAttemptResult::Success(false)
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false);
    }
}

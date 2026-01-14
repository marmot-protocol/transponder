//! Graceful shutdown handling.
//!
//! Listens for SIGTERM and SIGINT signals and coordinates shutdown.

use std::time::Duration;

use tokio::signal;
use tokio::sync::watch;
use tokio::time::timeout;
use tracing::{info, warn};

/// Shutdown coordinator.
pub struct ShutdownHandler {
    sender: watch::Sender<bool>,
    receiver: watch::Receiver<bool>,
}

impl ShutdownHandler {
    /// Create a new shutdown handler.
    pub fn new() -> Self {
        let (sender, receiver) = watch::channel(false);
        Self { sender, receiver }
    }

    /// Get a receiver for shutdown signals.
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.receiver.clone()
    }

    /// Trigger a shutdown.
    pub fn trigger(&self) {
        let _ = self.sender.send(true);
    }

    /// Wait for a shutdown signal (SIGTERM or SIGINT).
    pub async fn wait_for_signal(&self) {
        let ctrl_c = async {
            signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to install SIGTERM handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {
                info!("Received Ctrl+C, initiating shutdown");
            }
            _ = terminate => {
                info!("Received SIGTERM, initiating shutdown");
            }
        }

        self.trigger();
    }
}

impl Default for ShutdownHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Perform graceful shutdown with configurable timeout.
///
/// # Arguments
/// * `shutdown_fn` - The async function to execute during shutdown
/// * `timeout_secs` - Timeout in seconds before forcefully terminating
pub async fn graceful_shutdown<F, Fut>(shutdown_fn: F, timeout_secs: u64)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let timeout_duration = Duration::from_secs(timeout_secs);
    match timeout(timeout_duration, shutdown_fn()).await {
        Ok(()) => {
            info!("Graceful shutdown completed");
        }
        Err(_) => {
            warn!("Graceful shutdown timed out after {:?}", timeout_duration);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_shutdown_handler() {
        let handler = ShutdownHandler::new();
        let mut receiver = handler.subscribe();

        // Initially not shutdown
        assert!(!*receiver.borrow());

        // Trigger shutdown
        handler.trigger();

        // Should be marked as shutdown
        receiver.changed().await.unwrap();
        assert!(*receiver.borrow());
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let handler = ShutdownHandler::new();
        let mut rx1 = handler.subscribe();
        let mut rx2 = handler.subscribe();

        handler.trigger();

        rx1.changed().await.unwrap();
        rx2.changed().await.unwrap();

        assert!(*rx1.borrow());
        assert!(*rx2.borrow());
    }

    #[test]
    fn test_shutdown_handler_default() {
        let handler = ShutdownHandler::default();
        let receiver = handler.subscribe();
        // Default state should be false (not shutdown)
        assert!(!*receiver.borrow());
    }

    #[tokio::test]
    async fn test_graceful_shutdown_completes() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let completed = Arc::new(AtomicBool::new(false));
        let completed_clone = completed.clone();

        graceful_shutdown(
            || async move {
                // Simulate quick shutdown
                completed_clone.store(true, Ordering::SeqCst);
            },
            10,
        )
        .await;

        assert!(completed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_graceful_shutdown_timeout() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        // Test that shutdown times out after the specified duration
        let started = Arc::new(AtomicBool::new(false));
        let started_clone = started.clone();

        // Use a very short timeout (1 second) and a task that takes longer
        graceful_shutdown(
            || async move {
                started_clone.store(true, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_secs(5)).await;
            },
            1,
        )
        .await;

        // The task started but the function should have returned due to timeout
        assert!(started.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_graceful_shutdown_custom_timeout() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let completed = Arc::new(AtomicBool::new(false));
        let completed_clone = completed.clone();

        // Test with a custom timeout value
        graceful_shutdown(
            || async move {
                completed_clone.store(true, Ordering::SeqCst);
            },
            30,
        )
        .await;

        assert!(completed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_trigger_multiple_times() {
        let handler = ShutdownHandler::new();
        let mut receiver = handler.subscribe();

        // Trigger multiple times - should be idempotent
        handler.trigger();
        handler.trigger();
        handler.trigger();

        receiver.changed().await.unwrap();
        assert!(*receiver.borrow());
    }

    #[tokio::test]
    async fn test_subscribe_before_and_after_trigger() {
        let handler = ShutdownHandler::new();

        // Subscribe before trigger
        let mut rx_before = handler.subscribe();
        assert!(!*rx_before.borrow());

        handler.trigger();

        // Subscribe after trigger
        let rx_after = handler.subscribe();
        assert!(*rx_after.borrow()); // Should immediately see shutdown state

        rx_before.changed().await.unwrap();
        assert!(*rx_before.borrow());
    }
}

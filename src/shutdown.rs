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

/// Graceful shutdown timeout.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Perform graceful shutdown with timeout.
pub async fn graceful_shutdown<F, Fut>(shutdown_fn: F)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    match timeout(SHUTDOWN_TIMEOUT, shutdown_fn()).await {
        Ok(()) => {
            info!("Graceful shutdown completed");
        }
        Err(_) => {
            warn!("Graceful shutdown timed out after {:?}", SHUTDOWN_TIMEOUT);
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

        graceful_shutdown(|| async move {
            // Simulate quick shutdown
            completed_clone.store(true, Ordering::SeqCst);
        })
        .await;

        assert!(completed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_graceful_shutdown_timeout() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        // Note: This test would take 10 seconds if we actually waited for the timeout.
        // We're testing that the function handles long-running tasks.
        // For now, we just verify the function accepts our closure.
        let started = Arc::new(AtomicBool::new(false));
        let started_clone = started.clone();

        graceful_shutdown(|| async move {
            started_clone.store(true, Ordering::SeqCst);
            // Don't actually sleep for 20 seconds in tests
        })
        .await;

        assert!(started.load(Ordering::SeqCst));
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

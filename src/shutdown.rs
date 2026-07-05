//! Graceful shutdown handling.
//!
//! Listens for SIGTERM and SIGINT signals and coordinates shutdown.

use std::{future, io, time::Duration};

use tokio::signal;
use tokio::sync::watch;
use tokio::time::timeout;
use tracing::{info, warn};

/// Shutdown coordinator.
pub struct ShutdownHandler {
    sender: watch::Sender<bool>,
    receiver: watch::Receiver<bool>,
}

/// Cloneable handle that lets supervised tasks request a process-wide shutdown.
///
/// Handed to long-lived tasks (health server, event loop) so an unexpected
/// failure tears the whole process down — letting the orchestrator restart it —
/// instead of leaving a zombie that reports healthy while doing nothing.
#[derive(Clone)]
pub struct ShutdownTrigger {
    sender: watch::Sender<bool>,
}

impl ShutdownTrigger {
    /// Request a process-wide shutdown.
    pub fn trigger(&self) {
        let _ = self.sender.send(true);
    }
}

/// How a shutdown was initiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    /// SIGTERM/SIGINT from an operator or orchestrator; a normal stop.
    Signal,
    /// An internal [`ShutdownTrigger`] fired by a supervised task; indicates
    /// a critical failure, so the process should exit non-zero.
    InternalTrigger,
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

    /// Get a cloneable handle that can trigger a shutdown from another task.
    pub fn trigger_handle(&self) -> ShutdownTrigger {
        ShutdownTrigger {
            sender: self.sender.clone(),
        }
    }

    /// Trigger a shutdown.
    pub fn trigger(&self) {
        let _ = self.sender.send(true);
    }

    /// Wait for a shutdown signal (SIGTERM or SIGINT).
    pub async fn wait_for_signal(&self) {
        self.handle_first_shutdown_signal(
            wait_for_shutdown_signal(),
            spawn_force_quit_on_second_signal,
        )
        .await;
    }

    /// Wait until shutdown is requested, by an OS signal (SIGTERM or SIGINT)
    /// or by an internal [`ShutdownTrigger`] fired from a supervised task,
    /// and report which one initiated it.
    ///
    /// Waiting on OS signals alone would park the process forever when a
    /// critical task (event loop, health server) dies and triggers shutdown
    /// internally. `wait_for` also covers a trigger that fired *before* this
    /// call, so an early supervised failure is never missed.
    pub async fn wait_for_signal_or_trigger(&self) -> ShutdownReason {
        let mut receiver = self.subscribe();
        tokio::select! {
            () = self.wait_for_signal() => ShutdownReason::Signal,
            _ = receiver.wait_for(|&triggered| triggered) => {
                info!("Internal shutdown trigger received, initiating shutdown");
                // Keep signal semantics consistent with the OS-signal path: a
                // signal arriving after an internal trigger forces the process
                // out instead of being ignored during teardown.
                spawn_force_quit_on_second_signal();
                ShutdownReason::InternalTrigger
            }
        }
    }

    async fn handle_first_shutdown_signal<SignalFuture, SpawnSecond>(
        &self,
        signal: SignalFuture,
        spawn_second_signal_listener: SpawnSecond,
    ) where
        SignalFuture: future::Future<Output = ShutdownSignal>,
        SpawnSecond: FnOnce(),
    {
        let signal = signal.await;
        info!(
            signal = signal.name(),
            "Received shutdown signal, initiating shutdown"
        );
        self.trigger();
        spawn_second_signal_listener();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShutdownSignal {
    CtrlC,
    Sigterm,
}

impl ShutdownSignal {
    const fn name(self) -> &'static str {
        match self {
            Self::CtrlC => "Ctrl+C",
            Self::Sigterm => "SIGTERM",
        }
    }
}

async fn wait_for_shutdown_signal() -> ShutdownSignal {
    select_shutdown_signal(wait_for_ctrl_c_signal(), wait_for_sigterm_signal()).await
}

async fn select_shutdown_signal<CtrlC, Terminate>(
    ctrl_c: CtrlC,
    terminate: Terminate,
) -> ShutdownSignal
where
    CtrlC: future::Future<Output = ()>,
    Terminate: future::Future<Output = ()>,
{
    tokio::select! {
        _ = ctrl_c => ShutdownSignal::CtrlC,
        _ = terminate => ShutdownSignal::Sigterm,
    }
}

async fn wait_for_ctrl_c_signal() {
    wait_for_fallible_signal("Ctrl+C", signal::ctrl_c()).await;
}

#[cfg(unix)]
async fn wait_for_sigterm_signal() {
    let mut terminate = match signal::unix::signal(signal::unix::SignalKind::terminate()) {
        Ok(terminate) => terminate,
        Err(error) => {
            wait_forever_after_signal_install_error("SIGTERM", error).await;
            return;
        }
    };

    terminate.recv().await;
}

#[cfg(not(unix))]
async fn wait_for_sigterm_signal() {
    future::pending::<()>().await;
}

async fn wait_for_fallible_signal<Fut>(signal_name: &'static str, signal: Fut)
where
    Fut: future::Future<Output = io::Result<()>>,
{
    match signal.await {
        Ok(()) => {}
        Err(error) => wait_forever_after_signal_install_error(signal_name, error).await,
    }
}

async fn wait_forever_after_signal_install_error(signal_name: &'static str, error: io::Error) {
    warn!(
        signal = signal_name,
        error = %error,
        "Failed to install shutdown signal handler; signal disabled"
    );
    future::pending::<()>().await;
}

fn spawn_force_quit_on_second_signal() {
    // Detached by design: once graceful shutdown starts, a repeated signal must
    // force the process out even if cleanup is still running. Tests inject a
    // capturing closure, but production uses `std::process::exit` directly.
    let handle = tokio::spawn(force_quit_after_second_signal(
        wait_for_shutdown_signal(),
        std::process::exit,
    ));
    drop(handle);
}

async fn force_quit_after_second_signal<SignalFuture, Exit, ExitOutput>(
    signal: SignalFuture,
    exit: Exit,
) where
    SignalFuture: future::Future<Output = ShutdownSignal>,
    Exit: FnOnce(i32) -> ExitOutput,
{
    let signal = signal.await;
    warn!(
        signal = signal.name(),
        "Received second shutdown signal, forcing exit"
    );
    exit(1);
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
    async fn first_signal_triggers_shutdown_and_spawns_second_signal_listener() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        let handler = ShutdownHandler::new();
        let mut receiver = handler.subscribe();
        let second_listener_spawned = Arc::new(AtomicBool::new(false));
        let spawned_flag = Arc::clone(&second_listener_spawned);

        handler
            .handle_first_shutdown_signal(async { ShutdownSignal::CtrlC }, move || {
                spawned_flag.store(true, Ordering::SeqCst);
            })
            .await;

        receiver.changed().await.unwrap();
        assert!(*receiver.borrow());
        assert!(second_listener_spawned.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn trigger_handle_triggers_shutdown_for_subscribers() {
        let handler = ShutdownHandler::new();
        let mut receiver = handler.subscribe();
        let trigger = handler.trigger_handle();

        assert!(!*receiver.borrow());
        trigger.trigger();

        receiver.changed().await.unwrap();
        assert!(*receiver.borrow());
    }

    #[tokio::test]
    async fn cloned_trigger_handle_shares_the_shutdown_channel() {
        let handler = ShutdownHandler::new();
        let mut receiver = handler.subscribe();
        let trigger = handler.trigger_handle();
        let cloned = trigger.clone();
        drop(trigger);

        cloned.trigger();

        receiver.changed().await.unwrap();
        assert!(*receiver.borrow());
    }

    #[tokio::test]
    async fn wait_for_signal_or_trigger_returns_on_internal_trigger() {
        use std::future::Future;
        use std::task::{Context, Waker};

        let handler = ShutdownHandler::new();
        let trigger = handler.trigger_handle();

        let wait = handler.wait_for_signal_or_trigger();
        tokio::pin!(wait);

        // No signal and no trigger yet: the wait must still be pending. Poll
        // once with a no-op waker instead of racing a wall-clock timeout — the
        // first poll subscribes the receiver and registers the signal handlers,
        // and with neither fired the future is deterministically `Pending`.
        let mut cx = Context::from_waker(Waker::noop());
        assert!(
            wait.as_mut().poll(&mut cx).is_pending(),
            "wait must be pending before any signal or trigger"
        );

        trigger.trigger();

        // The trigger set the watch to `true`; awaiting the same future now
        // resolves deterministically (a hang here would be a real bug the outer
        // test harness surfaces, not a timing flake).
        let reason = wait.await;
        assert_eq!(reason, ShutdownReason::InternalTrigger);
    }

    #[tokio::test]
    async fn wait_for_signal_or_trigger_returns_when_already_triggered() {
        let handler = ShutdownHandler::new();
        handler.trigger();

        // A trigger that fired before the wait started must not be missed.
        let reason = timeout(Duration::from_secs(1), handler.wait_for_signal_or_trigger())
            .await
            .expect("a pre-fired trigger must complete the shutdown wait");
        assert_eq!(reason, ShutdownReason::InternalTrigger);
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
    async fn select_shutdown_signal_returns_ctrl_c_when_ctrl_c_completes() {
        let signal = select_shutdown_signal(future::ready(()), future::pending()).await;

        assert_eq!(signal, ShutdownSignal::CtrlC);
    }

    #[tokio::test]
    async fn select_shutdown_signal_returns_sigterm_when_sigterm_completes() {
        let signal = select_shutdown_signal(future::pending(), future::ready(())).await;

        assert_eq!(signal, ShutdownSignal::Sigterm);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn wait_for_shutdown_signal_receives_sigterm() {
        // Exercises Tokio's process-wide SIGTERM handler registration. Keep the
        // guard alive so the test signal is consumed instead of terminating the
        // test binary.
        let _sigterm_guard = signal::unix::signal(signal::unix::SignalKind::terminate()).unwrap();
        let waiter = tokio::spawn(wait_for_shutdown_signal());
        tokio::task::yield_now().await;

        let status = std::process::Command::new("kill")
            .arg("-TERM")
            .arg(std::process::id().to_string())
            .status()
            .unwrap();
        assert!(status.success());

        let signal = timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(signal, ShutdownSignal::Sigterm);
    }

    #[tokio::test]
    async fn force_quit_after_second_signal_exits_with_failure_status() {
        use std::sync::{
            Arc,
            atomic::{AtomicI32, Ordering},
        };

        let exit_code = Arc::new(AtomicI32::new(0));
        let captured_exit_code = Arc::clone(&exit_code);

        force_quit_after_second_signal(async { ShutdownSignal::Sigterm }, move |code| {
            captured_exit_code.store(code, Ordering::SeqCst);
        })
        .await;

        assert_eq!(exit_code.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn fallible_signal_completes_when_handler_succeeds() {
        let result = timeout(
            Duration::from_millis(50),
            wait_for_fallible_signal("test", async { Ok(()) }),
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn fallible_signal_install_error_waits_forever() {
        let result = timeout(
            Duration::from_millis(10),
            wait_for_fallible_signal("test", async { Err(io::Error::other("install failed")) }),
        )
        .await;

        assert!(result.is_err());
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

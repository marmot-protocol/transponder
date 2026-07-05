//! In-flight send task lifetime tracking.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::Notify;

/// Tracks the number of spawned send tasks that have not yet finished, so that
/// graceful shutdown can wait for them to complete.
///
/// This is deliberately decoupled from the concurrency
/// [`tokio::sync::Semaphore`]: a send
/// task that is in a retry backoff sleep releases its concurrency permit (see
/// [`crate::push::retry::BackoffPermit`]) so the slot can be reused, but the
/// task is still alive and may re-acquire a permit and send again. Counting
/// permits is therefore *not* a sound proof that all send tasks have finished.
/// This tracker counts task lifetimes end-to-end instead.
pub(crate) struct InFlightTracker {
    count: AtomicUsize,
    idle: Notify,
}

impl InFlightTracker {
    pub(crate) fn new() -> Self {
        Self {
            count: AtomicUsize::new(0),
            idle: Notify::new(),
        }
    }

    /// Register a newly spawned send task. The returned guard decrements the
    /// in-flight count when dropped (i.e. when the send task finishes) and
    /// wakes any shutdown waiter once the count reaches zero.
    pub(crate) fn enter(self: &Arc<Self>) -> InFlightGuard {
        self.count.fetch_add(1, Ordering::SeqCst);
        InFlightGuard {
            tracker: self.clone(),
        }
    }

    /// Wait until no send tasks are in flight.
    ///
    /// Uses the register-before-check pattern so a task that finishes between
    /// the count load and observing the notification cannot be missed: the
    /// `Notified` future is *enabled* (waiter registered) before the count is
    /// read. `notify_waiters()` does not store a permit, so the waiter must be
    /// registered first; `Notified::enable()` registers it eagerly without
    /// awaiting, which closes the lost-wakeup window.
    pub(crate) async fn wait_idle(&self) {
        loop {
            let notified = self.idle.notified();
            tokio::pin!(notified);
            // Register this waiter before reading the count.
            notified.as_mut().enable();
            if self.count.load(Ordering::SeqCst) == 0 {
                return;
            }
            notified.await;
        }
    }

    #[cfg(test)]
    pub(crate) fn in_flight_count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}

/// RAII guard returned by [`InFlightTracker::enter`]; decrements the in-flight
/// count and signals idle when the last in-flight task finishes.
pub(crate) struct InFlightGuard {
    tracker: Arc<InFlightTracker>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if self.tracker.count.fetch_sub(1, Ordering::SeqCst) == 1 {
            // Transitioned to zero in-flight tasks; wake any shutdown waiter.
            self.tracker.idle.notify_waiters();
        }
    }
}

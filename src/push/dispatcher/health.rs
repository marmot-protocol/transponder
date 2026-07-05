//! Passive per-provider delivery health tracking.

use std::sync::atomic::{AtomicU32, Ordering};

use crate::crypto::Platform;

/// Number of consecutive hard delivery failures after which a provider is
/// reported as not delivering (see [`DeliveryHealth`]).
///
/// "Hard" failures are outcomes indicating the provider itself is refusing or
/// failing requests: permanent send errors (which include authentication
/// rejections such as a revoked APNs signing key or an expired FCM service
/// account) and exhausted retry budgets. Invalid device tokens do NOT count —
/// a definitive invalid-token verdict proves the provider authenticated and
/// processed the request. The threshold trades detection speed against
/// flapping: five hard failures in a row with no intervening success is a
/// sustained outage signal, not an isolated transient blip.
pub const DELIVERY_FAILURE_STREAK_THRESHOLD: u32 = 5;

/// Passive per-provider delivery-health signal derived from real send
/// outcomes.
///
/// Tracks, for each push provider, the current streak of *consecutive* hard
/// send failures. The streak grows on permanent errors and exhausted retries,
/// and resets to zero whenever the provider demonstrably processes a request
/// (successful send or a definitive invalid-token verdict). The readiness
/// endpoint uses [`DeliveryHealth::is_delivering`] to gate `/ready` on live
/// delivery capability instead of static configuration alone.
///
/// The signal is passive: it observes outcomes of real traffic and never
/// probes the providers. If push traffic stops entirely, the last observed
/// state is retained until the next send.
#[derive(Debug, Default)]
pub struct DeliveryHealth {
    apns_hard_failure_streak: AtomicU32,
    fcm_hard_failure_streak: AtomicU32,
}

impl DeliveryHealth {
    fn streak(&self, platform: Platform) -> &AtomicU32 {
        match platform {
            Platform::Apns => &self.apns_hard_failure_streak,
            Platform::Fcm => &self.fcm_hard_failure_streak,
        }
    }

    /// Record that the provider processed a request (successful send, or a
    /// definitive invalid-token verdict), ending any hard-failure streak.
    pub(crate) fn record_processed(&self, platform: Platform) {
        self.streak(platform).store(0, Ordering::SeqCst);
    }

    /// Record a hard send failure (permanent error or exhausted retries).
    ///
    /// Saturates instead of wrapping so an arbitrarily long outage can never
    /// roll the streak back over to "delivering".
    pub(crate) fn record_hard_failure(&self, platform: Platform) {
        let _ = self
            .streak(platform)
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |streak| {
                Some(streak.saturating_add(1))
            });
    }

    /// Whether the provider is currently considered to be delivering: its
    /// consecutive hard-failure streak is below
    /// [`DELIVERY_FAILURE_STREAK_THRESHOLD`].
    #[must_use]
    pub fn is_delivering(&self, platform: Platform) -> bool {
        self.streak(platform).load(Ordering::SeqCst) < DELIVERY_FAILURE_STREAK_THRESHOLD
    }
}

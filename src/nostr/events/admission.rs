//! Per-token admission charge lifecycle and processing helpers.

use std::time::Instant as StdInstant;

use crate::crypto::Platform;
use crate::metrics::Metrics;
use crate::rate_limiter::{RateLimitReservation, RateLimiter};

#[must_use]
pub(crate) struct InFlightEventGuard<'a> {
    metrics: Option<&'a Metrics>,
}

impl<'a> InFlightEventGuard<'a> {
    pub(crate) fn new(metrics: Option<&'a Metrics>) -> Self {
        if let Some(m) = metrics {
            m.inc_events_in_flight();
        }

        Self { metrics }
    }
}

impl Drop for InFlightEventGuard<'_> {
    fn drop(&mut self) {
        if let Some(m) = self.metrics {
            m.dec_events_in_flight();
        }
    }
}

pub(crate) struct StageTimer(StdInstant);

impl StageTimer {
    pub(crate) fn start() -> Self {
        Self(StdInstant::now())
    }

    pub(crate) fn elapsed_secs(&self) -> f64 {
        self.0.elapsed().as_secs_f64()
    }
}

/// Outcome of [`EventProcessor::process_inner`].
///
/// Distinguishes a terminal result (notifications admitted, or the event
/// genuinely carried nothing dispatchable) from a purely transient per-token
/// rate-limit shed, which must be treated like the global-limiter shed:
/// retryable, not marked terminally seen, and not counted as processed.
pub(crate) enum ProcessOutcome {
    /// The event reached a terminal state: its admitted notifications (possibly
    /// zero when every token was invalid or targeted an unconfigured platform)
    /// were handed to the dispatcher; the per-event count is recorded via
    /// `observe_notifications_admitted_per_event`. Replays should
    /// short-circuit as duplicates.
    Admitted,
    /// Every token the event carried was shed purely by the per-token rate
    /// limiters, admitting zero notifications and dropping nothing terminally.
    /// This is transient back-pressure: the event stays retryable once budget
    /// recovers.
    RateLimitedShed,
}

/// A per-token admission charge that must be explicitly resolved.
///
/// Created after the encrypted-token limiter admits a token, and (once the
/// device-token limiter also admits) after that charge too. It makes the
/// charge/refund lifecycle transactional so no admission path can silently
/// strand a spent rate-limit increment (the class of bug behind #170 and #177):
///
/// - [`commit`](AdmissionGuard::commit) — the token was fully admitted and
///   handed toward the dispatcher; the charges are handed off to the caller's
///   dispatch-failure rollback ledger. Returns the keys and reservations.
/// - [`refund`](AdmissionGuard::refund) — the token is being dropped *after*
///   being charged (device-limiter reject per #170, or an undispatchable
///   platform / non-UTF-8 token discovered post-decrypt per #177). Every charge
///   the guard holds is rolled back so the drop leaves no spent budget.
/// - [`keep_charge`](AdmissionGuard::keep_charge) — the token is dropped but its
///   charge is *intentionally retained* (decrypt failure: an invalid encrypted
///   blob must still spend replay/spam budget, documented in #170).
///
/// The `Drop` impl asserts the guard was resolved. Because the limiter refund is
/// `async` (the stripe lock is a tokio `RwLock`), a `Drop`-time auto-refund
/// would have to block; the guard is therefore an explicit-consume guard rather
/// than a fire-and-forget RAII one. This keeps the refund decision in exactly
/// one place per exit path while remaining `async`-correct — the trade the
/// tracker calls out as acceptable when a blocking Drop is not.
#[must_use = "an AdmissionGuard must be committed, refunded, or explicitly kept"]
pub(crate) struct AdmissionGuard<'a> {
    encrypted_limiter: &'a RateLimiter<[u8; 32]>,
    device_limiter: &'a RateLimiter<[u8; 32]>,
    encrypted_key: [u8; 32],
    encrypted_reservation: RateLimitReservation,
    /// Present once the device-token limiter has also admitted the token.
    device: Option<([u8; 32], RateLimitReservation)>,
    resolved: bool,
}

impl<'a> AdmissionGuard<'a> {
    /// Record the encrypted-token charge just made for a token.
    pub(crate) fn new(
        encrypted_limiter: &'a RateLimiter<[u8; 32]>,
        device_limiter: &'a RateLimiter<[u8; 32]>,
        encrypted_key: [u8; 32],
        encrypted_reservation: RateLimitReservation,
    ) -> Self {
        Self {
            encrypted_limiter,
            device_limiter,
            encrypted_key,
            encrypted_reservation,
            device: None,
            resolved: false,
        }
    }

    /// Record the device-token charge for the same token.
    pub(crate) fn add_device_charge(
        &mut self,
        device_key: [u8; 32],
        reservation: RateLimitReservation,
    ) {
        self.device = Some((device_key, reservation));
    }

    /// Roll back every charge this guard holds (encrypted, and device if any).
    ///
    /// Used on every drop-after-charge path: a device-limiter reject (#170) and
    /// a post-decrypt undispatchable/non-UTF-8 drop (#177).
    pub(crate) async fn refund(mut self) {
        self.encrypted_limiter
            .rollback_increment(&self.encrypted_key, self.encrypted_reservation)
            .await;
        if let Some((device_key, reservation)) = self.device {
            self.device_limiter
                .rollback_increment(&device_key, reservation)
                .await;
        }
        self.resolved = true;
    }

    /// Intentionally keep the charge(s) — the drop is a deliberate budget spend.
    pub(crate) fn keep_charge(mut self) {
        self.resolved = true;
    }

    /// Hand off the fully-admitted charges to the caller's rollback ledger.
    pub(crate) fn commit(mut self) -> AdmittedCharges {
        self.resolved = true;
        let (device_key, device_reservation) = self
            .device
            .expect("commit requires a device-token charge to have been recorded");
        AdmittedCharges {
            encrypted_key: self.encrypted_key,
            encrypted_reservation: self.encrypted_reservation,
            device_key,
            device_reservation,
        }
    }
}

impl Drop for AdmissionGuard<'_> {
    fn drop(&mut self) {
        debug_assert!(
            self.resolved,
            "AdmissionGuard dropped without commit/refund/keep_charge — a rate-limit charge would be stranded"
        );
    }
}

/// Fully-admitted rate-limit charges for one token, recorded so a later
/// dispatch-admission failure can roll back exactly the increments it spent.
pub(crate) struct AdmittedCharges {
    pub(crate) encrypted_key: [u8; 32],
    pub(crate) encrypted_reservation: RateLimitReservation,
    pub(crate) device_key: [u8; 32],
    pub(crate) device_reservation: RateLimitReservation,
}

/// Metrics label for a push platform (matches the dispatcher's `platform`
/// label values so drop counters aggregate with send counters).
pub(crate) fn platform_metric_label(platform: Platform) -> &'static str {
    match platform {
        Platform::Apns => "apns",
        Platform::Fcm => "fcm",
    }
}

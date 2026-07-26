//! Short-lived Marmot Push trigger-content deduplication.

use std::num::NonZeroUsize;
use std::time::Duration;

use lru::LruCache;
use nostr_sdk::prelude::EventId;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::defaults::DEFAULT_DEDUP_RETENTION_SECS;

pub(crate) const DEDUP_WINDOW: Duration = Duration::from_secs(DEFAULT_DEDUP_RETENTION_SECS);
pub(crate) const CLEANUP_BATCH_SIZE: usize = 1000;

/// Result of trying to reserve a decoded trigger-content hash.
pub(crate) enum Reservation {
    /// This caller owns processing for the content hash.
    Acquired {
        /// Keeps the reservation alive for as long as the owner holds it.
        guard: ReservationGuard,
        /// The reservation was taken over from an owner that vanished without
        /// resolving it (see [`ReservationGuard`]). Surfaced so the caller can
        /// log the recovery; a healthy server never reclaims.
        reclaimed: bool,
    },
    /// The content hash already reached a terminal local outcome.
    Duplicate,
    /// Another task is processing the same content hash. Waiting for the
    /// owner's completion channel to close and then retrying the reservation
    /// avoids losing the trigger if that owner releases a transient
    /// reservation — or gives it up by unwinding.
    Wait(watch::Receiver<()>),
    /// Every cache slot is occupied by a live in-flight reservation.
    ///
    /// The validated relationship between event-processing concurrency and
    /// dedup capacity makes this unreachable in normal operation. Keeping an
    /// explicit fail-closed result prevents a future caller from evicting a
    /// live reservation and admitting a duplicate notification.
    AtCapacity,
}

/// Proof of ownership of an in-flight reservation.
///
/// The guard holds the only [`watch::Sender`] of the reservation's completion
/// channel; the store keeps receivers. Dropping the guard closes that channel,
/// which both wakes every concurrent duplicate waiting on the owner and marks
/// the store entry reclaimable. Ownership therefore ends on *every* exit path,
/// including a panic unwinding out of event processing or the task being
/// dropped at shutdown — the explicit
/// [`release`](SeenEventStore::release)/[`mark_terminal`](SeenEventStore::mark_terminal)
/// calls only decide whether the hash stays terminally seen, never whether the
/// reservation is given up (#370).
///
/// Nothing is ever sent on the channel: closing it is the signal, so the wake
/// cannot be skipped by an unwind that jumps over a `send`.
#[must_use = "dropping the guard immediately gives up the reservation"]
pub(crate) struct ReservationGuard {
    /// Held only for its `Drop`, which closes the completion channel.
    _completed: watch::Sender<()>,
}

enum EntryState {
    /// A reservation, with a receiver observing the owner's
    /// [`ReservationGuard`]. A closed channel means the owner is gone.
    InFlight(watch::Receiver<()>),
    Terminal,
}

impl EntryState {
    /// True when the entry is a reservation whose owner still exists.
    ///
    /// [`watch::Receiver::has_changed`] reports `Err` once every sender is
    /// dropped, and the guard holds the only sender for this channel.
    fn is_live_reservation(&self) -> bool {
        match self {
            EntryState::InFlight(completed) => completed.has_changed().is_ok(),
            EntryState::Terminal => false,
        }
    }

    /// True when the entry may be removed without stranding a live owner.
    ///
    /// Terminal entries are replay state, and an abandoned reservation is
    /// state nobody will ever resolve, so both are safe victims. Removing a
    /// live reservation is not: its concurrent duplicates would stop waiting
    /// on the owner and re-acquire, admitting a duplicate notification.
    fn is_reclaimable(&self) -> bool {
        !self.is_live_reservation()
    }
}

struct SeenTrigger {
    seen_at: Instant,
    state: EntryState,
}

/// What a `reserve` call found already resident for the content hash.
///
/// Resolved before mutating so the decision is not taken while the entry is
/// still borrowed from the cache.
enum Resident {
    Terminal,
    LiveReservation(watch::Receiver<()>),
    AbandonedReservation,
}

/// Bounded, volatile content-hash state.
///
/// Keys use [`EventId`] only as a convenient validated 32-byte wrapper. They
/// are SHA-256 hashes of decoded kind 446 content, never Nostr event IDs.
pub(crate) struct SeenEventStore {
    entries: LruCache<EventId, SeenTrigger>,
}

impl SeenEventStore {
    pub(crate) fn bounded(cache_size: NonZeroUsize) -> Self {
        Self {
            entries: LruCache::new(cache_size),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(crate) fn contains_terminal(&self, content_hash: &EventId) -> bool {
        self.entries
            .peek(content_hash)
            .is_some_and(|entry| matches!(entry.state, EntryState::Terminal))
    }

    pub(crate) fn reserve(&mut self, content_hash: EventId, now: Instant) -> Reservation {
        let resident = self
            .entries
            .peek(&content_hash)
            .map(|entry| match &entry.state {
                EntryState::Terminal => Resident::Terminal,
                EntryState::InFlight(completed) if completed.has_changed().is_ok() => {
                    // Cloning preserves the observed version, so the waiter is not
                    // woken spuriously by the channel's initial value.
                    Resident::LiveReservation(completed.clone())
                }
                EntryState::InFlight(_) => Resident::AbandonedReservation,
            });

        match resident {
            Some(Resident::Terminal) => return Reservation::Duplicate,
            Some(Resident::LiveReservation(completed)) => return Reservation::Wait(completed),
            // The previous owner dropped its guard without resolving the
            // reservation — a panic between acquiring it and completing, or a
            // task dropped mid-processing. Take the reservation over instead of
            // waiting on a channel that will never be sent on: that wait could
            // never end, and the entry is exempt from eviction and expiry while
            // it looks in flight.
            //
            // Taking over can re-dispatch content the vanished owner had
            // already handed to the dispatcher, so recovery may cost one
            // duplicate content-free push. That is the deliberate trade against
            // the alternative: a permanently stuck hash whose every redelivery
            // blocks forever holding an event-processing permit.
            Some(Resident::AbandonedReservation) => {
                return Reservation::Acquired {
                    guard: self.install_reservation(content_hash, now),
                    reclaimed: true,
                };
            }
            None => {}
        }

        if !self.make_room_without_evicting_live_reservation() {
            return Reservation::AtCapacity;
        }

        Reservation::Acquired {
            guard: self.install_reservation(content_hash, now),
            reclaimed: false,
        }
    }

    /// Insert (or overwrite) an in-flight reservation and hand its guard out.
    ///
    /// Overwriting is only reached for an abandoned reservation, whose
    /// receivers are dropped here; their waiters have already been woken by the
    /// previous owner's guard closing the channel.
    fn install_reservation(&mut self, content_hash: EventId, now: Instant) -> ReservationGuard {
        let (completed, receiver) = watch::channel(());
        self.entries.put(
            content_hash,
            SeenTrigger {
                seen_at: now,
                state: EntryState::InFlight(receiver),
            },
        );
        ReservationGuard {
            _completed: completed,
        }
    }

    /// Ensure one slot is available, evicting only reclaimable state.
    ///
    /// `LruCache::put` evicts the LRU entry without considering its state. A
    /// still-active reservation must remain resident so concurrent duplicates
    /// keep waiting on the same owner instead of re-acquiring after its watch
    /// channel is dropped. A reservation whose owner is gone carries no such
    /// obligation, so it is a victim like terminal state rather than dead
    /// weight that can push the cache to [`Reservation::AtCapacity`].
    fn make_room_without_evicting_live_reservation(&mut self) -> bool {
        if self.entries.len() < self.entries.cap().get() {
            return true;
        }

        let victim = self.entries.iter().rev().find_map(|(content_hash, entry)| {
            entry.state.is_reclaimable().then_some(*content_hash)
        });

        if let Some(content_hash) = victim {
            self.entries.pop(&content_hash);
            true
        } else {
            false
        }
    }

    /// Give up a reservation without recording a terminal outcome.
    ///
    /// Only the reservation's own owner calls this, so the resident entry is
    /// its reservation; the state check keeps a stray call from deleting
    /// terminal replay state. Waiters are woken by the owner dropping its
    /// [`ReservationGuard`], not here.
    pub(crate) fn release(&mut self, content_hash: &EventId) {
        if self
            .entries
            .peek(content_hash)
            .is_some_and(|entry| matches!(entry.state, EntryState::InFlight(_)))
        {
            self.entries.pop(content_hash);
        }
    }

    /// Complete a reservation, recording a terminal outcome for the hash.
    ///
    /// Returns `true` when the entry was absent and could be inserted. Returns
    /// `false` when the entry already existed or every slot is still in flight.
    /// Concurrent duplicates are woken when the owner drops its
    /// [`ReservationGuard`]; they then re-reserve and see this terminal state.
    pub(crate) fn mark_terminal(&mut self, content_hash: EventId, now: Instant) -> bool {
        if let Some(entry) = self.entries.peek_mut(&content_hash) {
            entry.state = EntryState::Terminal;
            entry.seen_at = now;
            self.entries.promote(&content_hash);
            false
        } else {
            if !self.make_room_without_evicting_live_reservation() {
                return false;
            }
            self.entries.put(
                content_hash,
                SeenTrigger {
                    seen_at: now,
                    state: EntryState::Terminal,
                },
            );
            true
        }
    }

    /// Content hashes the periodic cleanup may drop.
    ///
    /// Abandoned reservations are included: an owner that vanished leaves state
    /// nothing will resolve, and it must not hold a slot past the retention
    /// window just because it still looks in flight.
    pub(crate) fn expired_keys(&self, now: Instant, retention: Duration) -> Vec<EventId> {
        self.entries
            .iter()
            .rev()
            .take(CLEANUP_BATCH_SIZE)
            .filter(|(_, entry)| {
                entry.state.is_reclaimable() && now.duration_since(entry.seen_at) >= retention
            })
            .map(|(content_hash, _)| *content_hash)
            .collect()
    }

    pub(crate) fn pop(&mut self, content_hash: &EventId) {
        self.entries.pop(content_hash);
    }

    #[cfg(test)]
    pub(crate) fn put_terminal(&mut self, content_hash: EventId, seen_at: Instant) {
        self.entries.put(
            content_hash,
            SeenTrigger {
                seen_at,
                state: EntryState::Terminal,
            },
        );
    }

    /// Insert a reservation whose owner stays alive while the guard is held.
    #[cfg(test)]
    pub(crate) fn put_reservation(
        &mut self,
        content_hash: EventId,
        seen_at: Instant,
    ) -> ReservationGuard {
        self.install_reservation(content_hash, seen_at)
    }
}

#[cfg(test)]
pub(crate) fn instant_to_unix_secs(seen_at: Instant, now_wall: u64, now_instant: Instant) -> u64 {
    if seen_at >= now_instant {
        now_wall
    } else {
        now_wall.saturating_sub(now_instant.duration_since(seen_at).as_secs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> EventId {
        EventId::from_byte_array([byte; 32])
    }

    /// Acquire a reservation, asserting it was a fresh (non-reclaimed) one.
    fn acquire(store: &mut SeenEventStore, content_hash: EventId) -> ReservationGuard {
        match store.reserve(content_hash, Instant::now()) {
            Reservation::Acquired { guard, reclaimed } => {
                assert!(!reclaimed, "expected a fresh reservation");
                guard
            }
            _ => panic!("reservation must be acquired"),
        }
    }

    #[tokio::test]
    async fn released_owner_wakes_waiter_for_retry() {
        let mut store = SeenEventStore::bounded(NonZeroUsize::new(2).unwrap());
        let key = hash(1);
        let owner = acquire(&mut store, key);
        let Reservation::Wait(mut waiter) = store.reserve(key, Instant::now()) else {
            panic!("concurrent reservation must wait");
        };

        store.release(&key);
        // The wake is the owner's guard dropping, not the release itself.
        assert!(
            waiter.has_changed().is_ok(),
            "the completion channel outlives the release"
        );
        drop(owner);
        assert!(waiter.changed().await.is_err(), "the channel closes");
        let _retry = acquire(&mut store, key);
    }

    #[tokio::test]
    async fn terminal_owner_wakes_waiter_as_duplicate() {
        let mut store = SeenEventStore::bounded(NonZeroUsize::new(2).unwrap());
        let key = hash(2);
        let owner = acquire(&mut store, key);
        let Reservation::Wait(mut waiter) = store.reserve(key, Instant::now()) else {
            panic!("concurrent reservation must wait");
        };

        store.mark_terminal(key, Instant::now());
        drop(owner);
        assert!(waiter.changed().await.is_err(), "the channel closes");
        assert!(matches!(
            store.reserve(key, Instant::now()),
            Reservation::Duplicate
        ));
    }

    /// #370: an owner that vanishes mid-reservation (a panic between acquiring
    /// it and resolving it) must not strand the entry in flight forever.
    #[tokio::test]
    async fn abandoned_owner_wakes_waiter_and_the_reservation_is_reclaimed() {
        let mut store = SeenEventStore::bounded(NonZeroUsize::new(2).unwrap());
        let key = hash(3);
        let owner = acquire(&mut store, key);
        let Reservation::Wait(mut waiter) = store.reserve(key, Instant::now()) else {
            panic!("concurrent reservation must wait");
        };

        // No release, no mark_terminal: the owner simply ceases to exist.
        drop(owner);

        assert!(
            waiter.changed().await.is_err(),
            "the vanished owner must wake its waiters instead of hanging them"
        );
        assert!(
            matches!(
                store.reserve(key, Instant::now()),
                Reservation::Acquired {
                    reclaimed: true,
                    ..
                }
            ),
            "the retry must reclaim the abandoned reservation"
        );
    }

    #[test]
    fn abandoned_reservation_does_not_hold_a_slot_against_a_newcomer() {
        let mut store = SeenEventStore::bounded(NonZeroUsize::new(2).unwrap());
        drop(acquire(&mut store, hash(1)));
        drop(acquire(&mut store, hash(2)));

        // Both slots look in flight, but neither has an owner left.
        let _newcomer = acquire(&mut store, hash(3));
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn abandoned_reservation_expires_with_the_retention_window() {
        let mut store = SeenEventStore::bounded(NonZeroUsize::new(2).unwrap());
        let abandoned = hash(1);
        let live = hash(2);
        let reserved_at = Instant::now();

        drop(store.put_reservation(abandoned, reserved_at));
        let _owner = store.put_reservation(live, reserved_at);

        let expired = store.expired_keys(reserved_at + DEDUP_WINDOW, DEDUP_WINDOW);
        assert_eq!(
            expired,
            vec![abandoned],
            "cleanup reclaims abandoned reservations and never live ones"
        );
    }

    #[tokio::test]
    async fn capacity_pressure_evicts_terminal_state_not_in_flight_reservation() {
        let mut store = SeenEventStore::bounded(NonZeroUsize::new(2).unwrap());
        let in_flight = hash(1);
        let terminal = hash(2);
        let newcomer = hash(3);

        let owner = acquire(&mut store, in_flight);
        let Reservation::Wait(mut waiter) = store.reserve(in_flight, Instant::now()) else {
            panic!("concurrent reservation must wait");
        };
        assert!(store.mark_terminal(terminal, Instant::now()));

        let _newcomer_owner = acquire(&mut store, newcomer);
        assert!(
            waiter.has_changed().is_ok(),
            "the in-flight owner's completion channel must remain open"
        );

        store.mark_terminal(in_flight, Instant::now());
        drop(owner);
        assert!(waiter.changed().await.is_err(), "the channel closes");
        assert!(matches!(
            store.reserve(in_flight, Instant::now()),
            Reservation::Duplicate
        ));
    }

    #[test]
    fn all_in_flight_capacity_fails_closed_without_evicting_an_owner() {
        let mut store = SeenEventStore::bounded(NonZeroUsize::new(2).unwrap());
        let first = hash(1);
        let second = hash(2);

        let _first_owner = acquire(&mut store, first);
        let _second_owner = acquire(&mut store, second);
        assert!(matches!(
            store.reserve(hash(3), Instant::now()),
            Reservation::AtCapacity
        ));
        assert!(
            !store.mark_terminal(hash(4), Instant::now()),
            "terminal fallback must not evict an in-flight owner"
        );
        assert!(matches!(
            store.reserve(first, Instant::now()),
            Reservation::Wait(_)
        ));
    }

    #[test]
    fn test_only_store_helpers_cover_reservation_and_terminal_state() {
        let now = Instant::now();
        let mut store = SeenEventStore::bounded(NonZeroUsize::new(2).unwrap());

        let _owner = store.put_reservation(hash(1), now);
        store.put_terminal(hash(2), now);

        assert!(matches!(store.reserve(hash(1), now), Reservation::Wait(_)));
        assert!(matches!(
            store.reserve(hash(2), now),
            Reservation::Duplicate
        ));
        assert!(store.contains_terminal(&hash(2)));
    }
}

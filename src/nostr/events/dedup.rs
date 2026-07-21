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
    Acquired,
    /// The content hash already reached a terminal local outcome.
    Duplicate,
    /// Another task is processing the same content hash. Waiting for the
    /// receiver to change and then retrying avoids losing the trigger if that
    /// owner later releases a transient reservation.
    Wait(watch::Receiver<bool>),
    /// Every cache slot is occupied by an in-flight reservation.
    ///
    /// The validated relationship between event-processing concurrency and
    /// dedup capacity makes this unreachable in normal operation. Keeping an
    /// explicit fail-closed result prevents a future caller from evicting a
    /// live reservation and admitting a duplicate notification.
    AtCapacity,
}

enum EntryState {
    InFlight(watch::Sender<bool>),
    Terminal,
}

struct SeenTrigger {
    seen_at: Instant,
    state: EntryState,
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
        if let Some(entry) = self.entries.peek(&content_hash) {
            return match &entry.state {
                EntryState::Terminal => Reservation::Duplicate,
                EntryState::InFlight(completed) => Reservation::Wait(completed.subscribe()),
            };
        }

        if !self.make_room_without_evicting_in_flight() {
            return Reservation::AtCapacity;
        }

        let (completed, _receiver) = watch::channel(false);
        self.entries.put(
            content_hash,
            SeenTrigger {
                seen_at: now,
                state: EntryState::InFlight(completed),
            },
        );
        Reservation::Acquired
    }

    /// Ensure one slot is available, evicting only terminal state.
    ///
    /// `LruCache::put` evicts the LRU entry without considering its state. A
    /// still-active reservation must remain resident so concurrent duplicates
    /// keep waiting on the same owner instead of re-acquiring after its watch
    /// channel is dropped.
    fn make_room_without_evicting_in_flight(&mut self) -> bool {
        if self.entries.len() < self.entries.cap().get() {
            return true;
        }

        let terminal_victim = self.entries.iter().rev().find_map(|(content_hash, entry)| {
            matches!(entry.state, EntryState::Terminal).then_some(*content_hash)
        });

        if let Some(content_hash) = terminal_victim {
            self.entries.pop(&content_hash);
            true
        } else {
            false
        }
    }

    pub(crate) fn release(&mut self, content_hash: &EventId) {
        if let Some(entry) = self.entries.pop(content_hash)
            && let EntryState::InFlight(completed) = entry.state
        {
            completed.send_replace(true);
        }
    }

    /// Complete a reservation and wake every concurrent duplicate waiter.
    ///
    /// Returns `true` when the entry was absent and could be inserted. Returns
    /// `false` when the entry already existed or every slot is still in flight.
    pub(crate) fn mark_terminal(&mut self, content_hash: EventId, now: Instant) -> bool {
        if let Some(entry) = self.entries.peek_mut(&content_hash) {
            let prior = std::mem::replace(&mut entry.state, EntryState::Terminal);
            entry.seen_at = now;
            self.entries.promote(&content_hash);
            if let EntryState::InFlight(completed) = prior {
                completed.send_replace(true);
            }
            false
        } else {
            if !self.make_room_without_evicting_in_flight() {
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

    pub(crate) fn expired_keys(&self, now: Instant, retention: Duration) -> Vec<EventId> {
        self.entries
            .iter()
            .rev()
            .take(CLEANUP_BATCH_SIZE)
            .filter(|(_, entry)| {
                matches!(entry.state, EntryState::Terminal)
                    && now.duration_since(entry.seen_at) >= retention
            })
            .map(|(content_hash, _)| *content_hash)
            .collect()
    }

    pub(crate) fn pop(&mut self, content_hash: &EventId) {
        self.entries.pop(content_hash);
    }

    #[cfg(test)]
    pub(crate) fn put(&mut self, content_hash: EventId, seen_event: SeenEvent) {
        let state = if seen_event.terminal {
            EntryState::Terminal
        } else {
            let (completed, _receiver) = watch::channel(false);
            EntryState::InFlight(completed)
        };
        self.entries.put(
            content_hash,
            SeenTrigger {
                seen_at: seen_event.seen_at,
                state,
            },
        );
    }
}

#[cfg(test)]
pub(crate) struct SeenEvent {
    seen_at: Instant,
    terminal: bool,
}

#[cfg(test)]
impl SeenEvent {
    #[allow(dead_code)]
    pub(crate) fn reservation(seen_at: Instant) -> Self {
        Self {
            seen_at,
            terminal: false,
        }
    }

    pub(crate) fn terminal(seen_at: Instant) -> Self {
        Self {
            seen_at,
            terminal: true,
        }
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

    #[tokio::test]
    async fn released_owner_wakes_waiter_for_retry() {
        let mut store = SeenEventStore::bounded(NonZeroUsize::new(2).unwrap());
        let key = hash(1);
        assert!(matches!(
            store.reserve(key, Instant::now()),
            Reservation::Acquired
        ));
        let Reservation::Wait(mut waiter) = store.reserve(key, Instant::now()) else {
            panic!("concurrent reservation must wait");
        };

        store.release(&key);
        waiter.changed().await.unwrap();
        assert!(matches!(
            store.reserve(key, Instant::now()),
            Reservation::Acquired
        ));
    }

    #[tokio::test]
    async fn terminal_owner_wakes_waiter_as_duplicate() {
        let mut store = SeenEventStore::bounded(NonZeroUsize::new(2).unwrap());
        let key = hash(2);
        assert!(matches!(
            store.reserve(key, Instant::now()),
            Reservation::Acquired
        ));
        let Reservation::Wait(mut waiter) = store.reserve(key, Instant::now()) else {
            panic!("concurrent reservation must wait");
        };

        store.mark_terminal(key, Instant::now());
        waiter.changed().await.unwrap();
        assert!(matches!(
            store.reserve(key, Instant::now()),
            Reservation::Duplicate
        ));
    }

    #[tokio::test]
    async fn capacity_pressure_evicts_terminal_state_not_in_flight_reservation() {
        let mut store = SeenEventStore::bounded(NonZeroUsize::new(2).unwrap());
        let in_flight = hash(1);
        let terminal = hash(2);
        let newcomer = hash(3);

        assert!(matches!(
            store.reserve(in_flight, Instant::now()),
            Reservation::Acquired
        ));
        let Reservation::Wait(mut waiter) = store.reserve(in_flight, Instant::now()) else {
            panic!("concurrent reservation must wait");
        };
        assert!(store.mark_terminal(terminal, Instant::now()));

        assert!(matches!(
            store.reserve(newcomer, Instant::now()),
            Reservation::Acquired
        ));
        assert!(
            waiter.has_changed().is_ok(),
            "the in-flight owner's completion channel must remain open"
        );

        store.mark_terminal(in_flight, Instant::now());
        waiter.changed().await.unwrap();
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

        assert!(matches!(
            store.reserve(first, Instant::now()),
            Reservation::Acquired
        ));
        assert!(matches!(
            store.reserve(second, Instant::now()),
            Reservation::Acquired
        ));
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
    fn test_only_seen_event_helpers_cover_reservation_and_terminal_state() {
        let now = Instant::now();
        let mut store = SeenEventStore::bounded(NonZeroUsize::new(2).unwrap());

        store.put(hash(1), SeenEvent::reservation(now));
        store.put(hash(2), SeenEvent::terminal(now));

        assert!(matches!(store.reserve(hash(1), now), Reservation::Wait(_)));
        assert!(matches!(
            store.reserve(hash(2), now),
            Reservation::Duplicate
        ));
    }
}

//! Event-ID deduplication and durable replay state.

use std::collections::HashMap;
use std::fs::{self, OpenOptions as StdOpenOptions};
use std::num::NonZeroUsize;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use lru::LruCache;
use nostr_sdk::prelude::*;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::defaults::DEFAULT_DEDUP_RETENTION_SECS;
use crate::error::Result;

pub(crate) const DEDUP_WINDOW: Duration = Duration::from_secs(DEFAULT_DEDUP_RETENTION_SECS);

pub(crate) const CLEANUP_BATCH_SIZE: usize = 1000;

#[derive(Clone, Copy)]
pub(crate) struct SeenEvent {
    seen_at: Instant,
    terminal: bool,
}

impl SeenEvent {
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

pub(crate) enum SeenEventStore {
    Bounded(LruCache<EventId, SeenEvent>),
    Retained(HashMap<EventId, SeenEvent>),
}

impl SeenEventStore {
    pub(crate) fn bounded(cache_size: NonZeroUsize) -> Self {
        Self::Bounded(LruCache::new(cache_size))
    }

    pub(crate) fn retained() -> Self {
        Self::Retained(HashMap::new())
    }

    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Bounded(seen) => seen.len(),
            Self::Retained(seen) => seen.len(),
        }
    }

    pub(crate) fn contains(&self, event_id: &EventId) -> bool {
        match self {
            Self::Bounded(seen) => seen.contains(event_id),
            Self::Retained(seen) => seen.contains_key(event_id),
        }
    }

    pub(crate) fn put(&mut self, event_id: EventId, seen_event: SeenEvent) {
        match self {
            Self::Bounded(seen) => {
                seen.put(event_id, seen_event);
            }
            Self::Retained(seen) => {
                seen.insert(event_id, seen_event);
            }
        }
    }

    pub(crate) fn pop(&mut self, event_id: &EventId) {
        match self {
            Self::Bounded(seen) => {
                seen.pop(event_id);
            }
            Self::Retained(seen) => {
                seen.remove(event_id);
            }
        }
    }

    /// Refresh an existing reservation into a terminal entry in place.
    ///
    /// On the success hot path the ID is already present from `try_reserve`, so
    /// this mutates its `SeenEvent` (new `seen_at`, `terminal = true`) instead of
    /// re-inserting a fresh value. Returns `true` when the set size changed
    /// (i.e. the entry was absent and had to be inserted — e.g. an entry evicted
    /// by LRU pressure between reservation and completion), so the caller only
    /// pays a `dedup_cache_size` gauge write when the length actually moved. This
    /// removes the redundant second gauge update the double-lock success path
    /// carried (#197) while preserving the completion-timestamp-refresh and
    /// terminal-flip semantics `mark_seen` provided.
    pub(crate) fn mark_terminal(&mut self, event_id: EventId, seen_at: Instant) -> bool {
        match self {
            Self::Bounded(seen) => {
                if let Some(existing) = seen.peek_mut(&event_id) {
                    *existing = SeenEvent::terminal(seen_at);
                    // Promote to most-recently-used to match the prior `put`
                    // behavior, which refreshed LRU position on completion.
                    seen.promote(&event_id);
                    false
                } else {
                    seen.put(event_id, SeenEvent::terminal(seen_at));
                    true
                }
            }
            Self::Retained(seen) => seen
                .insert(event_id, SeenEvent::terminal(seen_at))
                .is_none(),
        }
    }

    pub(crate) fn expired_keys(&self, now: Instant, retention: Duration) -> Vec<EventId> {
        match self {
            Self::Bounded(seen) => seen
                .iter()
                .rev()
                .take(CLEANUP_BATCH_SIZE)
                .filter(|(_, seen_event)| now.duration_since(seen_event.seen_at) >= retention)
                .map(|(id, _)| *id)
                .collect(),
            Self::Retained(seen) => seen
                .iter()
                .filter(|(_, seen_event)| now.duration_since(seen_event.seen_at) >= retention)
                .map(|(id, _)| *id)
                .collect(),
        }
    }

    pub(crate) fn terminal_entries(
        &self,
        now_wall: u64,
        now_instant: Instant,
    ) -> Vec<(EventId, u64)> {
        match self {
            Self::Bounded(seen) => seen
                .iter()
                .filter_map(|(event_id, seen_event)| {
                    if seen_event.terminal {
                        Some((
                            *event_id,
                            instant_to_unix_secs(seen_event.seen_at, now_wall, now_instant),
                        ))
                    } else {
                        None
                    }
                })
                .collect(),
            Self::Retained(seen) => seen
                .iter()
                .filter_map(|(event_id, seen_event)| {
                    if seen_event.terminal {
                        Some((
                            *event_id,
                            instant_to_unix_secs(seen_event.seen_at, now_wall, now_instant),
                        ))
                    } else {
                        None
                    }
                })
                .collect(),
        }
    }
}

pub(crate) struct PersistentDedupState {
    pub(crate) path: PathBuf,
    pub(crate) write_lock: Mutex<()>,
}

impl PersistentDedupState {
    pub(crate) fn new(path: PathBuf) -> Result<Self> {
        Self::prepare_path(&path)?;
        Ok(Self {
            path,
            write_lock: Mutex::new(()),
        })
    }

    pub(crate) fn prepare_path(path: &Path) -> Result<()> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }

        let mut options = StdOpenOptions::new();
        options.create(true).append(true).read(true);
        #[cfg(unix)]
        options.mode(0o600);
        let _file = options.open(path)?;

        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    pub(crate) fn load_seen_events(path: &Path, retention: Duration) -> Result<SeenEventStore> {
        Self::prepare_path(path)?;

        let now_wall = Timestamp::now().as_secs();
        let now_instant = Instant::now();
        let mut seen = SeenEventStore::retained();
        let contents = fs::read_to_string(path)?;

        for line in contents.lines() {
            let mut fields = line.split_whitespace();
            let (Some(event_id_hex), Some(seen_at_secs), None) =
                (fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            let Ok(event_id) = EventId::from_hex(event_id_hex) else {
                continue;
            };
            let Ok(seen_at_secs) = seen_at_secs.parse::<u64>() else {
                continue;
            };
            let age = now_wall.saturating_sub(seen_at_secs);
            if age > retention.as_secs() {
                continue;
            }
            let seen_at = now_instant
                .checked_sub(Duration::from_secs(age))
                .unwrap_or(now_instant);
            seen.put(event_id, SeenEvent::terminal(seen_at));
        }

        Ok(seen)
    }

    pub(crate) async fn append_seen_locked(
        &self,
        event_id: EventId,
        seen_at_secs: u64,
    ) -> std::io::Result<()> {
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await?;
        #[cfg(unix)]
        tokio::fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600)).await?;
        file.write_all(format!("{} {}\n", event_id.to_hex(), seen_at_secs).as_bytes())
            .await?;
        file.flush().await
    }

    pub(crate) async fn rewrite_locked(&self, entries: &[(EventId, u64)]) -> std::io::Result<()> {
        let tmp_path = self.path.with_extension("tmp");
        let mut contents = String::new();
        for (event_id, seen_at_secs) in entries {
            use std::fmt::Write as _;
            let _ = writeln!(&mut contents, "{} {}", event_id.to_hex(), seen_at_secs);
        }
        tokio::fs::write(&tmp_path, contents).await?;
        #[cfg(unix)]
        tokio::fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600)).await?;
        tokio::fs::rename(&tmp_path, &self.path).await
    }
}

pub(crate) fn instant_to_unix_secs(seen_at: Instant, now_wall: u64, now_instant: Instant) -> u64 {
    let age = now_instant
        .checked_duration_since(seen_at)
        .unwrap_or_default()
        .as_secs();
    now_wall.saturating_sub(age)
}

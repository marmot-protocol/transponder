use std::num::NonZeroUsize;
use std::sync::Arc;

use lru::LruCache;
use nostr::error::Error;
use nostr::event::{Event, EventId};
use nostr_database::NostrDatabase;
use nostr_gossip::NostrGossip;
use tokio::sync::Mutex;

use crate::authenticator::Authenticator;
use crate::monitor::Monitor;
use crate::policy::AdmitPolicy;
use crate::transport::websocket::WebSocketTransport;

// LruCache pre-allocate, so keep this at a reasonable value.
// A good value may be <= 128k.
const MAX_VERIFICATION_CACHE_SIZE: usize = 128_000;

#[derive(Debug, Clone)]
pub(crate) struct SharedState {
    pub(crate) database: Arc<dyn NostrDatabase>,
    pub(crate) transport: Arc<dyn WebSocketTransport>,
    pub(crate) gossip: Option<Arc<dyn NostrGossip>>,
    verification_cache: Arc<Mutex<LruCache<EventId, ()>>>,
    pub(crate) admit_policy: Option<Arc<dyn AdmitPolicy>>,
    pub(crate) authenticator: Option<Arc<dyn Authenticator>>,
    pub(crate) monitor: Option<Monitor>,
}

impl SharedState {
    pub(crate) fn new(
        database: Arc<dyn NostrDatabase>,
        transport: Arc<dyn WebSocketTransport>,
        gossip: Option<Arc<dyn NostrGossip>>,
        admit_policy: Option<Arc<dyn AdmitPolicy>>,
        authenticator: Option<Arc<dyn Authenticator>>,
        monitor: Option<Monitor>,
    ) -> Self {
        let max_verification_cache_size: NonZeroUsize =
            NonZeroUsize::new(MAX_VERIFICATION_CACHE_SIZE)
                .expect("MAX_VERIFICATION_CACHE_SIZE must be greater than 0");

        Self {
            database,
            transport,
            gossip,
            verification_cache: Arc::new(Mutex::new(LruCache::new(max_verification_cache_size))),
            admit_policy,
            authenticator,
            monitor,
        }
    }

    #[inline]
    pub(crate) fn database(&self) -> &Arc<dyn NostrDatabase> {
        &self.database
    }

    #[inline]
    pub(crate) fn is_authenticator_available(&self) -> bool {
        self.authenticator.is_some()
    }

    /// Check if the event was already verified or verify it.
    ///
    /// This is useful if someone continues to send the same invalid event:
    /// since invalid events aren't stored in the database,
    /// skipping this check would result in the re-verification of the event.
    /// This may also be useful to avoid double verification if the event is received at the exact same time by many different Relay instances.
    ///
    /// This is important since event signature verification is a heavy job!
    pub(crate) async fn verify_and_cache(&self, event: &Event) -> Result<(), Error> {
        let mut cache = self.verification_cache.lock().await;

        // Full IDs avoid treating a hash collision as proof of event verification.
        if cache.contains(&event.id) {
            return Ok(());
        }

        // We now verify the event
        // If the event verification fails, the cache is not populated
        event.verify()?;

        // Event is verified, so we can cache it.
        cache.put(event.id, ());

        Ok(())
    }
}

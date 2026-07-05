//! Shared cached-credential machinery for the push provider clients.
//!
//! APNs and FCM each need a short-lived provider credential (an ES256 JWT and
//! an OAuth2 access token respectively) that is expensive to mint, safe to
//! reuse until expiry, and occasionally rejected by the provider. This module
//! owns the caching/invalidation semantics once so the two clients cannot
//! drift (issue #158):
//!
//! - [`AuthTokenGenerator`] is the provider-specific mint step.
//! - [`TokenCache`] wraps a generator with a read-lock fast path and a
//!   single-flight refresh that runs *outside* the cache write lock, so
//!   readers keep serving a still-valid token while a refresh is in flight
//!   (issue #86) and concurrent misses coalesce into a single mint.
//! - [`TokenCache::invalidate_if_matches`] evicts a provider-rejected
//!   credential only while it is still the cached one. *Whether* a rejection
//!   is credential-related is decided by the caller: APNs must parse the 403
//!   `reason` first and evict only for provider-token reasons (issue #145),
//!   while an FCM 401 is unambiguous and always evicts.

use std::time::{Duration, SystemTime};

use tokio::sync::{Mutex, RwLock};
use tracing::debug;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::Error;
use crate::push::retry::SendAttemptResult;

/// A freshly minted provider credential and the time it should be evicted
/// from the cache.
pub(crate) struct MintedToken {
    /// The credential material.
    pub(crate) token: Zeroizing<String>,
    /// Cache eviction deadline (already including any provider-reported
    /// lifetime and safety margin).
    pub(crate) expires_at: SystemTime,
}

/// Outcome of a credential mint attempt, classified for push retry handling.
///
/// Minting can fail permanently (misconfiguration, credential rejection) or
/// transiently (endpoint 429/5xx or a transport failure); the send path maps
/// the latter to a retriable attempt result instead of dropping the
/// notification (see PR #209 / issue #83).
#[derive(Debug)]
pub(crate) enum TokenAcquisitionError {
    /// Configuration, credential, or non-retriable provider rejection.
    Permanent(Error),
    /// Transient endpoint or transport failure.
    Retriable {
        /// The HTTP status that triggered the failure (0 for transport
        /// errors that never produced a response).
        status_code: u16,
        /// Optional provider-supplied backpressure hint.
        retry_after: Option<Duration>,
    },
}

impl TokenAcquisitionError {
    /// Build a permanent (non-retriable) acquisition failure.
    pub(crate) fn permanent(err: Error) -> Self {
        Self::Permanent(err)
    }

    /// Convert into the equivalent send-attempt classification.
    pub(crate) fn into_send_attempt(self) -> SendAttemptResult {
        match self {
            Self::Permanent(error) => SendAttemptResult::Permanent(error),
            Self::Retriable {
                status_code,
                retry_after,
            } => SendAttemptResult::Retriable {
                status_code,
                retry_after,
            },
        }
    }
}

/// Provider-specific credential mint step.
pub(crate) trait AuthTokenGenerator {
    /// Mint a fresh credential.
    ///
    /// Runs outside the cache write lock, so it may safely perform network
    /// IO; [`TokenCache`] guarantees at most one mint per cache is in flight
    /// at a time.
    async fn mint(&self) -> Result<MintedToken, TokenAcquisitionError>;
}

/// Cached provider credential.
#[derive(Zeroize, ZeroizeOnDrop)]
struct CachedToken {
    token: Zeroizing<String>,
    #[zeroize(skip)]
    expires_at: SystemTime,
}

/// Cached-credential store shared by the push clients.
pub(crate) struct TokenCache<G> {
    generator: G,
    cached: RwLock<Option<CachedToken>>,
    /// Single-flight refresh guard.
    ///
    /// A refreshing task holds this mutex — NOT the `cached` write lock —
    /// across the mint (which may be a network round-trip), and takes the
    /// write lock only briefly to store the result. Readers therefore keep
    /// serving a still-valid cached token during a refresh (issue #86), and
    /// concurrent cache misses queue here and coalesce onto the refreshed
    /// value via the double-check instead of minting redundantly.
    refresh: Mutex<()>,
}

impl<G> TokenCache<G> {
    /// Create an empty cache around a provider-specific generator.
    pub(crate) fn new(generator: G) -> Self {
        Self {
            generator,
            cached: RwLock::new(None),
            refresh: Mutex::new(()),
        }
    }

    /// The provider-specific generator (for configuration checks).
    pub(crate) fn generator(&self) -> &G {
        &self.generator
    }

    /// Return a clone of the cached credential if it is still valid.
    async fn read_valid(&self) -> Option<Zeroizing<String>> {
        let cached = self.cached.read().await;
        cached
            .as_ref()
            .filter(|token| token.expires_at > SystemTime::now())
            .map(|token| token.token.clone())
    }

    /// Invalidate the cached credential only if it still matches the one the
    /// failing request used.
    ///
    /// Under concurrency another task may have already refreshed the cache
    /// with a fresh credential between the time the failing request read its
    /// token and the time the provider rejection came back. Evicting
    /// unconditionally would discard that valid credential and force a
    /// redundant mint, so the eviction is gated on the cached entry still
    /// being the failing token.
    pub(crate) async fn invalidate_if_matches(&self, failing_token: &str) {
        let mut cached = self.cached.write().await;
        if cached
            .as_ref()
            .is_some_and(|token| token.token.as_str() == failing_token)
        {
            *cached = None;
            debug!("Invalidated cached provider credential after authentication rejection");
        }
    }
}

impl<G: AuthTokenGenerator> TokenCache<G> {
    /// Get a valid credential, minting a fresh one if the cache is empty or
    /// expired.
    ///
    /// The caller receives a short-lived zeroizing clone for request
    /// construction while the cache owns the reusable copy.
    pub(crate) async fn get(&self) -> Result<Zeroizing<String>, TokenAcquisitionError> {
        // Fast path: serve the cached credential under the read lock.
        if let Some(token) = self.read_valid().await {
            return Ok(token);
        }

        // Slow path: single-flight refresh. Concurrent misses queue on the
        // refresh mutex; the mint itself runs without holding the cache
        // write lock so readers are never blocked behind network IO.
        let _refresh_guard = self.refresh.lock().await;

        // Double-check: a concurrent task may have finished a refresh while
        // this one waited for the refresh guard.
        if let Some(token) = self.read_valid().await {
            return Ok(token);
        }

        let minted = self.generator.mint().await?;
        let outbound = minted.token.clone();
        let mut cached = self.cached.write().await;
        *cached = Some(CachedToken {
            token: minted.token,
            expires_at: minted.expires_at,
        });
        Ok(outbound)
    }
}

#[cfg(test)]
impl<G> TokenCache<G> {
    /// Mutable access to the generator for test configuration.
    pub(crate) fn generator_mut(&mut self) -> &mut G {
        &mut self.generator
    }

    /// Seed the cache with a credential (test setup).
    pub(crate) async fn seed(&self, token: &str, expires_at: SystemTime) {
        let mut cached = self.cached.write().await;
        *cached = Some(CachedToken {
            token: Zeroizing::new(token.to_owned()),
            expires_at,
        });
    }

    /// The currently cached credential value, if any (test inspection).
    pub(crate) async fn cached_token_value(&self) -> Option<String> {
        let cached = self.cached.read().await;
        cached.as_ref().map(|token| token.token.as_str().to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;
    use tokio::sync::Semaphore;

    /// Stub generator producing `token-1`, `token-2`, ... with a configurable
    /// TTL, an optional gate blocking the mint, and an optional number of
    /// initial failures.
    struct StubGenerator {
        mints: Arc<AtomicU32>,
        gate: Option<Arc<Semaphore>>,
        fail_first: u32,
        ttl: Duration,
    }

    impl StubGenerator {
        fn new() -> Self {
            Self {
                mints: Arc::new(AtomicU32::new(0)),
                gate: None,
                fail_first: 0,
                ttl: Duration::from_secs(3600),
            }
        }
    }

    impl AuthTokenGenerator for StubGenerator {
        async fn mint(&self) -> Result<MintedToken, TokenAcquisitionError> {
            if let Some(gate) = &self.gate {
                let permit = gate.acquire().await.expect("gate closed");
                permit.forget();
            }
            let n = self.mints.fetch_add(1, Ordering::SeqCst) + 1;
            if n <= self.fail_first {
                return Err(TokenAcquisitionError::permanent(Error::Fcm(format!(
                    "mint failure {n}"
                ))));
            }
            Ok(MintedToken {
                token: Zeroizing::new(format!("token-{n}")),
                expires_at: SystemTime::now() + self.ttl,
            })
        }
    }

    #[test]
    fn test_minted_and_cached_tokens_store_credentials_in_zeroizing_strings() {
        // Compile-time guard: cached credentials must stay zeroizing.
        fn assert_zeroizing_string(_: &Zeroizing<String>) {}

        let minted = MintedToken {
            token: Zeroizing::new("minted-credential".to_string()),
            expires_at: SystemTime::now(),
        };
        let cached = CachedToken {
            token: Zeroizing::new("cached-credential".to_string()),
            expires_at: SystemTime::now(),
        };

        assert_zeroizing_string(&minted.token);
        assert_zeroizing_string(&cached.token);
    }

    #[tokio::test]
    async fn test_get_mints_once_and_serves_cached_token() {
        let generator = StubGenerator::new();
        let mints = generator.mints.clone();
        let cache = TokenCache::new(generator);

        let first = cache.get().await.unwrap();
        let second = cache.get().await.unwrap();

        assert_eq!(first.as_str(), "token-1");
        assert_eq!(second.as_str(), "token-1");
        assert_eq!(mints.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_get_remints_after_expiry() {
        let generator = StubGenerator::new();
        let mints = generator.mints.clone();
        let cache = TokenCache::new(generator);

        cache
            .seed("expired-token", SystemTime::now() - Duration::from_secs(1))
            .await;

        let token = cache.get().await.unwrap();

        assert_eq!(token.as_str(), "token-1");
        assert_eq!(mints.load(Ordering::SeqCst), 1);
        assert_eq!(cache.cached_token_value().await.as_deref(), Some("token-1"));
    }

    #[tokio::test]
    async fn test_concurrent_misses_coalesce_into_a_single_mint() {
        // Block the mint behind a gate, fire several concurrent gets, then
        // release the gate: exactly one mint must run, and every waiter must
        // resolve to that one minted token via the double-check.
        let gate = Arc::new(Semaphore::new(0));
        let mut generator = StubGenerator::new();
        generator.gate = Some(gate.clone());
        let mints = generator.mints.clone();
        let cache = Arc::new(TokenCache::new(generator));

        let mut tasks = Vec::new();
        for _ in 0..5 {
            let cache = cache.clone();
            tasks.push(tokio::spawn(async move {
                cache.get().await.map(|token| token.as_str().to_owned())
            }));
        }

        // Let every task reach either the mint gate or the refresh mutex.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(mints.load(Ordering::SeqCst), 0, "mint should be gated");

        // Enough permits for every task to mint if single-flight were broken.
        gate.add_permits(5);

        for task in tasks {
            let token = task.await.unwrap().unwrap();
            assert_eq!(token, "token-1");
        }
        assert_eq!(
            mints.load(Ordering::SeqCst),
            1,
            "concurrent misses must coalesce into one mint"
        );
    }

    #[tokio::test]
    async fn test_readers_are_not_blocked_while_a_refresh_is_in_flight() {
        // Regression guard for issue #86: the mint must run WITHOUT holding
        // the cache write lock. Here a refresh is blocked mid-mint, and both
        // a cache write (seed) and a fast-path read must still complete.
        let gate = Arc::new(Semaphore::new(0));
        let mut generator = StubGenerator::new();
        generator.gate = Some(gate.clone());
        let mints = generator.mints.clone();
        let cache = Arc::new(TokenCache::new(generator));

        cache
            .seed("expired-token", SystemTime::now() - Duration::from_secs(1))
            .await;

        // Task A misses and blocks inside mint (holding only the refresh
        // mutex).
        let refresher = {
            let cache = cache.clone();
            tokio::spawn(async move { cache.get().await.map(|t| t.as_str().to_owned()) })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!refresher.is_finished());

        // If mint ran under the write lock, this seed (a write) and the
        // subsequent read would deadlock until the gate opened. Bound them
        // with timeouts to prove they complete during the in-flight refresh.
        tokio::time::timeout(
            Duration::from_millis(200),
            cache.seed("valid-token", SystemTime::now() + Duration::from_secs(3600)),
        )
        .await
        .expect("cache write must not block behind an in-flight mint");

        let served = tokio::time::timeout(Duration::from_millis(200), cache.get())
            .await
            .expect("fast-path read must not block behind an in-flight mint")
            .unwrap();
        assert_eq!(served.as_str(), "valid-token");

        // Release the refresher; it stores its minted token afterwards.
        gate.add_permits(1);
        let refreshed = refresher.await.unwrap().unwrap();
        assert_eq!(refreshed, "token-1");
        assert_eq!(mints.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_mint_error_propagates_and_next_get_retries() {
        let mut generator = StubGenerator::new();
        generator.fail_first = 1;
        let mints = generator.mints.clone();
        let cache = TokenCache::new(generator);

        let error = cache.get().await.unwrap_err();
        assert!(matches!(error, TokenAcquisitionError::Permanent(_)));
        assert_eq!(cache.cached_token_value().await, None);

        // A failed mint must not poison the cache: the next get mints again.
        let token = cache.get().await.unwrap();
        assert_eq!(token.as_str(), "token-2");
        assert_eq!(mints.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_invalidate_if_matches_evicts_only_the_failing_token() {
        let cache = TokenCache::new(StubGenerator::new());
        cache
            .seed("fresh-token", SystemTime::now() + Duration::from_secs(3600))
            .await;

        // A stale rejection (for a token another task already replaced) must
        // NOT evict the fresh credential.
        cache.invalidate_if_matches("stale-token").await;
        assert_eq!(
            cache.cached_token_value().await.as_deref(),
            Some("fresh-token")
        );

        // A rejection for the cached credential itself evicts it.
        cache.invalidate_if_matches("fresh-token").await;
        assert_eq!(cache.cached_token_value().await, None);
    }

    #[tokio::test]
    async fn test_invalidate_on_empty_cache_is_a_no_op() {
        let cache = TokenCache::new(StubGenerator::new());
        cache.invalidate_if_matches("anything").await;
        assert_eq!(cache.cached_token_value().await, None);
    }

    #[tokio::test]
    async fn test_waiter_reuses_token_minted_by_the_refresh_it_waited_on() {
        // Two tasks race a miss. The second must not re-mint after the first
        // stores its token: the double-check under the refresh mutex serves
        // the fresh value.
        let gate = Arc::new(Semaphore::new(0));
        let mut generator = StubGenerator::new();
        generator.gate = Some(gate.clone());
        let mints = generator.mints.clone();
        let cache = Arc::new(TokenCache::new(generator));

        let first = {
            let cache = cache.clone();
            tokio::spawn(async move { cache.get().await.map(|t| t.as_str().to_owned()) })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        let second = {
            let cache = cache.clone();
            tokio::spawn(async move { cache.get().await.map(|t| t.as_str().to_owned()) })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;

        gate.add_permits(2);

        assert_eq!(first.await.unwrap().unwrap(), "token-1");
        assert_eq!(second.await.unwrap().unwrap(), "token-1");
        assert_eq!(mints.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_token_acquisition_error_converts_to_send_attempt() {
        let permanent = TokenAcquisitionError::permanent(Error::Apns("bad".to_string()));
        assert!(matches!(
            permanent.into_send_attempt(),
            SendAttemptResult::Permanent(Error::Apns(_))
        ));

        let retriable = TokenAcquisitionError::Retriable {
            status_code: 503,
            retry_after: Some(Duration::from_secs(5)),
        };
        assert!(matches!(
            retriable.into_send_attempt(),
            SendAttemptResult::Retriable {
                status_code: 503,
                retry_after: Some(delay),
            } if delay == Duration::from_secs(5)
        ));
    }
}

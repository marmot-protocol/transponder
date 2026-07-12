//! Gift-wrapped notification event processing.

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use lru::LruCache;
use nostr_sdk::prelude::*;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tokio::time::Instant;
use tracing::{debug, trace, warn};

use super::admission::{
    AdmissionGuard, AdmittedCharges, InFlightEventGuard, ProcessOutcome, StageTimer,
    platform_metric_label,
};
use super::dedup::{
    CLEANUP_BATCH_SIZE, DEDUP_WINDOW, PersistentDedupState, SeenEvent, SeenEventStore,
};
use crate::crypto::{Nip59Handler, TokenDecryptor, TokenPayload};
use crate::defaults::{
    DEFAULT_GLOBAL_UNWRAP_LIMIT_PER_HOUR, DEFAULT_GLOBAL_UNWRAP_LIMIT_PER_MINUTE, DEFAULT_MAX_SIZE,
    DEFAULT_MAX_TOKENS_PER_EVENT, DEFAULT_RATE_LIMIT_PER_HOUR, DEFAULT_RATE_LIMIT_PER_MINUTE,
};
use crate::defaults::{
    DEFAULT_MAX_DEDUP_CACHE_SIZE, DEFAULT_MAX_NOTIFICATION_AGE_SECS,
    DEFAULT_MAX_NOTIFICATION_FUTURE_SKEW_SECS,
};
use crate::error::{Error, Result};
use crate::metrics::{EventOutcome, Metrics, OperationOutcome};
use crate::push::PushDispatcher;
use crate::rate_limiter::{RateLimitConfig, RateLimiter};

const FUTURE_NOTIFICATION_ERROR: &str = "Notification request timestamp is too far in the future";
const STALE_NOTIFICATION_ERROR: &str = "Notification request timestamp is stale";

/// Event processor for handling incoming gift-wrapped notifications.
pub struct EventProcessor {
    nip59_handler: Nip59Handler,
    token_decryptor: TokenDecryptor,
    push_dispatcher: Arc<PushDispatcher>,
    /// Event ID replay-protection state.
    seen_events: Arc<RwLock<SeenEventStore>>,
    /// Volatile per-token terminal replay state keyed by event ID plus the
    /// encrypted-token hash. This lets a mixed event stay retryable for tokens
    /// that were transiently shed while skipping siblings that already reached
    /// terminal local processing.
    terminal_tokens: Arc<RwLock<LruCache<[u8; 32], Instant>>>,
    /// Optional durable event-ID replay state.
    dedup_persistence: Option<Arc<PersistentDedupState>>,
    /// How long event IDs remain in replay state.
    dedup_retention: Duration,
    /// Maximum accepted age for the unwrapped notification rumor.
    max_notification_age: Duration,
    /// Tolerated sender/server clock skew for future-dated notification rumors.
    max_notification_future_skew: Duration,
    /// Global pre-unwrap admission limiter.
    ///
    /// Checked BEFORE the gift-wrap unwrap (ECDH + seal decryption) using a
    /// single fixed key so it acts as a cheap global throttle. The server's
    /// pubkey is public, so anyone can flood it with valid gift wraps; this
    /// budget sheds that traffic before spending asymmetric-crypto cycles.
    global_unwrap_limiter: RateLimiter<()>,
    /// Encrypted token rate limiter.
    encrypted_token_limiter: RateLimiter<[u8; 32]>,
    /// Device token rate limiter.
    device_token_limiter: RateLimiter<[u8; 32]>,
    /// Maximum encrypted tokens accepted in a single event.
    max_tokens_per_event: usize,
    metrics: Metrics,
}

struct AdmittedToken {
    charges: AdmittedCharges,
    replay_key: [u8; 32],
}

/// Configuration for token rate limiting.
///
/// The size fields are [`NonZeroUsize`] so a zero cache capacity or token
/// limit is unrepresentable here: production config rejects zeros at load
/// time with named-field errors instead of constructors silently substituting
/// defaults (`max_cache_size`) or rejecting every notification event
/// (`max_tokens_per_event`).
#[derive(Debug, Clone, Copy)]
pub struct TokenRateLimitConfig {
    /// Maximum entries in each rate limit cache.
    pub max_cache_size: NonZeroUsize,
    /// Maximum encrypted tokens accepted in a single event.
    pub max_tokens_per_event: NonZeroUsize,
    /// Max encrypted token requests per minute.
    pub encrypted_token_per_minute: u32,
    /// Max encrypted token requests per hour.
    pub encrypted_token_per_hour: u32,
    /// Max device token requests per minute.
    pub device_token_per_minute: u32,
    /// Max device token requests per hour.
    pub device_token_per_hour: u32,
    /// Global max gift-wrap unwraps (ECDH) per minute, across all senders.
    pub global_unwrap_per_minute: u32,
    /// Global max gift-wrap unwraps (ECDH) per hour, across all senders.
    pub global_unwrap_per_hour: u32,
}

impl Default for TokenRateLimitConfig {
    fn default() -> Self {
        Self {
            max_cache_size: NonZeroUsize::new(DEFAULT_MAX_SIZE)
                .expect("DEFAULT_MAX_SIZE is non-zero"),
            max_tokens_per_event: NonZeroUsize::new(DEFAULT_MAX_TOKENS_PER_EVENT)
                .expect("DEFAULT_MAX_TOKENS_PER_EVENT is non-zero"),
            encrypted_token_per_minute: DEFAULT_RATE_LIMIT_PER_MINUTE,
            encrypted_token_per_hour: DEFAULT_RATE_LIMIT_PER_HOUR,
            device_token_per_minute: DEFAULT_RATE_LIMIT_PER_MINUTE,
            device_token_per_hour: DEFAULT_RATE_LIMIT_PER_HOUR,
            global_unwrap_per_minute: DEFAULT_GLOBAL_UNWRAP_LIMIT_PER_MINUTE,
            global_unwrap_per_hour: DEFAULT_GLOBAL_UNWRAP_LIMIT_PER_HOUR,
        }
    }
}

impl TokenRateLimitConfig {
    /// Build from a validated [`crate::config::ServerConfig`].
    ///
    /// Size fields are validated as non-zero at config load time.
    #[must_use]
    pub fn from_server_config(server: &crate::config::ServerConfig) -> Self {
        Self {
            max_cache_size: NonZeroUsize::new(server.max_rate_limit_cache_size)
                .expect("server.max_rate_limit_cache_size validated non-zero"),
            max_tokens_per_event: NonZeroUsize::new(server.max_tokens_per_event)
                .expect("server.max_tokens_per_event validated non-zero"),
            encrypted_token_per_minute: server.encrypted_token_rate_limit_per_minute,
            encrypted_token_per_hour: server.encrypted_token_rate_limit_per_hour,
            device_token_per_minute: server.device_token_rate_limit_per_minute,
            device_token_per_hour: server.device_token_rate_limit_per_hour,
            global_unwrap_per_minute: server.global_unwrap_rate_limit_per_minute,
            global_unwrap_per_hour: server.global_unwrap_rate_limit_per_hour,
        }
    }
}

/// Replay-protection configuration for event IDs and notification freshness.
#[derive(Debug, Clone)]
pub struct ReplayProtectionConfig {
    /// Maximum in-memory event IDs retained for duplicate suppression when
    /// durable replay state is disabled.
    ///
    /// When `dedup_state_path` is set, all terminal event IDs inside
    /// `dedup_retention` are kept so durable replay state covers the full relay
    /// lookback window instead of being capped by this LRU size.
    ///
    /// `NonZeroUsize` so a zero capacity is unrepresentable here: production
    /// config rejects `server.max_dedup_cache_size = 0` at load time with a
    /// named-field error instead of the constructor silently substituting the
    /// default.
    pub max_dedup_cache_size: NonZeroUsize,
    /// Optional durable replay-state path.
    ///
    /// The file stores only public Nostr gift-wrap event IDs and the time they
    /// reached a terminal state. It does not store tokens, payloads, sender
    /// identities, device identifiers, or relay URLs.
    pub dedup_state_path: Option<PathBuf>,
    /// How long event IDs remain eligible for duplicate suppression.
    pub dedup_retention: Duration,
    /// Maximum accepted age for the unwrapped kind:446 notification rumor.
    ///
    /// Set to zero to disable the freshness bound.
    pub max_notification_age: Duration,
    /// Tolerated future clock skew for the unwrapped notification rumor.
    pub max_notification_future_skew: Duration,
}

impl Default for ReplayProtectionConfig {
    fn default() -> Self {
        Self {
            max_dedup_cache_size: NonZeroUsize::new(DEFAULT_MAX_DEDUP_CACHE_SIZE)
                .expect("DEFAULT_MAX_DEDUP_CACHE_SIZE is non-zero"),
            dedup_state_path: None,
            dedup_retention: DEDUP_WINDOW,
            max_notification_age: Duration::from_secs(DEFAULT_MAX_NOTIFICATION_AGE_SECS),
            max_notification_future_skew: Duration::from_secs(
                DEFAULT_MAX_NOTIFICATION_FUTURE_SKEW_SECS,
            ),
        }
    }
}

impl ReplayProtectionConfig {
    /// Build from a validated [`crate::config::ServerConfig`].
    #[must_use]
    pub fn from_server_config(server: &crate::config::ServerConfig) -> Self {
        let dedup_state_path = if server.dedup_state_path.as_os_str().is_empty() {
            None
        } else {
            Some(server.dedup_state_path.clone())
        };

        Self {
            max_dedup_cache_size: NonZeroUsize::new(server.max_dedup_cache_size)
                .expect("server.max_dedup_cache_size validated non-zero"),
            dedup_state_path,
            dedup_retention: Duration::from_secs(server.dedup_retention_secs),
            max_notification_age: Duration::from_secs(server.max_notification_age_secs),
            max_notification_future_skew: Duration::from_secs(
                server.max_notification_future_skew_secs,
            ),
        }
    }
}

impl EventProcessor {
    /// Create a new event processor with full replay-protection configuration.
    pub fn with_replay_config(
        nip59_handler: Nip59Handler,
        token_decryptor: TokenDecryptor,
        push_dispatcher: Arc<PushDispatcher>,
        rate_limit_config: TokenRateLimitConfig,
        replay_config: ReplayProtectionConfig,
        metrics: Metrics,
    ) -> Result<Self> {
        // `max_dedup_cache_size` is `NonZeroUsize`, so the previous silent
        // zero-to-default substitution is unrepresentable.
        let cache_size = replay_config.max_dedup_cache_size;
        let terminal_token_cache_size = NonZeroUsize::new(
            cache_size
                .get()
                .saturating_mul(rate_limit_config.max_tokens_per_event.get())
                .max(1),
        )
        .expect("token replay cache size is non-zero");

        let (seen_events, dedup_persistence) = if let Some(path) = replay_config.dedup_state_path {
            let seen =
                PersistentDedupState::load_seen_events(&path, replay_config.dedup_retention)?;
            (
                Arc::new(RwLock::new(seen)),
                Some(Arc::new(PersistentDedupState::new(path)?)),
            )
        } else {
            (
                Arc::new(RwLock::new(SeenEventStore::bounded(cache_size))),
                None,
            )
        };

        Ok(Self {
            nip59_handler,
            token_decryptor,
            push_dispatcher,
            seen_events,
            terminal_tokens: Arc::new(RwLock::new(LruCache::new(terminal_token_cache_size))),
            dedup_persistence,
            dedup_retention: replay_config.dedup_retention,
            max_notification_age: replay_config.max_notification_age,
            max_notification_future_skew: replay_config.max_notification_future_skew,
            // A single fixed `()` key, so capacity of 1 entry is sufficient.
            global_unwrap_limiter: RateLimiter::new(RateLimitConfig {
                max_per_minute: rate_limit_config.global_unwrap_per_minute,
                max_per_hour: rate_limit_config.global_unwrap_per_hour,
                max_entries: NonZeroUsize::MIN,
            }),
            encrypted_token_limiter: RateLimiter::new(RateLimitConfig {
                max_per_minute: rate_limit_config.encrypted_token_per_minute,
                max_per_hour: rate_limit_config.encrypted_token_per_hour,
                max_entries: rate_limit_config.max_cache_size,
            }),
            device_token_limiter: RateLimiter::new(RateLimitConfig {
                max_per_minute: rate_limit_config.device_token_per_minute,
                max_per_hour: rate_limit_config.device_token_per_hour,
                max_entries: rate_limit_config.max_cache_size,
            }),
            max_tokens_per_event: rate_limit_config.max_tokens_per_event.get(),
            metrics,
        })
    }

    /// Process an incoming event.
    ///
    /// Returns `Ok(true)` if the event was processed and marked seen.
    ///
    /// Returns `Ok(false)` if the event was already seen or if processing
    /// failed and the failure was logged/recorded. Processing failures are not
    /// propagated so the event loop can continue with later events.
    pub async fn process(&self, event: &Event) -> Result<bool> {
        let _in_flight = InFlightEventGuard::new(&self.metrics);
        let started_at = StageTimer::start();

        // Record event received
        self.metrics.record_event_received();

        // Logged at trace, not info: the kind:1059 event ID is a stable,
        // public correlation handle. Emitting it per-event at info would
        // persist delivery-timing metadata in logs (and downstream log
        // shipping) — exactly what this privacy-preserving server avoids.
        trace!(event_id = %event.id, "Received Nostr notification event");

        // Cheap duplicate fast path before the global admission gate. This
        // preserves duplicate-vs-shed metric fidelity without making a unique
        // flood take the event-dedup write lock before the cheap global
        // throttle.
        if self.contains_seen(&event.id).await {
            trace!("Skipping duplicate event");
            self.metrics.record_event_deduplicated();
            self.metrics.observe_event_processing_duration(
                EventOutcome::Duplicate,
                started_at.elapsed_secs(),
            );

            return Ok(false);
        }

        // Global pre-unwrap admission control.
        //
        // Checked BEFORE the expensive NIP-59 gift-wrap unwrap (ECDH + seal
        // decryption) and before the event-ID write reservation. The server
        // pubkey is public and gift wraps are sender-anonymous, so a cheap
        // GLOBAL throttle is the correct first write-free admission control for
        // unique-ID floods. When the budget is exceeded we shed the event
        // without unwrapping and without touching dedup state.
        let admission = self.global_unwrap_limiter.check_and_increment(&()).await;
        if !admission.is_allowed() {
            trace!(
                reason = admission.limit_reason(),
                "Shed event before unwrap (global admission control)"
            );
            self.metrics.record_event_shed();
            self.metrics
                .observe_event_processing_duration(EventOutcome::Shed, started_at.elapsed_secs());

            return Ok(false);
        }

        // Atomically reserve the event ID after admission.
        //
        // The reservation (check-and-mark) happens under a single write-lock
        // critical section so concurrent deliveries of the same event ID — now
        // possible because the event loop in `main.rs` processes events in
        // bounded-concurrency spawned tasks — cannot both pass the dedup gate
        // and dispatch duplicate notifications. A concurrent duplicate can
        // still race past the read-only fast path above; this reserve remains
        // the authoritative check. The reservation is rolled back
        // (`release_reservation`) on transient failures so those events remain
        // eligible for retry, preserving the prior "not marked seen on
        // transient failure" semantics.
        if !self.try_reserve(event.id).await {
            trace!("Skipping duplicate event");
            self.metrics.record_event_deduplicated();
            self.metrics.observe_event_processing_duration(
                EventOutcome::Duplicate,
                started_at.elapsed_secs(),
            );

            return Ok(false);
        }

        // Process the event
        match self.process_inner(event).await {
            Ok(ProcessOutcome::Admitted) => {
                // Refresh the seen timestamp now that processing succeeded, so
                // the dedup window is measured from completion. The reservation
                // taken above already keeps the event marked seen.
                self.mark_seen(event.id).await;

                // Logged at trace, not info: emitting a per-event success line
                // at the default level persists delivery-timing metadata in
                // logs (and downstream log shipping). The recipient fan-out
                // count is intentionally omitted — it is already captured in
                // Prometheus via `observe_notifications_admitted_per_event`.
                trace!("Processed notification event");

                self.metrics.record_event_processed();
                self.metrics.observe_event_processing_duration(
                    EventOutcome::Processed,
                    started_at.elapsed_secs(),
                );

                Ok(true)
            }
            Ok(ProcessOutcome::RateLimitedShed) => {
                // Every token was shed purely by a momentary per-token budget.
                // Mirror the global-shed path: this is transient back-pressure,
                // not a permanent result. Release the reservation so a relay
                // redelivery after the rate window resets is not dropped as a
                // duplicate, and do NOT count it as processed.
                self.release_reservation(&event.id).await;
                trace!("Shed event (all tokens per-token rate limited)");
                self.metrics.record_event_rate_limited();
                self.metrics.observe_event_processing_duration(
                    EventOutcome::RateLimited,
                    started_at.elapsed_secs(),
                );

                Ok(false)
            }
            Err(e) => {
                if Self::is_permanent_error(&e) {
                    // Permanent failures stay marked seen (via the reservation)
                    // so replays short-circuit as duplicates.
                    self.mark_seen(event.id).await;
                } else {
                    // Transient failures release the reservation so the event
                    // can be retried on a later delivery.
                    self.release_reservation(&event.id).await;
                }

                // Log but don't propagate - we want to continue processing other events
                warn!(error = %e, "Failed to process event");
                self.metrics.record_event_failed();
                self.metrics.observe_event_processing_duration(
                    EventOutcome::Failed,
                    started_at.elapsed_secs(),
                );

                Ok(false)
            }
        }
    }

    /// Returns true when an event failed in a way replaying it cannot fix.
    fn is_permanent_error(error: &Error) -> bool {
        match error {
            Error::Crypto(_) => true,
            Error::InvalidToken(message) => message != FUTURE_NOTIFICATION_ERROR,
            Error::Config(_)
            | Error::Nostr(_)
            | Error::Apns(_)
            | Error::Fcm(_)
            | Error::Dispatch(_)
            | Error::Io(_)
            | Error::Http(_)
            | Error::Json(_)
            | Error::Jwt(_)
            | Error::Base64(_)
            | Error::Hex(_) => false,
        }
    }

    fn validate_notification_freshness(&self, created_at: Timestamp) -> Result<()> {
        let now = Timestamp::now().as_secs();
        let created_at = created_at.as_secs();
        if created_at > now.saturating_add(self.max_notification_future_skew.as_secs()) {
            return Err(Error::InvalidToken(FUTURE_NOTIFICATION_ERROR.to_string()));
        }

        if !self.max_notification_age.is_zero()
            && now.saturating_sub(created_at) > self.max_notification_age.as_secs()
        {
            return Err(Error::InvalidToken(STALE_NOTIFICATION_ERROR.to_string()));
        }

        Ok(())
    }

    /// Inner processing logic for an event.
    async fn process_inner(&self, event: &Event) -> Result<ProcessOutcome> {
        // Unwrap the gift wrap to get the notification request
        let unwrap_started_at = StageTimer::start();
        let notification = match self.nip59_handler.unwrap(event).await {
            Ok(notification) => {
                self.metrics.observe_gift_wrap_unwrap_duration(
                    OperationOutcome::Success,
                    unwrap_started_at.elapsed_secs(),
                );

                notification
            }
            Err(e) => {
                self.metrics.observe_gift_wrap_unwrap_duration(
                    OperationOutcome::Failed,
                    unwrap_started_at.elapsed_secs(),
                );

                return Err(e);
            }
        };

        self.validate_notification_freshness(notification.created_at)?;

        debug!("Unwrapped notification request");

        // Parse the encrypted tokens from the content
        let parse_started_at = StageTimer::start();
        let token_bytes = match notification.parse_tokens_with_limit(self.max_tokens_per_event) {
            Ok(token_bytes) => {
                self.metrics.observe_notification_parse_duration(
                    OperationOutcome::Success,
                    parse_started_at.elapsed_secs(),
                );
                self.metrics.observe_tokens_per_event(token_bytes.len());
                self.metrics
                    .observe_notification_content_size_bytes(notification.content.len());

                token_bytes
            }
            Err(e) => {
                self.metrics.observe_notification_parse_duration(
                    OperationOutcome::Failed,
                    parse_started_at.elapsed_secs(),
                );

                return Err(e);
            }
        };

        // `parse_tokens_with_limit` rejects empty blobs with `InvalidToken`, so
        // `token_bytes` is non-empty on the `Ok` path; the "nothing admitted"
        // case is handled after the per-token loop.
        debug!(token_count = token_bytes.len(), "Decrypting tokens");

        // Decrypt each token and dispatch notifications, with rate limiting.
        //
        // Rate limiting happens BEFORE decryption intentionally:
        // Prevents wasting CPU on tokens we'll immediately rate-limit anyway.
        let mut payloads = Vec::with_capacity(token_bytes.len());
        let mut admitted_tokens: Vec<AdmittedToken> = Vec::with_capacity(token_bytes.len());
        // Track whether any token remains retryable due to transient per-token
        // rate limiting. Terminal sibling tokens are recorded in
        // `terminal_tokens` and skipped on redelivery, so they no longer force
        // the whole event into terminal event-ID dedup state.
        let mut rate_limited_any = false;
        for bytes in token_bytes {
            let encrypted_key = Self::hash_bytes(&bytes);
            let token_replay_key = Self::token_replay_key(&event.id, &encrypted_key);
            if self.token_is_terminal(&token_replay_key).await {
                trace!("Skipping token already terminal for this event");
                continue;
            }

            // Rate limit check 1: encrypted token (replay protection)
            let encrypted_result = self
                .encrypted_token_limiter
                .check_and_increment(&encrypted_key)
                .await;
            if encrypted_result.admission_evicted() {
                self.metrics
                    .record_rate_limit_admission_eviction("encrypted_token");
            }
            self.publish_rate_limit_gauge("encrypted_token", encrypted_result.sampled_cache_len());
            if !encrypted_result.is_allowed() {
                rate_limited_any = true;
                trace!(
                    reason = encrypted_result.limit_reason(),
                    "Rate limited encrypted token"
                );
                self.metrics
                    .record_rate_limited("encrypted_token", encrypted_result.limit_reason());

                continue;
            }
            let encrypted_reservation = encrypted_result
                .reservation()
                .expect("allowed encrypted-token admission must carry a reservation");
            // The encrypted-token limiter has now been charged. From here every
            // exit path must resolve this guard: refund on a device reject or an
            // undispatchable-token drop, keep on decrypt failure, commit on full
            // admission. This is the fix for the #170 stranded encrypted charge.
            let mut guard = AdmissionGuard::new(
                &self.encrypted_token_limiter,
                &self.device_token_limiter,
                encrypted_key,
                encrypted_reservation,
            );

            // The pre-unwrap global limiter charges once per event before
            // NIP-59 unwrap. Token decrypt also performs asymmetric ECDH, so
            // charge the same global budget once per actual decrypt attempt as
            // well. If the budget is exhausted, refund the encrypted-token
            // charge for this token and leave this plus the remaining tokens
            // retryable; distinct garbage blobs should not amplify one admitted
            // event into unbounded token-decrypt CPU.
            let decrypt_admission = self.global_unwrap_limiter.check_and_increment(&()).await;
            if !decrypt_admission.is_allowed() {
                guard.refund().await;
                rate_limited_any = true;
                trace!(
                    reason = decrypt_admission.limit_reason(),
                    "Rate limited token decrypt attempt"
                );
                self.metrics
                    .record_rate_limited("global_decrypt", decrypt_admission.limit_reason());

                break;
            }

            // Decrypt the token
            let decrypt_started_at = StageTimer::start();
            let payload = match self.token_decryptor.decrypt_bytes(&bytes) {
                Ok(p) => {
                    self.metrics.record_token_decrypted();
                    self.metrics.observe_token_decrypt_duration(
                        OperationOutcome::Success,
                        decrypt_started_at.elapsed_secs(),
                    );

                    p
                }
                Err(e) => {
                    // Silently ignore invalid tokens per MIP-05 spec.
                    // Keep the encrypted-token rate-limit increment: invalid
                    // encrypted blobs should still spend replay/spam budget.
                    // A decrypt failure is permanent for this token, but not
                    // for transiently-shed siblings in the same event.
                    guard.keep_charge();
                    self.mark_token_terminal(token_replay_key).await;
                    trace!(error = %e, "Failed to decrypt token (ignoring)");
                    self.metrics.record_token_decryption_failed();
                    self.metrics.observe_token_decrypt_duration(
                        OperationOutcome::Failed,
                        decrypt_started_at.elapsed_secs(),
                    );

                    continue;
                }
            };

            // Pre-charge dispatch filter (#177): the platform/token is only known
            // after decrypt, but it is known BEFORE the device-token limiter is
            // charged. If the dispatcher could not send this token — its platform
            // is unconfigured, or (FCM) the token bytes are not UTF-8 — drop it
            // now, refunding the encrypted charge (no device charge yet) and
            // recording a real drop metric, instead of letting `dispatch()` drop
            // it silently after both limiters were charged.
            if !self.push_dispatcher.accepts(payload.platform) {
                guard.refund().await;
                self.mark_token_terminal(token_replay_key).await;
                let platform = platform_metric_label(payload.platform);
                trace!(platform, "Dropping token: platform not configured");
                self.metrics.record_push_failed(platform, "unconfigured");

                continue;
            }
            if !PushDispatcher::token_is_encodable(&payload) {
                guard.refund().await;
                self.mark_token_terminal(token_replay_key).await;
                let platform = platform_metric_label(payload.platform);
                trace!(platform, "Dropping token: device token not encodable");
                self.metrics
                    .record_push_failed(platform, "invalid_encoding");

                continue;
            }

            // Rate limit check 2: Is this device token within rate limits?
            let device_key = Self::hash_device_token_key(&payload);
            let device_result = self
                .device_token_limiter
                .check_and_increment(&device_key)
                .await;
            if device_result.admission_evicted() {
                self.metrics
                    .record_rate_limit_admission_eviction("device_token");
            }
            self.publish_rate_limit_gauge("device_token", device_result.sampled_cache_len());
            if !device_result.is_allowed() {
                // The device limiter rejected this token. Refund the encrypted
                // charge already spent for it (#170): without this, the encrypted
                // blob's replay/spam budget was consumed for a token that was
                // never admitted, so a legitimate transient redelivery could read
                // as a replay.
                guard.refund().await;
                rate_limited_any = true;
                trace!(
                    reason = device_result.limit_reason(),
                    "Rate limited device token"
                );
                self.metrics
                    .record_rate_limited("device_token", device_result.limit_reason());

                continue;
            }
            let device_reservation = device_result
                .reservation()
                .expect("allowed device-token admission must carry a reservation");
            guard.add_device_charge(device_key, device_reservation);

            payloads.push(payload);
            // Keep this paired with `payloads`: dispatch admission failure
            // rolls back exactly the rate-limit increments for admitted work.
            admitted_tokens.push(AdmittedToken {
                charges: guard.commit(),
                replay_key: token_replay_key,
            });
        }

        if payloads.is_empty() {
            self.metrics.observe_notifications_admitted_per_event(0);

            // Any transiently rate-limited token keeps the event retryable. Any
            // terminal siblings have token-level terminal state and will be
            // skipped on redelivery.
            if rate_limited_any {
                return Ok(ProcessOutcome::RateLimitedShed);
            }
            return Ok(ProcessOutcome::Admitted);
        }

        // Dispatch notifications
        let dispatch_started_at = StageTimer::start();
        match self.push_dispatcher.dispatch(payloads).await {
            Ok(count) => {
                self.metrics.observe_push_dispatch_admission_duration(
                    OperationOutcome::Success,
                    dispatch_started_at.elapsed_secs(),
                );
                self.metrics.observe_notifications_admitted_per_event(count);

                for admitted in &admitted_tokens {
                    self.mark_token_terminal(admitted.replay_key).await;
                }

                if rate_limited_any {
                    Ok(ProcessOutcome::RateLimitedShed)
                } else {
                    Ok(ProcessOutcome::Admitted)
                }
            }
            Err(e) => {
                for admitted in &admitted_tokens {
                    let charges = &admitted.charges;
                    self.encrypted_token_limiter
                        .rollback_increment(&charges.encrypted_key, charges.encrypted_reservation)
                        .await;
                    self.device_token_limiter
                        .rollback_increment(&charges.device_key, charges.device_reservation)
                        .await;
                }

                self.metrics.observe_push_dispatch_admission_duration(
                    OperationOutcome::Failed,
                    dispatch_started_at.elapsed_secs(),
                );
                self.metrics.observe_notifications_admitted_per_event(0);

                Err(e)
            }
        }
    }

    /// Publish a sampled live rate-limit cache size to the gauge (#125).
    ///
    /// `check_and_increment` returns `Some(len)` on the sampled fraction of
    /// admissions and `None` otherwise, so this refreshes the
    /// `transponder_rate_limit_cache_size` gauge as the cache grows toward
    /// capacity — making saturation onset visible without waiting for the 60s
    /// cleanup tick — while keeping the metric's existing per-`cache_type`
    /// label shape and paying a gauge write only on sampled calls.
    fn publish_rate_limit_gauge(&self, cache_type: &str, sampled_len: Option<usize>) {
        if let Some(len) = sampled_len {
            self.metrics.set_rate_limit_cache_size(cache_type, len);
        }
    }

    /// Hash arbitrary bytes to a fixed-size key for rate limiting.
    fn hash_bytes(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Hash `(event_id, encrypted_token_hash)` into a bounded-cache key.
    fn token_replay_key(event_id: &EventId, encrypted_key: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(event_id.to_hex().as_bytes());
        hasher.update(encrypted_key);
        hasher.finalize().into()
    }

    async fn token_is_terminal(&self, replay_key: &[u8; 32]) -> bool {
        let terminal_tokens = self.terminal_tokens.read().await;
        terminal_tokens.contains(replay_key)
    }

    async fn mark_token_terminal(&self, replay_key: [u8; 32]) {
        let mut terminal_tokens = self.terminal_tokens.write().await;
        terminal_tokens.put(replay_key, Instant::now());
    }

    /// Hash device token key (platform || device_token) for rate limiting.
    fn hash_device_token_key(payload: &TokenPayload) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([payload.platform.as_byte()]);
        hasher.update(&payload.device_token);
        hasher.finalize().into()
    }

    /// Read-only check for event replay state.
    async fn contains_seen(&self, event_id: &EventId) -> bool {
        let seen = self.seen_events.read().await;
        seen.contains(event_id)
    }

    /// Test-facing duplicate check.
    #[cfg(test)]
    async fn is_duplicate(&self, event_id: &EventId) -> bool {
        self.contains_seen(event_id).await
    }

    /// Atomically reserve an event ID for processing.
    ///
    /// Returns `true` if the reservation succeeded (the event was previously
    /// unseen and is now marked seen), or `false` if the event was already
    /// seen/reserved — i.e. a duplicate.
    ///
    /// The check-and-insert happens under a single write-lock critical section
    /// so that concurrent deliveries of the same Nostr event ID (common when
    /// the same event arrives from multiple relays) cannot both observe the
    /// event as unseen. Without this, the bounded-concurrency event loop in
    /// `main.rs` — which spawns a task per event — would let duplicates race
    /// past a non-atomic check-then-mark sequence and dispatch duplicate push
    /// notifications.
    ///
    /// On transient (retryable) processing failure or admission shedding, the
    /// reservation must be released with [`Self::release_reservation`] so the
    /// event can be retried later.
    async fn try_reserve(&self, event_id: EventId) -> bool {
        let mut seen = self.seen_events.write().await;
        if seen.contains(&event_id) {
            return false;
        }
        seen.put(event_id, SeenEvent::reservation(Instant::now()));

        // Update cache size metric
        self.metrics.set_dedup_cache_size(seen.len());

        true
    }

    /// Release a previously reserved event ID.
    ///
    /// Used to roll back a [`Self::try_reserve`] when processing did not reach
    /// a terminal state (transient failure or pre-unwrap admission shedding),
    /// so the event remains eligible for retry. This is the inverse of the
    /// reservation and preserves the prior "not marked seen on transient
    /// failure" semantics.
    async fn release_reservation(&self, event_id: &EventId) {
        let mut seen = self.seen_events.write().await;
        seen.pop(event_id);

        // Update cache size metric
        self.metrics.set_dedup_cache_size(seen.len());
    }

    /// Refresh the seen timestamp for an already-reserved event.
    ///
    /// Called when processing reaches a terminal state (success or permanent
    /// failure) to keep the dedup entry. The entry already exists from
    /// [`Self::try_reserve`]; this updates its timestamp so the dedup window is
    /// measured from completion. Kept distinct from `try_reserve` for clarity
    /// at the call sites.
    async fn mark_seen(&self, event_id: EventId) {
        let now = Instant::now();
        {
            let mut seen = self.seen_events.write().await;
            // Refresh the existing reservation in place. On the success hot path
            // the ID is already present from `try_reserve`, so the size does not
            // change and the redundant second `dedup_cache_size` gauge write the
            // old double-lock path carried is skipped (#197). The gauge is only
            // touched on the rare path where the entry was evicted between
            // reservation and completion and had to be re-inserted.
            let size_changed = seen.mark_terminal(event_id, now);
            if size_changed {
                self.metrics.set_dedup_cache_size(seen.len());
            }
        }

        if let Some(ref state) = self.dedup_persistence {
            let _guard = state.write_lock.lock().await;
            if let Err(e) = state
                .append_seen_locked(event_id, Timestamp::now().as_secs())
                .await
            {
                warn!(
                    error = %e,
                    "Failed to persist event deduplication state"
                );
            }
        }
    }

    /// Clean up all caches by removing expired entries.
    ///
    /// Uses incremental cleanup for volatile LRU state to avoid holding write
    /// locks for extended periods. Durable replay state scans all retained IDs
    /// so the persisted set stays bounded by retention rather than cache size.
    /// Call periodically for full cleanup of all expired entries.
    pub async fn cleanup(&self) {
        // Clean event deduplication cache
        let persistence = self.dedup_persistence.clone();
        let _persistence_guard = if let Some(ref state) = persistence {
            Some(state.write_lock.lock().await)
        } else {
            None
        };

        let (evicted, remaining, retained_entries) = {
            let mut seen = self.seen_events.write().await;
            let now = Instant::now();
            let now_wall = Timestamp::now().as_secs();

            let expired_keys = seen.expired_keys(now, self.dedup_retention);

            for key in &expired_keys {
                seen.pop(key);
            }

            let retained_entries = if persistence.is_some() {
                seen.terminal_entries(now_wall, now)
            } else {
                Vec::new()
            };

            (expired_keys.len(), seen.len(), retained_entries)
        };

        if evicted > 0 {
            let rewrite_result = match persistence.as_ref() {
                Some(state) => state.rewrite_locked(&retained_entries).await,
                None => Ok(()),
            };
            if let Err(e) = rewrite_result {
                warn!(
                    error = %e,
                    "Failed to compact event deduplication state"
                );
            }
        }

        self.metrics.set_dedup_cache_size(remaining);
        if evicted > 0 {
            self.metrics.record_dedup_evictions(evicted);
        }
        if evicted > 0 {
            debug!(
                removed = evicted,
                remaining = remaining,
                "Cleaned up event deduplication cache"
            );
        }

        {
            let mut terminal_tokens = self.terminal_tokens.write().await;
            let now = Instant::now();
            let expired_keys: Vec<_> = terminal_tokens
                .iter()
                .rev()
                .take(CLEANUP_BATCH_SIZE)
                .filter(|(_, seen_at)| now.duration_since(**seen_at) >= self.dedup_retention)
                .map(|(key, _)| *key)
                .collect();
            for key in &expired_keys {
                terminal_tokens.pop(key);
            }
        }

        // Clean global pre-unwrap admission limiter cache.
        // It only holds a single fixed key, but cleaning it keeps the limiter
        // memory bounded and behavior consistent with the other limiters.
        self.global_unwrap_limiter.cleanup().await;

        // Clean encrypted token rate limiter cache
        let encrypted_stats = self.encrypted_token_limiter.cleanup().await;
        self.metrics
            .set_rate_limit_cache_size("encrypted_token", encrypted_stats.remaining);
        if encrypted_stats.evicted > 0 {
            self.metrics
                .record_rate_limit_evictions("encrypted_token", encrypted_stats.evicted);
        }
        if encrypted_stats.evicted > 0 {
            debug!(
                removed = encrypted_stats.evicted,
                remaining = encrypted_stats.remaining,
                "Cleaned up encrypted token rate limit cache"
            );
        }

        // Clean device token rate limiter cache
        let device_stats = self.device_token_limiter.cleanup().await;
        self.metrics
            .set_rate_limit_cache_size("device_token", device_stats.remaining);
        if device_stats.evicted > 0 {
            self.metrics
                .record_rate_limit_evictions("device_token", device_stats.evicted);
        }
        if device_stats.evicted > 0 {
            debug!(
                removed = device_stats.evicted,
                remaining = device_stats.remaining,
                "Cleaned up device token rate limit cache"
            );
        }
    }

    /// Returns the current number of entries in the deduplication cache.
    #[cfg(test)]
    pub fn cache_len(&self) -> usize {
        self.seen_events
            .try_read()
            .map(|guard| guard.len())
            .unwrap_or(0)
    }
}

/// Test-only fluent builder for [`EventProcessor`].
///
/// Production code should use [`EventProcessor::with_replay_config`] directly.
#[cfg(test)]
pub(crate) struct EventProcessorBuilder {
    nip59_handler: Nip59Handler,
    token_decryptor: TokenDecryptor,
    push_dispatcher: Arc<PushDispatcher>,
    rate_limit_config: TokenRateLimitConfig,
    replay_config: ReplayProtectionConfig,
    metrics: Metrics,
}

#[cfg(test)]
impl EventProcessorBuilder {
    pub(crate) fn new(
        nip59_handler: Nip59Handler,
        token_decryptor: TokenDecryptor,
        push_dispatcher: Arc<PushDispatcher>,
    ) -> Self {
        Self {
            nip59_handler,
            token_decryptor,
            push_dispatcher,
            rate_limit_config: TokenRateLimitConfig::default(),
            replay_config: ReplayProtectionConfig::default(),
            metrics: Metrics::disabled(),
        }
    }

    pub(crate) fn max_dedup_cache_size(mut self, size: usize) -> Self {
        self.replay_config.max_dedup_cache_size =
            NonZeroUsize::new(size).expect("dedup cache size must be non-zero");
        self
    }

    pub(crate) fn rate_limit_config(mut self, config: TokenRateLimitConfig) -> Self {
        self.rate_limit_config = config;
        self
    }

    pub(crate) fn replay_config(mut self, config: ReplayProtectionConfig) -> Self {
        self.replay_config = config;
        self
    }

    pub(crate) fn metrics(mut self, metrics: Metrics) -> Self {
        self.metrics = metrics;
        self
    }

    pub(crate) fn build(self) -> EventProcessor {
        EventProcessor::with_replay_config(
            self.nip59_handler,
            self.token_decryptor,
            self.push_dispatcher,
            self.rate_limit_config,
            self.replay_config,
            self.metrics,
        )
        .expect("test EventProcessorBuilder config cannot fail")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ApnsConfig;
    use crate::crypto::Platform;
    use crate::crypto::token::ENCRYPTED_TOKEN_SIZE;
    use crate::defaults::{
        DEFAULT_MAX_NOTIFICATION_AGE_SECS, DEFAULT_MAX_NOTIFICATION_FUTURE_SKEW_SECS,
        DEFAULT_MAX_TOKENS_PER_EVENT,
    };
    use crate::metrics::{EventOutcome, Metrics, OperationOutcome};
    use crate::nostr::events::dedup::{CLEANUP_BATCH_SIZE, DEDUP_WINDOW, instant_to_unix_secs};
    use crate::push::{ApnsClient, PushDispatcher};
    use crate::test_metrics::{
        counter_value, gauge_value as metric_gauge_value,
        histogram_sample_count as histogram_count, histogram_sample_sum,
    };
    use crate::test_support::{default_server_config, server_config_with};
    use crate::test_vectors::scenarios;

    #[test]
    fn token_rate_limit_config_from_server_config_matches_settings() {
        let server = server_config_with(default_server_config(), |server| {
            server.max_rate_limit_cache_size = 1234;
            server.max_tokens_per_event = 25;
            server.encrypted_token_rate_limit_per_minute = 111;
            server.encrypted_token_rate_limit_per_hour = 2222;
            server.device_token_rate_limit_per_minute = 333;
            server.device_token_rate_limit_per_hour = 4444;
            server.max_concurrent_event_processing = 7;
            server.global_unwrap_rate_limit_per_minute = 555;
            server.global_unwrap_rate_limit_per_hour = 6666;
        });

        let rate_limit_config = TokenRateLimitConfig::from_server_config(&server);

        assert_eq!(rate_limit_config.max_cache_size.get(), 1234);
        assert_eq!(rate_limit_config.max_tokens_per_event.get(), 25);
        assert_eq!(rate_limit_config.encrypted_token_per_minute, 111);
        assert_eq!(rate_limit_config.encrypted_token_per_hour, 2222);
        assert_eq!(rate_limit_config.device_token_per_minute, 333);
        assert_eq!(rate_limit_config.device_token_per_hour, 4444);
        assert_eq!(rate_limit_config.global_unwrap_per_minute, 555);
        assert_eq!(rate_limit_config.global_unwrap_per_hour, 6666);
    }

    #[test]
    fn replay_protection_config_from_server_config_matches_settings() {
        let state_path = PathBuf::from("/var/lib/transponder/dedup-events.log");
        let server = server_config_with(default_server_config(), |server| {
            server.max_dedup_cache_size = 77;
            server.dedup_state_path = state_path.clone();
            server.dedup_retention_secs = 88;
            server.max_notification_age_secs = 99;
            server.max_notification_future_skew_secs = 11;
        });

        let replay_config = ReplayProtectionConfig::from_server_config(&server);

        assert_eq!(replay_config.max_dedup_cache_size.get(), 77);
        assert_eq!(replay_config.dedup_state_path, Some(state_path));
        assert_eq!(replay_config.dedup_retention, Duration::from_secs(88));
        assert_eq!(replay_config.max_notification_age, Duration::from_secs(99));
        assert_eq!(
            replay_config.max_notification_future_skew,
            Duration::from_secs(11)
        );
    }

    #[test]
    fn replay_protection_config_from_server_config_disables_empty_state_path() {
        let server = server_config_with(default_server_config(), |server| {
            server.max_dedup_cache_size = 77;
            server.dedup_retention_secs = 88;
            server.max_notification_age_secs = 99;
            server.max_notification_future_skew_secs = 11;
        });

        let replay_config = ReplayProtectionConfig::from_server_config(&server);

        assert_eq!(replay_config.dedup_state_path, None);
    }

    fn gauge_value(metrics: &Metrics, name: &str) -> f64 {
        metric_gauge_value(metrics, name, &[])
    }

    fn create_processor(server_keys: &Keys) -> EventProcessor {
        let nip59_handler = Nip59Handler::new(server_keys.clone());
        let mut secp_secret_key =
            secp256k1::SecretKey::from_slice(&server_keys.secret_key().to_secret_bytes())
                .expect("valid secret key");
        let token_decryptor = TokenDecryptor::new(&mut secp_secret_key);
        let push_dispatcher = Arc::new(PushDispatcher::with_metrics(
            None,
            None,
            Metrics::disabled(),
        ));
        EventProcessorBuilder::new(nip59_handler, token_decryptor, push_dispatcher).build()
    }

    fn create_processor_with_cache_size(server_keys: &Keys, cache_size: usize) -> EventProcessor {
        let nip59_handler = Nip59Handler::new(server_keys.clone());
        let mut secp_secret_key =
            secp256k1::SecretKey::from_slice(&server_keys.secret_key().to_secret_bytes())
                .expect("valid secret key");
        let token_decryptor = TokenDecryptor::new(&mut secp_secret_key);
        let push_dispatcher = Arc::new(PushDispatcher::with_metrics(
            None,
            None,
            Metrics::disabled(),
        ));
        EventProcessorBuilder::new(nip59_handler, token_decryptor, push_dispatcher)
            .max_dedup_cache_size(cache_size)
            .build()
    }

    fn create_processor_with_replay_config(
        server_keys: &Keys,
        replay_config: ReplayProtectionConfig,
    ) -> EventProcessor {
        let nip59_handler = Nip59Handler::new(server_keys.clone());
        let mut secp_secret_key =
            secp256k1::SecretKey::from_slice(&server_keys.secret_key().to_secret_bytes())
                .expect("valid secret key");
        let token_decryptor = TokenDecryptor::new(&mut secp_secret_key);
        let push_dispatcher = Arc::new(PushDispatcher::with_metrics(
            None,
            None,
            Metrics::disabled(),
        ));
        EventProcessorBuilder::new(nip59_handler, token_decryptor, push_dispatcher)
            .replay_config(replay_config)
            .build()
    }

    fn create_processor_with_metrics(server_keys: &Keys) -> (EventProcessor, Metrics) {
        create_processor_with_metrics_and_rate_limits(server_keys, TokenRateLimitConfig::default())
    }

    fn create_processor_with_metrics_and_rate_limits(
        server_keys: &Keys,
        rate_limit_config: TokenRateLimitConfig,
    ) -> (EventProcessor, Metrics) {
        let nip59_handler = Nip59Handler::new(server_keys.clone());
        let mut secp_secret_key =
            secp256k1::SecretKey::from_slice(&server_keys.secret_key().to_secret_bytes())
                .expect("valid secret key");
        let token_decryptor = TokenDecryptor::new(&mut secp_secret_key);
        let apns_config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: crate::config::ApnsEnvironment::Sandbox,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
            alert_title: String::new(),
            alert_body: String::new(),
            collapse_id: String::new(),
        };
        let metrics = Metrics::new().expect("metrics");
        let push_dispatcher = Arc::new(PushDispatcher::with_metrics(
            Some(ApnsClient::mock(apns_config, true)),
            None,
            metrics.clone(),
        ));
        (
            EventProcessorBuilder::new(nip59_handler, token_decryptor, push_dispatcher)
                .rate_limit_config(rate_limit_config)
                .metrics(metrics.clone())
                .build(),
            metrics,
        )
    }

    async fn create_processor_with_shutdown_dispatcher_metrics(
        server_keys: &Keys,
    ) -> (EventProcessor, Metrics) {
        create_processor_with_shutdown_dispatcher_metrics_and_rate_limits(
            server_keys,
            TokenRateLimitConfig::default(),
        )
        .await
    }

    async fn create_processor_with_shutdown_dispatcher_metrics_and_rate_limits(
        server_keys: &Keys,
        rate_limit_config: TokenRateLimitConfig,
    ) -> (EventProcessor, Metrics) {
        let nip59_handler = Nip59Handler::new(server_keys.clone());
        let mut secp_secret_key =
            secp256k1::SecretKey::from_slice(&server_keys.secret_key().to_secret_bytes())
                .expect("valid secret key");
        let token_decryptor = TokenDecryptor::new(&mut secp_secret_key);
        let apns_config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: crate::config::ApnsEnvironment::Sandbox,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
            alert_title: String::new(),
            alert_body: String::new(),
            collapse_id: String::new(),
        };
        let metrics = Metrics::new().expect("metrics");
        let push_dispatcher = Arc::new(PushDispatcher::with_metrics(
            Some(ApnsClient::mock(apns_config, true)),
            None,
            metrics.clone(),
        ));
        push_dispatcher.wait_for_completion().await;

        (
            EventProcessorBuilder::new(nip59_handler, token_decryptor, push_dispatcher)
                .rate_limit_config(rate_limit_config)
                .metrics(metrics.clone())
                .build(),
            metrics,
        )
    }

    #[tokio::test]
    async fn test_process_valid_gift_wrap_event() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let device_token = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        let event =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;

        let processor = create_processor(&server_keys);
        let result = processor.process(&event).await;

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_process_valid_gift_wrap_event_records_metrics() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let device_token = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        let event =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;

        let (processor, metrics) = create_processor_with_metrics(&server_keys);
        let result = processor.process(&event).await;

        assert!(result.is_ok());
        assert!(result.unwrap());
        assert_eq!(
            counter_value(&metrics, "transponder_events_received_total", &[]),
            1.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_events_processed_total", &[]),
            1.0
        );
        assert_eq!(gauge_value(&metrics, "transponder_events_in_flight"), 0.0);
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_event_processing_duration_seconds",
                &[("outcome", EventOutcome::Processed.as_str())],
            ),
            1
        );
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_gift_wrap_unwrap_duration_seconds",
                &[("outcome", OperationOutcome::Success.as_str())],
            ),
            1
        );
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_notification_parse_duration_seconds",
                &[("outcome", OperationOutcome::Success.as_str())],
            ),
            1
        );
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_token_decrypt_duration_seconds",
                &[("outcome", OperationOutcome::Success.as_str())],
            ),
            1
        );
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_push_dispatch_admission_duration_seconds",
                &[("outcome", OperationOutcome::Success.as_str())],
            ),
            1
        );
        assert_eq!(
            histogram_count(&metrics, "transponder_tokens_per_event", &[]),
            1
        );
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_notifications_admitted_per_event",
                &[]
            ),
            1
        );
        // One encrypted token is 1084 bytes, transported as base64 text; the
        // metric records the received content size, not a reconstruction.
        assert_eq!(
            histogram_sample_sum(&metrics, "transponder_notification_content_size_bytes", &[]),
            (ENCRYPTED_TOKEN_SIZE.div_ceil(3) * 4) as f64
        );
    }

    #[tokio::test]
    async fn test_process_deduplicates_same_event() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let event = scenarios::single_apns_notification(
            &server_keys,
            &sender_keys,
            "deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678",
        )
        .await;

        let processor = create_processor(&server_keys);

        // First processing should succeed
        let result1 = processor.process(&event).await;
        assert!(result1.is_ok());
        assert!(result1.unwrap());

        // Second processing of same event should be deduplicated
        let result2 = processor.process(&event).await;
        assert!(result2.is_ok());
        assert!(!result2.unwrap());
    }

    #[tokio::test]
    async fn test_process_duplicate_event_records_metrics() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let event = scenarios::single_apns_notification(
            &server_keys,
            &sender_keys,
            "deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678",
        )
        .await;

        let (processor, metrics) = create_processor_with_metrics(&server_keys);

        assert!(processor.process(&event).await.unwrap());
        assert!(!processor.process(&event).await.unwrap());

        assert_eq!(
            counter_value(&metrics, "transponder_events_received_total", &[]),
            2.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_events_deduplicated_total", &[]),
            1.0
        );
        assert_eq!(gauge_value(&metrics, "transponder_events_in_flight"), 0.0);
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_event_processing_duration_seconds",
                &[("outcome", EventOutcome::Duplicate.as_str())],
            ),
            1
        );
    }

    #[tokio::test]
    async fn test_process_rejects_stale_notification_rumor() {
        use crate::test_vectors::{GiftWrapBuilder, NotificationContentBuilder};

        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let content = NotificationContentBuilder::new(&server_keys)
            .with_apns_token("deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678")
            .build();
        let stale_created_at = Timestamp::from_secs(
            Timestamp::now()
                .as_secs()
                .saturating_sub(DEFAULT_MAX_NOTIFICATION_AGE_SECS + 1),
        );
        let event = GiftWrapBuilder::new(server_keys.clone(), sender_keys)
            .build_with_created_at(&content, stale_created_at)
            .await;

        let (processor, metrics) = create_processor_with_metrics(&server_keys);
        let result = processor.process(&event).await;

        assert!(result.is_ok());
        assert!(!result.unwrap(), "stale notification must not dispatch");
        assert_eq!(
            counter_value(&metrics, "transponder_events_processed_total", &[]),
            0.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_events_failed_total", &[]),
            1.0
        );
        assert_eq!(processor.cache_len(), 1, "stale replays are terminal");
    }

    #[tokio::test]
    async fn test_process_rejects_future_notification_rumor() {
        use crate::test_vectors::{GiftWrapBuilder, NotificationContentBuilder};

        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let content = NotificationContentBuilder::new(&server_keys)
            .with_apns_token("deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678")
            .build();
        // One hour beyond the skew tolerance, not +1s: `process()` re-reads
        // `Timestamp::now()` (1-second granularity) when it validates freshness,
        // so a whole-second wall-clock tick between here and that read would
        // collapse a +1s margin onto the exact threshold (`>` becomes `==`) and
        // spuriously accept the event under load. A large margin exercises the
        // same "created_at exceeds now + skew" rejection path, drift-proof.
        let future_created_at = Timestamp::from_secs(
            Timestamp::now()
                .as_secs()
                .saturating_add(DEFAULT_MAX_NOTIFICATION_FUTURE_SKEW_SECS + 3600),
        );
        let event = GiftWrapBuilder::new(server_keys.clone(), sender_keys)
            .build_with_created_at(&content, future_created_at)
            .await;

        let (processor, metrics) = create_processor_with_metrics(&server_keys);
        let result = processor.process(&event).await;

        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "future-dated notification must not dispatch"
        );
        assert_eq!(
            counter_value(&metrics, "transponder_events_processed_total", &[]),
            0.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_events_failed_total", &[]),
            1.0
        );
        assert_eq!(
            processor.cache_len(),
            0,
            "future-dated replays must stay retryable"
        );

        let replay = processor.process(&event).await;
        assert!(replay.is_ok());
        assert!(!replay.unwrap());
        assert_eq!(
            counter_value(&metrics, "transponder_events_failed_total", &[]),
            2.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_events_deduplicated_total", &[]),
            0.0,
            "future-dated retry must not short-circuit as a duplicate"
        );
    }

    #[tokio::test]
    async fn test_dedup_state_persists_processed_event_across_processors() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let event = scenarios::single_apns_notification(
            &server_keys,
            &sender_keys,
            "deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678",
        )
        .await;
        let dir = tempfile::tempdir().expect("tempdir");
        let state_path = dir.path().join("dedup-state.tsv");

        let processor = create_processor_with_replay_config(
            &server_keys,
            ReplayProtectionConfig {
                dedup_state_path: Some(state_path.clone()),
                ..ReplayProtectionConfig::default()
            },
        );
        assert!(processor.process(&event).await.unwrap());

        let state = std::fs::read_to_string(&state_path).expect("dedup state written");
        assert!(
            state.contains(&event.id.to_hex()),
            "state file must record processed event IDs"
        );

        let restarted = create_processor_with_replay_config(
            &server_keys,
            ReplayProtectionConfig {
                dedup_state_path: Some(state_path),
                ..ReplayProtectionConfig::default()
            },
        );

        assert!(
            !restarted.process(&event).await.unwrap(),
            "a restarted processor must not re-dispatch an event already in durable dedup state"
        );
        assert!(restarted.is_duplicate(&event.id).await);
    }

    #[tokio::test]
    async fn test_durable_dedup_state_is_not_capped_by_lru_size() {
        let server_keys = Keys::generate();
        let dir = tempfile::tempdir().expect("tempdir");
        let state_path = dir.path().join("dedup-state.tsv");
        let replay_config = ReplayProtectionConfig {
            max_dedup_cache_size: NonZeroUsize::new(2).unwrap(),
            dedup_state_path: Some(state_path.clone()),
            ..ReplayProtectionConfig::default()
        };
        let processor = create_processor_with_replay_config(&server_keys, replay_config.clone());
        let event_ids: Vec<_> = (0..5)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0] = i;
                EventId::from_byte_array(bytes)
            })
            .collect();

        for event_id in &event_ids {
            processor.mark_seen(*event_id).await;
        }

        assert_eq!(processor.cache_len(), event_ids.len());
        assert!(processor.is_duplicate(&event_ids[0]).await);

        let restarted = create_processor_with_replay_config(&server_keys, replay_config);
        assert_eq!(restarted.cache_len(), event_ids.len());
        for event_id in event_ids {
            assert!(
                restarted.is_duplicate(&event_id).await,
                "durable replay state must retain every ID inside retention, even past max_dedup_cache_size"
            );
        }
    }

    #[test]
    fn test_dedup_state_loader_ignores_malformed_and_expired_rows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_path = dir.path().join("nested").join("dedup-state.tsv");
        let now = Timestamp::now().as_secs();
        let retained_id = EventId::from_byte_array([1u8; 32]);
        let expired_id = EventId::from_byte_array([2u8; 32]);
        let state = format!(
            "malformed\nnot-an-event-id {}\n{} not-a-timestamp\n{} {}\n{} {} extra\n{} {}\n",
            now,
            retained_id.to_hex(),
            expired_id.to_hex(),
            now.saturating_sub(61),
            EventId::from_byte_array([3u8; 32]).to_hex(),
            now,
            retained_id.to_hex(),
            now
        );
        std::fs::create_dir_all(state_path.parent().expect("state parent")).expect("mkdir");
        std::fs::write(&state_path, state).expect("write state");

        let seen = PersistentDedupState::load_seen_events(&state_path, Duration::from_secs(60))
            .expect("load state");

        assert!(seen.contains(&retained_id));
        assert!(!seen.contains(&expired_id));
        assert_eq!(seen.len(), 1);
    }

    #[tokio::test]
    async fn test_dedup_state_cleanup_compacts_terminal_entries_only() {
        let server_keys = Keys::generate();
        let dir = tempfile::tempdir().expect("tempdir");
        let state_path = dir.path().join("dedup-state.tsv");
        let processor = create_processor_with_replay_config(
            &server_keys,
            ReplayProtectionConfig {
                dedup_state_path: Some(state_path.clone()),
                dedup_retention: Duration::from_secs(1),
                ..ReplayProtectionConfig::default()
            },
        );
        let expired_id = EventId::from_byte_array([4u8; 32]);
        let retained_id = EventId::from_byte_array([5u8; 32]);
        let reserved_id = EventId::from_byte_array([6u8; 32]);

        {
            let mut seen = processor.seen_events.write().await;
            seen.put(
                expired_id,
                SeenEvent::terminal(Instant::now() - Duration::from_secs(2)),
            );
            seen.put(retained_id, SeenEvent::terminal(Instant::now()));
            seen.put(reserved_id, SeenEvent::reservation(Instant::now()));
        }

        processor.cleanup().await;

        let state = std::fs::read_to_string(&state_path).expect("compacted state");
        assert!(state.contains(&retained_id.to_hex()));
        assert!(!state.contains(&expired_id.to_hex()));
        assert!(!state.contains(&reserved_id.to_hex()));
        assert!(processor.is_duplicate(&retained_id).await);
        assert!(!processor.is_duplicate(&expired_id).await);
        assert!(processor.is_duplicate(&reserved_id).await);
    }

    #[tokio::test]
    async fn test_notification_freshness_can_be_disabled() {
        use crate::test_vectors::{GiftWrapBuilder, NotificationContentBuilder};

        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let content = NotificationContentBuilder::new(&server_keys)
            .with_apns_token("deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678")
            .build();
        let stale_created_at = Timestamp::from_secs(
            Timestamp::now()
                .as_secs()
                .saturating_sub(DEFAULT_MAX_NOTIFICATION_AGE_SECS + 1),
        );
        let event = GiftWrapBuilder::new(server_keys.clone(), sender_keys)
            .build_with_created_at(&content, stale_created_at)
            .await;
        let processor = create_processor_with_replay_config(
            &server_keys,
            ReplayProtectionConfig {
                max_notification_age: Duration::ZERO,
                ..ReplayProtectionConfig::default()
            },
        );

        assert!(processor.process(&event).await.unwrap());
    }

    #[test]
    fn future_freshness_error_is_retryable_but_stale_is_permanent() {
        assert!(!EventProcessor::is_permanent_error(&Error::InvalidToken(
            FUTURE_NOTIFICATION_ERROR.to_string()
        )));
        assert!(EventProcessor::is_permanent_error(&Error::InvalidToken(
            STALE_NOTIFICATION_ERROR.to_string()
        )));
    }

    #[tokio::test]
    async fn test_disabled_notification_age_still_rejects_future_rumor() {
        use crate::test_vectors::{GiftWrapBuilder, NotificationContentBuilder};

        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let content = NotificationContentBuilder::new(&server_keys)
            .with_apns_token("deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678")
            .build();
        let future_created_at = Timestamp::from_secs(
            Timestamp::now()
                .as_secs()
                .saturating_add(DEFAULT_MAX_NOTIFICATION_FUTURE_SKEW_SECS + 3600),
        );
        let event = GiftWrapBuilder::new(server_keys.clone(), sender_keys)
            .build_with_created_at(&content, future_created_at)
            .await;
        let processor = create_processor_with_replay_config(
            &server_keys,
            ReplayProtectionConfig {
                max_notification_age: Duration::ZERO,
                ..ReplayProtectionConfig::default()
            },
        );

        assert!(
            !processor.process(&event).await.unwrap(),
            "future skew validation must stay active when stale-age validation is disabled"
        );
    }

    #[test]
    fn test_instant_to_unix_secs_saturates_future_seen_at() {
        let now_instant = Instant::now();
        let now_wall = 123_456;

        assert_eq!(
            instant_to_unix_secs(now_instant + Duration::from_secs(1), now_wall, now_instant),
            now_wall
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_process_concurrent_duplicates_dispatch_once() {
        // Regression test for the dedup race introduced by bounded-concurrency
        // event processing in `main.rs`: the same Nostr event ID can be
        // delivered concurrently (e.g. from multiple relays) and processed in
        // parallel spawned tasks. The dedup check-and-mark must be atomic so
        // exactly one delivery is processed and the rest short-circuit as
        // duplicates, instead of all of them unwrapping and dispatching
        // duplicate push notifications.
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let event = scenarios::single_apns_notification(
            &server_keys,
            &sender_keys,
            "deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678",
        )
        .await;

        let (processor, metrics) = create_processor_with_metrics(&server_keys);
        let processor = Arc::new(processor);

        // Fan out many concurrent processings of the SAME event.
        const CONCURRENCY: usize = 32;
        let mut handles = Vec::with_capacity(CONCURRENCY);
        for _ in 0..CONCURRENCY {
            let processor = Arc::clone(&processor);
            let event = event.clone();
            handles.push(tokio::spawn(async move { processor.process(&event).await }));
        }

        let mut processed_true = 0usize;
        for handle in handles {
            if handle.await.expect("task panicked").expect("process ok") {
                processed_true += 1;
            }
        }

        // Exactly one delivery should report a successful (non-duplicate)
        // processing; every other delivery is deduplicated.
        assert_eq!(
            processed_true, 1,
            "exactly one concurrent delivery must be processed"
        );
        assert_eq!(
            counter_value(&metrics, "transponder_events_processed_total", &[]),
            1.0,
            "the event must be dispatched exactly once across concurrent deliveries"
        );
        assert_eq!(
            counter_value(&metrics, "transponder_events_deduplicated_total", &[]),
            (CONCURRENCY - 1) as f64,
            "all but one concurrent delivery must be deduplicated"
        );
        // Push dispatch admission is recorded once per processed event, so an
        // exactly-once value here proves the expensive unwrap+dispatch path ran
        // only once despite the concurrent flood.
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_notifications_admitted_per_event",
                &[]
            ),
            1,
            "notifications must be admitted/dispatched for exactly one delivery"
        );
        assert_eq!(processor.cache_len(), 1);
    }

    #[tokio::test]
    async fn test_process_different_events_not_deduplicated() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let event1 = scenarios::single_apns_notification(
            &server_keys,
            &sender_keys,
            "aaaa111122223333aaaa111122223333aaaa111122223333aaaa111122223333",
        )
        .await;

        let event2 = scenarios::single_apns_notification(
            &server_keys,
            &sender_keys,
            "bbbb444455556666bbbb444455556666bbbb444455556666bbbb444455556666",
        )
        .await;

        let processor = create_processor(&server_keys);

        let result1 = processor.process(&event1).await;
        let result2 = processor.process(&event2).await;

        assert!(result1.unwrap());
        assert!(result2.unwrap());
    }

    #[tokio::test]
    async fn test_process_wrong_recipient_fails() {
        let server_keys = Keys::generate();
        let wrong_server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let event = scenarios::single_apns_notification(
            &wrong_server_keys,
            &sender_keys,
            "deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678",
        )
        .await;

        let processor = create_processor(&server_keys);
        let result = processor.process(&event).await;

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_process_permanent_failure_is_deduplicated_on_replay() {
        let server_keys = Keys::generate();
        let wrong_server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let event = scenarios::single_apns_notification(
            &wrong_server_keys,
            &sender_keys,
            "deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678",
        )
        .await;

        let (processor, metrics) = create_processor_with_metrics(&server_keys);

        assert!(!processor.process(&event).await.unwrap());
        assert!(!processor.process(&event).await.unwrap());

        assert_eq!(
            counter_value(&metrics, "transponder_events_failed_total", &[]),
            1.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_events_deduplicated_total", &[]),
            1.0
        );
        assert_eq!(processor.cache_len(), 1);
    }

    #[tokio::test]
    async fn test_process_failed_event_records_metrics() {
        let server_keys = Keys::generate();
        let wrong_server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let event = scenarios::single_apns_notification(
            &wrong_server_keys,
            &sender_keys,
            "deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678",
        )
        .await;

        let (processor, metrics) = create_processor_with_metrics(&server_keys);
        let result = processor.process(&event).await;

        assert!(result.is_ok());
        assert!(!result.unwrap());
        assert_eq!(
            counter_value(&metrics, "transponder_events_failed_total", &[]),
            1.0
        );
        assert_eq!(gauge_value(&metrics, "transponder_events_in_flight"), 0.0);
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_event_processing_duration_seconds",
                &[("outcome", EventOutcome::Failed.as_str())],
            ),
            1
        );
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_gift_wrap_unwrap_duration_seconds",
                &[("outcome", OperationOutcome::Failed.as_str())],
            ),
            1
        );
    }

    #[tokio::test]
    async fn test_process_dispatch_failure_records_zero_admissions() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let device_token = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        let event =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;

        let (processor, metrics) =
            create_processor_with_shutdown_dispatcher_metrics(&server_keys).await;
        let result = processor.process(&event).await;

        assert!(result.is_ok());
        assert!(!result.unwrap());
        assert_eq!(
            counter_value(&metrics, "transponder_events_failed_total", &[]),
            1.0
        );
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_push_dispatch_admission_duration_seconds",
                &[("outcome", OperationOutcome::Failed.as_str())],
            ),
            1
        );
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_notifications_admitted_per_event",
                &[]
            ),
            1
        );
        assert_eq!(
            histogram_sample_sum(
                &metrics,
                "transponder_notifications_admitted_per_event",
                &[]
            ),
            0.0
        );
    }

    #[tokio::test]
    async fn test_process_transient_dispatch_failure_is_retryable() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let device_token = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        let event =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;

        let (processor, metrics) =
            create_processor_with_shutdown_dispatcher_metrics(&server_keys).await;

        assert!(!processor.process(&event).await.unwrap());
        assert!(!processor.process(&event).await.unwrap());

        assert_eq!(
            counter_value(&metrics, "transponder_events_failed_total", &[]),
            2.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_events_deduplicated_total", &[]),
            0.0
        );
        assert_eq!(processor.cache_len(), 0);
    }

    #[tokio::test]
    async fn test_process_dispatch_failure_does_not_spend_rate_limit_budget() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let device_token = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        let event =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;

        let (processor, metrics) =
            create_processor_with_shutdown_dispatcher_metrics_and_rate_limits(
                &server_keys,
                TokenRateLimitConfig {
                    max_cache_size: NonZeroUsize::new(100).unwrap(),
                    max_tokens_per_event: NonZeroUsize::new(DEFAULT_MAX_TOKENS_PER_EVENT).unwrap(),
                    encrypted_token_per_minute: 1,
                    encrypted_token_per_hour: 1,
                    device_token_per_minute: 1,
                    device_token_per_hour: 1,
                    global_unwrap_per_minute: 1000,
                    global_unwrap_per_hour: 10000,
                },
            )
            .await;

        assert!(!processor.process(&event).await.unwrap());
        assert!(!processor.process(&event).await.unwrap());

        assert_eq!(
            counter_value(&metrics, "transponder_events_failed_total", &[]),
            2.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_events_processed_total", &[]),
            0.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_events_deduplicated_total", &[]),
            0.0
        );
        assert_eq!(processor.cache_len(), 0);
    }

    #[tokio::test]
    async fn test_rate_limited_event_does_not_dispatch_or_rollback_budget() {
        use crate::test_vectors::{
            GiftWrapBuilder, NotificationContentBuilder, TestToken, TokenEncryptor,
        };
        use base64::prelude::*;

        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let device_token = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        let encryptor = TokenEncryptor::from_keys(&server_keys);
        let encrypted = encryptor.encrypt(&TestToken::apns(device_token));
        let encrypted_key = EventProcessor::hash_bytes(&encrypted);
        let content = NotificationContentBuilder::new(&server_keys)
            .with_raw_token(BASE64_STANDARD.encode(&encrypted))
            .build();
        let event = GiftWrapBuilder::new(server_keys.clone(), sender_keys)
            .build(&content)
            .await;

        let (processor, metrics) =
            create_processor_with_shutdown_dispatcher_metrics_and_rate_limits(
                &server_keys,
                TokenRateLimitConfig {
                    max_cache_size: NonZeroUsize::new(100).unwrap(),
                    max_tokens_per_event: NonZeroUsize::new(DEFAULT_MAX_TOKENS_PER_EVENT).unwrap(),
                    encrypted_token_per_minute: 0,
                    encrypted_token_per_hour: 100,
                    device_token_per_minute: 100,
                    device_token_per_hour: 100,
                    global_unwrap_per_minute: 1000,
                    global_unwrap_per_hour: 10000,
                },
            )
            .await;

        // The single token is shed by the encrypted-token limiter, admitting
        // zero notifications. This is a pure per-token rate shed, so the event
        // is transient back-pressure: `process` returns false and the event is
        // left retryable rather than marked terminally seen.
        assert!(!processor.process(&event).await.unwrap());
        assert_eq!(processor.cache_len(), 0);

        assert_eq!(
            processor
                .encrypted_token_limiter
                .peek_counts(&encrypted_key)
                .await,
            Some((0, 0))
        );
        assert!(processor.device_token_limiter.is_empty().await);
        assert_eq!(
            counter_value(&metrics, "transponder_events_processed_total", &[]),
            0.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_events_rate_limited_total", &[]),
            1.0
        );
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_tokens_rate_limited_total",
                &[("type", "encrypted_token"), ("reason", "minute")],
            ),
            1.0
        );
        assert!(metrics.gather().into_iter().all(|family| {
            family.name() != "transponder_push_dispatch_admission_duration_seconds"
        }));
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_notifications_admitted_per_event",
                &[]
            ),
            1
        );
        assert_eq!(
            histogram_sample_sum(
                &metrics,
                "transponder_notifications_admitted_per_event",
                &[]
            ),
            0.0
        );
    }

    #[tokio::test]
    async fn test_process_empty_token_blob() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let event = scenarios::empty_notification(&server_keys, &sender_keys).await;

        let processor = create_processor(&server_keys);
        let result = processor.process(&event).await;

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_process_empty_token_blob_records_parse_failure_metrics() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let event = scenarios::empty_notification(&server_keys, &sender_keys).await;

        let (processor, metrics) = create_processor_with_metrics(&server_keys);
        let result = processor.process(&event).await;

        assert!(result.is_ok());
        assert!(!result.unwrap());
        assert_eq!(
            counter_value(&metrics, "transponder_events_failed_total", &[]),
            1.0
        );
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_notification_parse_duration_seconds",
                &[("outcome", OperationOutcome::Failed.as_str())],
            ),
            1
        );
    }

    #[tokio::test]
    async fn test_process_invalid_token_failure_is_deduplicated_on_replay() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let event = scenarios::empty_notification(&server_keys, &sender_keys).await;

        let (processor, metrics) = create_processor_with_metrics(&server_keys);

        assert!(!processor.process(&event).await.unwrap());
        assert!(!processor.process(&event).await.unwrap());

        assert_eq!(
            counter_value(&metrics, "transponder_events_failed_total", &[]),
            1.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_events_deduplicated_total", &[]),
            1.0
        );
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_notification_parse_duration_seconds",
                &[("outcome", OperationOutcome::Failed.as_str())],
            ),
            1
        );
        assert_eq!(processor.cache_len(), 1);
    }

    #[tokio::test]
    async fn test_process_multi_token_notification() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let event = scenarios::multi_token_notification(&server_keys, &sender_keys).await;

        let processor = create_processor(&server_keys);
        let result = processor.process(&event).await;

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_process_non_gift_wrap_event_fails() {
        let server_keys = Keys::generate();
        let some_keys = Keys::generate();

        let event = EventBuilder::text_note("Hello, world!")
            .sign_with_keys(&some_keys)
            .unwrap();

        let processor = create_processor(&server_keys);
        let result = processor.process(&event).await;

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_cleanup_removes_old_entries() {
        tokio::time::pause();

        let server_keys = Keys::generate();
        let processor = create_processor(&server_keys);

        // Add an event
        processor.mark_seen(EventId::all_zeros()).await;
        assert!(processor.is_duplicate(&EventId::all_zeros()).await);

        // Cleanup shouldn't remove it (it's recent)
        processor.cleanup().await;
        assert!(processor.is_duplicate(&EventId::all_zeros()).await);

        // Advance time past the dedup window
        tokio::time::advance(DEDUP_WINDOW + Duration::from_secs(1)).await;

        // Now cleanup should remove it
        processor.cleanup().await;
        assert!(!processor.is_duplicate(&EventId::all_zeros()).await);
    }

    #[tokio::test]
    async fn test_fcm_token_processing() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let event = scenarios::single_fcm_notification(
            &server_keys,
            &sender_keys,
            "fcm-device-token-12345",
        )
        .await;

        let processor = create_processor(&server_keys);
        let result = processor.process(&event).await;

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_cache_size_limit_evicts_oldest_entries() {
        let server_keys = Keys::generate();
        let processor = create_processor_with_cache_size(&server_keys, 3);

        let event_ids: Vec<EventId> = (0..5)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0] = i;
                EventId::from_byte_array(bytes)
            })
            .collect();

        for event_id in &event_ids {
            processor.mark_seen(*event_id).await;
        }

        assert_eq!(processor.cache_len(), 3);

        // First two entries should have been evicted (LRU)
        assert!(!processor.is_duplicate(&event_ids[0]).await);
        assert!(!processor.is_duplicate(&event_ids[1]).await);

        // Last three entries should still be present
        assert!(processor.is_duplicate(&event_ids[2]).await);
        assert!(processor.is_duplicate(&event_ids[3]).await);
        assert!(processor.is_duplicate(&event_ids[4]).await);
    }

    #[tokio::test]
    #[should_panic(expected = "dedup cache size must be non-zero")]
    async fn test_cache_size_zero_is_rejected() {
        // A zero dedup cache size is no longer silently swapped for the default:
        // `ReplayProtectionConfig::max_dedup_cache_size` is `NonZeroUsize`, so a
        // zero is unrepresentable. Production config rejects
        // `server.max_dedup_cache_size = 0` at load time before it can reach the
        // constructor (see the config validation tests); this asserts the
        // in-memory construction path cannot be built with a zero either.
        let server_keys = Keys::generate();
        let _ = create_processor_with_cache_size(&server_keys, 0);
    }

    #[tokio::test]
    async fn test_cache_lru_access_updates_order() {
        let server_keys = Keys::generate();
        let processor = create_processor_with_cache_size(&server_keys, 3);

        let event_ids: Vec<EventId> = (0..4)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0] = i;
                EventId::from_byte_array(bytes)
            })
            .collect();

        processor.mark_seen(event_ids[0]).await;
        processor.mark_seen(event_ids[1]).await;
        processor.mark_seen(event_ids[2]).await;

        // Access the first event again (makes it most recently used)
        processor.mark_seen(event_ids[0]).await;

        // Add a 4th event - should evict event_ids[1] (now the LRU)
        processor.mark_seen(event_ids[3]).await;

        assert!(!processor.is_duplicate(&event_ids[1]).await);
        assert!(processor.is_duplicate(&event_ids[0]).await);
        assert!(processor.is_duplicate(&event_ids[2]).await);
        assert!(processor.is_duplicate(&event_ids[3]).await);
    }

    #[tokio::test]
    async fn test_cleanup_processes_limited_entries() {
        tokio::time::pause();

        let server_keys = Keys::generate();
        let processor = create_processor(&server_keys);

        // Add more entries than CLEANUP_BATCH_SIZE
        let num_entries = CLEANUP_BATCH_SIZE + 500;
        let old_time = Instant::now() - DEDUP_WINDOW - Duration::from_secs(1);

        {
            let mut seen = processor.seen_events.write().await;
            for i in 0..num_entries {
                let mut bytes = [0u8; 32];
                bytes[0..4].copy_from_slice(&(i as u32).to_le_bytes());
                let event_id = EventId::from_byte_array(bytes);
                seen.put(event_id, SeenEvent::terminal(old_time));
            }
        }

        assert_eq!(processor.cache_len(), num_entries);

        // Run cleanup once - should only remove up to CLEANUP_BATCH_SIZE entries
        processor.cleanup().await;

        let remaining = processor.cache_len();
        assert!(
            remaining >= num_entries - CLEANUP_BATCH_SIZE,
            "Cleanup removed more than CLEANUP_BATCH_SIZE entries: expected at least {}, got {}",
            num_entries - CLEANUP_BATCH_SIZE,
            remaining
        );

        // Run cleanup again - should remove remaining old entries
        processor.cleanup().await;

        assert_eq!(
            processor.cache_len(),
            0,
            "Expected all expired entries to be removed after two cleanup cycles"
        );
    }

    #[tokio::test]
    async fn test_cleanup_scans_stale_lru_entries_first() {
        tokio::time::pause();

        let server_keys = Keys::generate();
        let processor = create_processor(&server_keys);
        let old_time = Instant::now() - DEDUP_WINDOW - Duration::from_secs(1);
        let recent_time = Instant::now();
        let stale_count = 10;
        let recent_count = CLEANUP_BATCH_SIZE;

        let event_id = |i: usize| {
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&(i as u32).to_le_bytes());
            EventId::from_byte_array(bytes)
        };
        let stale_ids: Vec<_> = (0..stale_count).map(event_id).collect();
        let recent_ids: Vec<_> = (stale_count..stale_count + recent_count)
            .map(event_id)
            .collect();

        {
            let mut seen = processor.seen_events.write().await;
            for event_id in &stale_ids {
                seen.put(*event_id, SeenEvent::terminal(old_time));
            }
            for event_id in &recent_ids {
                seen.put(*event_id, SeenEvent::terminal(recent_time));
            }
        }

        assert_eq!(processor.cache_len(), stale_count + recent_count);

        processor.cleanup().await;

        assert_eq!(
            processor.cache_len(),
            recent_count,
            "Expected cleanup to reclaim stale entries from the LRU end"
        );
        for event_id in stale_ids {
            assert!(!processor.is_duplicate(&event_id).await);
        }
        for event_id in recent_ids {
            assert!(processor.is_duplicate(&event_id).await);
        }
    }

    #[tokio::test]
    async fn test_cleanup_preserves_recent_entries() {
        tokio::time::pause();

        let server_keys = Keys::generate();
        let processor = create_processor(&server_keys);

        let old_time = Instant::now() - DEDUP_WINDOW - Duration::from_secs(1);
        let recent_time = Instant::now();

        {
            let mut seen = processor.seen_events.write().await;

            // Add some old entries
            for i in 0..100 {
                let mut bytes = [0u8; 32];
                bytes[0..4].copy_from_slice(&(i as u32).to_le_bytes());
                let event_id = EventId::from_byte_array(bytes);
                seen.put(event_id, SeenEvent::terminal(old_time));
            }

            // Add some recent entries
            for i in 100..150 {
                let mut bytes = [0u8; 32];
                bytes[0..4].copy_from_slice(&(i as u32).to_le_bytes());
                let event_id = EventId::from_byte_array(bytes);
                seen.put(event_id, SeenEvent::terminal(recent_time));
            }
        }

        assert_eq!(processor.cache_len(), 150);

        // Cleanup should remove old entries but keep recent ones
        processor.cleanup().await;

        assert_eq!(
            processor.cache_len(),
            50,
            "Expected 50 recent entries to remain after cleanup"
        );
    }

    // === Rate Limiting Integration Tests ===

    fn create_processor_with_rate_limits(
        server_keys: &Keys,
        rate_limit_config: TokenRateLimitConfig,
    ) -> EventProcessor {
        let nip59_handler = Nip59Handler::new(server_keys.clone());
        let mut secp_secret_key =
            secp256k1::SecretKey::from_slice(&server_keys.secret_key().to_secret_bytes())
                .expect("valid secret key");
        let token_decryptor = TokenDecryptor::new(&mut secp_secret_key);
        // Wire a configured APNs mock so APNs tokens are genuinely dispatchable.
        // With no client the #177 pre-charge filter would (correctly) drop and
        // refund every APNs token as "unconfigured", so the device/encrypted
        // rate-limit paths these helpers exercise would never actually charge.
        let apns_config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: crate::config::ApnsEnvironment::Sandbox,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
            alert_title: String::new(),
            alert_body: String::new(),
            collapse_id: String::new(),
        };
        let push_dispatcher = Arc::new(PushDispatcher::with_metrics(
            Some(ApnsClient::mock(apns_config, true)),
            None,
            Metrics::disabled(),
        ));
        EventProcessorBuilder::new(nip59_handler, token_decryptor, push_dispatcher)
            .rate_limit_config(rate_limit_config)
            .build()
    }

    #[tokio::test]
    async fn test_zero_admission_event_records_metrics() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let device_token = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        let (processor, metrics) = create_processor_with_metrics_and_rate_limits(
            &server_keys,
            TokenRateLimitConfig {
                max_cache_size: NonZeroUsize::new(100).unwrap(),
                max_tokens_per_event: NonZeroUsize::new(DEFAULT_MAX_TOKENS_PER_EVENT).unwrap(),
                encrypted_token_per_minute: 100,
                encrypted_token_per_hour: 1000,
                device_token_per_minute: 1,
                device_token_per_hour: 100,
                global_unwrap_per_minute: 1000,
                global_unwrap_per_hour: 10000,
            },
        );

        let event1 =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;
        assert!(processor.process(&event1).await.unwrap());

        // The second event reuses the same device token, so its only token is
        // shed by the device-token limiter. Zero admission by a pure per-token
        // rate shed is transient: it returns false and is not counted processed.
        let event2 =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;
        assert!(!processor.process(&event2).await.unwrap());

        assert_eq!(
            counter_value(&metrics, "transponder_events_processed_total", &[]),
            1.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_events_rate_limited_total", &[]),
            1.0
        );
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_tokens_rate_limited_total",
                &[("type", "device_token"), ("reason", "minute")],
            ),
            1.0
        );
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_notifications_admitted_per_event",
                &[]
            ),
            2
        );
        assert_eq!(
            histogram_sample_sum(
                &metrics,
                "transponder_notifications_admitted_per_event",
                &[]
            ),
            1.0
        );
    }

    #[tokio::test]
    async fn test_device_token_rate_limiting() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        // Create processor with very low device token rate limit
        let processor = create_processor_with_rate_limits(
            &server_keys,
            TokenRateLimitConfig {
                max_cache_size: NonZeroUsize::new(100).unwrap(),
                max_tokens_per_event: NonZeroUsize::new(DEFAULT_MAX_TOKENS_PER_EVENT).unwrap(),
                encrypted_token_per_minute: 100, // High limit for encrypted tokens
                encrypted_token_per_hour: 1000,
                device_token_per_minute: 2, // Only allow 2 per minute per device
                device_token_per_hour: 100,
                global_unwrap_per_minute: 1000,
                global_unwrap_per_hour: 10000,
            },
        );

        // Same device token, but different encrypted blobs (re-encrypted each time)
        let device_token = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        // First notification should succeed
        let event1 =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;
        let result1 = processor.process(&event1).await;
        assert!(result1.is_ok());
        assert!(result1.unwrap(), "First notification should be processed");

        // Second notification to same device should succeed (within limit)
        let event2 =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;
        let result2 = processor.process(&event2).await;
        assert!(result2.is_ok());
        assert!(result2.unwrap(), "Second notification should be processed");

        // Third notification to same device should be rate limited. Its only
        // token is shed by the device-token limiter, admitting zero
        // notifications. A pure per-token rate shed is transient back-pressure,
        // so the event returns false and stays retryable (not marked seen).
        let event3 =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;
        let result3 = processor.process(&event3).await;
        assert!(result3.is_ok());
        assert!(!result3.unwrap());

        // A different device should still work
        let other_device = "1111111122222222333333334444444411111111222222223333333344444444";
        let event4 =
            scenarios::single_apns_notification(&server_keys, &sender_keys, other_device).await;
        let result4 = processor.process(&event4).await;
        assert!(result4.is_ok());
        assert!(
            result4.unwrap(),
            "Different device should not be rate limited"
        );
    }

    #[tokio::test]
    async fn test_encrypted_token_rate_limiting() {
        use crate::test_vectors::{
            GiftWrapBuilder, NotificationContentBuilder, TestToken, TokenEncryptor,
        };

        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        // Create processor with very low encrypted token rate limit
        let processor = create_processor_with_rate_limits(
            &server_keys,
            TokenRateLimitConfig {
                max_cache_size: NonZeroUsize::new(100).unwrap(),
                max_tokens_per_event: NonZeroUsize::new(DEFAULT_MAX_TOKENS_PER_EVENT).unwrap(),
                encrypted_token_per_minute: 2, // Only allow 2 per minute per encrypted token
                encrypted_token_per_hour: 100,
                device_token_per_minute: 100, // High limit for device tokens
                device_token_per_hour: 1000,
                global_unwrap_per_minute: 1000,
                global_unwrap_per_hour: 10000,
            },
        );

        // Encrypt a token once and reuse the same encrypted blob
        let encryptor = TokenEncryptor::from_keys(&server_keys);
        let test_token =
            TestToken::apns("deadbeef12345678deadbeef12345678deadbeef12345678deadbeef12345678");
        let encrypted_b64 = encryptor.encrypt_base64(&test_token);

        // Create events with the exact same encrypted token
        let content = NotificationContentBuilder::new(&server_keys)
            .with_raw_token(encrypted_b64.clone())
            .build();

        let event1 = GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(&content)
            .await;
        let result1 = processor.process(&event1).await;
        assert!(result1.is_ok());
        assert!(
            result1.unwrap(),
            "First use of encrypted token should succeed"
        );

        let event2 = GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(&content)
            .await;
        let result2 = processor.process(&event2).await;
        assert!(result2.is_ok());
        assert!(
            result2.unwrap(),
            "Second use of encrypted token should succeed"
        );

        // Third use of the same encrypted blob should be rate limited. The only
        // token is shed by the encrypted-token limiter, admitting zero
        // notifications. A pure per-token rate shed is transient back-pressure,
        // so the event returns false and stays retryable (not marked seen).
        let event3 = GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(&content)
            .await;
        let result3 = processor.process(&event3).await;
        assert!(result3.is_ok());
        assert!(!result3.unwrap());

        // A different encrypted token (same device) should work since we rate limit
        // encrypted tokens first
        let encrypted_b64_2 = encryptor.encrypt_base64(&test_token);
        let content2 = NotificationContentBuilder::new(&server_keys)
            .with_raw_token(encrypted_b64_2)
            .build();
        let event4 = GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(&content2)
            .await;
        let result4 = processor.process(&event4).await;
        assert!(result4.is_ok());
        assert!(result4.unwrap(), "Different encrypted token should work");
    }

    #[tokio::test]
    async fn test_device_reject_refunds_encrypted_charge() {
        // #170: when the device-token limiter rejects a token, the encrypted
        // charge already spent for that same token must be rolled back, so a
        // legitimate transient redelivery does not read as a replay.
        use crate::test_vectors::{
            GiftWrapBuilder, NotificationContentBuilder, TestToken, TokenEncryptor,
        };
        use base64::prelude::*;

        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let device_token = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        // Device limiter allows 1/min; encrypted allows many. The device token
        // is the same across events (same device), encrypted blobs differ.
        let processor = create_processor_with_rate_limits(
            &server_keys,
            TokenRateLimitConfig {
                max_cache_size: NonZeroUsize::new(100).unwrap(),
                max_tokens_per_event: NonZeroUsize::new(DEFAULT_MAX_TOKENS_PER_EVENT).unwrap(),
                encrypted_token_per_minute: 100,
                encrypted_token_per_hour: 1000,
                device_token_per_minute: 1,
                device_token_per_hour: 100,
                global_unwrap_per_minute: 1000,
                global_unwrap_per_hour: 10000,
            },
        );

        // First event: admitted, consumes the single device slot.
        let event1 =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;
        assert!(processor.process(&event1).await.unwrap());

        // Second event: a fresh encrypted blob for the SAME device. The device
        // limiter is now at its 1/min cap and rejects the token.
        let encryptor = TokenEncryptor::from_keys(&server_keys);
        let encrypted = encryptor.encrypt(&TestToken::apns(device_token));
        let encrypted_key = EventProcessor::hash_bytes(&encrypted);
        let content = NotificationContentBuilder::new(&server_keys)
            .with_raw_token(BASE64_STANDARD.encode(&encrypted))
            .build();
        let event2 = GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(&content)
            .await;

        assert!(!processor.process(&event2).await.unwrap());

        // The encrypted charge for event2's blob was refunded on the device
        // reject: its key holds no residual hit (the entry is removed once both
        // counters reach zero).
        assert_eq!(
            processor
                .encrypted_token_limiter
                .peek_counts(&encrypted_key)
                .await,
            None,
            "device reject must refund the encrypted-token charge (#170)"
        );
    }

    #[tokio::test]
    async fn test_unconfigured_platform_token_refunds_and_counts_drop() {
        // #177: a decrypted token whose platform has no configured client must
        // be dropped BEFORE it can strand rate-limit budget, and the drop must
        // be visible via a real metric.
        use crate::push::FcmClient;
        use crate::test_vectors::{
            GiftWrapBuilder, NotificationContentBuilder, TestToken, TokenEncryptor,
        };
        use base64::prelude::*;

        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        // FCM-only dispatcher, but the event carries an APNs token → unconfigured.
        let nip59_handler = Nip59Handler::new(server_keys.clone());
        let mut secp_secret_key =
            secp256k1::SecretKey::from_slice(&server_keys.secret_key().to_secret_bytes())
                .expect("valid secret key");
        let token_decryptor = TokenDecryptor::new(&mut secp_secret_key);
        let fcm_config = crate::config::FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };
        let metrics = Metrics::new().expect("metrics");
        let push_dispatcher = Arc::new(PushDispatcher::with_metrics(
            None,
            Some(FcmClient::mock(fcm_config, true)),
            metrics.clone(),
        ));
        let processor = EventProcessorBuilder::new(nip59_handler, token_decryptor, push_dispatcher)
            .metrics(metrics.clone())
            .build();

        let encryptor = TokenEncryptor::from_keys(&server_keys);
        let encrypted = encryptor.encrypt(&TestToken::apns(
            "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344",
        ));
        let encrypted_key = EventProcessor::hash_bytes(&encrypted);
        let content = NotificationContentBuilder::new(&server_keys)
            .with_raw_token(BASE64_STANDARD.encode(&encrypted))
            .build();
        let event = GiftWrapBuilder::new(server_keys.clone(), sender_keys)
            .build(&content)
            .await;

        // The APNs token is dropped as unconfigured; the event carried nothing
        // dispatchable (terminal, not a retryable rate shed).
        assert!(processor.process(&event).await.unwrap());

        // The encrypted charge was refunded — no stranded budget (#177).
        assert_eq!(
            processor
                .encrypted_token_limiter
                .peek_counts(&encrypted_key)
                .await,
            None,
            "unconfigured-platform drop must refund the encrypted charge"
        );
        // The device limiter was never charged (drop happens before it).
        assert!(processor.device_token_limiter.is_empty().await);
        // The drop is recorded by a real metric.
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_push_failed_total",
                &[("platform", "apns"), ("reason", "unconfigured")],
            ),
            1.0,
            "unconfigured-platform drop must be counted (#177)"
        );
    }

    #[tokio::test]
    async fn test_prefiltered_drop_does_not_touch_delivery_health() {
        // Reconciliation invariant with the push-provider rework (#233): a token
        // dropped by the #177 pre-filter in process_inner never reaches the send
        // path, so it is NOT a delivery attempt and must not touch the provider's
        // DeliveryHealth streak (which gates /ready). No streak increment (would
        // wrongly flag a healthy provider) and no reset (would wrongly clear a
        // real failure streak).
        use crate::push::FcmClient;
        use crate::test_vectors::{
            GiftWrapBuilder, NotificationContentBuilder, TestToken, TokenEncryptor,
        };
        use base64::prelude::*;

        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        // FCM-only dispatcher; the event carries an APNs token → pre-filtered as
        // unconfigured before it can reach send_push.
        let nip59_handler = Nip59Handler::new(server_keys.clone());
        let mut secp_secret_key =
            secp256k1::SecretKey::from_slice(&server_keys.secret_key().to_secret_bytes())
                .expect("valid secret key");
        let token_decryptor = TokenDecryptor::new(&mut secp_secret_key);
        let fcm_config = crate::config::FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };
        let metrics = Metrics::new().expect("metrics");
        let push_dispatcher = Arc::new(PushDispatcher::with_metrics(
            None,
            Some(FcmClient::mock(fcm_config, true)),
            metrics.clone(),
        ));
        // Retain a handle to inspect DeliveryHealth after processing.
        let dispatcher_handle = Arc::clone(&push_dispatcher);
        let processor = EventProcessorBuilder::new(nip59_handler, token_decryptor, push_dispatcher)
            .metrics(metrics.clone())
            .build();

        // Seed a real hard-failure streak on FCM just below the flagging
        // threshold (a genuine prior outage), so we can prove a pre-filtered APNs
        // drop neither resets FCM's streak nor touches APNs's.
        use crate::push::dispatcher::DELIVERY_FAILURE_STREAK_THRESHOLD;
        for _ in 0..DELIVERY_FAILURE_STREAK_THRESHOLD - 1 {
            dispatcher_handle
                .delivery_health()
                .record_hard_failure(Platform::Fcm);
        }

        let encryptor = TokenEncryptor::from_keys(&server_keys);
        let encrypted = encryptor.encrypt(&TestToken::apns(
            "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344",
        ));
        let content = NotificationContentBuilder::new(&server_keys)
            .with_raw_token(BASE64_STANDARD.encode(&encrypted))
            .build();
        let event = GiftWrapBuilder::new(server_keys.clone(), sender_keys)
            .build(&content)
            .await;

        assert!(processor.process(&event).await.unwrap());

        // APNs was never a delivery attempt: its streak is untouched (still 0 →
        // delivering), so the pre-filter did not spuriously flag it.
        assert!(
            dispatcher_handle.is_apns_delivering(),
            "a pre-filtered APNs drop must not increment APNs delivery-health streak"
        );
        // FCM's genuine prior streak was NOT reset by the unrelated APNs drop.
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_push_failed_total",
                &[("platform", "apns"), ("reason", "unconfigured")],
            ),
            1.0
        );
        assert!(
            dispatcher_handle.is_fcm_delivering(),
            "streak just below threshold is still delivering"
        );
        // One more FCM hard failure reaches the threshold — which only holds if
        // the seeded streak survived, proving the APNs pre-filter drop did not
        // silently reset FCM's real hard-failure streak.
        dispatcher_handle
            .delivery_health()
            .record_hard_failure(Platform::Fcm);
        assert!(
            !dispatcher_handle.is_fcm_delivering(),
            "pre-filter drop must not have reset FCM's real hard-failure streak"
        );
    }

    #[tokio::test]
    async fn test_non_utf8_fcm_token_refunds_and_counts_drop() {
        // #177: an FCM token whose device bytes are not UTF-8 is undeliverable.
        // It must be dropped before charging the device limiter, its encrypted
        // charge refunded, and the drop counted as invalid_encoding.
        use crate::crypto::token::{ENCRYPTED_TOKEN_SIZE, PLATFORM_FCM};
        use crate::push::FcmClient;
        use crate::test_vectors::{
            GiftWrapBuilder, NotificationContentBuilder, TestToken, TokenEncryptor,
        };
        use base64::prelude::*;

        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let fcm_config = crate::config::FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };
        let metrics = Metrics::new().expect("metrics");
        let nip59_handler = Nip59Handler::new(server_keys.clone());
        let mut secp_secret_key =
            secp256k1::SecretKey::from_slice(&server_keys.secret_key().to_secret_bytes())
                .expect("valid secret key");
        let token_decryptor = TokenDecryptor::new(&mut secp_secret_key);
        let push_dispatcher = Arc::new(PushDispatcher::with_metrics(
            None,
            Some(FcmClient::mock(fcm_config, true)),
            metrics.clone(),
        ));
        let processor = EventProcessorBuilder::new(nip59_handler, token_decryptor, push_dispatcher)
            .metrics(metrics.clone())
            .build();

        // Build an FCM token whose device bytes are not valid UTF-8.
        let encryptor = TokenEncryptor::from_keys(&server_keys);
        let non_utf8_fcm = TestToken {
            platform: PLATFORM_FCM,
            device_token: vec![0xff, 0xfe, 0x00, 0x01],
        };
        let encrypted = encryptor.encrypt(&non_utf8_fcm);
        assert_eq!(encrypted.len(), ENCRYPTED_TOKEN_SIZE);
        let encrypted_key = EventProcessor::hash_bytes(&encrypted);
        let content = NotificationContentBuilder::new(&server_keys)
            .with_raw_token(BASE64_STANDARD.encode(&encrypted))
            .build();
        let event = GiftWrapBuilder::new(server_keys.clone(), sender_keys)
            .build(&content)
            .await;

        assert!(processor.process(&event).await.unwrap());

        assert_eq!(
            processor
                .encrypted_token_limiter
                .peek_counts(&encrypted_key)
                .await,
            None,
            "non-UTF-8 FCM drop must refund the encrypted charge"
        );
        assert!(processor.device_token_limiter.is_empty().await);
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_push_failed_total",
                &[("platform", "fcm"), ("reason", "invalid_encoding")],
            ),
            1.0,
            "non-UTF-8 FCM drop must be counted as invalid_encoding (#177)"
        );
    }

    #[tokio::test]
    async fn test_decrypt_failure_keeps_encrypted_charge() {
        // #170 note: the decrypt-failure path intentionally KEEPS the encrypted
        // charge (invalid blobs still spend replay/spam budget). Guard against a
        // regression from the refund refactor.
        use crate::test_vectors::{GiftWrapBuilder, NotificationContentBuilder};
        use base64::prelude::*;

        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        // A correctly-sized but undecryptable blob (random bytes).
        let junk = vec![0x11u8; crate::crypto::token::ENCRYPTED_TOKEN_SIZE];
        let encrypted_key = EventProcessor::hash_bytes(&junk);
        let content = NotificationContentBuilder::new(&server_keys)
            .with_raw_token(BASE64_STANDARD.encode(&junk))
            .build();
        let event = GiftWrapBuilder::new(server_keys.clone(), sender_keys)
            .build(&content)
            .await;

        let processor = create_processor_with_rate_limits(
            &server_keys,
            TokenRateLimitConfig {
                max_cache_size: NonZeroUsize::new(100).unwrap(),
                max_tokens_per_event: NonZeroUsize::new(DEFAULT_MAX_TOKENS_PER_EVENT).unwrap(),
                encrypted_token_per_minute: 100,
                encrypted_token_per_hour: 1000,
                device_token_per_minute: 100,
                device_token_per_hour: 1000,
                global_unwrap_per_minute: 1000,
                global_unwrap_per_hour: 10000,
            },
        );

        assert!(processor.process(&event).await.unwrap());

        // The encrypted charge is retained: the blob spent its replay budget.
        assert_eq!(
            processor
                .encrypted_token_limiter
                .peek_counts(&encrypted_key)
                .await,
            Some((1, 1)),
            "decrypt-failure path must keep the encrypted charge (#170 note)"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_device_rejects_do_not_strand_encrypted_charges() {
        // Concurrency regression for the #170 guard: many distinct-blob events
        // for the SAME device are processed in parallel. The device limiter
        // admits only a few; the rest are device-rejected and must each refund
        // their (distinct) encrypted charge. Afterwards the encrypted limiter
        // must hold no more residual charges than the device limiter admitted —
        // no interleaving may strand an encrypted increment.
        use crate::test_vectors::{
            GiftWrapBuilder, NotificationContentBuilder, TestToken, TokenEncryptor,
        };
        use base64::prelude::*;

        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let device_token = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        const DEVICE_LIMIT: u32 = 3;
        let processor = Arc::new(create_processor_with_rate_limits(
            &server_keys,
            TokenRateLimitConfig {
                max_cache_size: NonZeroUsize::new(1000).unwrap(),
                max_tokens_per_event: NonZeroUsize::new(DEFAULT_MAX_TOKENS_PER_EVENT).unwrap(),
                encrypted_token_per_minute: 1000,
                encrypted_token_per_hour: 10000,
                device_token_per_minute: DEVICE_LIMIT,
                device_token_per_hour: 1000,
                global_unwrap_per_minute: 100000,
                global_unwrap_per_hour: 1000000,
            },
        ));

        // Build many events, each with a distinct encrypted blob for the same
        // device token, and track each blob's encrypted-limiter key.
        let encryptor = TokenEncryptor::from_keys(&server_keys);
        const EVENTS: usize = 40;
        let mut events = Vec::with_capacity(EVENTS);
        let mut encrypted_keys = Vec::with_capacity(EVENTS);
        for _ in 0..EVENTS {
            let encrypted = encryptor.encrypt(&TestToken::apns(device_token));
            encrypted_keys.push(EventProcessor::hash_bytes(&encrypted));
            let content = NotificationContentBuilder::new(&server_keys)
                .with_raw_token(BASE64_STANDARD.encode(&encrypted))
                .build();
            events.push(
                GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
                    .build(&content)
                    .await,
            );
        }

        let mut handles = Vec::with_capacity(EVENTS);
        for event in events {
            let processor = Arc::clone(&processor);
            handles.push(tokio::spawn(async move { processor.process(&event).await }));
        }
        for handle in handles {
            let _ = handle.await.expect("task panicked");
        }

        // Count encrypted charges that remain across every distinct blob.
        let mut residual_encrypted = 0usize;
        for key in &encrypted_keys {
            if processor
                .encrypted_token_limiter
                .peek_counts(key)
                .await
                .is_some()
            {
                residual_encrypted += 1;
            }
        }

        // The device limiter admitted at most DEVICE_LIMIT tokens; every other
        // blob's encrypted charge was refunded on its device reject. Anything
        // above DEVICE_LIMIT would be a stranded charge.
        assert!(
            residual_encrypted <= DEVICE_LIMIT as usize,
            "stranded encrypted charges: {residual_encrypted} > device limit {DEVICE_LIMIT}"
        );
        // All admitted tokens share one device key (same device token), so the
        // device limiter holds a single entry whose hit count equals the number
        // of admitted tokens. Residual encrypted charges must equal exactly that
        // — one retained encrypted charge per admitted (device-charged) token,
        // none stranded.
        let device_payload = TokenPayload {
            platform: Platform::Apns,
            device_token: hex::decode(device_token).expect("valid hex"),
        };
        let device_key = EventProcessor::hash_device_token_key(&device_payload);
        let device_hits = processor
            .device_token_limiter
            .peek_counts(&device_key)
            .await
            .map(|(minute, _)| minute as usize)
            .unwrap_or(0);
        assert_eq!(
            residual_encrypted, device_hits,
            "residual encrypted charges must match device-admitted hit count exactly"
        );
    }

    #[tokio::test]
    async fn test_live_rate_limit_cache_size_gauge_updates_before_cleanup() {
        // #125: the rate-limit cache-size gauge must reflect growth on the
        // admission path, not only at the 60s cleanup tick. The first admission
        // is sampled, so the gauge is non-zero after processing without any
        // cleanup call.
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let device_token = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        let event =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;
        let (processor, metrics) = create_processor_with_metrics(&server_keys);

        assert!(processor.process(&event).await.unwrap());

        // No cleanup() has run; the gauge was updated opportunistically on the
        // sampled admission.
        assert_eq!(
            metric_gauge_value(
                &metrics,
                "transponder_rate_limit_cache_size",
                &[("type", "encrypted_token")],
            ),
            1.0,
            "encrypted-token cache-size gauge must update on admission (#125)"
        );
        assert_eq!(
            metric_gauge_value(
                &metrics,
                "transponder_rate_limit_cache_size",
                &[("type", "device_token")],
            ),
            1.0,
            "device-token cache-size gauge must update on admission (#125)"
        );
    }

    #[tokio::test]
    async fn test_successful_path_updates_dedup_gauge_once() {
        // #197: the successful path folds the completion refresh so it does not
        // redundantly re-write the dedup cache-size gauge. After processing one
        // fresh event the gauge reads exactly 1 (reservation), and mark_seen's
        // in-place terminal refresh does not change it.
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let device_token = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        let event =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;
        let (processor, metrics) = create_processor_with_metrics(&server_keys);

        assert!(processor.process(&event).await.unwrap());

        assert_eq!(
            gauge_value(&metrics, "transponder_dedup_cache_size"),
            1.0,
            "dedup gauge reflects the single retained terminal entry"
        );
        assert!(processor.is_duplicate(&event.id).await);
        // The completion refresh kept the entry terminal (a replay dedups).
        assert!(!processor.process(&event).await.unwrap());
    }

    #[tokio::test]
    async fn test_rate_limit_window_reset() {
        use crate::test_vectors::{
            GiftWrapBuilder, NotificationContentBuilder, TestToken, TokenEncryptor,
        };

        tokio::time::pause();

        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        let processor = create_processor_with_rate_limits(
            &server_keys,
            TokenRateLimitConfig {
                max_cache_size: NonZeroUsize::new(100).unwrap(),
                max_tokens_per_event: NonZeroUsize::new(DEFAULT_MAX_TOKENS_PER_EVENT).unwrap(),
                encrypted_token_per_minute: 1,
                encrypted_token_per_hour: 100,
                device_token_per_minute: 100,
                device_token_per_hour: 1000,
                global_unwrap_per_minute: 1000,
                global_unwrap_per_hour: 10000,
            },
        );

        let encryptor = TokenEncryptor::from_keys(&server_keys);
        let test_token =
            TestToken::apns("aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344");
        let encrypted_b64 = encryptor.encrypt_base64(&test_token);
        let content = NotificationContentBuilder::new(&server_keys)
            .with_raw_token(encrypted_b64)
            .build();

        // First request succeeds
        let event1 = GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(&content)
            .await;
        assert!(processor.process(&event1).await.unwrap());

        // Second request is rate limited (same encrypted token)
        let event2 = GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(&content)
            .await;
        processor.process(&event2).await.unwrap();
        // Can't easily assert the token was skipped without metrics, but we can test window reset

        // Advance time past the minute window
        tokio::time::advance(Duration::from_secs(61)).await;

        // Now the same token should be allowed again
        let event3 = GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(&content)
            .await;
        let result3 = processor.process(&event3).await;
        assert!(result3.is_ok());
        assert!(
            result3.unwrap(),
            "Token should be allowed after window reset"
        );
    }

    // === Per-Token Rate-Limit Shed Tests (issue #195) ===

    /// An event whose every (non-empty) token is shed by a per-token rate
    /// limiter must be treated like a global shed: the reservation is released,
    /// the event is not marked terminally seen, and a redelivery within the
    /// dedup window is admitted once the rate window resets.
    #[tokio::test]
    async fn test_all_tokens_rate_limited_leaves_event_retryable() {
        use crate::test_vectors::{
            GiftWrapBuilder, NotificationContentBuilder, TestToken, TokenEncryptor,
        };

        tokio::time::pause();

        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let device_token = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        // Only one device notification per minute is allowed.
        let (processor, metrics) = create_processor_with_metrics_and_rate_limits(
            &server_keys,
            TokenRateLimitConfig {
                max_cache_size: NonZeroUsize::new(100).unwrap(),
                max_tokens_per_event: NonZeroUsize::new(DEFAULT_MAX_TOKENS_PER_EVENT).unwrap(),
                encrypted_token_per_minute: 100,
                encrypted_token_per_hour: 1000,
                device_token_per_minute: 1,
                device_token_per_hour: 100,
                global_unwrap_per_minute: 1000,
                global_unwrap_per_hour: 10000,
            },
        );

        // Spend the device-token budget on an unrelated event.
        let warmup =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;
        assert!(processor.process(&warmup).await.unwrap());

        // Reuse the exact same encrypted blob so a redelivery is a genuine dedup
        // candidate: identical event content and (below) identical event ID.
        let encryptor = TokenEncryptor::from_keys(&server_keys);
        let encrypted_b64 = encryptor.encrypt_base64(&TestToken::apns(device_token));
        let content = NotificationContentBuilder::new(&server_keys)
            .with_raw_token(encrypted_b64)
            .build();
        let event = GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(&content)
            .await;

        // Every token is shed by the device-token limiter, so zero notifications
        // are admitted. The shed is a pure per-token rate shed: transient.
        assert!(!processor.process(&event).await.unwrap());

        // The event was NOT marked terminally seen, so it stays retryable.
        assert!(!processor.is_duplicate(&event.id).await);
        assert_eq!(processor.cache_len(), 1); // only `warmup` remains terminal
        assert_eq!(
            counter_value(&metrics, "transponder_events_processed_total", &[]),
            1.0 // only `warmup`
        );
        assert_eq!(
            counter_value(&metrics, "transponder_events_rate_limited_total", &[]),
            1.0
        );

        // A relay redelivery of the same event ID within the dedup window is not
        // dropped as a duplicate; once the rate window resets it is admitted.
        tokio::time::advance(Duration::from_secs(61)).await;
        assert!(processor.process(&event).await.unwrap());
        assert_eq!(
            counter_value(&metrics, "transponder_events_processed_total", &[]),
            2.0
        );
    }

    /// A zero-admission event caused by a genuinely invalid (undecryptable)
    /// token — not rate limiting — stays terminal: it is marked seen and a
    /// replay short-circuits as a duplicate rather than being retried.
    #[tokio::test]
    async fn test_all_tokens_invalid_is_terminal_not_rate_limited() {
        use crate::test_vectors::{GiftWrapBuilder, NotificationContentBuilder};
        use base64::prelude::*;

        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();

        // A correctly sized but undecryptable token blob: parsing succeeds, but
        // decryption fails, so the token is dropped for a permanent reason.
        let garbage = BASE64_STANDARD.encode([0u8; ENCRYPTED_TOKEN_SIZE]);
        let content = NotificationContentBuilder::new(&server_keys)
            .with_raw_token(garbage)
            .build();
        let event = GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(&content)
            .await;

        let (processor, metrics) = create_processor_with_metrics(&server_keys);

        // Zero admission, but the cause is a permanently invalid token, so the
        // event is terminal (processed with zero notifications), not a rate shed.
        assert!(processor.process(&event).await.unwrap());
        assert!(processor.is_duplicate(&event.id).await);
        assert_eq!(processor.cache_len(), 1);
        assert_eq!(
            counter_value(&metrics, "transponder_events_processed_total", &[]),
            1.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_events_rate_limited_total", &[]),
            0.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_tokens_decryption_failed_total", &[]),
            1.0
        );

        // A replay short-circuits as a duplicate, confirming terminal semantics.
        assert!(!processor.process(&event).await.unwrap());
        assert_eq!(
            counter_value(&metrics, "transponder_events_deduplicated_total", &[]),
            1.0
        );
    }

    /// When an event carries a mix of rate-limited and invalid tokens and admits
    /// none, the rate-limited token keeps the event retryable. The invalid
    /// sibling is terminal at token granularity and is skipped on redelivery.
    #[tokio::test]
    async fn test_mixed_rate_limited_and_invalid_zero_admission_retries_shed_token() {
        use crate::test_vectors::{
            GiftWrapBuilder, NotificationContentBuilder, TestToken, TokenEncryptor,
        };
        use base64::prelude::*;

        tokio::time::pause();

        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let device_token = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        let (processor, metrics) = create_processor_with_metrics_and_rate_limits(
            &server_keys,
            TokenRateLimitConfig {
                max_cache_size: NonZeroUsize::new(100).unwrap(),
                max_tokens_per_event: NonZeroUsize::new(DEFAULT_MAX_TOKENS_PER_EVENT).unwrap(),
                // The valid token's device budget is exhausted by the warmup, so
                // it is rate-limited; the other token is undecryptable.
                encrypted_token_per_minute: 100,
                encrypted_token_per_hour: 1000,
                device_token_per_minute: 1,
                device_token_per_hour: 100,
                global_unwrap_per_minute: 1000,
                global_unwrap_per_hour: 10000,
            },
        );

        let warmup =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;
        assert!(processor.process(&warmup).await.unwrap());

        let encryptor = TokenEncryptor::from_keys(&server_keys);
        let valid_b64 = encryptor.encrypt_base64(&TestToken::apns(device_token));
        let garbage_b64 = BASE64_STANDARD.encode([0u8; ENCRYPTED_TOKEN_SIZE]);
        let content = NotificationContentBuilder::new(&server_keys)
            .with_raw_token(valid_b64)
            .with_raw_token(garbage_b64)
            .build();
        let event = GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(&content)
            .await;

        // Zero admitted, but one token was transiently rate-limited, so the
        // event stays retryable despite its permanently invalid sibling.
        assert!(!processor.process(&event).await.unwrap());
        assert!(!processor.is_duplicate(&event.id).await);
        assert_eq!(
            counter_value(&metrics, "transponder_events_rate_limited_total", &[]),
            1.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_events_processed_total", &[]),
            1.0 // only `warmup`
        );
        assert_eq!(
            counter_value(&metrics, "transponder_tokens_decryption_failed_total", &[]),
            1.0
        );

        tokio::time::advance(Duration::from_secs(61)).await;

        // The replay skips the invalid sibling already marked terminal and
        // admits the formerly rate-limited token.
        assert!(processor.process(&event).await.unwrap());
        assert_eq!(
            counter_value(&metrics, "transponder_events_processed_total", &[]),
            2.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_tokens_decryption_failed_total", &[]),
            1.0,
            "terminal invalid sibling must not be decrypted again on replay"
        );
    }

    #[tokio::test]
    async fn test_mixed_rate_limited_and_admitted_tokens_retries_only_shed_token() {
        use crate::test_vectors::{
            GiftWrapBuilder, NotificationContentBuilder, TestToken, TokenEncryptor,
        };

        tokio::time::pause();

        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let rate_limited_device =
            "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";
        let admitted_device = "bbccddaa22334455bbccddaa22334455bbccddaa22334455bbccddaa22334455";

        let (processor, metrics) = create_processor_with_metrics_and_rate_limits(
            &server_keys,
            TokenRateLimitConfig {
                max_cache_size: NonZeroUsize::new(100).unwrap(),
                max_tokens_per_event: NonZeroUsize::new(DEFAULT_MAX_TOKENS_PER_EVENT).unwrap(),
                encrypted_token_per_minute: 100,
                encrypted_token_per_hour: 1000,
                device_token_per_minute: 1,
                device_token_per_hour: 100,
                global_unwrap_per_minute: 1000,
                global_unwrap_per_hour: 10000,
            },
        );

        let warmup =
            scenarios::single_apns_notification(&server_keys, &sender_keys, rate_limited_device)
                .await;
        assert!(processor.process(&warmup).await.unwrap());

        let encryptor = TokenEncryptor::from_keys(&server_keys);
        let rate_limited_b64 = encryptor.encrypt_base64(&TestToken::apns(rate_limited_device));
        let admitted_b64 = encryptor.encrypt_base64(&TestToken::apns(admitted_device));
        let content = NotificationContentBuilder::new(&server_keys)
            .with_raw_token(rate_limited_b64)
            .with_raw_token(admitted_b64)
            .build();
        let event = GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(&content)
            .await;

        // One sibling is admitted, but the event remains retryable for the
        // transiently shed token.
        assert!(!processor.process(&event).await.unwrap());
        assert!(!processor.is_duplicate(&event.id).await);
        assert_eq!(
            counter_value(&metrics, "transponder_events_rate_limited_total", &[]),
            1.0
        );
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_push_dispatched_total",
                &[("platform", "apns")],
            ),
            2.0 // warmup + admitted sibling
        );

        tokio::time::advance(Duration::from_secs(61)).await;

        // The admitted sibling is terminal and skipped; only the formerly shed
        // token is admitted on replay.
        assert!(processor.process(&event).await.unwrap());
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_push_dispatched_total",
                &[("platform", "apns")],
            ),
            3.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_events_processed_total", &[]),
            2.0 // warmup + replay
        );
    }

    // === Global Pre-Unwrap Admission Control Tests ===

    fn flood_rate_limit_config(
        global_unwrap_per_minute: u32,
        global_unwrap_per_hour: u32,
    ) -> TokenRateLimitConfig {
        TokenRateLimitConfig {
            max_cache_size: NonZeroUsize::new(100).unwrap(),
            max_tokens_per_event: NonZeroUsize::new(DEFAULT_MAX_TOKENS_PER_EVENT).unwrap(),
            // Generous per-token limits so only the global limiter can shed.
            encrypted_token_per_minute: 100_000,
            encrypted_token_per_hour: 100_000,
            device_token_per_minute: 100_000,
            device_token_per_hour: 100_000,
            global_unwrap_per_minute,
            global_unwrap_per_hour,
        }
    }

    #[tokio::test]
    async fn test_global_limiter_charges_each_token_decrypt_attempt() {
        use crate::test_vectors::{
            GiftWrapBuilder, NotificationContentBuilder, TestToken, TokenEncryptor,
        };

        tokio::time::pause();

        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let first_device = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";
        let second_device = "bbccddaa22334455bbccddaa22334455bbccddaa22334455bbccddaa22334455";

        // Budget: one unit for gift-wrap unwrap and one unit for exactly one
        // token decrypt. A second distinct token in the same event must be
        // shed before decrypt rather than amplifying CPU past the global cap.
        let (processor, metrics) = create_processor_with_metrics_and_rate_limits(
            &server_keys,
            flood_rate_limit_config(2, 1000),
        );

        let encryptor = TokenEncryptor::from_keys(&server_keys);
        let content = NotificationContentBuilder::new(&server_keys)
            .with_raw_token(encryptor.encrypt_base64(&TestToken::apns(first_device)))
            .with_raw_token(encryptor.encrypt_base64(&TestToken::apns(second_device)))
            .build();
        let event = GiftWrapBuilder::new(server_keys.clone(), sender_keys.clone())
            .build(&content)
            .await;

        assert!(
            !processor.process(&event).await.unwrap(),
            "event remains retryable for the token shed by the global decrypt budget"
        );
        assert!(!processor.is_duplicate(&event.id).await);
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_push_dispatched_total",
                &[("platform", "apns")],
            ),
            1.0
        );
        assert_eq!(
            counter_value(&metrics, "transponder_events_rate_limited_total", &[]),
            1.0
        );
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_tokens_rate_limited_total",
                &[("type", "global_decrypt"), ("reason", "minute")],
            ),
            1.0
        );

        tokio::time::advance(Duration::from_secs(61)).await;

        assert!(
            processor.process(&event).await.unwrap(),
            "redelivery should skip the first terminal token and admit the previously shed token"
        );
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_push_dispatched_total",
                &[("platform", "apns")],
            ),
            2.0
        );
    }

    #[tokio::test]
    async fn test_global_limiter_sheds_flood_before_unwrap() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let device_token = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        // Allow exactly 2 single-token events per minute. Each consumes one
        // global unit for unwrap and one for token decrypt; the third flood
        // event must be shed before unwrap.
        let (processor, metrics) = create_processor_with_metrics_and_rate_limits(
            &server_keys,
            flood_rate_limit_config(4, 1000),
        );

        let limit = 2usize;
        for _ in 0..limit {
            // Distinct event IDs so dedup never short-circuits the unwrap path.
            let event =
                scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;
            assert!(processor.process(&event).await.unwrap());
        }

        // The (N+1)th event exceeds the global budget and is shed.
        let flood_event =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;
        assert!(!processor.process(&flood_event).await.unwrap());

        // Exactly one event was shed.
        assert_eq!(
            counter_value(&metrics, "transponder_events_shed_total", &[]),
            1.0
        );

        // The shed is recorded under its own duration-histogram outcome, not
        // as a failure: back-pressure must not inflate the failed bucket.
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_event_processing_duration_seconds",
                &[("outcome", EventOutcome::Shed.as_str())],
            ),
            1
        );
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_event_processing_duration_seconds",
                &[("outcome", EventOutcome::Failed.as_str())],
            ),
            0
        );

        // The shed event was NOT unwrapped: only `limit` unwraps were observed.
        assert_eq!(
            histogram_count(
                &metrics,
                "transponder_gift_wrap_unwrap_duration_seconds",
                &[("outcome", OperationOutcome::Success.as_str())],
            ),
            limit as u64
        );
    }

    #[tokio::test]
    async fn test_global_limiter_does_not_mark_shed_event_seen() {
        tokio::time::pause();

        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let device_token = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        // Only 1 single-token event per minute allowed (unwrap + decrypt).
        let (processor, _metrics) = create_processor_with_metrics_and_rate_limits(
            &server_keys,
            flood_rate_limit_config(2, 1000),
        );

        let event =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;

        // First event consumes the global budget.
        assert!(processor.process(&event).await.unwrap());

        // Same event again: deduplicated, so it is not shed.
        assert!(!processor.process(&event).await.unwrap());

        // A different event is shed (budget exhausted) and must NOT be marked seen.
        let flood_event =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;
        assert!(!processor.process(&flood_event).await.unwrap());
        assert!(!processor.is_duplicate(&flood_event.id).await);

        // After the window resets, the previously shed event is admitted.
        tokio::time::advance(Duration::from_secs(61)).await;
        assert!(processor.process(&flood_event).await.unwrap());
    }

    #[tokio::test]
    async fn test_global_limiter_recovers_after_window() {
        tokio::time::pause();

        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let device_token = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        let (processor, metrics) = create_processor_with_metrics_and_rate_limits(
            &server_keys,
            flood_rate_limit_config(2, 1000),
        );

        let event1 =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;
        assert!(processor.process(&event1).await.unwrap());

        let event2 =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;
        assert!(!processor.process(&event2).await.unwrap());
        assert_eq!(
            counter_value(&metrics, "transponder_events_shed_total", &[]),
            1.0
        );

        // Past the minute window, budget recovers and events flow again.
        tokio::time::advance(Duration::from_secs(61)).await;

        let event3 =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;
        assert!(processor.process(&event3).await.unwrap());
        assert_eq!(
            counter_value(&metrics, "transponder_events_shed_total", &[]),
            1.0
        );
    }

    #[tokio::test]
    async fn test_admission_path_eviction_records_metric() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let device_token = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        let (processor, metrics) = create_processor_with_metrics_and_rate_limits(
            &server_keys,
            TokenRateLimitConfig {
                max_cache_size: NonZeroUsize::new(3).unwrap(),
                max_tokens_per_event: NonZeroUsize::new(DEFAULT_MAX_TOKENS_PER_EVENT).unwrap(),
                encrypted_token_per_minute: 100,
                encrypted_token_per_hour: 1000,
                device_token_per_minute: 100,
                device_token_per_hour: 1000,
                global_unwrap_per_minute: 1000,
                global_unwrap_per_hour: 10000,
            },
        );

        for _ in 0..3 {
            let event =
                scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;
            assert!(processor.process(&event).await.unwrap());
        }

        let event =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;
        assert!(processor.process(&event).await.unwrap());

        assert_eq!(
            counter_value(
                &metrics,
                "transponder_rate_limit_admission_evictions_total",
                &[("type", "encrypted_token")],
            ),
            1.0
        );
        assert_eq!(
            counter_value(
                &metrics,
                "transponder_rate_limit_admission_evictions_total",
                &[("type", "device_token")],
            ),
            0.0
        );
    }

    #[tokio::test]
    async fn test_capacity_limit_records_metric() {
        let server_keys = Keys::generate();
        let sender_keys = Keys::generate();
        let device_token = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        let (processor, metrics) = create_processor_with_metrics_and_rate_limits(
            &server_keys,
            TokenRateLimitConfig {
                max_cache_size: NonZeroUsize::new(3).unwrap(),
                max_tokens_per_event: NonZeroUsize::new(DEFAULT_MAX_TOKENS_PER_EVENT).unwrap(),
                encrypted_token_per_minute: 1,
                encrypted_token_per_hour: 100,
                device_token_per_minute: 100,
                device_token_per_hour: 1000,
                global_unwrap_per_minute: 1000,
                global_unwrap_per_hour: 10000,
            },
        );

        for _ in 0..3 {
            let event =
                scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;
            assert!(processor.process(&event).await.unwrap());
        }

        // The sole token is shed by the capacity limit, so the event is a
        // retryable rate-limit shed (returns false, not marked seen).
        let event =
            scenarios::single_apns_notification(&server_keys, &sender_keys, device_token).await;
        assert!(!processor.process(&event).await.unwrap());

        assert_eq!(
            counter_value(
                &metrics,
                "transponder_tokens_rate_limited_total",
                &[("type", "encrypted_token"), ("reason", "capacity")],
            ),
            1.0
        );
    }
}

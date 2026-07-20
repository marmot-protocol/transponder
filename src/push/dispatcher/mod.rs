//! Push notification dispatcher.
//!
//! Routes decrypted tokens to the appropriate push service (APNs or FCM)
//! with a bounded queue and semaphore-based concurrency control.
//!
//! # Bounded Queue Pattern
//!
//! To prevent unbounded task spawning (a potential DoS vector), the dispatcher
//! uses a bounded channel. When the queue is full, new notification batches are
//! rejected before admission. This provides backpressure and protects against
//! OOM conditions during traffic spikes.
//!
//! # Security
//!
//! Device tokens are wrapped in `Zeroizing<String>` while queued and while
//! handed to provider clients, reducing avoidable cleartext heap copies before
//! request serialization.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};
use zeroize::Zeroizing;

use crate::crypto::{Platform, TokenPayload};
use crate::error::{Error, Result};
use crate::metrics::Metrics;
use crate::push::retry::PushSendOutcome;
use crate::push::{ApnsClient, FcmClient};

/// Maximum concurrent outbound push requests.
const MAX_CONCURRENT_PUSHES: usize = 100;

/// Maximum number of simultaneously *live* send tasks (active plus
/// sleeping-in-backoff), as a multiple of [`MAX_CONCURRENT_PUSHES`].
///
/// A send task releases its concurrency permit during a retry backoff sleep
/// (see [`crate::push::retry::BackoffPermit`]) so an active HTTP slot is not
/// wasted while sleeping, but the task stays alive and still holds a decrypted
/// device token. Under a provider 429/5xx storm every in-flight task can enter
/// backoff and release its permit at once, letting the recv loop drain the
/// entire queue and spawn thousands of live token-holding tasks — the
/// concurrency bound silently balloons to the queue size (#160).
///
/// A second semaphore, acquired at task *spawn* and held for the task's whole
/// life (never released during backoff), caps the live-task count
/// independently. Sizing it at 2x the active-concurrency limit leaves generous
/// headroom for tasks legitimately sleeping in backoff while still bounding
/// decrypted-token residency to a small constant instead of the 10k queue.
const LIVE_TASK_MULTIPLIER: usize = 2;

/// Maximum number of simultaneously live send tasks. See
/// [`LIVE_TASK_MULTIPLIER`].
const MAX_LIVE_SEND_TASKS: usize = MAX_CONCURRENT_PUSHES * LIVE_TASK_MULTIPLIER;

/// Maximum number of pending notifications in the queue.
///
/// This bounds the memory used by waiting tasks. When this limit is reached,
/// new notification batches are rejected to protect against DoS attacks.
const MAX_PENDING_QUEUE_SIZE: usize = 10_000;

mod health;
mod inflight;

pub use health::{DELIVERY_FAILURE_STREAK_THRESHOLD, DeliveryHealth};
pub(crate) use inflight::InFlightTracker;

/// Metrics/logging label for a push platform.
fn platform_label(platform: Platform) -> &'static str {
    match platform {
        Platform::Apns => "apns",
        Platform::Fcm => "fcm",
    }
}

/// Internal message for the push queue.
enum PushMessage {
    Send {
        platform: Platform,
        token: Zeroizing<String>,
    },
    Shutdown,
}

struct QueuedPushMessage {
    platform: Platform,
    token: Zeroizing<String>,
}

/// Cloneable shared state handed to the queue-draining dispatcher loop and, in
/// turn, to each spawned send task. Groups the fields so the spawn path stays a
/// single argument rather than a long positional list.
#[derive(Clone)]
struct DispatchWorkerContext {
    apns_client: Option<Arc<ApnsClient>>,
    fcm_client: Option<Arc<FcmClient>>,
    /// Active-HTTP concurrency limit (released during backoff sleeps).
    semaphore: Arc<Semaphore>,
    /// Live-task limit (held for a task's whole life; see [`MAX_LIVE_SEND_TASKS`]).
    live_task_semaphore: Arc<Semaphore>,
    inflight: Arc<InFlightTracker>,
    /// Passive per-provider delivery-health signal (see [`DeliveryHealth`]).
    delivery_health: Arc<DeliveryHealth>,
    metrics: Metrics,
}

/// Push notification dispatcher.
pub struct PushDispatcher {
    apns_client: Option<Arc<ApnsClient>>,
    fcm_client: Option<Arc<FcmClient>>,
    semaphore: Arc<Semaphore>,
    /// Caps the number of simultaneously live send tasks (see
    /// [`MAX_LIVE_SEND_TASKS`]). A permit is acquired at task spawn and held
    /// for the task's whole life, so a task sleeping in backoff still counts.
    ///
    /// The dispatcher loop holds its own clone (via [`DispatchWorkerContext`]);
    /// this retained handle lets shutdown/tests observe the live-task bound.
    #[cfg_attr(not(test), allow(dead_code))]
    live_task_semaphore: Arc<Semaphore>,
    sender: mpsc::Sender<PushMessage>,
    queue_depth: Arc<AtomicUsize>,
    shutting_down: Arc<AtomicBool>,
    admission_lock: tokio::sync::Mutex<()>,
    dispatcher_handle: tokio::sync::Mutex<Option<JoinHandle<()>>>,
    inflight: Arc<InFlightTracker>,
    delivery_health: Arc<DeliveryHealth>,
    metrics: Metrics,
}

impl PushDispatcher {
    /// Create a new push dispatcher.
    ///
    /// This spawns a dispatcher task that processes the bounded queue of notifications.
    #[allow(dead_code)]
    pub fn new(apns_client: Option<ApnsClient>, fcm_client: Option<FcmClient>) -> Self {
        Self::with_metrics(apns_client, fcm_client, Metrics::disabled())
    }

    /// Create a new push dispatcher with metrics.
    ///
    /// This spawns a dispatcher task that processes the bounded queue of notifications.
    pub fn with_metrics(
        apns_client: Option<ApnsClient>,
        fcm_client: Option<FcmClient>,
        metrics: Metrics,
    ) -> Self {
        let apns_client = apns_client.map(Arc::new);
        let fcm_client = fcm_client.map(Arc::new);
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_PUSHES));
        let live_task_semaphore = Arc::new(Semaphore::new(MAX_LIVE_SEND_TASKS));
        let (sender, receiver) = mpsc::channel(MAX_PENDING_QUEUE_SIZE);
        let queue_depth = Arc::new(AtomicUsize::new(0));
        let shutting_down = Arc::new(AtomicBool::new(false));
        let inflight = Arc::new(InFlightTracker::new());
        let delivery_health = Arc::new(DeliveryHealth::default());

        // Initialize push capacity metrics
        metrics.set_push_queue_size(0);
        metrics.set_push_queue_capacity(MAX_PENDING_QUEUE_SIZE);
        metrics.set_push_semaphore_available(MAX_CONCURRENT_PUSHES);
        metrics.set_push_concurrency_limit(MAX_CONCURRENT_PUSHES);
        metrics.set_push_live_tasks_available(MAX_LIVE_SEND_TASKS);
        metrics.set_push_live_tasks_limit(MAX_LIVE_SEND_TASKS);

        // Spawn the queue dispatcher task.
        let worker_context = DispatchWorkerContext {
            apns_client: apns_client.clone(),
            fcm_client: fcm_client.clone(),
            semaphore: semaphore.clone(),
            live_task_semaphore: live_task_semaphore.clone(),
            inflight: inflight.clone(),
            delivery_health: delivery_health.clone(),
            metrics: metrics.clone(),
        };
        let dispatcher_handle =
            Self::spawn_dispatcher(receiver, queue_depth.clone(), worker_context);

        Self {
            apns_client,
            fcm_client,
            semaphore,
            live_task_semaphore,
            sender,
            queue_depth,
            shutting_down,
            admission_lock: tokio::sync::Mutex::new(()),
            dispatcher_handle: tokio::sync::Mutex::new(Some(dispatcher_handle)),
            inflight,
            delivery_health,
            metrics,
        }
    }

    fn update_queue_size_metric(metrics: &Metrics, queue_depth: &AtomicUsize) {
        metrics.set_push_queue_size(queue_depth.load(Ordering::SeqCst));
    }

    fn increment_queue_depth(queue_depth: &AtomicUsize, count: usize) {
        queue_depth.fetch_add(count, Ordering::SeqCst);
    }

    fn decrement_queue_depth(queue_depth: &AtomicUsize) {
        let _ = queue_depth.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
            current.checked_sub(1)
        });
    }

    fn update_semaphore_available_metric(metrics: &Metrics, semaphore: &Semaphore) {
        metrics.set_push_semaphore_available(semaphore.available_permits());
    }

    fn update_live_task_available_metric(metrics: &Metrics, live_task_semaphore: &Semaphore) {
        metrics.set_push_live_tasks_available(live_task_semaphore.available_permits());
    }

    async fn acquire_push_permit(
        semaphore: Arc<Semaphore>,
        metrics: &Metrics,
    ) -> std::result::Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::AcquireError> {
        let permit = semaphore.clone().acquire_owned().await?;
        Self::update_semaphore_available_metric(metrics, &semaphore);
        Ok(permit)
    }

    async fn acquire_live_task_permit(
        live_task_semaphore: Arc<Semaphore>,
        metrics: &Metrics,
    ) -> std::result::Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::AcquireError> {
        let permit = live_task_semaphore.clone().acquire_owned().await?;
        Self::update_live_task_available_metric(metrics, &live_task_semaphore);
        Ok(permit)
    }

    fn record_send_outcome(
        service_name: &str,
        platform: Platform,
        outcome: PushSendOutcome,
        metrics: &Metrics,
        delivery_health: &DeliveryHealth,
    ) {
        let platform_str = platform_label(platform);
        match outcome {
            PushSendOutcome::Sent => {
                delivery_health.record_processed(platform);
                trace!(service = service_name, "push notification sent");
                metrics.record_push_success(platform_str);
            }
            PushSendOutcome::InvalidToken => {
                // A definitive invalid-token verdict proves the provider
                // authenticated and processed the request, so it ends any
                // hard-failure streak.
                delivery_health.record_processed(platform);
                trace!(
                    service = service_name,
                    "push notification failed (invalid token)"
                );
                metrics.record_push_failed(platform_str, "invalid_token");
            }
            PushSendOutcome::LocallyRejected => {
                // The provider was never contacted, so this says nothing about
                // delivery health and must neither heal nor harm its signal.
                trace!(service = service_name, "push token rejected locally");
                metrics.record_push_failed(platform_str, "locally_rejected");
            }
            PushSendOutcome::Throttled => {
                // Backpressure proves the provider is reachable and must not be
                // promoted into a provider-outage readiness signal.
                trace!(service = service_name, "push notification throttled");
                metrics.record_push_failed(platform_str, "throttled");
            }
            PushSendOutcome::RetriesExhausted => {
                delivery_health.record_hard_failure(platform);
                trace!(
                    service = service_name,
                    "push notification failed (retries exhausted)"
                );
                metrics.record_push_failed(platform_str, "retries_exhausted");
            }
        }
    }

    fn record_missing_client(
        platform: Platform,
        metrics: &Metrics,
        delivery_health: &DeliveryHealth,
    ) {
        let platform_str = platform_label(platform);
        delivery_health.record_hard_failure(platform);
        warn!(
            platform = platform_str,
            "Push task reached send path without a configured provider client"
        );
        metrics.record_push_failed(platform_str, "missing_client");
    }

    async fn send_push(
        platform: Platform,
        token: Zeroizing<String>,
        apns_client: Option<Arc<ApnsClient>>,
        fcm_client: Option<Arc<FcmClient>>,
        metrics: Metrics,
        delivery_health: &DeliveryHealth,
        backoff_permit: Option<&mut crate::push::retry::BackoffPermit>,
    ) {
        let platform_str = platform_label(platform);

        match platform {
            Platform::Apns => {
                if let Some(client) = apns_client {
                    match client.send(token, backoff_permit).await {
                        Ok(outcome) => {
                            Self::record_send_outcome(
                                "APNs",
                                platform,
                                outcome,
                                &metrics,
                                delivery_health,
                            );
                        }
                        Err(e) => {
                            // Permanent send errors include provider auth
                            // rejections (revoked key, expired credentials),
                            // so they count toward the hard-failure streak.
                            delivery_health.record_hard_failure(platform);
                            // Redact any embedded URL before logging: the APNs
                            // URL carries the device token (#172). The send
                            // path already strips it, but redact again here so
                            // this log sink is safe regardless.
                            debug!(error = %e.redact_transport_url(), "APNs send error");
                            metrics.record_push_failed(platform_str, "error");
                        }
                    }
                } else {
                    Self::record_missing_client(platform, &metrics, delivery_health);
                }
            }
            Platform::Fcm => {
                if let Some(client) = fcm_client {
                    match client.send(token, backoff_permit).await {
                        Ok(outcome) => {
                            Self::record_send_outcome(
                                "FCM",
                                platform,
                                outcome,
                                &metrics,
                                delivery_health,
                            );
                        }
                        Err(e) => {
                            // Permanent send errors include provider auth
                            // rejections (revoked key, expired credentials),
                            // so they count toward the hard-failure streak.
                            delivery_health.record_hard_failure(platform);
                            // Uniform with APNs: strip any embedded URL before
                            // logging (#172). FCM's URL carries no token, but
                            // keeping the redaction uniform is defense-in-depth.
                            debug!(error = %e.redact_transport_url(), "FCM send error");
                            metrics.record_push_failed(platform_str, "error");
                        }
                    }
                } else {
                    Self::record_missing_client(platform, &metrics, delivery_health);
                }
            }
        }
        // Token is automatically zeroed when dropped here.
    }

    /// Spawn a single dispatcher task that drains the push queue.
    fn spawn_dispatcher(
        mut receiver: mpsc::Receiver<PushMessage>,
        queue_depth: Arc<AtomicUsize>,
        ctx: DispatchWorkerContext,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let metrics = ctx.metrics.clone();
            loop {
                match receiver.recv().await {
                    Some(PushMessage::Send { platform, token }) => {
                        Self::decrement_queue_depth(&queue_depth);
                        Self::update_queue_size_metric(&metrics, &queue_depth);

                        // Bound the number of simultaneously LIVE send tasks
                        // (active + sleeping-in-backoff) first: this permit is
                        // held for the task's whole life and is NOT released
                        // during backoff, so a provider storm can no longer let
                        // released concurrency permits balloon live
                        // token-holding tasks to the queue size (#160). The
                        // recv loop blocks here once MAX_LIVE_SEND_TASKS tasks
                        // are alive, applying backpressure to the queue instead.
                        let live_task_permit = match Self::acquire_live_task_permit(
                            ctx.live_task_semaphore.clone(),
                            &metrics,
                        )
                        .await
                        {
                            Ok(p) => p,
                            Err(_) => {
                                debug!("Live-task semaphore closed, dispatcher exiting");
                                break;
                            }
                        };

                        // Acquire a concurrency permit before spawning the send
                        // task. This semaphore, not a worker pool, is the
                        // outbound *active-HTTP* concurrency limit; the send's
                        // backoff releases it during sleeps (the live-task
                        // permit above stays held).
                        let permit = match Self::acquire_push_permit(
                            ctx.semaphore.clone(),
                            &metrics,
                        )
                        .await
                        {
                            Ok(p) => p,
                            Err(_) => {
                                // The dispatcher never closes this semaphore today; if a
                                // future change does, the dequeued token is zeroed as this
                                // loop scope unwinds.
                                drop(live_task_permit);
                                Self::update_live_task_available_metric(
                                    &metrics,
                                    &ctx.live_task_semaphore,
                                );
                                debug!("Push semaphore closed, dispatcher exiting");
                                break;
                            }
                        };

                        let apns_client = ctx.apns_client.clone();
                        let fcm_client = ctx.fcm_client.clone();
                        let task_metrics = metrics.clone();
                        let semaphore = ctx.semaphore.clone();
                        let live_task_semaphore = ctx.live_task_semaphore.clone();
                        let delivery_health = ctx.delivery_health.clone();

                        // Register the send task as in-flight BEFORE spawning
                        // so graceful shutdown can never observe a window where
                        // a live send task is uncounted. The guard is moved into
                        // the task and dropped only when the task body finishes
                        // (after all retries/backoff), independent of whether the
                        // task currently holds a concurrency permit.
                        let inflight_guard = ctx.inflight.enter();

                        tokio::spawn(async move {
                            // Decrements the in-flight count when this task
                            // completes, signalling idle to any shutdown waiter.
                            let _inflight_guard = inflight_guard;

                            // Wrap the permit so the send's internal backoff
                            // can release the in-flight slot during sleeps and
                            // re-acquire it before the next attempt.
                            let mut backoff_permit =
                                crate::push::retry::BackoffPermit::new(semaphore.clone(), permit);

                            Self::send_push(
                                platform,
                                token,
                                apns_client,
                                fcm_client,
                                task_metrics.clone(),
                                &delivery_health,
                                Some(&mut backoff_permit),
                            )
                            .await;

                            // Release the held permit (owned by backoff_permit)
                            // before reading available permits for the metric.
                            drop(backoff_permit);

                            Self::update_semaphore_available_metric(&task_metrics, &semaphore);
                            // Held until the send task has finished all
                            // attempts/backoff, bounding live token-holding
                            // tasks even across backoff sleeps (#160).
                            drop(live_task_permit);
                            Self::update_live_task_available_metric(
                                &task_metrics,
                                &live_task_semaphore,
                            );
                        });
                    }
                    Some(PushMessage::Shutdown) => {
                        debug!("Push dispatcher received shutdown signal");
                        break;
                    }
                    None => {
                        debug!("Push queue channel closed, dispatcher exiting");
                        break;
                    }
                }
            }
        })
    }

    /// Dispatch push notifications for all payloads.
    ///
    /// This queues notifications for processing by the dispatcher task. The batch is
    /// only accepted if enough queue capacity exists for all notifications, so
    /// callers can safely treat a successful return as "all notifications were
    /// admitted locally". Invalid tokens are silently ignored as advisory push hygiene.
    pub async fn dispatch(&self, payloads: Vec<TokenPayload>) -> Result<usize> {
        let _admission_guard = self.admission_lock.lock().await;
        let requested_count = payloads.len();
        let mut messages = Vec::with_capacity(requested_count);

        for payload in payloads {
            // These platform/encoding filters are now a defensive second layer:
            // `process_inner` pre-filters undispatchable tokens (unconfigured
            // platform / non-UTF-8 FCM) via `accepts` / `token_is_encodable`
            // BEFORE charging the rate limiters, so it can refund and count the
            // drop (#177). Keeping the checks here too means `dispatch` never
            // enqueues an undeliverable token even if a caller skips the
            // pre-filter, but in the normal event path these `continue`s do not
            // fire.
            // Extract token as Zeroizing<String> for automatic cleanup
            let (platform, token): (Platform, Zeroizing<String>) = match payload.platform {
                Platform::Apns => {
                    if self.apns_client.is_none() {
                        trace!("APNs not configured, skipping notification");
                        continue;
                    }
                    (Platform::Apns, payload.device_token_hex())
                }
                Platform::Fcm => {
                    if self.fcm_client.is_none() {
                        trace!("FCM not configured, skipping notification");
                        continue;
                    }
                    match payload.device_token_string() {
                        Some(token) => (Platform::Fcm, token),
                        None => {
                            trace!("Invalid FCM token (not UTF-8)");
                            continue;
                        }
                    }
                }
            };
            // Note: payload (TokenPayload) is automatically zeroed when dropped here
            // due to its ZeroizeOnDrop implementation

            messages.push(QueuedPushMessage { platform, token });
        }

        let message_count = messages.len();
        // Check shutdown after platform/token filtering so post-shutdown requests
        // always fail while the rejection metric only counts admissible messages.
        if self.shutting_down.load(Ordering::SeqCst) {
            self.metrics
                .record_push_queue_rejected(message_count as u64);

            debug!("Dispatcher shutting down, ignoring dispatch request");
            return Err(Error::Dispatch("Dispatcher is shutting down".to_string()));
        }

        if messages.is_empty() {
            return Ok(0);
        }

        let mut permits =
            self.sender
                .try_reserve_many(message_count)
                .map_err(|error| match error {
                    mpsc::error::TrySendError::Full(_) => {
                        self.metrics
                            .record_push_queue_rejected(message_count as u64);

                        warn!(
                            requested = message_count,
                            available = self.sender.capacity(),
                            "Push queue full, rejecting notification batch"
                        );
                        Error::Dispatch(format!(
                            "Push queue full: unable to queue {message_count} notifications"
                        ))
                    }
                    mpsc::error::TrySendError::Closed(_) => {
                        self.metrics
                            .record_push_queue_rejected(message_count as u64);

                        warn!("Push queue closed, rejecting notification batch");
                        Error::Dispatch("Push queue closed".to_string())
                    }
                })?;

        // Increment the queue depth for the whole batch *before* sending any
        // message into the channel. A message becomes dequeueable the instant
        // `permit.send(...)` runs, so a worker can decrement `queue_depth`
        // immediately. If the increment happened after the send loop, that
        // worker decrement could fire while `queue_depth` is still 0; the
        // saturating `checked_sub` would drop it, and the subsequent batch
        // increment would over-count, drifting the gauge upward over time.
        // `admission_lock` serializes dispatch calls, so accounting for the
        // batch up front cannot double-count.
        Self::increment_queue_depth(&self.queue_depth, message_count);
        Self::update_queue_size_metric(&self.metrics, &self.queue_depth);

        for message in messages {
            let platform_str = platform_label(message.platform);

            let permit = permits
                .next()
                .expect("reserved permits should match queued message count");
            permit.send(PushMessage::Send {
                platform: message.platform,
                token: message.token,
            });

            self.metrics.record_push_dispatched(platform_str);
        }

        Ok(message_count)
    }

    /// Whether the dispatcher has a client wired for `platform`.
    ///
    /// This is the cheap pre-charge admission gate: `process_inner` calls it
    /// *before* spending rate-limit budget so a token targeting an unconfigured
    /// platform is dropped without charging (and refunding) the limiters (#177).
    /// It mirrors the platform-client presence check inside [`Self::dispatch`]
    /// (`apns_client.is_some()` / `fcm_client.is_some()`), keeping the two in
    /// lock-step: `dispatch` still filters defensively, but a token this returns
    /// `false` for never reaches it.
    #[must_use]
    pub fn accepts(&self, platform: Platform) -> bool {
        match platform {
            Platform::Apns => self.apns_client.is_some(),
            Platform::Fcm => self.fcm_client.is_some(),
        }
    }

    /// Whether `payload`'s device token is transport-encodable for its platform.
    ///
    /// FCM tokens are sent as UTF-8 strings, so a non-UTF-8 device-token blob is
    /// undeliverable and [`Self::dispatch`] would silently drop it. Checking here
    /// lets `process_inner` treat that token as a terminal drop and refund /
    /// count it, rather than spend rate-limit budget on a notification that can
    /// never be sent (#177). APNs tokens are hex-encoded from raw bytes, so they
    /// are always encodable.
    #[must_use]
    pub fn token_is_encodable(payload: &TokenPayload) -> bool {
        match payload.platform {
            Platform::Apns => true,
            Platform::Fcm => payload.device_token_string().is_some(),
        }
    }

    /// Check if APNs is configured and ready.
    #[must_use]
    pub fn has_apns(&self) -> bool {
        self.apns_client
            .as_ref()
            .map(|c| c.is_configured())
            .unwrap_or(false)
    }

    /// Check if FCM is configured and ready.
    #[must_use]
    pub fn has_fcm(&self) -> bool {
        self.fcm_client
            .as_ref()
            .map(|c| c.is_configured())
            .unwrap_or(false)
    }

    /// Check if at least one push service is configured.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.has_apns() || self.has_fcm()
    }

    /// Passive per-provider delivery-health signal (see [`DeliveryHealth`]).
    ///
    /// Test-only: production readers go through [`Self::is_apns_delivering`]
    /// and [`Self::is_fcm_delivering`]; tests use this to simulate observed
    /// send outcomes.
    #[cfg(test)]
    #[must_use]
    pub fn delivery_health(&self) -> &DeliveryHealth {
        &self.delivery_health
    }

    /// Whether APNs is currently delivering: it is not in a sustained streak
    /// of consecutive hard send failures (auth rejections, permanent errors,
    /// exhausted retries). Always `true` until failures are observed.
    #[must_use]
    pub fn is_apns_delivering(&self) -> bool {
        self.delivery_health.is_delivering(Platform::Apns)
    }

    /// Whether FCM is currently delivering: it is not in a sustained streak
    /// of consecutive hard send failures (auth rejections, permanent errors,
    /// exhausted retries). Always `true` until failures are observed.
    #[must_use]
    pub fn is_fcm_delivering(&self) -> bool {
        self.delivery_health.is_delivering(Platform::Fcm)
    }

    /// Wait for all in-flight push notifications to complete.
    ///
    /// This is used during graceful shutdown. It stops accepting new dispatches,
    /// enqueues one shutdown message behind any queued notifications, and then
    /// waits for the dispatcher task to exit. This guarantees queued work is
    /// drained before shutdown completes.
    pub async fn wait_for_completion(&self) {
        {
            let _admission_guard = self.admission_lock.lock().await;
            self.shutting_down.store(true, Ordering::SeqCst);
        }

        // Wake/shed retries parked in backoff. Closing also prevents the queue
        // loop from admitting fresh HTTP work during bounded teardown.
        self.semaphore.close();

        // Never hold the admission lock across a potentially blocking bounded
        // channel send; concurrent dispatchers can now observe shutdown and
        // fail fast.
        let _ = self.sender.send(PushMessage::Shutdown).await;

        let dispatcher_handle = {
            let mut handle = self.dispatcher_handle.lock().await;
            handle.take()
        };

        if let Some(handle) = dispatcher_handle {
            match handle.await {
                Ok(()) => {}
                Err(error) => {
                    warn!(error = %error, "Push dispatcher exited unexpectedly during shutdown");
                }
            }
        }

        // Wait for all spawned send tasks to finish. We track task lifetimes
        // explicitly rather than draining concurrency permits: a send task in a
        // retry backoff sleep releases its permit (see `BackoffPermit`), so
        // "all permits acquired" does NOT prove every send task has finished —
        // a sleeping retry holds no permit yet is still alive and may re-acquire
        // a permit and send again. The in-flight tracker counts task lifetimes
        // end-to-end, so this honours the drain guarantee even under provider
        // backoff storms.
        self.inflight.wait_idle().await;

        self.queue_depth.store(0, Ordering::SeqCst);
        self.metrics.set_push_queue_size(0);
        self.metrics
            .set_push_semaphore_available(self.semaphore.available_permits());
        self.metrics
            .set_push_live_tasks_available(self.live_task_semaphore.available_permits());

        debug!("All queued push notifications drained");
    }

    /// Returns the current queue capacity available.
    ///
    /// This is useful for monitoring and testing.
    #[cfg(test)]
    #[must_use]
    pub fn queue_capacity(&self) -> usize {
        self.sender.capacity()
    }

    /// Returns the maximum queue size.
    #[cfg(test)]
    #[must_use]
    pub fn max_queue_size(&self) -> usize {
        MAX_PENDING_QUEUE_SIZE
    }

    /// Available live-task permits (test inspection for the #160 bound).
    #[cfg(test)]
    #[must_use]
    fn available_live_task_permits(&self) -> usize {
        self.live_task_semaphore.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_metrics::{
        counter_value as metric_counter_value, gauge_value as metric_gauge_value,
    };
    use std::time::Duration;

    fn gauge_metric_value(metrics: &crate::metrics::Metrics, name: &str) -> i64 {
        metric_gauge_value(metrics, name, &[]) as i64
    }

    fn counter_metric_value(metrics: &crate::metrics::Metrics, name: &str) -> u64 {
        metric_counter_value(metrics, name, &[]) as u64
    }

    fn queue_size_metric_value(metrics: &crate::metrics::Metrics) -> i64 {
        gauge_metric_value(metrics, "transponder_push_queue_size")
    }

    fn apns_test_payload() -> TokenPayload {
        TokenPayload {
            platform: Platform::Apns,
            device_token: vec![0xaa, 0xbb, 0xcc],
        }
    }

    fn repeated_apns_payloads(count: usize) -> Vec<TokenPayload> {
        (0..count).map(|_| apns_test_payload()).collect()
    }

    fn push_failed_metric_value(
        metrics: &crate::metrics::Metrics,
        platform: &str,
        reason: &str,
    ) -> u64 {
        metric_counter_value(
            metrics,
            "transponder_push_failed_total",
            &[("platform", platform), ("reason", reason)],
        ) as u64
    }

    fn push_success_metric_value(metrics: &crate::metrics::Metrics, platform: &str) -> u64 {
        metric_counter_value(
            metrics,
            "transponder_push_success_total",
            &[("platform", platform)],
        ) as u64
    }

    #[tokio::test]
    async fn send_push_records_invalid_token_metrics() {
        // FCM still short-circuits a clearly-malformed (here empty) token to
        // the InvalidToken outcome before spending an OAuth round-trip. The
        // APNs client no longer re-validates token format (issue #199): the
        // dispatcher only ever feeds it even-length hex from
        // `TokenPayload::device_token_hex()`, the single source of truth, so
        // there is no dispatch-path APNs "invalid_token" case to exercise.
        use crate::config::FcmConfig;
        use crate::metrics::Metrics;
        use crate::push::FcmClient;

        let fcm_config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };
        let metrics = Metrics::new().unwrap();

        let delivery_health = DeliveryHealth::default();

        PushDispatcher::send_push(
            Platform::Fcm,
            Zeroizing::new("".to_string()),
            None,
            Some(Arc::new(FcmClient::mock(fcm_config, true))),
            metrics.clone(),
            &delivery_health,
            None,
        )
        .await;

        assert_eq!(
            push_failed_metric_value(&metrics, "fcm", "locally_rejected"),
            1
        );
    }

    #[tokio::test]
    async fn send_push_records_missing_client_failures() {
        let metrics = crate::metrics::Metrics::new().unwrap();
        let delivery_health = DeliveryHealth::default();

        for _ in 0..DELIVERY_FAILURE_STREAK_THRESHOLD {
            PushDispatcher::send_push(
                Platform::Apns,
                Zeroizing::new("deadbeef".to_string()),
                None,
                None,
                metrics.clone(),
                &delivery_health,
                None,
            )
            .await;
        }

        assert_eq!(
            push_failed_metric_value(&metrics, "apns", "missing_client"),
            DELIVERY_FAILURE_STREAK_THRESHOLD as u64
        );
        assert!(
            !delivery_health.is_delivering(Platform::Apns),
            "missing APNs client should count as a hard delivery failure"
        );

        PushDispatcher::send_push(
            Platform::Fcm,
            Zeroizing::new("fcm-token".to_string()),
            None,
            None,
            metrics.clone(),
            &delivery_health,
            None,
        )
        .await;

        assert_eq!(
            push_failed_metric_value(&metrics, "fcm", "missing_client"),
            1
        );
    }

    #[test]
    fn test_send_outcome_metrics_distinguish_invalid_token_and_retries_exhausted() {
        let metrics = crate::metrics::Metrics::new().unwrap();
        let metrics = metrics.clone();
        let delivery_health = DeliveryHealth::default();

        PushDispatcher::record_send_outcome(
            "APNs",
            Platform::Apns,
            PushSendOutcome::InvalidToken,
            &metrics,
            &delivery_health,
        );
        PushDispatcher::record_send_outcome(
            "APNs",
            Platform::Apns,
            PushSendOutcome::RetriesExhausted,
            &metrics,
            &delivery_health,
        );
        PushDispatcher::record_send_outcome(
            "FCM",
            Platform::Fcm,
            PushSendOutcome::Sent,
            &metrics,
            &delivery_health,
        );

        assert_eq!(
            push_failed_metric_value(&metrics, "apns", "invalid_token"),
            1
        );
        assert_eq!(
            push_failed_metric_value(&metrics, "apns", "retries_exhausted"),
            1
        );
        assert_eq!(push_success_metric_value(&metrics, "fcm"), 1);
    }

    #[test]
    fn delivery_health_defaults_to_delivering() {
        let health = DeliveryHealth::default();

        assert!(health.is_delivering(Platform::Apns));
        assert!(health.is_delivering(Platform::Fcm));
    }

    #[test]
    fn delivery_health_flags_provider_after_sustained_hard_failure_score() {
        let health = DeliveryHealth::default();
        let failures_to_trip = DELIVERY_FAILURE_STREAK_THRESHOLD.div_ceil(2);

        for _ in 0..failures_to_trip - 1 {
            health.record_hard_failure(Platform::Apns);
        }
        assert!(
            health.is_delivering(Platform::Apns),
            "a streak below the threshold must not flag the provider"
        );

        health.record_hard_failure(Platform::Apns);
        assert!(
            !health.is_delivering(Platform::Apns),
            "reaching the threshold must flag the provider as not delivering"
        );
        assert!(
            health.is_delivering(Platform::Fcm),
            "platforms must be tracked independently"
        );
    }

    #[test]
    fn delivery_health_processed_request_ends_streak() {
        let health = DeliveryHealth::default();

        for _ in 0..DELIVERY_FAILURE_STREAK_THRESHOLD.div_ceil(2) {
            health.record_hard_failure(Platform::Fcm);
        }
        assert!(!health.is_delivering(Platform::Fcm));

        health.record_processed(Platform::Fcm);
        assert!(
            !health.is_delivering(Platform::Fcm),
            "one processed request must not erase accumulated outage evidence"
        );
        for _ in 0..DELIVERY_FAILURE_STREAK_THRESHOLD {
            health.record_processed(Platform::Fcm);
        }
        assert!(health.is_delivering(Platform::Fcm));
    }

    #[test]
    fn record_send_outcome_updates_delivery_health() {
        let metrics = Metrics::disabled();
        let delivery_health = DeliveryHealth::default();

        for _ in 0..DELIVERY_FAILURE_STREAK_THRESHOLD {
            PushDispatcher::record_send_outcome(
                "APNs",
                Platform::Apns,
                PushSendOutcome::RetriesExhausted,
                &metrics,
                &delivery_health,
            );
        }
        assert!(
            !delivery_health.is_delivering(Platform::Apns),
            "consecutive exhausted-retry outcomes must flag the provider"
        );

        // An invalid-token verdict proves the provider processed a request and
        // decays the score, but one success cannot hide a sustained outage.
        PushDispatcher::record_send_outcome(
            "APNs",
            Platform::Apns,
            PushSendOutcome::InvalidToken,
            &metrics,
            &delivery_health,
        );
        assert!(!delivery_health.is_delivering(Platform::Apns));
    }

    #[tokio::test]
    async fn dispatcher_reports_delivering_by_default() {
        let dispatcher = PushDispatcher::new(None, None);

        assert!(dispatcher.is_apns_delivering());
        assert!(dispatcher.is_fcm_delivering());

        for _ in 0..DELIVERY_FAILURE_STREAK_THRESHOLD {
            dispatcher
                .delivery_health()
                .record_hard_failure(Platform::Apns);
        }

        assert!(!dispatcher.is_apns_delivering());
        assert!(dispatcher.is_fcm_delivering());
    }

    #[tokio::test]
    async fn test_dispatcher_no_clients() {
        let dispatcher = PushDispatcher::new(None, None);
        assert!(!dispatcher.has_apns());
        assert!(!dispatcher.has_fcm());
        assert!(!dispatcher.is_ready());
    }

    #[tokio::test]
    async fn test_dispatch_empty_payloads() {
        let dispatcher = PushDispatcher::new(None, None);

        // Should not panic with empty payloads
        assert_eq!(dispatcher.dispatch(vec![]).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_accepts_reflects_configured_platforms() {
        use crate::config::ApnsConfig;
        use crate::push::ApnsClient;

        // No clients: accepts nothing.
        let none = PushDispatcher::new(None, None);
        assert!(!none.accepts(Platform::Apns));
        assert!(!none.accepts(Platform::Fcm));

        // APNs-only: accepts APNs, rejects FCM (mirrors dispatch()'s filter).
        let apns_config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: crate::config::ApnsEnvironment::Sandbox,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
        };
        let apns_only = PushDispatcher::new(Some(ApnsClient::mock(apns_config, true)), None);
        assert!(apns_only.accepts(Platform::Apns));
        assert!(!apns_only.accepts(Platform::Fcm));
    }

    #[test]
    fn test_token_is_encodable_matches_dispatch_encoding() {
        // APNs tokens (hex-encoded) are always encodable, including binary bytes.
        assert!(PushDispatcher::token_is_encodable(&TokenPayload {
            platform: Platform::Apns,
            device_token: vec![0xff, 0x00, 0x01],
        }));
        // UTF-8 FCM token is encodable.
        assert!(PushDispatcher::token_is_encodable(&TokenPayload {
            platform: Platform::Fcm,
            device_token: b"fcm-token-123".to_vec(),
        }));
        // Non-UTF-8 FCM token is NOT encodable — dispatch() would drop it.
        assert!(!PushDispatcher::token_is_encodable(&TokenPayload {
            platform: Platform::Fcm,
            device_token: vec![0xff, 0xfe, 0x00, 0x01],
        }));
    }

    #[tokio::test]
    async fn test_dispatch_without_clients() {
        let dispatcher = PushDispatcher::new(None, None);

        let payloads = vec![
            TokenPayload {
                platform: Platform::Apns,
                device_token: vec![0xaa, 0xbb, 0xcc],
            },
            TokenPayload {
                platform: Platform::Fcm,
                device_token: b"fcm-token-123".to_vec(),
            },
        ];

        // Should not panic - just skips notifications
        assert_eq!(dispatcher.dispatch(payloads).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_wait_for_completion() {
        let dispatcher = PushDispatcher::new(None, None);

        // Should complete immediately when no pushes in flight
        let result =
            tokio::time::timeout(Duration::from_secs(1), dispatcher.wait_for_completion()).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_has_apns_with_configured_client() {
        use crate::config::ApnsConfig;
        use crate::push::ApnsClient;

        let config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: crate::config::ApnsEnvironment::Sandbox,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
        };

        let apns_client = ApnsClient::mock(config, true);
        let dispatcher = PushDispatcher::new(Some(apns_client), None);

        assert!(dispatcher.has_apns());
        assert!(!dispatcher.has_fcm());
        assert!(dispatcher.is_ready());
    }

    #[tokio::test]
    async fn test_has_fcm_with_configured_client() {
        use crate::config::FcmConfig;
        use crate::push::FcmClient;

        let config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };

        let fcm_client = FcmClient::mock(config, true);
        let dispatcher = PushDispatcher::new(None, Some(fcm_client));

        assert!(!dispatcher.has_apns());
        assert!(dispatcher.has_fcm());
        assert!(dispatcher.is_ready());
    }

    #[tokio::test]
    async fn test_dispatch_apns_without_apns_client() {
        use crate::config::FcmConfig;
        use crate::push::FcmClient;

        // Only FCM client configured
        let fcm_config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };
        let fcm_client = FcmClient::mock(fcm_config, true);
        let dispatcher = PushDispatcher::new(None, Some(fcm_client));

        // Try to dispatch an APNs payload - should be skipped
        let payloads = vec![TokenPayload {
            platform: Platform::Apns,
            device_token: vec![0xaa, 0xbb, 0xcc],
        }];

        assert_eq!(dispatcher.dispatch(payloads).await.unwrap(), 0);
        // Should not panic, just skip the notification
    }

    #[tokio::test]
    async fn test_dispatch_fcm_without_fcm_client() {
        use crate::config::ApnsConfig;
        use crate::push::ApnsClient;

        // Only APNs client configured
        let apns_config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: crate::config::ApnsEnvironment::Sandbox,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
        };
        let apns_client = ApnsClient::mock(apns_config, true);
        let dispatcher = PushDispatcher::new(Some(apns_client), None);

        // Try to dispatch an FCM payload - should be skipped
        let payloads = vec![TokenPayload {
            platform: Platform::Fcm,
            device_token: b"fcm-token-123".to_vec(),
        }];

        assert_eq!(dispatcher.dispatch(payloads).await.unwrap(), 0);
        // Should not panic, just skip the notification
    }

    #[tokio::test]
    async fn test_dispatch_fcm_invalid_utf8_token() {
        use crate::config::FcmConfig;
        use crate::push::FcmClient;

        let fcm_config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };
        let fcm_client = FcmClient::mock(fcm_config, true);
        let dispatcher = PushDispatcher::new(None, Some(fcm_client));

        // Invalid UTF-8 FCM token - should be skipped
        let payloads = vec![TokenPayload {
            platform: Platform::Fcm,
            device_token: vec![0xff, 0xfe, 0x00, 0x01], // Invalid UTF-8
        }];

        assert_eq!(dispatcher.dispatch(payloads).await.unwrap(), 0);
        // Should not panic, just skip the notification
    }

    #[tokio::test]
    async fn test_dispatch_both_platforms() {
        use crate::config::{ApnsConfig, FcmConfig};
        use crate::metrics::Metrics;
        use crate::push::{ApnsClient, FcmClient};

        let apns_config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: crate::config::ApnsEnvironment::Sandbox,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
        };
        let apns_client = ApnsClient::mock(apns_config, true);

        let fcm_config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };
        let fcm_client = FcmClient::mock(fcm_config, true);

        let metrics = Metrics::new().unwrap();
        let dispatcher =
            PushDispatcher::with_metrics(Some(apns_client), Some(fcm_client), metrics.clone());

        // Dispatch both APNs and FCM payloads
        let payloads = vec![
            TokenPayload {
                platform: Platform::Apns,
                device_token: vec![0xaa, 0xbb, 0xcc],
            },
            TokenPayload {
                platform: Platform::Fcm,
                device_token: b"fcm-token-123".to_vec(),
            },
        ];

        assert_eq!(dispatcher.dispatch(payloads).await.unwrap(), 2);
        // Tasks are spawned - give them time to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify metrics
        let families = metrics.gather();
        let mut apns_dispatched = false;
        let mut fcm_dispatched = false;

        for family in families {
            if family.name() == "transponder_push_dispatched_total" {
                for metric in family.get_metric() {
                    for label in metric.get_label() {
                        if label.name() == "platform" {
                            if label.value() == "apns" {
                                assert_eq!(metric.get_counter().value, Some(1.0));
                                apns_dispatched = true;
                            } else if label.value() == "fcm" {
                                assert_eq!(metric.get_counter().value, Some(1.0));
                                fcm_dispatched = true;
                            }
                        }
                    }
                }
            }
        }

        assert!(apns_dispatched, "APNs dispatch metric missing");
        assert!(fcm_dispatched, "FCM dispatch metric missing");
    }

    #[tokio::test]
    async fn test_queue_metric_updates_after_dispatcher_dequeue() {
        use crate::config::ApnsConfig;
        use crate::metrics::Metrics;
        use crate::push::ApnsClient;

        let apns_config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: crate::config::ApnsEnvironment::Sandbox,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
        };

        let metrics = Metrics::new().unwrap();
        let dispatcher = PushDispatcher::with_metrics(
            Some(ApnsClient::mock(apns_config, true)),
            None,
            metrics.clone(),
        );

        let permits = dispatcher
            .semaphore
            .acquire_many(MAX_CONCURRENT_PUSHES as u32)
            .await
            .unwrap();

        let payloads = repeated_apns_payloads(2);

        assert_eq!(dispatcher.dispatch(payloads).await.unwrap(), 2);

        for _ in 0..20 {
            if queue_size_metric_value(&metrics) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(queue_size_metric_value(&metrics), 1);

        drop(permits);
        dispatcher.wait_for_completion().await;
    }

    #[tokio::test]
    async fn test_is_ready_both_clients() {
        use crate::config::{ApnsConfig, FcmConfig};
        use crate::push::{ApnsClient, FcmClient};

        let apns_config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: crate::config::ApnsEnvironment::Sandbox,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
        };
        let apns_client = ApnsClient::mock(apns_config, true);

        let fcm_config = FcmConfig {
            enabled: true,
            service_account_path: String::new(),
            project_id: "test-project".to_string(),
        };
        let fcm_client = FcmClient::mock(fcm_config, true);

        let dispatcher = PushDispatcher::new(Some(apns_client), Some(fcm_client));

        assert!(dispatcher.has_apns());
        assert!(dispatcher.has_fcm());
        assert!(dispatcher.is_ready());
    }

    #[tokio::test]
    async fn test_has_apns_unconfigured_client() {
        use crate::config::ApnsConfig;
        use crate::push::ApnsClient;

        // APNs client that is not properly configured
        let apns_config = ApnsConfig {
            enabled: false, // Disabled
            key_id: String::new(),
            team_id: String::new(),
            private_key_path: String::new(),
            environment: crate::config::ApnsEnvironment::Sandbox,
            bundle_id: String::new(),
            payload_mode: Default::default(),
        };
        let apns_client = ApnsClient::mock(apns_config, false);
        let dispatcher = PushDispatcher::new(Some(apns_client), None);

        assert!(!dispatcher.has_apns()); // Client exists but not configured
        assert!(!dispatcher.is_ready());
    }

    #[tokio::test]
    async fn test_has_fcm_unconfigured_client() {
        use crate::config::FcmConfig;
        use crate::push::FcmClient;

        // FCM client that is not properly configured
        let fcm_config = FcmConfig {
            enabled: false, // Disabled
            service_account_path: String::new(),
            project_id: String::new(),
        };
        let fcm_client = FcmClient::mock(fcm_config, false);
        let dispatcher = PushDispatcher::new(None, Some(fcm_client));

        assert!(!dispatcher.has_fcm()); // Client exists but not configured
        assert!(!dispatcher.is_ready());
    }

    #[tokio::test]
    async fn test_queue_capacity() {
        let dispatcher = PushDispatcher::new(None, None);

        // Queue should have capacity available
        assert!(dispatcher.queue_capacity() > 0);
        assert_eq!(dispatcher.max_queue_size(), MAX_PENDING_QUEUE_SIZE);
    }

    #[tokio::test]
    async fn test_dispatch_after_shutdown() {
        use crate::config::ApnsConfig;
        use crate::push::ApnsClient;

        let dispatcher = PushDispatcher::new(
            Some(ApnsClient::mock(
                ApnsConfig {
                    enabled: true,
                    key_id: "KEY123".to_string(),
                    team_id: "TEAM456".to_string(),
                    private_key_path: String::new(),
                    environment: crate::config::ApnsEnvironment::Sandbox,
                    bundle_id: "com.example.app".to_string(),
                    payload_mode: Default::default(),
                },
                true,
            )),
            None,
        );

        // Shutdown the dispatcher
        dispatcher.wait_for_completion().await;

        // Dispatch should be ignored after shutdown
        let payloads = vec![TokenPayload {
            platform: Platform::Apns,
            device_token: vec![0xaa, 0xbb, 0xcc],
        }];

        let error = dispatcher.dispatch(payloads).await.unwrap_err();
        assert!(matches!(error, Error::Dispatch(_)));
    }

    #[tokio::test]
    async fn test_capacity_metrics_initialized() {
        use crate::metrics::Metrics;

        let metrics = Metrics::new().unwrap();
        let _dispatcher = PushDispatcher::with_metrics(None, None, metrics.clone());

        assert_eq!(queue_size_metric_value(&metrics), 0);
        assert_eq!(
            gauge_metric_value(&metrics, "transponder_push_queue_capacity"),
            MAX_PENDING_QUEUE_SIZE as i64
        );
        assert_eq!(
            gauge_metric_value(&metrics, "transponder_push_semaphore_available"),
            MAX_CONCURRENT_PUSHES as i64
        );
        assert_eq!(
            gauge_metric_value(&metrics, "transponder_push_concurrency_limit"),
            MAX_CONCURRENT_PUSHES as i64
        );
        assert_eq!(
            gauge_metric_value(&metrics, "transponder_push_live_tasks_available"),
            MAX_LIVE_SEND_TASKS as i64
        );
        assert_eq!(
            gauge_metric_value(&metrics, "transponder_push_live_tasks_limit"),
            MAX_LIVE_SEND_TASKS as i64
        );
    }

    #[tokio::test]
    async fn test_semaphore_available_metric_updates_on_permit_acquire() {
        use crate::metrics::Metrics;

        let metrics = Metrics::new().unwrap();
        let metrics = metrics.clone();
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_PUSHES));

        metrics.set_push_semaphore_available(MAX_CONCURRENT_PUSHES);

        let permit = PushDispatcher::acquire_push_permit(semaphore.clone(), &metrics)
            .await
            .expect("permit should be acquired");

        assert_eq!(
            gauge_metric_value(&metrics, "transponder_push_semaphore_available"),
            (MAX_CONCURRENT_PUSHES - 1) as i64
        );

        drop(permit);
        PushDispatcher::update_semaphore_available_metric(&metrics, &semaphore);

        assert_eq!(
            gauge_metric_value(&metrics, "transponder_push_semaphore_available"),
            MAX_CONCURRENT_PUSHES as i64
        );
    }

    #[tokio::test]
    async fn test_live_task_available_metric_updates_on_permit_acquire() {
        use crate::metrics::Metrics;

        let metrics = Metrics::new().unwrap();
        let metrics = metrics.clone();
        let semaphore = Arc::new(Semaphore::new(MAX_LIVE_SEND_TASKS));

        metrics.set_push_live_tasks_available(MAX_LIVE_SEND_TASKS);

        let permit = PushDispatcher::acquire_live_task_permit(semaphore.clone(), &metrics)
            .await
            .expect("permit should be acquired");

        assert_eq!(
            gauge_metric_value(&metrics, "transponder_push_live_tasks_available"),
            (MAX_LIVE_SEND_TASKS - 1) as i64
        );

        drop(permit);
        PushDispatcher::update_live_task_available_metric(&metrics, &semaphore);

        assert_eq!(
            gauge_metric_value(&metrics, "transponder_push_live_tasks_available"),
            MAX_LIVE_SEND_TASKS as i64
        );
    }

    #[tokio::test]
    async fn test_live_task_metric_exposes_saturation_when_active_permits_are_idle() {
        use crate::metrics::Metrics;

        let metrics = Metrics::new().unwrap();
        let live_task_semaphore = Arc::new(Semaphore::new(MAX_LIVE_SEND_TASKS));
        let mut permits = Vec::with_capacity(MAX_LIVE_SEND_TASKS);

        metrics.set_push_semaphore_available(MAX_CONCURRENT_PUSHES);
        metrics.set_push_live_tasks_available(MAX_LIVE_SEND_TASKS);

        for _ in 0..MAX_LIVE_SEND_TASKS {
            permits.push(
                PushDispatcher::acquire_live_task_permit(live_task_semaphore.clone(), &metrics)
                    .await
                    .expect("permit should be acquired"),
            );
        }

        assert_eq!(
            gauge_metric_value(&metrics, "transponder_push_semaphore_available"),
            MAX_CONCURRENT_PUSHES as i64,
            "active HTTP permits can be fully available while live tasks are saturated"
        );
        assert_eq!(
            gauge_metric_value(&metrics, "transponder_push_live_tasks_available"),
            0
        );

        drop(permits);
        PushDispatcher::update_live_task_available_metric(&metrics, &live_task_semaphore);
        assert_eq!(
            gauge_metric_value(&metrics, "transponder_push_live_tasks_available"),
            MAX_LIVE_SEND_TASKS as i64
        );
    }

    #[tokio::test]
    async fn test_dispatch_after_shutdown_records_rejection_metric() {
        use crate::config::ApnsConfig;
        use crate::metrics::Metrics;
        use crate::push::ApnsClient;

        let metrics = Metrics::new().unwrap();
        let dispatcher = PushDispatcher::with_metrics(
            Some(ApnsClient::mock(
                ApnsConfig {
                    enabled: true,
                    key_id: "KEY123".to_string(),
                    team_id: "TEAM456".to_string(),
                    private_key_path: String::new(),
                    environment: crate::config::ApnsEnvironment::Sandbox,
                    bundle_id: "com.example.app".to_string(),
                    payload_mode: Default::default(),
                },
                true,
            )),
            None,
            metrics.clone(),
        );

        dispatcher.wait_for_completion().await;

        let payloads = vec![TokenPayload {
            platform: Platform::Apns,
            device_token: vec![0xaa, 0xbb, 0xcc],
        }];

        let error = dispatcher.dispatch(payloads).await.unwrap_err();
        assert!(matches!(error, Error::Dispatch(_)));
        assert_eq!(
            counter_metric_value(&metrics, "transponder_push_queue_rejected_total"),
            1
        );
    }

    #[tokio::test]
    async fn test_dispatch_after_shutdown_rejects_only_admissible_payloads() {
        use crate::config::ApnsConfig;
        use crate::metrics::Metrics;
        use crate::push::ApnsClient;

        let metrics = Metrics::new().unwrap();
        let dispatcher = PushDispatcher::with_metrics(
            Some(ApnsClient::mock(
                ApnsConfig {
                    enabled: true,
                    key_id: "KEY123".to_string(),
                    team_id: "TEAM456".to_string(),
                    private_key_path: String::new(),
                    environment: crate::config::ApnsEnvironment::Sandbox,
                    bundle_id: "com.example.app".to_string(),
                    payload_mode: Default::default(),
                },
                true,
            )),
            None,
            metrics.clone(),
        );

        dispatcher.wait_for_completion().await;

        let payloads = vec![
            TokenPayload {
                platform: Platform::Apns,
                device_token: vec![0xaa, 0xbb, 0xcc],
            },
            TokenPayload {
                platform: Platform::Fcm,
                device_token: b"fcm-token-123".to_vec(),
            },
        ];

        let error = dispatcher.dispatch(payloads).await.unwrap_err();
        assert!(matches!(error, Error::Dispatch(_)));
        assert_eq!(
            counter_metric_value(&metrics, "transponder_push_queue_rejected_total"),
            1
        );
    }

    #[tokio::test]
    async fn test_dispatch_after_shutdown_rejects_filtered_batch() {
        let dispatcher = PushDispatcher::new(None, None);

        dispatcher.wait_for_completion().await;

        let payloads = vec![TokenPayload {
            platform: Platform::Apns,
            device_token: vec![0xaa, 0xbb, 0xcc],
        }];

        let error = dispatcher.dispatch(payloads).await.unwrap_err();
        assert!(matches!(error, Error::Dispatch(_)));
    }

    #[tokio::test]
    async fn test_bounded_queue_prevents_unbounded_growth() {
        use crate::config::ApnsConfig;
        use crate::push::ApnsClient;

        // Create a dispatcher with a mock client
        let apns_config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: crate::config::ApnsEnvironment::Sandbox,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
        };
        let apns_client = ApnsClient::mock(apns_config, true);
        let dispatcher = PushDispatcher::new(Some(apns_client), None);

        // The queue should be bounded
        assert!(dispatcher.queue_capacity() <= MAX_PENDING_QUEUE_SIZE);
        assert_eq!(dispatcher.max_queue_size(), MAX_PENDING_QUEUE_SIZE);
    }

    #[tokio::test]
    async fn test_wait_for_completion_drains_backlog_before_returning() {
        use crate::config::ApnsConfig;
        use crate::push::ApnsClient;

        let apns_config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: crate::config::ApnsEnvironment::Sandbox,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
        };
        let dispatcher = Arc::new(PushDispatcher::new(
            Some(ApnsClient::mock(apns_config, true)),
            None,
        ));

        let permits = dispatcher
            .semaphore
            .acquire_many(MAX_CONCURRENT_PUSHES as u32)
            .await
            .unwrap();

        let payloads = repeated_apns_payloads(MAX_CONCURRENT_PUSHES + 2);
        assert_eq!(
            dispatcher.dispatch(payloads).await.unwrap(),
            MAX_CONCURRENT_PUSHES + 2
        );

        let shutdown_dispatcher = dispatcher.clone();
        let shutdown_handle = tokio::spawn(async move {
            shutdown_dispatcher.wait_for_completion().await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(permits);

        tokio::time::timeout(Duration::from_secs(1), shutdown_handle)
            .await
            .expect("shutdown should complete")
            .expect("shutdown task should not panic");

        assert_eq!(dispatcher.queue_capacity(), MAX_PENDING_QUEUE_SIZE);
    }

    #[tokio::test]
    async fn test_concurrency_limit_blocks_when_semaphore_is_saturated() {
        use crate::config::ApnsConfig;
        use crate::push::ApnsClient;

        let apns_config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: crate::config::ApnsEnvironment::Sandbox,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
        };
        let dispatcher = Arc::new(PushDispatcher::new(
            Some(ApnsClient::mock(apns_config, true)),
            None,
        ));
        assert_eq!(
            dispatcher.semaphore.available_permits(),
            MAX_CONCURRENT_PUSHES
        );

        // Saturate the semaphore as if MAX_CONCURRENT_PUSHES sends are already
        // in flight. The next queued push is the 101st send and must block in
        // the dispatcher until a permit is released.
        let saturated_permits = dispatcher
            .semaphore
            .acquire_many(MAX_CONCURRENT_PUSHES as u32)
            .await
            .unwrap();

        assert_eq!(
            dispatcher
                .dispatch(vec![TokenPayload {
                    platform: Platform::Apns,
                    device_token: vec![0xaa, 0xbb, 0xcc],
                }])
                .await
                .unwrap(),
            1
        );

        let shutdown_dispatcher = dispatcher.clone();
        let shutdown_handle = tokio::spawn(async move {
            shutdown_dispatcher.wait_for_completion().await;
        });

        tokio::time::timeout(Duration::from_secs(1), shutdown_handle)
            .await
            .expect("shutdown should close admission instead of waiting for capacity")
            .expect("shutdown task should not panic");
        drop(saturated_permits);
        assert_eq!(
            dispatcher.semaphore.available_permits(),
            MAX_CONCURRENT_PUSHES
        );
    }

    #[tokio::test]
    async fn test_dispatch_rejects_batch_larger_than_queue() {
        use crate::config::ApnsConfig;
        use crate::metrics::Metrics;
        use crate::push::ApnsClient;

        let apns_config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: crate::config::ApnsEnvironment::Sandbox,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
        };
        let apns_client = ApnsClient::mock(apns_config, true);
        let metrics = Metrics::new().unwrap();
        let dispatcher = PushDispatcher::with_metrics(Some(apns_client), None, metrics.clone());

        let payloads = repeated_apns_payloads(MAX_PENDING_QUEUE_SIZE + 1);

        let error = dispatcher.dispatch(payloads).await.unwrap_err();

        assert!(matches!(error, Error::Dispatch(message) if message.contains("Push queue full")));
        assert_eq!(
            counter_metric_value(&metrics, "transponder_push_queue_rejected_total"),
            (MAX_PENDING_QUEUE_SIZE + 1) as u64
        );
    }

    /// Regression test for the increment-after-send race in `dispatch()`.
    ///
    /// `dispatch()` must increment `queue_depth` for the whole batch *before*
    /// sending any message into the channel. A message becomes dequeueable the
    /// instant `permit.send(...)` runs, so a worker can decrement `queue_depth`
    /// immediately. If the increment happened after the send loop, a worker
    /// decrement could fire while `queue_depth` was still 0; the saturating
    /// `checked_sub` would silently drop it, and the later batch increment would
    /// over-count. Across many batches the `transponder_push_queue_size` gauge
    /// would drift upward and stop reflecting the real queue depth.
    ///
    /// Here each dispatched message is fully drained (the mock send succeeds and
    /// no permits are held back), so the *correct* steady-state gauge value is
    /// exactly 0 after every batch. With the buggy ordering at least one
    /// decrement per batch raced ahead of the increment and was clamped away,
    /// leaving the gauge stuck above 0 and climbing. We run several batches and
    /// assert the gauge returns to exactly 0 each time — i.e. no upward drift.
    ///
    /// This test deliberately uses a **multi-threaded** runtime. The race only
    /// manifests when a worker task runs concurrently with `dispatch()` on a
    /// different thread: under the default current-thread runtime there is no
    /// `.await` point between the (buggy) post-loop increment and the sends, so
    /// a worker can never be polled in between and the buggy ordering would pass
    /// undetected. With `worker_threads = 2` the worker pool can dequeue and
    /// decrement on a separate thread while `dispatch()` is still running,
    /// reproducing the lost-decrement race the fix guards against.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_queue_depth_does_not_drift_across_batches() {
        use crate::config::ApnsConfig;
        use crate::metrics::Metrics;
        use crate::push::ApnsClient;

        let apns_config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: crate::config::ApnsEnvironment::Sandbox,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
        };

        let metrics = Metrics::new().unwrap();
        let dispatcher = PushDispatcher::with_metrics(
            Some(ApnsClient::mock(apns_config, true)),
            None,
            metrics.clone(),
        );

        // Many small batches maximize the number of opportunities for a worker
        // to dequeue (and decrement) before the batch increment would have run
        // under the old ordering.
        for _ in 0..50 {
            let payloads = repeated_apns_payloads(4);
            assert_eq!(dispatcher.dispatch(payloads).await.unwrap(), 4);

            // Let the worker pool fully drain the batch.
            tokio::time::sleep(Duration::from_millis(5)).await;

            // The queue is genuinely empty now; the gauge must read exactly 0.
            // Any value above 0 means decrements were lost to the race and the
            // counter has drifted upward.
            assert_eq!(
                queue_size_metric_value(&metrics),
                0,
                "queue_size gauge drifted above 0 — decrement-after-send race regressed"
            );
        }

        dispatcher.wait_for_completion().await;
    }

    #[tokio::test]
    async fn test_inflight_tracker_blocks_until_guard_dropped() {
        let tracker = Arc::new(InFlightTracker::new());

        // No in-flight tasks: wait_idle returns immediately.
        tokio::time::timeout(Duration::from_millis(200), tracker.wait_idle())
            .await
            .expect("wait_idle should return immediately with no in-flight tasks");

        // Hold a guard, then assert wait_idle does NOT return until it is dropped.
        let guard = tracker.enter();
        assert_eq!(tracker.in_flight_count(), 1);

        let waiter_tracker = tracker.clone();
        let waiter = tokio::spawn(async move { waiter_tracker.wait_idle().await });

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !waiter.is_finished(),
            "wait_idle must not complete while a guard is still held"
        );

        drop(guard);

        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("wait_idle should complete after the last guard is dropped")
            .expect("waiter task should not panic");

        assert_eq!(tracker.in_flight_count(), 0);
    }

    /// Regression for transponder#65: graceful shutdown must wait for send tasks
    /// that are sitting in a retry backoff sleep, even though such a task has
    /// released its concurrency permit (so "all permits acquired" would wrongly
    /// declare the pool drained). The drain guarantee is enforced by the
    /// in-flight task tracker, not by permit accounting.
    #[tokio::test]
    async fn test_wait_for_completion_waits_for_retry_task_during_backoff() {
        use crate::push::retry::{BackoffPermit, RetryConfig, SendAttemptResult, with_retry};
        use std::sync::atomic::AtomicU32;

        let dispatcher = Arc::new(PushDispatcher::new(None, None));

        // Acquire one real permit from the dispatcher's semaphore and wrap it,
        // mirroring exactly what spawn_workers does for a send task.
        let permit = dispatcher
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore should grant a permit");
        let mut backoff_permit = BackoffPermit::new(dispatcher.semaphore.clone(), permit);

        // Register the simulated send task as in-flight, just like the real path.
        let guard = dispatcher.inflight.enter();

        // A retry config with a backoff long enough to observe the sleep window
        // deterministically from the test even after retry jitter shortens the
        // fallback sleep by up to half.
        let config = RetryConfig {
            max_retries: 3,
            initial_backoff: Duration::from_millis(600),
        };
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_op = attempts.clone();

        // Spawn the simulated send task: one retriable result forces a backoff
        // sleep (during which the permit is released), then success.
        let send_task = tokio::spawn(async move {
            let _guard = guard;
            let result = with_retry(
                &config,
                "test",
                || {
                    let n = attempts_op.clone();
                    async move {
                        if n.fetch_add(1, Ordering::SeqCst) == 0 {
                            SendAttemptResult::Retriable {
                                status_code: 429,
                                retry_after: None,
                            }
                        } else {
                            SendAttemptResult::Success(true)
                        }
                    }
                },
                Some(&mut backoff_permit),
                Metrics::disabled(),
            )
            .await;
            assert!(matches!(result, Ok(PushSendOutcome::RetriesExhausted)));
        });

        // Let the task reach its backoff sleep (first attempt + release of permit).
        tokio::time::sleep(Duration::from_millis(100)).await;

        // During backoff the permit IS released, so the now-unsound "acquire all
        // permits" approach would observe a fully-available pool and wrongly
        // declare drain complete. Prove the permit is free:
        assert_eq!(
            dispatcher.semaphore.available_permits(),
            MAX_CONCURRENT_PUSHES,
            "the retry task should have released its permit during the backoff sleep"
        );

        // Despite the free permit, wait_for_completion must NOT return while the
        // retry task is still alive.
        let shutdown_dispatcher = dispatcher.clone();
        let shutdown = tokio::spawn(async move {
            shutdown_dispatcher.wait_for_completion().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !shutdown.is_finished(),
            "wait_for_completion must not complete while a retry task is sleeping in backoff"
        );

        // Once the backoff ends, the closed semaphore aborts the retry instead
        // of allowing another provider request during teardown.
        send_task.await.expect("send task should not panic");

        tokio::time::timeout(Duration::from_secs(2), shutdown)
            .await
            .expect("wait_for_completion should complete after the retry task finishes")
            .expect("shutdown task should not panic");

        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_live_task_bound_is_twice_the_concurrency_limit() {
        // The live-task ceiling must be a small constant multiple of the
        // active-concurrency limit, not the queue size (#160).
        const _: () = assert!(MAX_LIVE_SEND_TASKS == MAX_CONCURRENT_PUSHES * 2);
        const _: () = assert!(MAX_LIVE_SEND_TASKS < MAX_PENDING_QUEUE_SIZE);
    }

    #[tokio::test]
    async fn test_live_task_semaphore_caps_live_tasks_under_backoff_storm() {
        // Regression for #160: under a provider 429 storm every in-flight send
        // enters backoff and RELEASES its concurrency permit while staying
        // alive (still holding a decrypted token). The recv loop would then
        // reacquire the freed concurrency permits and drain the whole queue,
        // ballooning live token-holding tasks to the queue size. The live-task
        // semaphore (acquired at spawn, held across backoff) must cap live
        // tasks at MAX_LIVE_SEND_TASKS regardless of how many are queued.
        use crate::config::ApnsConfig;
        use crate::push::ApnsClient;
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Every send gets a 429 with a long Retry-After, so tasks stay in
        // backoff (permit released, live-task permit held) for the whole test.
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/3/device/[a-f0-9]+"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "30"))
            .mount(&mock_server)
            .await;

        let apns_config = ApnsConfig {
            enabled: true,
            key_id: "KEY123".to_string(),
            team_id: "TEAM456".to_string(),
            private_key_path: String::new(),
            environment: crate::config::ApnsEnvironment::Sandbox,
            bundle_id: "com.example.app".to_string(),
            payload_mode: Default::default(),
        };
        let mut client = ApnsClient::mock(apns_config, true);
        client.test_base_url = Some(mock_server.uri());
        client
            .seed_token(
                "cached",
                std::time::SystemTime::now() + Duration::from_secs(3600),
            )
            .await;
        let metrics = crate::metrics::Metrics::new().unwrap();
        let dispatcher = Arc::new(PushDispatcher::with_metrics(
            Some(client),
            None,
            metrics.clone(),
        ));

        // Queue far more messages than the live-task ceiling.
        let batch = MAX_LIVE_SEND_TASKS + 300;
        assert_eq!(
            dispatcher
                .dispatch(repeated_apns_payloads(batch))
                .await
                .unwrap(),
            batch
        );

        // Wait until the live-task semaphore is exhausted (recv loop blocked on
        // it), i.e. exactly MAX_LIVE_SEND_TASKS tasks are alive.
        for _ in 0..200 {
            if dispatcher.available_live_task_permits() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            dispatcher.available_live_task_permits(),
            0,
            "live-task semaphore should be fully consumed under the storm"
        );
        assert_eq!(
            gauge_metric_value(&metrics, "transponder_push_live_tasks_available"),
            0,
            "live-task metric should expose saturation while tasks sleep in backoff"
        );

        // The cap must hold: even though tasks keep releasing their concurrency
        // permits during backoff, no more than MAX_LIVE_SEND_TASKS are alive,
        // so the remaining messages stay queued rather than spawned.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(dispatcher.available_live_task_permits(), 0);
        assert!(
            dispatcher.queue_capacity() < MAX_PENDING_QUEUE_SIZE,
            "messages beyond the live-task ceiling must stay queued, not spawned"
        );

        // Point the client at nothing further; abandon the storming tasks by
        // dropping the dispatcher (test process ends). We do not wait_for
        // completion here because the 30s Retry-After would stall the test;
        // the invariant under test (bounded live tasks) is already proven.
    }
}

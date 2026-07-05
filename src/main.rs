//! Transponder - MIP-05 Push Notification Server
//!
//! A privacy-preserving push notification server implementing the Marmot MIP-05
//! specification. Listens for gift-wrapped Nostr events on configured relays,
//! decrypts notification requests, and dispatches silent push notifications
//! to APNs and FCM.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::Parser;
use nostr_sdk::prelude::*;
use tokio::sync::broadcast::{self, error::RecvError};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{EnvFilter, Layer, fmt, prelude::*};
use zeroize::Zeroizing;

mod config;
mod crypto;
mod error;
mod metrics;
mod nostr;
mod push;
mod rate_limiter;
mod redaction;
mod server;
mod shutdown;
mod telemetry;

#[cfg(test)]
mod test_metrics;
#[cfg(test)]
mod test_vectors;

use config::AppConfig;
use crypto::{Nip59Handler, TokenDecryptor};
use metrics::Metrics;
use nostr::client::RelayClient;
use nostr::events::EventProcessor;
use push::{ApnsClient, FcmClient, PushDispatcher};
use server::HealthServer;
use shutdown::{ShutdownHandler, ShutdownTrigger};

/// Transponder - MIP-05 Push Notification Server
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Path to configuration file
    #[arg(short, long, default_value = "config/default.toml", global = true)]
    config: String,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Generate a new Nostr key pair for the server
    GenerateKeys {
        /// Write the generated private key to this file with 0600 permissions
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,

        /// Print the generated private key to stdout
        #[arg(long)]
        show_private_key: bool,
    },
    /// Probe a running Transponder instance for container health checks
    Healthcheck {
        /// Health endpoint URL to probe
        #[arg(long, default_value = "http://127.0.0.1:8080/health")]
        url: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotificationReceiveAction {
    Continue,
    Shutdown,
}

fn classify_notification_receive_error(error: &RecvError) -> NotificationReceiveAction {
    match error {
        RecvError::Lagged(_) => NotificationReceiveAction::Continue,
        RecvError::Closed => NotificationReceiveAction::Shutdown,
    }
}

fn record_notification_receive_metrics(metrics: Option<&Metrics>, error: &RecvError) {
    if let RecvError::Lagged(skipped) = error
        && let Some(metrics) = metrics
    {
        metrics.record_relay_notifications_lagged();
        metrics.record_relay_notifications_dropped(*skipped);
    }
}

#[cfg(feature = "tor")]
const TOR_FEATURE_ENABLED: bool = true;
#[cfg(not(feature = "tor"))]
const TOR_FEATURE_ENABLED: bool = false;

/// Cadence of the background relay-status refresh.
///
/// The refresher recomputes the cached relay connection status (and the
/// `relays_connected` gauges) on this fixed interval, so readiness probes can
/// be pure reads of the snapshot and gauge updates track connection state
/// rather than probe traffic. Five seconds keeps `/ready` at most one refresh
/// interval behind real connection changes for typical orchestrator probe
/// periods (10s+) while enumerating the relay pool rarely.
const RELAY_STATUS_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

fn validate_startup_config(server_private_key: &str, relays: &config::RelayConfig) -> Result<()> {
    if server_private_key.is_empty() {
        anyhow::bail!("Server private key is required");
    }

    if relays.clearnet.is_empty() && relays.onion.is_empty() {
        anyhow::bail!("At least one relay must be configured");
    }

    if !TOR_FEATURE_ENABLED && !relays.onion.is_empty() {
        anyhow::bail!("Onion relays require the 'tor' feature");
    }

    Ok(())
}

fn build_rate_limit_config(server: &config::ServerConfig) -> nostr::events::TokenRateLimitConfig {
    nostr::events::TokenRateLimitConfig {
        max_cache_size: server.max_rate_limit_cache_size,
        max_tokens_per_event: server.max_tokens_per_event,
        encrypted_token_per_minute: server.encrypted_token_rate_limit_per_minute,
        encrypted_token_per_hour: server.encrypted_token_rate_limit_per_hour,
        device_token_per_minute: server.device_token_rate_limit_per_minute,
        device_token_per_hour: server.device_token_rate_limit_per_hour,
        global_unwrap_per_minute: server.global_unwrap_rate_limit_per_minute,
        global_unwrap_per_hour: server.global_unwrap_rate_limit_per_hour,
    }
}

fn build_replay_protection_config(
    server: &config::ServerConfig,
) -> nostr::events::ReplayProtectionConfig {
    let dedup_state_path = if server.dedup_state_path.as_os_str().is_empty() {
        None
    } else {
        Some(server.dedup_state_path.clone())
    };

    nostr::events::ReplayProtectionConfig {
        max_dedup_cache_size: server.max_dedup_cache_size,
        dedup_state_path,
        dedup_retention: Duration::from_secs(server.dedup_retention_secs),
        max_notification_age: Duration::from_secs(server.max_notification_age_secs),
        max_notification_future_skew: Duration::from_secs(server.max_notification_future_skew_secs),
    }
}

fn parse_server_secret_key(server_private_key: &str) -> Result<SecretKey> {
    SecretKey::parse(server_private_key).context("Invalid server private key")
}

/// Number of permits to use for the event-processing semaphore.
///
/// Bounds total in-flight gift-wrap unwrap (ECDH) work. A configured value of
/// zero would deadlock the event loop (no permit could ever be acquired), so it
/// is clamped up to a single permit, preserving sequential processing.
#[must_use]
fn event_processing_permits(max_concurrent_event_processing: usize) -> usize {
    max_concurrent_event_processing.max(1)
}

/// Outcome of racing relay startup against a shutdown signal.
#[derive(Debug)]
enum StartupOutcome<T, S> {
    /// Startup finished; carries the connect result.
    Connected(T),
    /// A shutdown signal arrived before startup finished; carries the signal
    /// future's output (e.g. the [`shutdown::ShutdownReason`]).
    ShutdownRequested(S),
}

/// Awaits a startup future while remaining responsive to a shutdown signal.
///
/// The signal future must already have its SIGTERM/SIGINT handlers installed
/// *before* the startup work is awaited, so a signal that arrives while waiting
/// for relay connections exits promptly instead of being ignored until the
/// connect timeout elapses. Shutdown is preferred (`biased`) so a signal that is
/// already pending wins over a startup future that resolves in the same poll.
async fn run_startup_or_shutdown<T, S, StartupFut, SignalFut>(
    startup: StartupFut,
    signal_fut: SignalFut,
) -> StartupOutcome<T, S>
where
    StartupFut: std::future::Future<Output = T>,
    SignalFut: std::future::Future<Output = S>,
{
    tokio::select! {
        biased;

        reason = signal_fut => StartupOutcome::ShutdownRequested(reason),
        result = startup => StartupOutcome::Connected(result),
    }
}

/// Map how shutdown was initiated to the process exit result.
///
/// A signal-initiated stop is a clean exit. An internally triggered stop means
/// a supervised critical task failed; exiting non-zero makes orchestrators
/// with on-failure restart policies reschedule the process instead of
/// treating the stop as intentional.
fn shutdown_result(reason: shutdown::ShutdownReason) -> Result<()> {
    match reason {
        shutdown::ShutdownReason::Signal => Ok(()),
        shutdown::ShutdownReason::InternalTrigger => Err(anyhow::anyhow!(
            "shutting down after a critical task failure"
        )),
    }
}

async fn acquire_event_processing_permit_or_shutdown(
    semaphore: Arc<Semaphore>,
    shutdown: &mut watch::Receiver<bool>,
) -> Option<OwnedSemaphorePermit> {
    // Prefer shutdown over newly available capacity so teardown does not admit
    // more event-processing work after a shutdown signal is visible.
    tokio::select! {
        biased;

        _ = shutdown.changed() => {
            debug!("Event processor shutting down before permit acquisition");
            None
        },
        permit = semaphore.acquire_owned() => permit.ok(),
    }
}

/// Why the event-consumer loop exited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventLoopExit {
    /// The loop observed the shutdown signal; expected during teardown.
    ShutdownRequested,
    /// The relay notification channel closed while the process was supposed
    /// to keep running; unexpected, must tear the process down.
    ChannelClosed,
}

/// Map an event-loop exit to a supervision result.
///
/// A shutdown-signal exit is the expected teardown path; a channel close means
/// event processing silently died and, left alone, the process would become a
/// zombie that reports healthy while handling zero events (#151).
fn event_loop_exit_to_supervision_result(
    exit: EventLoopExit,
) -> std::result::Result<(), &'static str> {
    match exit {
        EventLoopExit::ShutdownRequested => Ok(()),
        EventLoopExit::ChannelClosed => Err("relay notification channel closed"),
    }
}

/// Trigger a process-wide shutdown when a critical task fails.
///
/// Expected exits pass `Ok(())` and are left alone. Any `Err` means a task the
/// process cannot live without (health server, event loop) died while the rest
/// of the process kept running; triggering shutdown makes the process exit so
/// the orchestrator restarts it instead of leaving a zombie.
fn supervise_critical_task<E: std::fmt::Display>(
    task: &'static str,
    result: std::result::Result<(), E>,
    shutdown_trigger: &ShutdownTrigger,
) {
    if let Err(error) = result {
        error!(task, error = %error, "Critical task exited unexpectedly; triggering shutdown");
        shutdown_trigger.trigger();
    }
}

/// Drain relay notifications and process events with bounded concurrency.
///
/// Each admitted event is processed in its own task spawned onto `event_tasks`,
/// gated by a semaphore. The receive loop drains the broadcast channel quickly
/// so it does not fall behind and trigger `Lagged` overflow, while the
/// semaphore caps total in-flight gift-wrap unwrap (ECDH) work so a flood
/// cannot spawn unbounded crypto tasks. An owned permit is acquired BEFORE
/// spawning and dropped when the spawned task finishes; when the budget is
/// exhausted the loop awaits a free permit (applying back-pressure) while
/// still remaining responsive to shutdown signals.
///
/// Spawning through the [`TaskTracker`] keeps in-flight unwrap work joinable:
/// [`staged_teardown`] waits for these tasks before draining the push
/// dispatcher, so notifications mid-unwrap at shutdown are delivered instead
/// of aborted (#84, #173).
async fn run_event_loop(
    mut notifications: broadcast::Receiver<RelayPoolNotification>,
    mut shutdown: watch::Receiver<bool>,
    event_semaphore: Arc<Semaphore>,
    processor: Arc<EventProcessor>,
    event_tasks: TaskTracker,
    metrics: Option<Metrics>,
) -> EventLoopExit {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                info!("Event processor shutting down");
                return EventLoopExit::ShutdownRequested;
            }
            result = notifications.recv() => {
                match result {
                    Ok(notification) => {
                        let RelayPoolNotification::Event { event, .. } = notification else {
                            continue;
                        };

                        // Acquire a permit before spawning so total in-flight
                        // unwrap work stays bounded. `None` means shutdown won
                        // while waiting (or the semaphore closed, which never
                        // happens here), so intentionally drop this event.
                        let Some(permit) = acquire_event_processing_permit_or_shutdown(
                            Arc::clone(&event_semaphore),
                            &mut shutdown,
                        )
                        .await
                        else {
                            return EventLoopExit::ShutdownRequested;
                        };

                        let processor = processor.clone();
                        event_tasks.spawn(async move {
                            // Hold the permit for the lifetime of the task; it
                            // is released when `permit` is dropped on return.
                            let _permit = permit;
                            if let Err(e) = processor.process(&event).await {
                                debug!(error = %e, "Event processing error");
                            }
                        });
                    }
                    Err(e) => {
                        record_notification_receive_metrics(metrics.as_ref(), &e);

                        match classify_notification_receive_error(&e) {
                            NotificationReceiveAction::Continue => {
                                warn!(error = %e, "Lagged relay notifications, continuing");
                            }
                            NotificationReceiveAction::Shutdown => {
                                error!(error = %e, "Notification channel closed");
                                return EventLoopExit::ChannelClosed;
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Tear down the pipeline in dependency order, producers before consumers.
///
/// The stage order is load-bearing (#173, #84):
///
/// 1. Join the event loop. The shutdown watch has already fired, so it stops
///    admitting events; joining it guarantees no new processing task can be
///    spawned after the tracker is closed.
/// 2. Close and drain the task tracker. In-flight gift-wrap unwraps run to
///    completion and their `dispatch()` calls are still accepted, because the
///    push dispatcher has not flipped `shutting_down` yet.
/// 3. Drain the push dispatcher. `wait_for_completion` rejects new dispatches
///    from its first instant, so it must run only after every producer above
///    is quiesced.
/// 4. Disconnect relays. This closes the notification broadcast channel, which
///    is only safe (no spurious `Closed` error) once the event loop is gone.
/// 5. Join the remaining supervised tasks (health server, cleanup, relay
///    status refresher).
///
/// The caller bounds the whole sequence with the configured shutdown timeout
/// via [`shutdown::graceful_shutdown`].
async fn staged_teardown(
    event_handle: tokio::task::JoinHandle<()>,
    event_tasks: TaskTracker,
    push_dispatcher: Arc<PushDispatcher>,
    relay_client: Arc<RelayClient>,
    health_handle: tokio::task::JoinHandle<()>,
    cleanup_handle: tokio::task::JoinHandle<()>,
    status_refresh_handle: tokio::task::JoinHandle<()>,
) {
    let _ = event_handle.await;

    event_tasks.close();
    event_tasks.wait().await;

    push_dispatcher.wait_for_completion().await;

    if let Err(e) = relay_client.disconnect().await {
        warn!(error = %e, "Error disconnecting from relays");
    }

    let _ = tokio::join!(health_handle, cleanup_handle, status_refresh_handle);
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Handle subcommands
    if let Some(command) = args.command {
        return match command {
            Command::GenerateKeys {
                output,
                show_private_key,
            } => generate_keys(output.as_deref(), show_private_key),
            Command::Healthcheck { url } => run_healthcheck(&url).await,
        };
    }

    // Load configuration
    let config = AppConfig::load(&args.config)
        .with_context(|| format!("Failed to load config from {}", args.config))?;

    // Initialize error reporting before logging so a GlitchTip client exists for
    // the first captured event. The guard is held for the whole process and
    // dropped last, flushing buffered events — including any fatal error captured
    // below. It must stay in `main` rather than move into `run`, or it would drop
    // before that error is recorded.
    let _glitchtip_guard = telemetry::init(&config.glitchtip)?;

    // Initialize logging
    init_logging(&config.logging)?;

    info!(
        version = env!("CARGO_PKG_VERSION"),
        config_path = %args.config,
        "Starting Transponder"
    );

    let result = run(config).await;
    if let Err(error) = &result {
        error!(error = %error, "Fatal error, shutting down");
    }
    result
}

/// Bring the server up and run until shutdown.
///
/// Split from `main` so a failure during startup or the run loop is logged at
/// `ERROR` — and therefore reported to GlitchTip — instead of only surfacing on
/// process exit. The GlitchTip guard stays in `main` so it outlives this call
/// and flushes the captured event. Failures *before* this point (config load,
/// `telemetry::init`, `init_logging`) occur before the subscriber and client
/// exist, so they surface only on stderr, not in GlitchTip.
async fn run(mut config: AppConfig) -> Result<()> {
    // Initialize metrics
    let metrics = if config.metrics.enabled {
        match Metrics::new() {
            Ok(m) => {
                m.init_server_info(env!("CARGO_PKG_VERSION"));
                info!("Metrics initialized");
                Some(m)
            }
            Err(e) => {
                error!(error = %e, "Failed to initialize metrics");
                None
            }
        }
    } else {
        info!("Metrics disabled");
        None
    };

    let server_private_key = resolve_server_private_key(&mut config.server)?;

    // Validate configuration
    validate_startup_config(server_private_key.as_str(), &config.relays)?;

    // Create server keys
    let secret_key = parse_server_secret_key(server_private_key.as_str())?;
    let keys = Keys::new(secret_key);
    drop(server_private_key);

    debug!(
        pubkey = %keys.public_key().to_hex(),
        "Server public key"
    );

    // Initialize crypto handlers
    let nip59_handler = Nip59Handler::new(keys.clone());
    // Convert nostr_sdk SecretKey to secp256k1 SecretKey for TokenDecryptor
    let secret_bytes = Zeroizing::new(keys.secret_key().to_secret_bytes());
    let mut secp_secret_key = secp256k1::SecretKey::from_slice(secret_bytes.as_ref())
        .context("Failed to create secp256k1 secret key")?;
    let token_decryptor = TokenDecryptor::new(&mut secp_secret_key);

    // Initialize push clients
    let apns_client = if config.apns.enabled {
        match ApnsClient::with_metrics(config.apns.clone(), metrics.clone()).await {
            Ok(client) => {
                if client.is_configured() {
                    info!(
                        environment = %config.apns.environment,
                        payload_mode = %config.apns.payload_mode,
                        "APNs push service configured"
                    );
                    Some(client)
                } else {
                    warn!("APNs enabled but not fully configured");
                    None
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to initialize APNs client");
                None
            }
        }
    } else {
        info!("APNs push service disabled");
        None
    };

    let fcm_client = if config.fcm.enabled {
        match FcmClient::with_metrics(config.fcm.clone(), metrics.clone()).await {
            Ok(client) => {
                if client.is_configured() {
                    info!("FCM push service configured");
                    Some(client)
                } else {
                    warn!("FCM enabled but not fully configured");
                    None
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to initialize FCM client");
                None
            }
        }
    } else {
        info!("FCM push service disabled");
        None
    };

    // Create push dispatcher
    let push_dispatcher = Arc::new(PushDispatcher::with_metrics(
        apns_client,
        fcm_client,
        metrics.clone(),
    ));

    if !push_dispatcher.is_ready() {
        warn!("No push services configured - notifications will not be sent");
    }

    // Create the event processor with configured replay protection and rate
    // limiting. Constructed before any relay network work so the event
    // consumer can start polling the moment the notification receiver exists
    // (see below).
    let rate_limit_config = build_rate_limit_config(&config.server);
    let replay_config = build_replay_protection_config(&config.server);
    let event_processor = Arc::new(
        EventProcessor::with_replay_config(
            nip59_handler,
            token_decryptor,
            push_dispatcher.clone(),
            rate_limit_config,
            replay_config,
            metrics.clone(),
        )
        .context("Failed to initialize event replay protection")?,
    );

    // Initialize relay client
    let relay_client = Arc::new(
        RelayClient::with_metrics(keys.clone(), config.relays.clone(), metrics.clone())
            .await
            .context("Failed to create relay client")?,
    );

    // Initialize shutdown handler before connecting so a SIGTERM/SIGINT during
    // startup exits promptly. Without this, signal handlers were installed only
    // after `connect()` returned, so a signal received while waiting for relays
    // (potentially up to the whole connection timeout) was ignored.
    let shutdown = ShutdownHandler::new();

    // Bind the health server before any relay work so a bind failure — almost
    // always a permanent misconfiguration — fails startup fast instead of
    // leaving a process running with dead /health, /ready, and /metrics
    // endpoints.
    let health_server = HealthServer::new(
        config.health.clone(),
        relay_client.clone(),
        push_dispatcher.clone(),
        metrics.clone(),
    );
    let health_listener = health_server
        .bind()
        .await
        .context("Failed to start health server")?;

    // Serve under supervision: a runtime health-server failure triggers global
    // shutdown so the orchestrator restarts the process instead of leaving it
    // running with no external health signal.
    let health_shutdown = shutdown.subscribe();
    let health_trigger = shutdown.trigger_handle();
    let health_handle = tokio::spawn(async move {
        let result = health_server.serve(health_listener, health_shutdown).await;
        supervise_critical_task("health server", result, &health_trigger);
    });

    // Connect to relays, but bail out immediately if a shutdown signal (or an
    // internal trigger from a supervised task) arrives while we are still
    // waiting for the first relay to connect.
    match run_startup_or_shutdown(
        relay_client.connect(),
        shutdown.wait_for_signal_or_trigger(),
    )
    .await
    {
        StartupOutcome::Connected(result) => {
            result.context("Failed to connect to relays")?;
        }
        StartupOutcome::ShutdownRequested(reason) => {
            info!("Shutdown signal received during startup; stopping before relay connection");
            if let Err(e) = relay_client.disconnect().await {
                warn!(error = %e, "Error disconnecting from relays during startup shutdown");
            }
            // The shutdown watch is already set, so the health task exits on
            // its own; join it to finish teardown cleanly.
            let _ = health_handle.await;
            info!("Transponder stopped");
            return shutdown_result(reason);
        }
    }

    // Obtain the broadcast receiver BEFORE issuing the subscription REQ.
    //
    // `notifications()` returns a fresh `tokio::sync::broadcast::Receiver`, which
    // only observes messages broadcast after it is created. The subscription uses a
    // 2-day lookback, so relays immediately stream the stored backlog of gift wraps.
    // If the receiver were created after `subscribe()` (e.g. inside the spawned event
    // task), any backlog delivered before the task is first polled would be broadcast
    // to zero receivers and silently dropped — broadcast channels do not replay
    // history. Creating the receiver first closes that startup window entirely.
    let notifications = relay_client.notifications();

    // Spawn the event consumer BEFORE `subscribe()` streams the backlog and
    // before the `publish_inbox_relays()` network round-trip below. The early
    // receiver above only prevents the "zero receivers" drop; a consumer must
    // also be POLLING before any startup await that can block for a meaningful
    // duration, or the backlog can overflow the bounded broadcast buffer while
    // nothing drains it and the oldest gift wraps are silently lost.
    //
    // The loop runs under supervision: an unexpected exit (notification
    // channel closed) triggers global shutdown instead of leaving a zombie
    // process that reports healthy while processing nothing.
    let event_permits = event_processing_permits(config.server.max_concurrent_event_processing);
    let event_semaphore = Arc::new(Semaphore::new(event_permits));
    let event_tasks = TaskTracker::new();
    let event_shutdown = shutdown.subscribe();
    let event_trigger = shutdown.trigger_handle();
    let event_handle = {
        let processor = event_processor.clone();
        let event_tasks = event_tasks.clone();
        let event_metrics = metrics.clone();
        tokio::spawn(async move {
            let exit = run_event_loop(
                notifications,
                event_shutdown,
                event_semaphore,
                processor,
                event_tasks,
                event_metrics,
            )
            .await;
            supervise_critical_task(
                "event loop",
                event_loop_exit_to_supervision_result(exit),
                &event_trigger,
            );
        })
    };

    // Subscribe to events
    relay_client
        .subscribe(keys.public_key())
        .await
        .context("Failed to subscribe to events")?;

    // Publish inbox relay list
    if let Err(e) = relay_client.publish_inbox_relays().await {
        warn!(error = %e, "Failed to publish inbox relay list");
    }

    // Start periodic cleanup task
    let mut cleanup_shutdown = shutdown.subscribe();
    let event_processor_cleanup = event_processor.clone();

    let cleanup_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));

        loop {
            tokio::select! {
                _ = cleanup_shutdown.changed() => {
                    break;
                }
                _ = interval.tick() => {
                    event_processor_cleanup.cleanup().await;
                }
            }
        }
    });

    // Start the background relay-status refresher. After startup it is the
    // only writer of the cached relay status (and the relays_connected
    // gauges): `/ready` and other readers consume the snapshot without
    // recomputing it, so unauthenticated probes cannot drive lock or gauge
    // churn (see RelayClient::refresh_status).
    let mut status_refresh_shutdown = shutdown.subscribe();
    let status_refresh_client = relay_client.clone();
    let status_refresh_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(RELAY_STATUS_REFRESH_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = status_refresh_shutdown.changed() => {
                    break;
                }
                _ = interval.tick() => {
                    status_refresh_client.refresh_status().await;
                }
            }
        }
    });

    info!("Transponder running");

    // Wait for a shutdown signal or an internal trigger from a supervised
    // task (health-server failure, notification channel close).
    let shutdown_reason = shutdown.wait_for_signal_or_trigger().await;

    info!("Initiating graceful shutdown");

    // Wait for the full shutdown sequence under one deadline. If an early step
    // consumes the budget, `graceful_shutdown` drops the future and later cleanup
    // steps are skipped rather than extending the configured shutdown bound.
    shutdown::graceful_shutdown(
        || {
            staged_teardown(
                event_handle,
                event_tasks,
                push_dispatcher,
                relay_client,
                health_handle,
                cleanup_handle,
                status_refresh_handle,
            )
        },
        config.server.shutdown_timeout_secs,
    )
    .await;

    info!("Transponder stopped");
    shutdown_result(shutdown_reason)
}

fn create_private_key_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    options
        .open(path)
        .with_context(|| format!("Failed to create private key file {}", path.display()))
}

fn write_private_key_file(path: &Path, secret_hex: &str) -> Result<()> {
    let mut file = create_private_key_file(path)?;
    file.write_all(secret_hex.as_bytes())
        .with_context(|| format!("Failed to write private key file {}", path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("Failed to write private key file {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("Failed to sync private key file {}", path.display()))
}

/// Generate a new Nostr key pair.
fn generate_keys(output: Option<&Path>, show_private_key: bool) -> Result<()> {
    let keys = Keys::generate();
    let secret_hex = Zeroizing::new(keys.secret_key().to_secret_hex());

    if let Some(path) = output {
        write_private_key_file(path, secret_hex.as_str())?;
    }

    println!("Generated new Nostr key pair:\n");
    println!("Public key (hex):  {}", keys.public_key().to_hex());
    println!("Public key (npub): {}", keys.public_key().to_bech32()?);
    println!();

    if show_private_key {
        eprintln!(
            "WARNING: The private key below enables decryption of ALL notification tokens. Do not share, log, or commit it."
        );
        println!("Private key (hex): {}", secret_hex.as_str());
        println!();
    }

    if let Some(path) = output {
        println!("Secret written to: {}", path.display());
        println!("Configure the server with:");
        println!("  [server]");
        println!("  private_key_file = \"{}\"", path.display());
    } else if !show_private_key {
        println!("Secret material was not printed.");
        println!("Store a fresh secret directly in a restricted file:");
        println!("  transponder generate-keys --output /path/to/transponder-server.key");
        println!("Use --show-private-key only in a secure, non-logged terminal.");
    }

    println!();
    println!("Share the public key (hex or npub) with clients so they can");
    println!("encrypt notification tokens for your server.");

    Ok(())
}

/// Resolve the server private key from config or a mounted secret file.
fn resolve_server_private_key(config: &mut config::ServerConfig) -> Result<Zeroizing<String>> {
    let private_key = config.private_key.trim();
    if !private_key.is_empty() {
        let private_key = Zeroizing::new(std::mem::take(&mut *config.private_key));

        return if private_key.trim().len() == private_key.len() {
            Ok(private_key)
        } else {
            Ok(Zeroizing::new(private_key.trim().to_string()))
        };
    }

    let private_key_file = config.private_key_file.trim();
    if private_key_file.is_empty() {
        return Ok(Zeroizing::new(String::new()));
    }

    let key_path = Path::new(private_key_file);
    let key = Zeroizing::new(fs::read_to_string(key_path).with_context(|| {
        format!(
            "Failed to read server private key file {}",
            key_path.display()
        )
    })?);

    if key.trim().len() == key.len() {
        Ok(key)
    } else {
        Ok(Zeroizing::new(key.trim().to_string()))
    }
}

/// Probe a Transponder health endpoint and return a non-zero exit on failure.
async fn run_healthcheck(url: &str) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .context("Failed to create healthcheck client")?;

    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("Failed to reach health endpoint at {url}"))?;

    if response.status().is_success() {
        return Ok(());
    }

    anyhow::bail!("Healthcheck failed with status {}", response.status())
}

fn configured_logging_filter(level: &str) -> Result<EnvFilter> {
    EnvFilter::try_new(level).with_context(|| format!("invalid logging.level filter: {level}"))
}

fn logging_filter(config: &config::LoggingConfig) -> Result<EnvFilter> {
    logging_filter_from_env(config, std::env::var(EnvFilter::DEFAULT_ENV))
}

fn logging_filter_from_env(
    config: &config::LoggingConfig,
    env_filter: std::result::Result<String, std::env::VarError>,
) -> Result<EnvFilter> {
    match env_filter {
        Ok(env_filter) => EnvFilter::try_new(&env_filter)
            .with_context(|| format!("invalid RUST_LOG filter: {env_filter}")),
        Err(std::env::VarError::NotPresent) => configured_logging_filter(&config.level),
        Err(error) => Err(error).context("invalid RUST_LOG environment variable"),
    }
}

/// Initialize the tracing subscriber based on configuration.
fn init_logging(config: &config::LoggingConfig) -> Result<()> {
    let filter = logging_filter(config)?;

    // Build the console layer for the configured format (`None` disables console
    // logging). The `EnvFilter` is attached per-layer to the fmt layer only, so it
    // never gates the GlitchTip layer: error reporting stays independent of console
    // verbosity — a tightened `RUST_LOG`, or `format = "off"`, does not silence it.
    // The GlitchTip layer carries its own ERROR-level filter (see `telemetry`).
    let console_layer: Option<Box<dyn Layer<tracing_subscriber::Registry> + Send + Sync>> =
        match config.format.as_str() {
            "json" => Some(fmt::layer().json().with_filter(filter).boxed()),
            "pretty" => Some(fmt::layer().pretty().with_filter(filter).boxed()),
            "off" => None,
            _ => Some(fmt::layer().with_filter(filter).boxed()),
        };

    tracing_subscriber::registry()
        .with(console_layer)
        .with(telemetry::glitchtip_layer())
        .init();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, http::StatusCode, routing::get};
    use std::io::Write;
    use tempfile::NamedTempFile;
    use tokio::net::TcpListener;

    #[test]
    fn event_processing_permits_clamps_zero_to_one() {
        assert_eq!(event_processing_permits(0), 1);
    }

    #[test]
    fn event_processing_permits_preserves_positive_values() {
        assert_eq!(event_processing_permits(1), 1);
        assert_eq!(event_processing_permits(64), 64);
        assert_eq!(event_processing_permits(1000), 1000);
    }

    #[tokio::test]
    async fn event_semaphore_caps_in_flight_permits() {
        let permits = event_processing_permits(3);
        let semaphore = Arc::new(Semaphore::new(permits));

        // Acquire up to the cap; all succeed.
        let p1 = Arc::clone(&semaphore).acquire_owned().await.unwrap();
        let _p2 = Arc::clone(&semaphore).acquire_owned().await.unwrap();
        let _p3 = Arc::clone(&semaphore).acquire_owned().await.unwrap();
        assert_eq!(semaphore.available_permits(), 0);

        // No permit is available while the cap is reached.
        assert!(Arc::clone(&semaphore).try_acquire_owned().is_err());

        // Releasing one permit frees a slot for the next event.
        drop(p1);
        assert_eq!(semaphore.available_permits(), 1);
        assert!(Arc::clone(&semaphore).try_acquire_owned().is_ok());
    }

    #[tokio::test]
    async fn event_permit_wait_acquires_available_permit() {
        let semaphore = Arc::new(Semaphore::new(1));
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let permit =
            acquire_event_processing_permit_or_shutdown(Arc::clone(&semaphore), &mut shutdown_rx)
                .await
                .expect("available permit should be acquired");

        assert_eq!(semaphore.available_permits(), 0);
        drop(permit);
        assert_eq!(semaphore.available_permits(), 1);
    }

    #[tokio::test]
    async fn event_permit_wait_exits_when_shutdown_arrives() {
        let semaphore = Arc::new(Semaphore::new(1));
        let _held_permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let permit_wait =
            acquire_event_processing_permit_or_shutdown(Arc::clone(&semaphore), &mut shutdown_rx);
        tokio::pin!(permit_wait);

        let pending_before_shutdown =
            tokio::time::timeout(Duration::from_millis(10), &mut permit_wait).await;
        assert!(pending_before_shutdown.is_err());

        shutdown_tx.send(true).unwrap();

        let result = tokio::time::timeout(Duration::from_secs(1), &mut permit_wait)
            .await
            .expect("shutdown should interrupt a saturated permit wait");

        assert!(result.is_none());
        assert_eq!(semaphore.available_permits(), 0);
    }

    #[tokio::test]
    async fn run_startup_or_shutdown_returns_connected_when_startup_finishes_first() {
        // A signal future that never resolves models no signal arriving; the
        // startup future's result must be surfaced verbatim.
        let outcome = run_startup_or_shutdown(
            async { Ok::<(), anyhow::Error>(()) },
            std::future::pending::<()>(),
        )
        .await;

        assert!(matches!(outcome, StartupOutcome::Connected(Ok(()))));
    }

    #[tokio::test]
    async fn run_startup_or_shutdown_surfaces_startup_error() {
        let outcome = run_startup_or_shutdown(
            async { Err::<(), anyhow::Error>(anyhow::anyhow!("connect failed")) },
            std::future::pending::<()>(),
        )
        .await;

        match outcome {
            StartupOutcome::Connected(Err(error)) => {
                assert_eq!(error.to_string(), "connect failed");
            }
            other => panic!("expected a surfaced startup error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_startup_or_shutdown_returns_shutdown_when_signal_arrives_first() {
        // Startup never finishes, so only the already-ready signal can win.
        // The signal future's output (here the shutdown reason) is carried
        // through so the caller can map it to the process exit result.
        let outcome = run_startup_or_shutdown(
            std::future::pending::<Result<()>>(),
            std::future::ready(shutdown::ShutdownReason::Signal),
        )
        .await;

        assert!(matches!(
            outcome,
            StartupOutcome::ShutdownRequested(shutdown::ShutdownReason::Signal)
        ));
    }

    #[tokio::test]
    async fn run_startup_or_shutdown_prefers_shutdown_when_both_ready() {
        // When both futures are ready in the same poll, the `biased` select must
        // prefer shutdown so a pending signal is never masked by a connect that
        // resolves simultaneously.
        let outcome = run_startup_or_shutdown(
            std::future::ready(Ok::<(), anyhow::Error>(())),
            std::future::ready(()),
        )
        .await;

        assert!(matches!(outcome, StartupOutcome::ShutdownRequested(())));
    }

    #[test]
    fn shutdown_result_treats_signal_as_clean_exit() {
        assert!(shutdown_result(shutdown::ShutdownReason::Signal).is_ok());
    }

    #[test]
    fn shutdown_result_treats_internal_trigger_as_failure() {
        let error = shutdown_result(shutdown::ShutdownReason::InternalTrigger)
            .expect_err("an internally triggered shutdown must exit non-zero");

        assert!(error.to_string().contains("critical task failure"));
    }

    #[test]
    fn notification_receive_lag_is_recoverable() {
        let action = classify_notification_receive_error(&RecvError::Lagged(3));

        assert_eq!(action, NotificationReceiveAction::Continue);
    }

    #[test]
    fn notification_receive_close_is_terminal() {
        let action = classify_notification_receive_error(&RecvError::Closed);

        assert_eq!(action, NotificationReceiveAction::Shutdown);
    }

    #[test]
    fn notification_receive_lag_records_metrics() {
        let metrics = Metrics::new().unwrap();

        record_notification_receive_metrics(Some(&metrics), &RecvError::Lagged(3));

        assert_eq!(metrics.relay_notifications_lagged_total.get(), 1);
        assert_eq!(metrics.relay_notifications_dropped_total.get(), 3);
    }

    #[test]
    fn notification_receive_close_does_not_record_metrics() {
        let metrics = Metrics::new().unwrap();

        record_notification_receive_metrics(Some(&metrics), &RecvError::Closed);

        assert_eq!(metrics.relay_notifications_lagged_total.get(), 0);
        assert_eq!(metrics.relay_notifications_dropped_total.get(), 0);
    }

    fn test_event_processor() -> Arc<EventProcessor> {
        let keys = Keys::generate();
        let nip59_handler = Nip59Handler::new(keys.clone());
        let mut secp_secret_key =
            secp256k1::SecretKey::from_slice(&keys.secret_key().to_secret_bytes())
                .expect("valid secret key");
        let token_decryptor = TokenDecryptor::new(&mut secp_secret_key);
        let push_dispatcher = Arc::new(PushDispatcher::new(None, None));
        Arc::new(EventProcessor::new(
            nip59_handler,
            token_decryptor,
            push_dispatcher,
        ))
    }

    fn test_event_notification() -> RelayPoolNotification {
        let event = EventBuilder::text_note("task lifecycle test")
            .sign_with_keys(&Keys::generate())
            .expect("signable test event");
        RelayPoolNotification::Event {
            relay_url: RelayUrl::parse("ws://127.0.0.1:7777").unwrap(),
            subscription_id: SubscriptionId::new("test-sub"),
            event: Box::new(event),
        }
    }

    fn test_relay_client_config() -> config::RelayConfig {
        config::RelayConfig {
            clearnet: vec![],
            allow_unencrypted_clearnet_relays: true,
            onion: vec![],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 5,
        }
    }

    /// Poll until the processor has reserved exactly `expected` event IDs,
    /// proving the spawned processing task actually ran.
    async fn wait_for_cache_len(processor: &EventProcessor, expected: usize) -> bool {
        for _ in 0..100 {
            if processor.cache_len() == expected {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    #[test]
    fn event_loop_shutdown_exit_is_expected() {
        assert!(event_loop_exit_to_supervision_result(EventLoopExit::ShutdownRequested).is_ok());
    }

    #[test]
    fn event_loop_channel_close_exit_is_a_supervised_failure() {
        let error = event_loop_exit_to_supervision_result(EventLoopExit::ChannelClosed)
            .expect_err("channel close must be supervised as a failure");

        assert!(error.contains("notification channel closed"));
    }

    #[test]
    fn supervise_critical_task_triggers_shutdown_on_error() {
        let handler = ShutdownHandler::new();
        let receiver = handler.subscribe();

        supervise_critical_task("test task", Err::<(), _>("boom"), &handler.trigger_handle());

        assert!(*receiver.borrow());
    }

    #[test]
    fn supervise_critical_task_leaves_clean_exits_alone() {
        let handler = ShutdownHandler::new();
        let receiver = handler.subscribe();

        supervise_critical_task("test task", Ok::<(), &str>(()), &handler.trigger_handle());

        assert!(!*receiver.borrow());
    }

    #[tokio::test]
    async fn run_event_loop_exits_when_shutdown_signal_fires() {
        let (_notification_tx, notifications) = broadcast::channel::<RelayPoolNotification>(4);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        shutdown_tx.send(true).unwrap();

        let exit = tokio::time::timeout(
            Duration::from_secs(1),
            run_event_loop(
                notifications,
                shutdown_rx,
                Arc::new(Semaphore::new(1)),
                test_event_processor(),
                TaskTracker::new(),
                None,
            ),
        )
        .await
        .expect("shutdown signal must end the event loop");

        assert_eq!(exit, EventLoopExit::ShutdownRequested);
    }

    #[tokio::test]
    async fn run_event_loop_reports_channel_close_as_unexpected_exit() {
        let (notification_tx, notifications) = broadcast::channel::<RelayPoolNotification>(4);
        drop(notification_tx);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        let exit = tokio::time::timeout(
            Duration::from_secs(1),
            run_event_loop(
                notifications,
                shutdown_rx,
                Arc::new(Semaphore::new(1)),
                test_event_processor(),
                TaskTracker::new(),
                None,
            ),
        )
        .await
        .expect("channel close must end the event loop");

        assert_eq!(exit, EventLoopExit::ChannelClosed);
    }

    #[tokio::test]
    async fn run_event_loop_processes_events_through_the_task_tracker() {
        let (notification_tx, notifications) = broadcast::channel(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let semaphore = Arc::new(Semaphore::new(2));
        let processor = test_event_processor();
        let event_tasks = TaskTracker::new();

        let loop_handle = tokio::spawn(run_event_loop(
            notifications,
            shutdown_rx,
            Arc::clone(&semaphore),
            Arc::clone(&processor),
            event_tasks.clone(),
            None,
        ));

        notification_tx.send(test_event_notification()).unwrap();

        assert!(
            wait_for_cache_len(&processor, 1).await,
            "the event-processing task must run and reserve the event ID"
        );

        shutdown_tx.send(true).unwrap();
        let exit = tokio::time::timeout(Duration::from_secs(1), loop_handle)
            .await
            .expect("loop must exit on shutdown")
            .expect("loop task must not panic");
        assert_eq!(exit, EventLoopExit::ShutdownRequested);

        // In-flight processing work is tracked, joinable, and releases its
        // semaphore permit when done.
        event_tasks.close();
        tokio::time::timeout(Duration::from_secs(1), event_tasks.wait())
            .await
            .expect("tracked processing tasks must drain");
        assert_eq!(semaphore.available_permits(), 2);
    }

    #[tokio::test]
    async fn run_event_loop_skips_non_event_notifications() {
        let (notification_tx, notifications) = broadcast::channel(4);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let processor = test_event_processor();
        let event_tasks = TaskTracker::new();

        let loop_handle = tokio::spawn(run_event_loop(
            notifications,
            shutdown_rx,
            Arc::new(Semaphore::new(1)),
            Arc::clone(&processor),
            event_tasks.clone(),
            None,
        ));

        notification_tx
            .send(RelayPoolNotification::Shutdown)
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        shutdown_tx.send(true).unwrap();
        let exit = tokio::time::timeout(Duration::from_secs(1), loop_handle)
            .await
            .expect("loop must exit on shutdown")
            .expect("loop task must not panic");

        assert_eq!(exit, EventLoopExit::ShutdownRequested);
        assert_eq!(
            processor.cache_len(),
            0,
            "non-event notifications must not spawn processing work"
        );
        assert!(event_tasks.is_empty());
    }

    #[tokio::test]
    async fn run_event_loop_continues_after_lagged_notifications() {
        // Capacity 1: the second pre-loop send overwrites the first, so the
        // loop's first recv yields `Lagged` and must keep consuming.
        let (notification_tx, notifications) = broadcast::channel(1);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let metrics = Metrics::new().unwrap();
        let processor = test_event_processor();
        let event_tasks = TaskTracker::new();

        notification_tx.send(test_event_notification()).unwrap();
        notification_tx.send(test_event_notification()).unwrap();

        let loop_handle = tokio::spawn(run_event_loop(
            notifications,
            shutdown_rx,
            Arc::new(Semaphore::new(1)),
            Arc::clone(&processor),
            event_tasks.clone(),
            Some(metrics.clone()),
        ));

        // The surviving (newest) event is still processed after the lag.
        assert!(
            wait_for_cache_len(&processor, 1).await,
            "the loop must keep processing after a lag"
        );
        assert_eq!(metrics.relay_notifications_lagged_total.get(), 1);
        assert_eq!(metrics.relay_notifications_dropped_total.get(), 1);

        shutdown_tx.send(true).unwrap();
        let exit = tokio::time::timeout(Duration::from_secs(1), loop_handle)
            .await
            .expect("loop must exit on shutdown")
            .expect("loop task must not panic");
        assert_eq!(exit, EventLoopExit::ShutdownRequested);
    }

    #[tokio::test]
    async fn staged_teardown_waits_for_in_flight_event_tasks() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let event_tasks = TaskTracker::new();
        let finished = Arc::new(AtomicBool::new(false));
        let finished_flag = Arc::clone(&finished);
        event_tasks.spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            finished_flag.store(true, Ordering::SeqCst);
        });

        let push_dispatcher = Arc::new(PushDispatcher::new(None, None));
        let relay_client = Arc::new(
            RelayClient::new(Keys::generate(), test_relay_client_config())
                .await
                .unwrap(),
        );

        let event_handle = tokio::spawn(async {});
        let health_handle = tokio::spawn(async {});
        let cleanup_handle = tokio::spawn(async {});
        let status_refresh_handle = tokio::spawn(async {});

        tokio::time::timeout(
            Duration::from_secs(5),
            staged_teardown(
                event_handle,
                event_tasks.clone(),
                push_dispatcher,
                relay_client,
                health_handle,
                cleanup_handle,
                status_refresh_handle,
            ),
        )
        .await
        .expect("staged teardown must complete");

        assert!(
            finished.load(Ordering::SeqCst),
            "in-flight event tasks must finish before teardown completes"
        );
        assert!(event_tasks.is_closed());
    }

    #[tokio::test]
    async fn staged_teardown_joins_the_event_loop_before_closing_the_tracker() {
        use std::sync::atomic::{AtomicBool, Ordering};

        // Model the shutdown race from the teardown-ordering bug: the event
        // loop admits one final event right before it exits. Because teardown
        // joins the loop before closing the tracker, that late task is still
        // tracked, drained, and its dispatch window stays open.
        let event_tasks = TaskTracker::new();
        let late_task_finished = Arc::new(AtomicBool::new(false));

        let event_handle = {
            let event_tasks = event_tasks.clone();
            let finished = Arc::clone(&late_task_finished);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(30)).await;
                event_tasks.spawn(async move {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    finished.store(true, Ordering::SeqCst);
                });
            })
        };

        let push_dispatcher = Arc::new(PushDispatcher::new(None, None));
        let relay_client = Arc::new(
            RelayClient::new(Keys::generate(), test_relay_client_config())
                .await
                .unwrap(),
        );
        let health_handle = tokio::spawn(async {});
        let cleanup_handle = tokio::spawn(async {});
        let status_refresh_handle = tokio::spawn(async {});

        tokio::time::timeout(
            Duration::from_secs(5),
            staged_teardown(
                event_handle,
                event_tasks.clone(),
                push_dispatcher,
                relay_client,
                health_handle,
                cleanup_handle,
                status_refresh_handle,
            ),
        )
        .await
        .expect("staged teardown must complete");

        assert!(
            late_task_finished.load(Ordering::SeqCst),
            "a task admitted right before the event loop exits must still be drained"
        );
    }

    fn test_logging_config(level: &str) -> config::LoggingConfig {
        config::LoggingConfig {
            level: level.to_string(),
            format: "json".to_string(),
        }
    }

    #[test]
    fn logging_filter_uses_configured_filter_without_env_filter() {
        assert!(
            logging_filter_from_env(
                &test_logging_config("info"),
                Err(std::env::VarError::NotPresent)
            )
            .is_ok()
        );
    }

    #[test]
    fn logging_filter_rejects_invalid_configured_filter_without_panic() {
        let config = test_logging_config("target=lvl");
        let result = std::panic::catch_unwind(|| {
            logging_filter_from_env(&config, Err(std::env::VarError::NotPresent))
        });
        let error = match result.expect("invalid logging.level should not panic") {
            Ok(_) => panic!("invalid logging.level should return an error"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("invalid logging.level filter: target=lvl")
        );
    }

    #[test]
    fn logging_filter_prefers_env_filter_over_invalid_configured_filter() {
        assert!(
            logging_filter_from_env(&test_logging_config("target=lvl"), Ok("warn".to_string()))
                .is_ok()
        );
    }

    #[test]
    fn logging_filter_rejects_invalid_env_filter_without_using_config() {
        let error =
            logging_filter_from_env(&test_logging_config("info"), Ok("target=lvl".to_string()))
                .expect_err("invalid RUST_LOG should return an error");

        assert!(
            error
                .to_string()
                .contains("invalid RUST_LOG filter: target=lvl")
        );
    }

    #[tokio::test]
    async fn healthcheck_command_accepts_success_status() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route("/health", get(|| async { StatusCode::OK }));

        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let result = run_healthcheck(&format!("http://{addr}/health")).await;

        server.abort();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn healthcheck_command_rejects_error_status() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/health",
            get(|| async { (StatusCode::SERVICE_UNAVAILABLE, "not ready") }),
        );

        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let result = run_healthcheck(&format!("http://{addr}/health")).await;

        server.abort();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn healthcheck_command_reports_unreachable_endpoint() {
        let result = run_healthcheck("http://127.0.0.1:1/health").await;

        let error = result.expect_err("healthcheck should fail for unreachable endpoints");
        assert!(
            error
                .to_string()
                .contains("Failed to reach health endpoint at http://127.0.0.1:1/health")
        );
    }

    #[test]
    fn resolve_server_private_key_prefers_inline_value() {
        let mut config = config::ServerConfig {
            private_key: Zeroizing::new("abc123".to_string()),
            private_key_file: "/tmp/ignored".to_string(),
            shutdown_timeout_secs: 10,
            max_dedup_cache_size: 100_000,
            dedup_state_path: PathBuf::new(),
            dedup_retention_secs: crate::nostr::events::DEFAULT_DEDUP_RETENTION_SECS,
            max_notification_age_secs: crate::nostr::events::DEFAULT_MAX_NOTIFICATION_AGE_SECS,
            max_notification_future_skew_secs:
                crate::nostr::events::DEFAULT_MAX_NOTIFICATION_FUTURE_SKEW_SECS,
            max_rate_limit_cache_size: 100_000,
            max_tokens_per_event: crate::crypto::nip59::DEFAULT_MAX_TOKENS_PER_EVENT,
            encrypted_token_rate_limit_per_minute: 240,
            encrypted_token_rate_limit_per_hour: 5000,
            device_token_rate_limit_per_minute: 240,
            device_token_rate_limit_per_hour: 5000,
            max_concurrent_event_processing: 64,
            global_unwrap_rate_limit_per_minute: 600,
            global_unwrap_rate_limit_per_hour: 30_000,
        };

        assert_eq!(
            resolve_server_private_key(&mut config).unwrap().as_str(),
            "abc123"
        );
        assert_eq!(config.private_key.as_str(), "");
    }

    #[test]
    fn resolve_server_private_key_reads_secret_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "abc123").unwrap();

        let mut config = config::ServerConfig {
            private_key: Zeroizing::new(String::new()),
            private_key_file: file.path().display().to_string(),
            shutdown_timeout_secs: 10,
            max_dedup_cache_size: 100_000,
            dedup_state_path: PathBuf::new(),
            dedup_retention_secs: crate::nostr::events::DEFAULT_DEDUP_RETENTION_SECS,
            max_notification_age_secs: crate::nostr::events::DEFAULT_MAX_NOTIFICATION_AGE_SECS,
            max_notification_future_skew_secs:
                crate::nostr::events::DEFAULT_MAX_NOTIFICATION_FUTURE_SKEW_SECS,
            max_rate_limit_cache_size: 100_000,
            max_tokens_per_event: crate::crypto::nip59::DEFAULT_MAX_TOKENS_PER_EVENT,
            encrypted_token_rate_limit_per_minute: 240,
            encrypted_token_rate_limit_per_hour: 5000,
            device_token_rate_limit_per_minute: 240,
            device_token_rate_limit_per_hour: 5000,
            max_concurrent_event_processing: 64,
            global_unwrap_rate_limit_per_minute: 600,
            global_unwrap_rate_limit_per_hour: 30_000,
        };

        assert_eq!(
            resolve_server_private_key(&mut config).unwrap().as_str(),
            "abc123"
        );
    }

    #[test]
    fn resolve_server_private_key_treats_whitespace_inline_value_as_empty() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "abc123").unwrap();

        let mut config = config::ServerConfig {
            private_key: Zeroizing::new("   \n\t  ".to_string()),
            private_key_file: format!("  {}  ", file.path().display()),
            shutdown_timeout_secs: 10,
            max_dedup_cache_size: 100_000,
            dedup_state_path: PathBuf::new(),
            dedup_retention_secs: crate::nostr::events::DEFAULT_DEDUP_RETENTION_SECS,
            max_notification_age_secs: crate::nostr::events::DEFAULT_MAX_NOTIFICATION_AGE_SECS,
            max_notification_future_skew_secs:
                crate::nostr::events::DEFAULT_MAX_NOTIFICATION_FUTURE_SKEW_SECS,
            max_rate_limit_cache_size: 100_000,
            max_tokens_per_event: crate::crypto::nip59::DEFAULT_MAX_TOKENS_PER_EVENT,
            encrypted_token_rate_limit_per_minute: 240,
            encrypted_token_rate_limit_per_hour: 5000,
            device_token_rate_limit_per_minute: 240,
            device_token_rate_limit_per_hour: 5000,
            max_concurrent_event_processing: 64,
            global_unwrap_rate_limit_per_minute: 600,
            global_unwrap_rate_limit_per_hour: 30_000,
        };

        assert_eq!(
            resolve_server_private_key(&mut config).unwrap().as_str(),
            "abc123"
        );
    }

    #[test]
    fn resolve_server_private_key_returns_empty_when_unset() {
        let mut config = config::ServerConfig {
            private_key: Zeroizing::new(String::new()),
            private_key_file: String::new(),
            shutdown_timeout_secs: 10,
            max_dedup_cache_size: 100_000,
            dedup_state_path: PathBuf::new(),
            dedup_retention_secs: crate::nostr::events::DEFAULT_DEDUP_RETENTION_SECS,
            max_notification_age_secs: crate::nostr::events::DEFAULT_MAX_NOTIFICATION_AGE_SECS,
            max_notification_future_skew_secs:
                crate::nostr::events::DEFAULT_MAX_NOTIFICATION_FUTURE_SKEW_SECS,
            max_rate_limit_cache_size: 100_000,
            max_tokens_per_event: crate::crypto::nip59::DEFAULT_MAX_TOKENS_PER_EVENT,
            encrypted_token_rate_limit_per_minute: 240,
            encrypted_token_rate_limit_per_hour: 5000,
            device_token_rate_limit_per_minute: 240,
            device_token_rate_limit_per_hour: 5000,
            max_concurrent_event_processing: 64,
            global_unwrap_rate_limit_per_minute: 600,
            global_unwrap_rate_limit_per_hour: 30_000,
        };

        assert_eq!(
            resolve_server_private_key(&mut config).unwrap().as_str(),
            ""
        );
    }

    #[test]
    fn resolve_server_private_key_reports_missing_secret_file() {
        let mut config = config::ServerConfig {
            private_key: Zeroizing::new(String::new()),
            private_key_file: "/tmp/definitely-missing-transponder-key".to_string(),
            shutdown_timeout_secs: 10,
            max_dedup_cache_size: 100_000,
            dedup_state_path: PathBuf::new(),
            dedup_retention_secs: crate::nostr::events::DEFAULT_DEDUP_RETENTION_SECS,
            max_notification_age_secs: crate::nostr::events::DEFAULT_MAX_NOTIFICATION_AGE_SECS,
            max_notification_future_skew_secs:
                crate::nostr::events::DEFAULT_MAX_NOTIFICATION_FUTURE_SKEW_SECS,
            max_rate_limit_cache_size: 100_000,
            max_tokens_per_event: crate::crypto::nip59::DEFAULT_MAX_TOKENS_PER_EVENT,
            encrypted_token_rate_limit_per_minute: 240,
            encrypted_token_rate_limit_per_hour: 5000,
            device_token_rate_limit_per_minute: 240,
            device_token_rate_limit_per_hour: 5000,
            max_concurrent_event_processing: 64,
            global_unwrap_rate_limit_per_minute: 600,
            global_unwrap_rate_limit_per_hour: 30_000,
        };

        let error = resolve_server_private_key(&mut config)
            .expect_err("missing secret file should return an error");
        assert!(
            error
                .to_string()
                .contains("Failed to read server private key file")
        );
    }

    #[test]
    fn validate_startup_config_rejects_missing_private_key() {
        let relays = config::RelayConfig {
            clearnet: vec!["wss://relay.example.com".to_string()],
            allow_unencrypted_clearnet_relays: false,
            onion: Vec::new(),
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 30,
        };

        let error = validate_startup_config("", &relays)
            .expect_err("missing private key should be rejected");
        assert_eq!(error.to_string(), "Server private key is required");
    }

    #[test]
    fn validate_startup_config_rejects_missing_relays() {
        let relays = config::RelayConfig {
            clearnet: Vec::new(),
            allow_unencrypted_clearnet_relays: false,
            onion: Vec::new(),
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 30,
        };

        let error = validate_startup_config("abc123", &relays)
            .expect_err("missing relays should be rejected");
        assert_eq!(error.to_string(), "At least one relay must be configured");
    }

    #[test]
    #[cfg(not(feature = "tor"))]
    fn validate_startup_config_rejects_onion_relays_without_tor_feature() {
        let relays = config::RelayConfig {
            clearnet: vec!["wss://relay.example.com".to_string()],
            allow_unencrypted_clearnet_relays: false,
            onion: vec!["wss://example.onion".to_string()],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 30,
        };

        let error = validate_startup_config("abc123", &relays)
            .expect_err("onion relays should require the tor feature");
        assert_eq!(error.to_string(), "Onion relays require the 'tor' feature");
    }

    #[test]
    #[cfg(feature = "tor")]
    fn validate_startup_config_accepts_onion_only_relays() {
        let relays = config::RelayConfig {
            clearnet: Vec::new(),
            allow_unencrypted_clearnet_relays: false,
            onion: vec!["wss://example.onion".to_string()],
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            connection_timeout_secs: 30,
        };

        assert!(validate_startup_config("abc123", &relays).is_ok());
    }

    #[test]
    fn parse_server_secret_key_accepts_nsec_format() {
        let secret_key = Keys::generate().secret_key().to_bech32().unwrap();

        let parsed_key = parse_server_secret_key(&secret_key).unwrap();

        assert_eq!(parsed_key.to_bech32().unwrap(), secret_key);
    }

    #[test]
    fn parse_server_secret_key_accepts_resolved_file_value() {
        let secret_key = Keys::generate().secret_key().to_bech32().unwrap();
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "  {secret_key}  ").unwrap();

        let mut config = config::ServerConfig {
            private_key: Zeroizing::new(String::new()),
            private_key_file: file.path().display().to_string(),
            shutdown_timeout_secs: 10,
            max_dedup_cache_size: 100_000,
            dedup_state_path: PathBuf::new(),
            dedup_retention_secs: crate::nostr::events::DEFAULT_DEDUP_RETENTION_SECS,
            max_notification_age_secs: crate::nostr::events::DEFAULT_MAX_NOTIFICATION_AGE_SECS,
            max_notification_future_skew_secs:
                crate::nostr::events::DEFAULT_MAX_NOTIFICATION_FUTURE_SKEW_SECS,
            max_rate_limit_cache_size: 100_000,
            max_tokens_per_event: crate::crypto::nip59::DEFAULT_MAX_TOKENS_PER_EVENT,
            encrypted_token_rate_limit_per_minute: 240,
            encrypted_token_rate_limit_per_hour: 5000,
            device_token_rate_limit_per_minute: 240,
            device_token_rate_limit_per_hour: 5000,
            max_concurrent_event_processing: 64,
            global_unwrap_rate_limit_per_minute: 600,
            global_unwrap_rate_limit_per_hour: 30_000,
        };

        let resolved_key = resolve_server_private_key(&mut config).unwrap();
        let parsed_key = parse_server_secret_key(resolved_key.as_str()).unwrap();

        assert_eq!(parsed_key.to_bech32().unwrap(), secret_key);
    }

    #[test]
    fn build_rate_limit_config_matches_server_settings() {
        let server = config::ServerConfig {
            private_key: Zeroizing::new(String::new()),
            private_key_file: String::new(),
            shutdown_timeout_secs: 10,
            max_dedup_cache_size: 100_000,
            dedup_state_path: PathBuf::new(),
            dedup_retention_secs: crate::nostr::events::DEFAULT_DEDUP_RETENTION_SECS,
            max_notification_age_secs: crate::nostr::events::DEFAULT_MAX_NOTIFICATION_AGE_SECS,
            max_notification_future_skew_secs:
                crate::nostr::events::DEFAULT_MAX_NOTIFICATION_FUTURE_SKEW_SECS,
            max_rate_limit_cache_size: 1234,
            max_tokens_per_event: 25,
            encrypted_token_rate_limit_per_minute: 111,
            encrypted_token_rate_limit_per_hour: 2222,
            device_token_rate_limit_per_minute: 333,
            device_token_rate_limit_per_hour: 4444,
            max_concurrent_event_processing: 7,
            global_unwrap_rate_limit_per_minute: 555,
            global_unwrap_rate_limit_per_hour: 6666,
        };

        let rate_limit_config = build_rate_limit_config(&server);

        assert_eq!(rate_limit_config.max_cache_size, 1234);
        assert_eq!(rate_limit_config.max_tokens_per_event, 25);
        assert_eq!(rate_limit_config.encrypted_token_per_minute, 111);
        assert_eq!(rate_limit_config.encrypted_token_per_hour, 2222);
        assert_eq!(rate_limit_config.device_token_per_minute, 333);
        assert_eq!(rate_limit_config.device_token_per_hour, 4444);
        assert_eq!(rate_limit_config.global_unwrap_per_minute, 555);
        assert_eq!(rate_limit_config.global_unwrap_per_hour, 6666);
    }

    #[test]
    fn build_replay_protection_config_matches_server_settings() {
        let state_path = PathBuf::from("/var/lib/transponder/dedup-events.log");
        let server = config::ServerConfig {
            private_key: Zeroizing::new(String::new()),
            private_key_file: String::new(),
            shutdown_timeout_secs: 10,
            max_dedup_cache_size: 77,
            dedup_state_path: state_path.clone(),
            dedup_retention_secs: 88,
            max_notification_age_secs: 99,
            max_notification_future_skew_secs: 11,
            max_rate_limit_cache_size: 100_000,
            max_tokens_per_event: crate::crypto::nip59::DEFAULT_MAX_TOKENS_PER_EVENT,
            encrypted_token_rate_limit_per_minute: 240,
            encrypted_token_rate_limit_per_hour: 5000,
            device_token_rate_limit_per_minute: 240,
            device_token_rate_limit_per_hour: 5000,
            max_concurrent_event_processing: 64,
            global_unwrap_rate_limit_per_minute: 600,
            global_unwrap_rate_limit_per_hour: 30_000,
        };

        let replay_config = build_replay_protection_config(&server);

        assert_eq!(replay_config.max_dedup_cache_size, 77);
        assert_eq!(replay_config.dedup_state_path, Some(state_path));
        assert_eq!(replay_config.dedup_retention, Duration::from_secs(88));
        assert_eq!(replay_config.max_notification_age, Duration::from_secs(99));
        assert_eq!(
            replay_config.max_notification_future_skew,
            Duration::from_secs(11)
        );
    }

    #[test]
    fn build_replay_protection_config_disables_empty_state_path() {
        let server = config::ServerConfig {
            private_key: Zeroizing::new(String::new()),
            private_key_file: String::new(),
            shutdown_timeout_secs: 10,
            max_dedup_cache_size: 77,
            dedup_state_path: PathBuf::new(),
            dedup_retention_secs: 88,
            max_notification_age_secs: 99,
            max_notification_future_skew_secs: 11,
            max_rate_limit_cache_size: 100_000,
            max_tokens_per_event: crate::crypto::nip59::DEFAULT_MAX_TOKENS_PER_EVENT,
            encrypted_token_rate_limit_per_minute: 240,
            encrypted_token_rate_limit_per_hour: 5000,
            device_token_rate_limit_per_minute: 240,
            device_token_rate_limit_per_hour: 5000,
            max_concurrent_event_processing: 64,
            global_unwrap_rate_limit_per_minute: 600,
            global_unwrap_rate_limit_per_hour: 30_000,
        };

        let replay_config = build_replay_protection_config(&server);

        assert_eq!(replay_config.dedup_state_path, None);
    }
}

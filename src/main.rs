//! Transponder - MIP-05 Push Notification Server
//!
//! A privacy-preserving push notification server implementing the Marmot MIP-05
//! specification. Listens for gift-wrapped Nostr events on configured relays,
//! decrypts notification requests, and dispatches silent push notifications
//! to APNs and FCM.

use std::sync::Arc;
use std::time::Duration;
use std::{fs, path::Path};

use anyhow::{Context, Result};
use clap::Parser;
use nostr_sdk::prelude::*;
use tokio::sync::broadcast::error::RecvError;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

mod config;
mod crypto;
mod error;
mod metrics;
mod nostr;
mod push;
mod rate_limiter;
mod server;
mod shutdown;

#[cfg(test)]
mod test_vectors;

use config::AppConfig;
use crypto::{Nip59Handler, TokenDecryptor};
use metrics::Metrics;
use nostr::client::RelayClient;
use nostr::events::EventProcessor;
use push::{ApnsClient, FcmClient, PushDispatcher};
use server::HealthServer;
use shutdown::ShutdownHandler;

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
    GenerateKeys,
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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Handle subcommands
    if let Some(command) = args.command {
        return match command {
            Command::GenerateKeys => generate_keys(),
            Command::Healthcheck { url } => run_healthcheck(&url).await,
        };
    }

    // Load configuration
    let config = AppConfig::load(&args.config)
        .with_context(|| format!("Failed to load config from {}", args.config))?;

    // Initialize logging
    init_logging(&config.logging)?;

    // Initialize metrics
    let metrics = if config.metrics.enabled {
        match Metrics::new() {
            Ok(m) => {
                m.init_server_info(env!("CARGO_PKG_VERSION"));
                Some(m)
            }
            Err(e) => {
                error!(error = %e, "Failed to initialize metrics");
                None
            }
        }
    } else {
        debug!("Metrics disabled");
        None
    };

    info!(
        version = env!("CARGO_PKG_VERSION"),
        config_path = %args.config,
        "Starting Transponder"
    );

    let server_private_key = resolve_server_private_key(&config.server)?;

    // Validate configuration
    if server_private_key.is_empty() {
        anyhow::bail!("Server private key is required");
    }

    if config.relays.clearnet.is_empty() && config.relays.onion.is_empty() {
        anyhow::bail!("At least one relay must be configured");
    }

    // Create server keys
    let secret_key =
        SecretKey::from_hex(&server_private_key).context("Invalid server private key")?;
    let keys = Keys::new(secret_key);

    info!(
        pubkey = %keys.public_key().to_hex(),
        "Server public key"
    );

    // Initialize crypto handlers
    let nip59_handler = Nip59Handler::new(keys.clone());
    // Convert nostr_sdk SecretKey to secp256k1 SecretKey for TokenDecryptor
    let secp_secret_key = secp256k1::SecretKey::from_slice(&keys.secret_key().to_secret_bytes())
        .context("Failed to create secp256k1 secret key")?;
    let token_decryptor = TokenDecryptor::new(secp_secret_key);

    // Initialize push clients
    let apns_client = if config.apns.enabled {
        match ApnsClient::with_metrics(config.apns.clone(), metrics.clone()).await {
            Ok(client) => {
                if client.is_configured() {
                    info!("APNs client initialized");
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
        debug!("APNs disabled");
        None
    };

    let fcm_client = if config.fcm.enabled {
        match FcmClient::with_metrics(config.fcm.clone(), metrics.clone()).await {
            Ok(client) => {
                if client.is_configured() {
                    info!("FCM client initialized");
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
        debug!("FCM disabled");
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

    // Initialize relay client
    let relay_client = Arc::new(
        RelayClient::with_metrics(keys.clone(), config.relays.clone(), metrics.clone())
            .await
            .context("Failed to create relay client")?,
    );

    // Connect to relays
    relay_client
        .connect()
        .await
        .context("Failed to connect to relays")?;

    // Subscribe to events
    relay_client
        .subscribe(keys.public_key())
        .await
        .context("Failed to subscribe to events")?;

    // Publish inbox relay list
    if let Err(e) = relay_client.publish_inbox_relays().await {
        warn!(error = %e, "Failed to publish inbox relay list");
    }

    // Create event processor with configured cache sizes and rate limiting
    let rate_limit_config = nostr::events::TokenRateLimitConfig {
        max_cache_size: config.server.max_rate_limit_cache_size,
        encrypted_token_per_minute: config.server.encrypted_token_rate_limit_per_minute,
        encrypted_token_per_hour: config.server.encrypted_token_rate_limit_per_hour,
        device_token_per_minute: config.server.device_token_rate_limit_per_minute,
        device_token_per_hour: config.server.device_token_rate_limit_per_hour,
    };
    let event_processor = Arc::new(EventProcessor::with_full_config(
        nip59_handler,
        token_decryptor,
        push_dispatcher.clone(),
        config.server.max_dedup_cache_size,
        rate_limit_config,
        metrics.clone(),
    ));

    // Initialize shutdown handler
    let shutdown = ShutdownHandler::new();

    // Start health server
    let health_server = HealthServer::new(
        config.health.clone(),
        relay_client.clone(),
        push_dispatcher.clone(),
        metrics.clone(),
    );

    let health_shutdown = shutdown.subscribe();
    let health_handle = tokio::spawn(async move {
        if let Err(e) = health_server.run(health_shutdown).await {
            error!(error = %e, "Health server error");
        }
    });

    // Start event processing loop
    let mut event_shutdown = shutdown.subscribe();
    let event_processor_clone = event_processor.clone();
    let relay_client_clone = relay_client.clone();

    let event_handle = tokio::spawn(async move {
        let mut notifications = relay_client_clone.notifications();

        loop {
            tokio::select! {
                _ = event_shutdown.changed() => {
                    info!("Event processor shutting down");
                    break;
                }
                result = notifications.recv() => {
                    match result {
                        Ok(notification) => {
                            if let RelayPoolNotification::Event { event, .. } = notification
                                && let Err(e) = event_processor_clone.process(&event).await
                            {
                                debug!(error = %e, "Event processing error");
                            }
                        }
                        Err(e) => {
                            match classify_notification_receive_error(&e) {
                                NotificationReceiveAction::Continue => {
                                    warn!(error = %e, "Lagged relay notifications, continuing");
                                }
                                NotificationReceiveAction::Shutdown => {
                                    error!(error = %e, "Notification channel closed");
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    });

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

    info!("Transponder running");

    // Wait for shutdown signal
    shutdown.wait_for_signal().await;

    info!("Initiating graceful shutdown");

    // Wait for in-flight push notifications
    shutdown::graceful_shutdown(
        || async {
            push_dispatcher.wait_for_completion().await;
        },
        config.server.shutdown_timeout_secs,
    )
    .await;

    // Disconnect from relays
    if let Err(e) = relay_client.disconnect().await {
        warn!(error = %e, "Error disconnecting from relays");
    }

    // Wait for tasks to complete
    let _ = tokio::join!(event_handle, health_handle, cleanup_handle);

    info!("Transponder stopped");
    Ok(())
}

/// Generate a new Nostr key pair and print to stdout.
fn generate_keys() -> Result<()> {
    let keys = Keys::generate();

    println!("Generated new Nostr key pair:\n");
    println!("Private key (hex): {}", keys.secret_key().to_secret_hex());
    println!("Public key (hex):  {}", keys.public_key().to_hex());
    println!("Public key (npub): {}", keys.public_key().to_bech32()?);
    println!();
    println!("Add the private key to your configuration:");
    println!("  [server]");
    println!("  private_key = \"{}\"", keys.secret_key().to_secret_hex());
    println!();
    println!("Or set via environment variable:");
    println!(
        "  export TRANSPONDER_SERVER_PRIVATE_KEY=\"{}\"",
        keys.secret_key().to_secret_hex()
    );
    println!();
    println!("Share the public key (hex or npub) with clients so they can");
    println!("encrypt notification tokens for your server.");

    Ok(())
}

/// Resolve the server private key from config or a mounted secret file.
fn resolve_server_private_key(config: &config::ServerConfig) -> Result<String> {
    if !config.private_key.is_empty() {
        return Ok(config.private_key.trim().to_string());
    }

    if config.private_key_file.is_empty() {
        return Ok(String::new());
    }

    let key_path = Path::new(&config.private_key_file);
    let key = fs::read_to_string(key_path).with_context(|| {
        format!(
            "Failed to read server private key file {}",
            key_path.display()
        )
    })?;

    Ok(key.trim().to_string())
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

/// Initialize the tracing subscriber based on configuration.
fn init_logging(config: &config::LoggingConfig) -> Result<()> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.level));

    match config.format.as_str() {
        "json" => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().json())
                .init();
        }
        "pretty" => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().pretty())
                .init();
        }
        "off" => {
            // No logging
        }
        _ => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer())
                .init();
        }
    }

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
    fn notification_receive_lag_is_recoverable() {
        let action = classify_notification_receive_error(&RecvError::Lagged(3));

        assert_eq!(action, NotificationReceiveAction::Continue);
    }

    #[test]
    fn notification_receive_close_is_terminal() {
        let action = classify_notification_receive_error(&RecvError::Closed);

        assert_eq!(action, NotificationReceiveAction::Shutdown);
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

    #[test]
    fn resolve_server_private_key_prefers_inline_value() {
        let config = config::ServerConfig {
            private_key: "abc123".to_string(),
            private_key_file: "/tmp/ignored".to_string(),
            shutdown_timeout_secs: 10,
            max_dedup_cache_size: 100_000,
            max_rate_limit_cache_size: 100_000,
            encrypted_token_rate_limit_per_minute: 240,
            encrypted_token_rate_limit_per_hour: 5000,
            device_token_rate_limit_per_minute: 240,
            device_token_rate_limit_per_hour: 5000,
        };

        assert_eq!(resolve_server_private_key(&config).unwrap(), "abc123");
    }

    #[test]
    fn resolve_server_private_key_reads_secret_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "abc123").unwrap();

        let config = config::ServerConfig {
            private_key: String::new(),
            private_key_file: file.path().display().to_string(),
            shutdown_timeout_secs: 10,
            max_dedup_cache_size: 100_000,
            max_rate_limit_cache_size: 100_000,
            encrypted_token_rate_limit_per_minute: 240,
            encrypted_token_rate_limit_per_hour: 5000,
            device_token_rate_limit_per_minute: 240,
            device_token_rate_limit_per_hour: 5000,
        };

        assert_eq!(resolve_server_private_key(&config).unwrap(), "abc123");
    }
}

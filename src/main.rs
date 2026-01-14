//! Transponder - MIP-05 Push Notification Server
//!
//! A privacy-preserving push notification server implementing the Marmot MIP-05
//! specification. Listens for gift-wrapped Nostr events on configured relays,
//! decrypts notification requests, and dispatches silent push notifications
//! to APNs and FCM.

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use nostr_sdk::prelude::*;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

mod config;
mod crypto;
mod error;
mod nostr;
mod push;
mod server;
mod shutdown;

#[cfg(test)]
mod test_vectors;

use config::AppConfig;
use crypto::{Nip59Handler, TokenDecryptor};
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Handle subcommands
    if let Some(Command::GenerateKeys) = args.command {
        return generate_keys();
    }

    // Load configuration
    let config = AppConfig::load(&args.config)
        .with_context(|| format!("Failed to load config from {}", args.config))?;

    // Initialize logging
    init_logging(&config.logging)?;

    info!(
        version = env!("CARGO_PKG_VERSION"),
        config_path = %args.config,
        "Starting Transponder"
    );

    // Validate configuration
    if config.server.private_key.is_empty() {
        anyhow::bail!("Server private key is required");
    }

    if config.relays.clearnet.is_empty() && config.relays.onion.is_empty() {
        anyhow::bail!("At least one relay must be configured");
    }

    // Create server keys
    let secret_key =
        SecretKey::from_hex(&config.server.private_key).context("Invalid server private key")?;
    let keys = Keys::new(secret_key);

    info!(
        pubkey = %keys.public_key().to_hex(),
        "Server public key"
    );

    // Initialize crypto handlers
    let nip59_handler = Nip59Handler::new(keys.clone());
    let token_decryptor = TokenDecryptor::new(keys.clone());

    // Initialize push clients
    let apns_client = if config.apns.enabled {
        match ApnsClient::new(config.apns.clone()).await {
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
        match FcmClient::new(config.fcm.clone()).await {
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
    let push_dispatcher = Arc::new(PushDispatcher::new(apns_client, fcm_client));

    if !push_dispatcher.is_ready() {
        warn!("No push services configured - notifications will not be sent");
    }

    // Initialize relay client
    let relay_client = Arc::new(
        RelayClient::new(keys.clone(), config.relays.clone())
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

    // Create event processor with configured cache size
    let event_processor = Arc::new(EventProcessor::with_cache_size(
        nip59_handler,
        token_decryptor,
        push_dispatcher.clone(),
        config.server.max_dedup_cache_size,
    ));

    // Initialize shutdown handler
    let shutdown = ShutdownHandler::new();

    // Start health server
    let health_server = HealthServer::new(
        config.health.clone(),
        relay_client.clone(),
        push_dispatcher.clone(),
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
                            error!(error = %e, "Notification channel error");
                            break;
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
    shutdown::graceful_shutdown(|| async {
        push_dispatcher.wait_for_completion().await;
    })
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

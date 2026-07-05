//! Transponder binary entry point.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{error, info};

use transponder::app::{generate_keys, init_logging, run, run_healthcheck};
use transponder::config::AppConfig;
use transponder::telemetry;

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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(command) = args.command {
        return match command {
            Command::GenerateKeys {
                output,
                show_private_key,
            } => generate_keys(output.as_deref(), show_private_key),
            Command::Healthcheck { url } => run_healthcheck(&url).await,
        };
    }

    let config = AppConfig::load(&args.config)
        .with_context(|| format!("Failed to load config from {}", args.config))?;

    // The guard must stay in `main` so it outlives `run` and flushes GlitchTip events.
    let _glitchtip_guard = telemetry::init(&config.glitchtip)?;

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

//! Content Scanner agent CLI.
//!
//! Scans uploaded files for malware using ClamAV daemon.

use anyhow::Result;
use clap::Parser;
use sentinel_agent_content_scanner::{Config, ContentScannerAgent};
use sentinel_agent_sdk::AgentRunner;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Content Scanner agent for Sentinel - malware scanning with ClamAV.
#[derive(Parser, Debug)]
#[command(name = "sentinel-agent-content-scanner")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to configuration file.
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,

    /// Socket path for agent communication.
    #[arg(short, long, default_value = "/tmp/sentinel-content-scanner.sock")]
    socket: PathBuf,

    /// Print example configuration and exit.
    #[arg(long)]
    example_config: bool,

    /// Validate configuration and exit.
    #[arg(long)]
    validate: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();

    // Print example config if requested
    if args.example_config {
        println!("{}", Config::example());
        return Ok(());
    }

    // Load configuration
    let config = Config::load(&args.config)?;

    // Validate only if requested
    if args.validate {
        info!("Configuration is valid");
        return Ok(());
    }

    info!(
        config = %args.config.display(),
        socket = %args.socket.display(),
        "Starting Content Scanner agent"
    );

    // Create agent
    let agent = ContentScannerAgent::new(config);

    // Run agent
    AgentRunner::new(agent)
        .with_name("content-scanner")
        .with_socket(&args.socket)
        .run()
        .await?;

    Ok(())
}

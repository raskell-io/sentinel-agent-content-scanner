//! Content Scanner agent CLI.
//!
//! Scans uploaded files for malware using ClamAV daemon.

use anyhow::{Context, Result};
use clap::Parser;
use sentinel_agent_content_scanner::{Config, ContentScannerAgent};
use sentinel_agent_protocol::v2::GrpcAgentServerV2;
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

    /// gRPC address to listen on (e.g., "0.0.0.0:50051").
    /// Defaults to "0.0.0.0:50051" if not specified.
    #[arg(short, long, env = "CONTENT_SCANNER_GRPC_ADDRESS")]
    grpc_address: Option<String>,

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

    // Create agent
    let agent = ContentScannerAgent::new(config);

    // Determine transport mode - v2 protocol requires gRPC
    if let Some(grpc_addr) = args.grpc_address {
        info!(
            config = %args.config.display(),
            grpc_address = %grpc_addr,
            "Starting Content Scanner agent (gRPC v2)"
        );

        let addr = grpc_addr
            .parse()
            .context("Invalid gRPC address format (expected host:port)")?;

        let server = GrpcAgentServerV2::new("content-scanner", Box::new(agent));

        info!("Content Scanner agent ready and listening on gRPC");

        server
            .run(addr)
            .await
            .context("Failed to run Content Scanner gRPC server")?;
    } else {
        // Default to gRPC on localhost:50051 if no socket specified
        let default_addr = "0.0.0.0:50051";
        info!(
            config = %args.config.display(),
            grpc_address = %default_addr,
            "Starting Content Scanner agent (gRPC v2, default address)"
        );

        let addr = default_addr
            .parse()
            .expect("Default address should always parse");

        let server = GrpcAgentServerV2::new("content-scanner", Box::new(agent));

        info!("Content Scanner agent ready and listening on gRPC");
        info!("Note: Use --grpc-address to specify a custom address");

        server
            .run(addr)
            .await
            .context("Failed to run Content Scanner gRPC server")?;
    }

    Ok(())
}

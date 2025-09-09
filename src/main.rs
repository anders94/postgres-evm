use clap::Parser;
use postgres_evm::{
    config::Config,
    db::{create_pool, init_db},
    logging::init_verbose,
    rpc::start_rpc_server,
};
use std::path::PathBuf;
use tokio::signal;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(default_value = "config.toml")]
    config: PathBuf,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    // Parse command line arguments
    let args = Args::parse();
    
    info!("Loading configuration from {:?}", args.config);
    let mut config = Config::from_file(args.config)?;
    
    // Override verbose setting from command line
    if args.verbose {
        config.server.verbose = true;
    }
    
    // Initialize verbose logging
    init_verbose(config.server.verbose);
    if config.server.verbose {
        info!("Verbose logging enabled");
    }
    
    // Create database connection pool
    info!("Connecting to database {}:{}", config.database.host, config.database.port);
    let pool = create_pool(&config.database)?;
    
    // Initialize database
    info!("Initializing database");
    init_db(&pool).await?;
    
    // Start RPC server
    info!("Starting RPC server on {}:{}", config.server.host, config.server.port);
    let server_addr = start_rpc_server(config.server.clone(), pool.clone(), config.chain.chain_id).await?;
    info!("RPC server running at {}", server_addr);
    
    // Wait for shutdown signal
    match signal::ctrl_c().await {
        Ok(()) => {
            info!("Received shutdown signal");
        }
        Err(err) => {
            error!("Error waiting for shutdown signal: {}", err);
        }
    }
    
    info!("Shutting down");
    Ok(())
}
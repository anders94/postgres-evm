use postgres_evm::{
    config::Config,
    db::{create_pool, init_db},
    rpc::start_rpc_server,
};
use std::path::PathBuf;
use tokio::signal;
use tracing::{error, info};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    // Load configuration
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());
    let config_path = PathBuf::from(config_path);
    
    info!("Loading configuration from {:?}", config_path);
    let config = Config::from_file(config_path)?;
    
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
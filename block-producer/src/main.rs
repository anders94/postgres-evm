use clap::Parser;
use deadpool_postgres::Pool;
use ethers_core::types::{H256, U256};
use postgres_evm::{
    config::Config,
    db::{create_pool, init_db},
    errors::{AppError, Result},
    models::{BlockEntry, BlockInfo, EthereumReceipt, TransactionEntry},
};
use std::{path::PathBuf, str::FromStr, time::Duration};
use tokio::{
    signal,
    time::{self, Instant},
};
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    /// Block production interval in seconds
    #[arg(short, long, default_value_t = 15)]
    interval: u64,
}

struct BlockProducer {
    pool: Pool,
    interval: Duration,
    chain_id: u64,
}

impl BlockProducer {
    fn new(pool: Pool, interval: Duration, chain_id: u64) -> Self {
        Self {
            pool,
            interval,
            chain_id,
        }
    }

    async fn start(&self) -> Result<()> {
        info!("Block producer started with interval: {:?}", self.interval);
        
        let mut interval = time::interval(self.interval);
        
        loop {
            interval.tick().await;
            
            match self.produce_block().await {
                Ok(block_number) => {
                    info!("Successfully produced block #{}", block_number);
                }
                Err(e) => {
                    error!("Failed to produce block: {}", e);
                }
            }
        }
    }

    async fn produce_block(&self) -> Result<i64> {
        let mut client = self.pool.get().await?;
        
        // Begin transaction
        let tx = client.transaction().await?;
        
        // Get the latest block number
        let latest_block = tx
            .query_opt(
                "SELECT number, hash, parent_hash, timestamp FROM blocks ORDER BY number DESC LIMIT 1",
                &[],
            )
            .await?;
        
        let (block_number, parent_hash) = if let Some(row) = latest_block {
            let number: i64 = row.get(0);
            let hash: String = row.get(1);
            (number + 1, hash)
        } else {
            // Genesis block
            (0, "0x0000000000000000000000000000000000000000000000000000000000000000".to_string())
        };
        
        // Get pending transactions
        let rows = tx
            .query(
                "SELECT hash, value, result FROM transactions 
                 WHERE block_number IS NULL AND result IS NOT NULL 
                 ORDER BY created_at ASC
                 LIMIT 1000",
                &[],
            )
            .await?;
        
        if rows.is_empty() {
            tx.rollback().await?;
            info!("No pending transactions, skipping block production");
            return Ok(block_number);
        }
        
        let mut transactions = Vec::with_capacity(rows.len());
        let mut gas_used: i64 = 0;
        
        for row in &rows {
            let hash: String = row.get(0);
            let result: Vec<u8> = row.get(2);
            
            // Parse receipt to get gas used
            let receipt: EthereumReceipt = serde_json::from_slice(&result)
                .map_err(|e| AppError::EncodingError(format!("Failed to decode receipt: {}", e)))?;
            
            gas_used += receipt.gas_used.as_u64() as i64;
            transactions.push(hash);
        }
        
        // Generate block hash (in a real system, this would be more complex)
        let timestamp = chrono::Utc::now().timestamp();
        let block_hash = format!(
            "0x{:064x}", 
            (block_number as u64) ^ (timestamp as u64) ^ (transactions.len() as u64)
        );
        
        // Create the block
        let block = BlockEntry {
            number: block_number,
            hash: block_hash.clone(),
            parent_hash,
            timestamp,
            gas_limit: 30_000_000, // 30M gas limit
            gas_used,
            base_fee_per_gas: Some(1_000_000_000), // 1 gwei
            created_at: std::time::SystemTime::now(),
        };
        
        // Insert the block
        tx.execute(
            "INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_limit, gas_used, base_fee_per_gas) 
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &block.number,
                &block.hash,
                &block.parent_hash,
                &block.timestamp,
                &block.gas_limit,
                &block.gas_used,
                &block.base_fee_per_gas,
            ],
        )
        .await?;
        
        // Update transaction block numbers
        for hash in &transactions {
            tx.execute(
                "UPDATE transactions SET block_number = $1 WHERE hash = $2",
                &[&block_number, hash],
            )
            .await?;
        }
        
        // Commit the transaction
        tx.commit().await?;
        
        info!(
            "Produced block #{} with {} transactions, gas used: {}", 
            block_number, 
            transactions.len(),
            gas_used
        );
        
        Ok(block_number)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    // Parse command line arguments
    let args = Args::parse();
    
    // Load configuration
    info!("Loading configuration from {:?}", args.config);
    let config = Config::from_file(args.config)?;
    
    // Create database connection pool
    info!("Connecting to database {}:{}", config.database.host, config.database.port);
    let pool = create_pool(&config.database)?;
    
    // Initialize database
    info!("Initializing database");
    init_db(&pool).await?;
    
    // Create block producer
    let interval = Duration::from_secs(args.interval);
    let block_producer = BlockProducer::new(pool, interval, config.chain.chain_id);
    
    // Start block production in a separate task
    let producer_handle = tokio::spawn(async move {
        if let Err(e) = block_producer.start().await {
            error!("Block producer error: {}", e);
        }
    });
    
    // Wait for shutdown signal
    match signal::ctrl_c().await {
        Ok(()) => {
            info!("Received shutdown signal");
        }
        Err(err) => {
            error!("Error waiting for shutdown signal: {}", err);
        }
    }
    
    // Abort the block producer task
    producer_handle.abort();
    
    info!("Shutting down");
    Ok(())
}
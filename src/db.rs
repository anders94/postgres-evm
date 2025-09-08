use deadpool_postgres::{Pool, PoolConfig, Runtime, Manager};
use tokio_postgres::Config as PgConfig;

use crate::config::DatabaseConfig;
use crate::errors::{AppError, Result};

// Extend AppError to handle deadpool build errors
impl From<deadpool::managed::BuildError<tokio_postgres::Error>> for AppError {
    fn from(error: deadpool::managed::BuildError<tokio_postgres::Error>) -> Self {
        match error {
            deadpool::managed::BuildError::Backend(e) => AppError::DatabaseError(e),
            e => AppError::TransactionError(format!("Failed to build database pool: {:?}", e))
        }
    }
}

pub fn create_pool(config: &DatabaseConfig) -> Result<Pool> {
    let mut pg_config = PgConfig::new();
    pg_config.host(&config.host);
    pg_config.port(config.port);
    pg_config.user(&config.username);
    pg_config.password(&config.password);
    pg_config.dbname(&config.database_name);
    pg_config.application_name("postgres-evm");

    let pool_config = PoolConfig {
        max_size: config.max_connections as usize,
        ..Default::default()
    };

    let manager = Manager::new(pg_config, tokio_postgres::NoTls);
    
    let pool = Pool::builder(manager)
        .config(pool_config)
        .runtime(Runtime::Tokio1)
        .build()?;

    Ok(pool)
}

pub async fn init_db(pool: &Pool) -> Result<()> {
    let client = pool.get().await?;
    
    // Test connection
    let result = client.query_one("SELECT 1", &[]).await?;
    let value: i32 = result.get(0);
    
    if value != 1 {
        return Err(AppError::TransactionError(
            "Failed to connect to database".to_string()
        ));
    }
    
    // Check if we have any blocks, and create a genesis block if not
    let block_count = client
        .query_one("SELECT COUNT(*) FROM blocks", &[])
        .await?;
    let count: i64 = block_count.get(0);
    
    if count == 0 {
        // Create genesis block
        let genesis_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        let genesis_hash = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let parent_hash = "0x0000000000000000000000000000000000000000000000000000000000000000";
        
        client.execute(
            "INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_limit, gas_used, base_fee_per_gas) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[&0i64, &genesis_hash, &parent_hash, &genesis_timestamp, &15_000_000i64, &0i64, &1_000_000_000i64],
        ).await?;
        
        tracing::info!("Created genesis block with hash {}", genesis_hash);
    }
    
    Ok(())
}
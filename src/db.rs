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
    
    Ok(())
}
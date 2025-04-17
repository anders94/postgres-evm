use deadpool_postgres::{Config, Pool, PoolConfig, Runtime};
use tokio_postgres::NoTls;

use crate::config::DatabaseConfig;
use crate::errors::Result;

pub fn create_pool(config: &DatabaseConfig) -> Result<Pool> {
    let mut pg_config = tokio_postgres::Config::new();
    pg_config.host(&config.host);
    pg_config.port(config.port);
    pg_config.user(&config.username);
    pg_config.password(&config.password);
    pg_config.dbname(&config.database_name);
    pg_config.application_name("postgres-evm");

    let pool_config = PoolConfig {
        max_size: config.max_connections,
        ..Default::default()
    };

    let pool = Pool::builder(pg_config)
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
        return Err(crate::errors::AppError::DatabaseError(
            tokio_postgres::Error::from(std::io::Error::new(
                std::io::ErrorKind::Other, 
                "Failed to connect to database"
            ))
        ));
    }
    
    Ok(())
}
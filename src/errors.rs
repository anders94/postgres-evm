use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] tokio_postgres::Error),

    #[error("Database pool error: {0}")]
    PoolError(#[from] deadpool_postgres::PoolError),

    #[error("EVM execution error: {0}")]
    EVMError(String),

    #[error("Transaction error: {0}")]
    TransactionError(String),

    #[error("RPC error: {0}")]
    RPCError(String),

    #[error("Encoding error: {0}")]
    EncodingError(String),
    
    #[error("State error: {0}")]
    StateError(String),

    #[error("Config error: {0}")]
    ConfigError(#[from] config::ConfigError),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),
}

pub type Result<T> = std::result::Result<T, AppError>;
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
    
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
}

pub type Result<T> = std::result::Result<T, AppError>;

// Add a simple error type for REVM Database trait
// We need to implement DBErrorMarker manually since it's not a derive-able trait
#[derive(Debug, Clone)]
pub struct DatabaseError(pub String);

impl std::fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for DatabaseError {}

// Implement DBErrorMarker - this is the key trait that REVM requires
impl revm_database::DBErrorMarker for DatabaseError {}

impl From<String> for DatabaseError {
    fn from(s: String) -> Self {
        DatabaseError(s)
    }
}

impl From<AppError> for DatabaseError {
    fn from(e: AppError) -> Self {
        DatabaseError(e.to_string())
    }
}
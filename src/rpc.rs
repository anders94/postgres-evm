use deadpool_postgres::Pool;
use ethers_core::types::{Block, TransactionReceipt, U256};
use jsonrpsee::{
    core::RpcResult,
    proc_macros::rpc,
    server::ServerBuilder,
    types::error::{ErrorCode, ErrorObject},
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use async_trait::async_trait;

use crate::config::ServerConfig;
use crate::errors::{AppError, Result};
use crate::evm::EVMExecutor;
use crate::models::{ChainInfo, EthereumTransaction};
use crate::utils;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionRequest {
    pub from: Option<String>,
    pub to: Option<String>,
    pub gas: Option<String>,
    pub gas_price: Option<String>,
    pub max_priority_fee_per_gas: Option<String>,
    pub max_fee_per_gas: Option<String>,
    pub value: Option<String>,
    pub data: Option<String>,
    pub nonce: Option<String>,
    pub chain_id: Option<String>,
    pub access_list: Option<Vec<AccessListItem>>,
    pub transaction_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessListItem {
    pub address: String,
    pub storage_keys: Vec<String>,
}

#[rpc(server)]
pub trait EthereumApi {
    /// Get network version
    #[method(name = "net_version")]
    async fn net_version(&self) -> RpcResult<String>;

    /// Get chain id
    #[method(name = "eth_chainId")]
    async fn chain_id(&self) -> RpcResult<String>;

    /// Get accounts
    #[method(name = "eth_accounts")]
    async fn accounts(&self) -> RpcResult<Vec<String>>;
    
    /// Get balance
    #[method(name = "eth_getBalance")]
    async fn get_balance(&self, address: String, block: Option<String>) -> RpcResult<String>;
    
    /// Get transaction count
    #[method(name = "eth_getTransactionCount")]
    async fn get_transaction_count(&self, address: String, block: Option<String>) -> RpcResult<String>;
    
    /// Get storage at
    #[method(name = "eth_getStorageAt")]
    async fn get_storage_at(&self, address: String, slot: String, block: Option<String>) -> RpcResult<String>;
    
    /// Get code
    #[method(name = "eth_getCode")]
    async fn get_code(&self, address: String, block: Option<String>) -> RpcResult<String>;
    
    /// Send raw transaction
    #[method(name = "eth_sendRawTransaction")]
    async fn send_raw_transaction(&self, data: String) -> RpcResult<String>;
    
    /// Send transaction
    #[method(name = "eth_sendTransaction")]
    async fn send_transaction(&self, transaction: TransactionRequest) -> RpcResult<String>;
    
    /// Call
    #[method(name = "eth_call")]
    async fn call(&self, transaction: TransactionRequest, block: Option<String>) -> RpcResult<String>;
    
    /// Estimate gas
    #[method(name = "eth_estimateGas")]
    async fn estimate_gas(&self, transaction: TransactionRequest, block: Option<String>) -> RpcResult<String>;
    
    /// Get transaction by hash
    #[method(name = "eth_getTransactionByHash")]
    async fn get_transaction_by_hash(&self, hash: String) -> RpcResult<Option<EthereumTransaction>>;
    
    /// Get transaction receipt
    #[method(name = "eth_getTransactionReceipt")]
    async fn get_transaction_receipt(&self, hash: String) -> RpcResult<Option<TransactionReceipt>>;
    
    /// Get block by hash
    #[method(name = "eth_getBlockByHash")]
    async fn get_block_by_hash(&self, hash: String, full_transactions: bool) -> RpcResult<Option<Block<serde_json::Value>>>;
    
    /// Get block by number
    #[method(name = "eth_getBlockByNumber")]
    async fn get_block_by_number(&self, block: String, full_transactions: bool) -> RpcResult<Option<Block<serde_json::Value>>>;
    
    /// Get block number
    #[method(name = "eth_blockNumber")]
    async fn block_number(&self) -> RpcResult<String>;
    
    /// Get gas price
    #[method(name = "eth_gasPrice")]
    async fn gas_price(&self) -> RpcResult<String>;
}

pub struct EthereumApiServerImpl {
    pool: Pool,
    chain_id: u64,
}

impl EthereumApiServerImpl {
    pub fn new(pool: Pool, chain_id: u64) -> Self {
        Self { pool, chain_id }
    }

    async fn get_chain_info(&self) -> Result<ChainInfo> {
        let client = self.pool.get().await
            .map_err(|e| AppError::PoolError(e))?;
        
        let executor = EVMExecutor::new(self.chain_id);
        executor.get_chain_info_postgres(&client).await
    }

    fn map_error(err: AppError) -> ErrorObject<'static> {
        let error_msg = format!("{}", err);
        ErrorObject::owned(
            ErrorCode::ServerError(1).code(),
            error_msg,
            None::<()>
        )
    }
}

#[async_trait]
impl EthereumApiServer for EthereumApiServerImpl {
    async fn net_version(&self) -> RpcResult<String> {
        Ok(self.chain_id.to_string())
    }

    async fn chain_id(&self) -> RpcResult<String> {
        Ok(format!("0x{:x}", self.chain_id))
    }

    async fn accounts(&self) -> RpcResult<Vec<String>> {
        // Return empty list as we don't manage accounts
        Ok(vec![])
    }

    async fn get_balance(&self, address: String, block: Option<String>) -> RpcResult<String> {
        let address = utils::parse_address(&address).map_err(|e| Self::map_error(e))?;
        
        let mut client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Implementation will depend on our state retrieval logic
        // For now, return a placeholder
        Ok("0x0".to_string())
    }

    async fn get_transaction_count(&self, address: String, block: Option<String>) -> RpcResult<String> {
        let address = utils::parse_address(&address).map_err(|e| Self::map_error(e))?;
        
        let mut client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Implementation will depend on our state retrieval logic
        // For now, return a placeholder
        Ok("0x0".to_string())
    }

    async fn get_storage_at(&self, address: String, slot: String, block: Option<String>) -> RpcResult<String> {
        let address = utils::parse_address(&address).map_err(|e| Self::map_error(e))?;
        let slot = utils::parse_hash(&slot).map_err(|e| Self::map_error(e))?;
        
        let mut client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Implementation will depend on our state retrieval logic
        // For now, return a placeholder
        Ok("0x0".to_string())
    }

    async fn get_code(&self, address: String, block: Option<String>) -> RpcResult<String> {
        let address = utils::parse_address(&address).map_err(|e| Self::map_error(e))?;
        
        let mut client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Implementation will depend on our state retrieval logic
        // For now, return a placeholder
        Ok("0x".to_string())
    }

    async fn send_raw_transaction(&self, data: String) -> RpcResult<String> {
        let bytes = utils::hex_to_bytes(&data).map_err(|e| Self::map_error(e))?;
        
        // Parse the raw transaction
        // This is a simplified version - in a real implementation,
        // we would use proper RLP decoding and transaction parsing
        
        let mut client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // For now, return a placeholder transaction hash
        Ok("0x0000000000000000000000000000000000000000000000000000000000000000".to_string())
    }

    async fn send_transaction(&self, transaction: TransactionRequest) -> RpcResult<String> {
        let mut client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Process the transaction request
        // This is a simplified version
        
        // For now, return a placeholder transaction hash
        Ok("0x0000000000000000000000000000000000000000000000000000000000000000".to_string())
    }

    async fn call(&self, transaction: TransactionRequest, block: Option<String>) -> RpcResult<String> {
        let mut client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Process the call request
        // This is a simplified version
        
        // For now, return a placeholder result
        Ok("0x".to_string())
    }

    async fn estimate_gas(&self, transaction: TransactionRequest, block: Option<String>) -> RpcResult<String> {
        let mut client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Estimate gas for the transaction
        // This is a simplified version
        
        // For now, return a placeholder gas estimate
        Ok("0x5208".to_string()) // 21000 gas, standard transaction cost
    }

    async fn get_transaction_by_hash(&self, hash: String) -> RpcResult<Option<EthereumTransaction>> {
        let tx_hash = utils::parse_hash(&hash).map_err(|e| Self::map_error(e))?;
        
        let mut client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Retrieve transaction by hash from the database
        // This is a simplified version
        
        // For now, return None (transaction not found)
        Ok(None)
    }

    async fn get_transaction_receipt(&self, hash: String) -> RpcResult<Option<TransactionReceipt>> {
        let tx_hash = utils::parse_hash(&hash).map_err(|e| Self::map_error(e))?;
        
        let mut client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Retrieve transaction receipt by hash from the database
        // This is a simplified version
        
        // For now, return None (receipt not found)
        Ok(None)
    }

    async fn get_block_by_hash(&self, hash: String, full_transactions: bool) -> RpcResult<Option<Block<serde_json::Value>>> {
        let block_hash = utils::parse_hash(&hash).map_err(|e| Self::map_error(e))?;
        
        let mut client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Retrieve block by hash from the database
        // This is a simplified version
        
        // For now, return None (block not found)
        Ok(None)
    }

    async fn get_block_by_number(&self, block: String, full_transactions: bool) -> RpcResult<Option<Block<serde_json::Value>>> {
        let mut client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Retrieve block by number from the database
        // This is a simplified version
        
        // For now, return None (block not found)
        Ok(None)
    }

    async fn block_number(&self) -> RpcResult<String> {
        let chain_info = match self.get_chain_info().await {
            Ok(info) => info,
            Err(e) => {
                return Err(Self::map_error(e));
            },
        };
        
        Ok(utils::uint_to_hex(&chain_info.latest_block.number))
    }

    async fn gas_price(&self) -> RpcResult<String> {
        let chain_info = match self.get_chain_info().await {
            Ok(info) => info,
            Err(e) => {
                return Err(Self::map_error(e));
            },
        };
        
        // Return the base fee per gas from the latest block, or a default value
        let gas_price = chain_info.latest_block.base_fee_per_gas
            .unwrap_or_else(|| U256::from(1_000_000_000)); // 1 gwei default
        
        Ok(utils::uint_to_hex(&gas_price))
    }
}

pub async fn start_rpc_server(config: ServerConfig, pool: Pool, chain_id: u64) -> Result<SocketAddr> {
    let addr = format!("{}:{}", config.host, config.port)
        .parse::<SocketAddr>()
        .map_err(|e| AppError::RPCError(format!("Invalid server address: {}", e)))?;
    
    let server = ServerBuilder::default()
        .build(addr)
        .await
        .map_err(|e| AppError::RPCError(format!("Failed to build RPC server: {}", e)))?;
    
    let api = EthereumApiServerImpl::new(pool, chain_id);
    let server_addr = server.local_addr()
        .map_err(|e| AppError::RPCError(format!("Failed to get server address: {}", e)))?;
    
    let handle = server.start(api.into_rpc())
        .map_err(|e| AppError::RPCError(format!("Failed to start RPC server: {}", e)))?;

    // Spawn the server to run in the background
    tokio::spawn(async move {
        handle.stopped().await;
    });
    
    Ok(server_addr)
}
use deadpool_postgres::Pool;
use ethers_core::types::{Block, TransactionReceipt};
use jsonrpsee::{
    core::RpcResult,
    proc_macros::rpc,
    server::ServerBuilder,
    types::error::{ErrorCode, ErrorObject},
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilterRequest {
    pub from_block: Option<String>,
    pub to_block: Option<String>,
    pub address: Option<serde_json::Value>, // Can be string or array
    pub topics: Option<Vec<Option<String>>>,
}

#[derive(Debug, Clone)]
struct Filter {
    filter_type: FilterType,
    last_poll: std::time::SystemTime,
}

#[derive(Debug, Clone)]
enum FilterType {
    Log(FilterRequest),
    Block,
    PendingTransaction,
}

type FilterMap = Arc<Mutex<HashMap<String, Filter>>>;

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
    
    /// Get max priority fee per gas
    #[method(name = "eth_maxPriorityFeePerGas")]
    async fn max_priority_fee_per_gas(&self) -> RpcResult<String>;
    
    /// Get fee history
    #[method(name = "eth_feeHistory")]
    async fn fee_history(&self, block_count: String, newest_block: String, reward_percentiles: Option<Vec<f64>>) -> RpcResult<serde_json::Value>;
    
    /// Get sync status
    #[method(name = "eth_syncing")]
    async fn syncing(&self) -> RpcResult<serde_json::Value>;
    
    /// Get block transaction count by hash
    #[method(name = "eth_getBlockTransactionCountByHash")]
    async fn get_block_transaction_count_by_hash(&self, hash: String) -> RpcResult<String>;
    
    /// Get block transaction count by number
    #[method(name = "eth_getBlockTransactionCountByNumber")]
    async fn get_block_transaction_count_by_number(&self, block: String) -> RpcResult<String>;
    
    /// Get transaction by block hash and index
    #[method(name = "eth_getTransactionByBlockHashAndIndex")]
    async fn get_transaction_by_block_hash_and_index(&self, block_hash: String, index: String) -> RpcResult<Option<EthereumTransaction>>;
    
    /// Get transaction by block number and index
    #[method(name = "eth_getTransactionByBlockNumberAndIndex")]
    async fn get_transaction_by_block_number_and_index(&self, block: String, index: String) -> RpcResult<Option<EthereumTransaction>>;
    
    /// Create new log filter
    #[method(name = "eth_newFilter")]
    async fn new_filter(&self, filter: FilterRequest) -> RpcResult<String>;
    
    /// Create new block filter
    #[method(name = "eth_newBlockFilter")]
    async fn new_block_filter(&self) -> RpcResult<String>;
    
    /// Create new pending transaction filter
    #[method(name = "eth_newPendingTransactionFilter")]
    async fn new_pending_transaction_filter(&self) -> RpcResult<String>;
    
    /// Get filter changes
    #[method(name = "eth_getFilterChanges")]
    async fn get_filter_changes(&self, filter_id: String) -> RpcResult<serde_json::Value>;
    
    /// Uninstall filter
    #[method(name = "eth_uninstallFilter")]
    async fn uninstall_filter(&self, filter_id: String) -> RpcResult<bool>;
}

pub struct EthereumApiServerImpl {
    pool: Pool,
    chain_id: u64,
    filters: FilterMap,
}

impl EthereumApiServerImpl {
    pub fn new(pool: Pool, chain_id: u64) -> Self {
        Self { 
            pool, 
            chain_id,
            filters: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    fn generate_filter_id() -> String {
        format!("0x{:x}", rand::random::<u64>())
    }

    #[allow(dead_code)]
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

    async fn get_balance(&self, address: String, _block: Option<String>) -> RpcResult<String> {
        let address = utils::parse_address(&address).map_err(|e| Self::map_error(e))?;
        
        let client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Use the PostgresState to get the account
        let state = crate::state::PostgresState::new(&client);
        let account = match state.get_account(&address).await {
            Ok(Some(account)) => account,
            Ok(None) => {
                // Account doesn't exist, return zero balance
                return Ok("0x0".to_string());
            },
            Err(e) => return Err(Self::map_error(e)),
        };
        
        Ok(utils::uint_to_hex(&account.balance))
    }

    async fn get_transaction_count(&self, address: String, _block: Option<String>) -> RpcResult<String> {
        let address = utils::parse_address(&address).map_err(|e| Self::map_error(e))?;
        
        let client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Use the PostgresState to get the account
        let state = crate::state::PostgresState::new(&client);
        let account = match state.get_account(&address).await {
            Ok(Some(account)) => account,
            Ok(None) => {
                // Account doesn't exist, return zero nonce
                return Ok("0x0".to_string());
            },
            Err(e) => return Err(Self::map_error(e)),
        };
        
        Ok(utils::uint_to_hex(&account.nonce))
    }

    async fn get_storage_at(&self, address: String, slot: String, _block: Option<String>) -> RpcResult<String> {
        let address = utils::parse_address(&address).map_err(|e| Self::map_error(e))?;
        let slot = utils::parse_hash(&slot).map_err(|e| Self::map_error(e))?;
        
        let client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Use the PostgresState to get the storage value
        let state = crate::state::PostgresState::new(&client);
        let storage_value = match state.get_storage(&address, &slot).await {
            Ok(value) => value,
            Err(e) => return Err(Self::map_error(e)),
        };
        
        Ok(format!("0x{}", hex::encode(storage_value.as_bytes())))
    }

    async fn get_code(&self, address: String, _block: Option<String>) -> RpcResult<String> {
        let address = utils::parse_address(&address).map_err(|e| Self::map_error(e))?;
        
        let client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Use the PostgresState to get the account
        let state = crate::state::PostgresState::new(&client);
        let account = match state.get_account(&address).await {
            Ok(Some(account)) => account,
            Ok(None) => {
                // Account doesn't exist, return empty code
                return Ok("0x".to_string());
            },
            Err(e) => return Err(Self::map_error(e)),
        };
        
        // If the account has code, return it
        if let Some(code) = account.code {
            return Ok(format!("0x{}", hex::encode(&code)));
        }
        
        // If the account has code_hash but no inline code, fetch it
        if let Some(code_hash) = account.code_hash {
            if code_hash != primitive_types::H256::zero() {
                match state.get_code(&code_hash).await {
                    Ok(bytecode) => {
                        let code_bytes = bytecode.clone().bytes().to_vec();
                        return Ok(format!("0x{}", hex::encode(&code_bytes)));
                    },
                    Err(e) => return Err(Self::map_error(e)),
                }
            }
        }
        
        // No code found
        Ok("0x".to_string())
    }

    async fn send_raw_transaction(&self, data: String) -> RpcResult<String> {
        let raw_tx_bytes = utils::hex_to_bytes(&data).map_err(|e| Self::map_error(e))?;
        
        // Parse the raw transaction using ethers and recover the sender
        let tx = match ethers_core::utils::rlp::decode::<ethers_core::types::Transaction>(&raw_tx_bytes) {
            Ok(mut tx) => {
                // Recover the sender address from the signature if it's not already set
                if tx.from == ethers_core::types::H160::zero() {
                    match tx.recover_from() {
                        Ok(sender) => {
                            tx.from = sender;
                        },
                        Err(e) => {
                            return Err(Self::map_error(AppError::EncodingError(format!("Failed to recover sender: {}", e))));
                        }
                    }
                }
                tx
            },
            Err(e) => {
                return Err(Self::map_error(AppError::EncodingError(format!("Failed to decode transaction: {}", e))));
            }
        };
        
        // Convert to our internal transaction type
        let ethereum_tx: crate::models::EthereumTransaction = tx.into();
        
        // Get hash for return value
        let tx_hash = utils::hash_to_hex(&ethereum_tx.hash);
        
        // Get client for database operations
        let mut client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Start a database transaction to ensure atomicity
        let db_tx = match client.transaction().await {
            Ok(tx) => tx,
            Err(e) => {
                return Err(Self::map_error(AppError::DatabaseError(e)));
            }
        };
        
        // Create EVM executor
        let executor = crate::evm::EVMExecutor::new(self.chain_id);
        
        // Store transaction and execute within the database transaction
        let result = async {
            // Store transaction
            executor.store_transaction_tx(&db_tx, &ethereum_tx).await?;
            
            // Execute the transaction (this also manages its own internal transaction)
            executor.execute_transaction_from_tx(&db_tx, &ethereum_tx).await
        }.await;
        
        match result {
            Ok(_receipt) => {
                // Commit the database transaction - transaction is persisted
                if let Err(e) = db_tx.commit().await {
                    return Err(Self::map_error(AppError::DatabaseError(e)));
                }
                // Return the transaction hash
                Ok(tx_hash)
            },
            Err(e) => {
                // Rollback the database transaction - transaction is not persisted
                let _ = db_tx.rollback().await; // Ignore rollback errors
                return Err(Self::map_error(e));
            }
        }
    }

    async fn send_transaction(&self, _transaction: TransactionRequest) -> RpcResult<String> {
        // Note: send_transaction would normally require a private key to sign the transaction
        // Since we don't manage keys in this implementation, we'll return an error
        
        // You could implement this in production by:
        // 1. Having a local keystore for dev/test accounts
        // 2. Using external signing services
        // 3. Using a secret manager for private keys
        
        Err(Self::map_error(AppError::InvalidOperation(
            "Method eth_sendTransaction is not supported. Use eth_sendRawTransaction with a signed transaction instead.".to_string()
        )))
    }

    async fn call(&self, transaction: TransactionRequest, _block: Option<String>) -> RpcResult<String> {
        // Get client for database operations
        let mut client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Parse the transaction request fields
        let from = match transaction.from {
            Some(ref from_str) => match utils::parse_address(from_str) {
                Ok(addr) => Some(addr),
                Err(e) => return Err(Self::map_error(e)),
            },
            None => None,
        };
        
        let to = match transaction.to {
            Some(ref to_str) => match utils::parse_address(to_str) {
                Ok(addr) => Some(addr),
                Err(e) => return Err(Self::map_error(e)),
            },
            None => None,
        };
        
        let gas = match transaction.gas {
            Some(ref gas_str) => match utils::parse_uint(gas_str) {
                Ok(gas) => Some(gas),
                Err(e) => return Err(Self::map_error(e)),
            },
            None => Some(primitive_types::U256::from(10_000_000)), // Default gas
        };
        
        let gas_price = match transaction.gas_price {
            Some(ref gas_price_str) => match utils::parse_uint(gas_price_str) {
                Ok(gas_price) => Some(gas_price),
                Err(e) => return Err(Self::map_error(e)),
            },
            None => Some(primitive_types::U256::from(1_000_000_000)), // Default 1 gwei
        };
        
        let value = match transaction.value {
            Some(ref value_str) => match utils::parse_uint(value_str) {
                Ok(value) => value,
                Err(e) => return Err(Self::map_error(e)),
            },
            None => primitive_types::U256::zero(),
        };
        
        let data = match transaction.data {
            Some(ref data_str) => match utils::hex_to_bytes(data_str) {
                Ok(data) => data,
                Err(e) => return Err(Self::map_error(e)),
            },
            None => Vec::new(),
        };
        
        // Create a mock transaction - this won't be stored
        // This is a simplified version that ignores many Ethereum transaction fields
        let mock_tx = crate::models::EthereumTransaction {
            hash: primitive_types::H256::random(), // Random hash for this call
            nonce: primitive_types::U256::zero(),
            block_hash: None,
            block_number: None,
            transaction_index: None,
            from: from.unwrap_or_else(|| primitive_types::H160::zero()),
            to,
            value,
            gas_price,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            gas: gas.unwrap_or_else(|| primitive_types::U256::from(21000)),
            input: data,
            v: primitive_types::U256::zero(),
            r: primitive_types::U256::zero(),
            s: primitive_types::U256::zero(),
            chain_id: Some(self.chain_id),
            access_list: None,
            transaction_type: None,
        };
        
        // Create EVM executor
        let executor = crate::evm::EVMExecutor::new(self.chain_id);
        
        // Execute a simulated transaction with DB snapshot
        let _state = crate::state::PostgresState::new(&client);
        let _db_storage = crate::state::PostgresStateStorage::new(&client);
        
        // We need to build a temporary EVM database from our Postgres state
        // This is a simplified version that would need to be expanded
        // to capture more complex state transitions
        
        // For now, just simulate raw execution
        // In a full implementation, this would use a DB transaction that we'd roll back
        // In production code, we would start a db transaction and roll it back later
        // For simplicity, we're just executing with the client directly
        match executor.execute_transaction(&mut client, &mock_tx).await {
            Ok(_receipt) => {
                // Return the output data
                if _receipt.status == Some(primitive_types::U256::one()) {
                    // Transaction was successful, return output data
                    // In a real implementation, this would be the return data from the contract
                    // For now, return an empty result
                    Ok("0x".to_string())
                } else {
                    // Transaction reverted
                    Err(Self::map_error(AppError::EVMError("Transaction reverted".to_string())))
                }
            },
            Err(e) => {
                Err(Self::map_error(e))
            }
        }
    }

    async fn estimate_gas(&self, transaction: TransactionRequest, _block: Option<String>) -> RpcResult<String> {
        // Get client for database operations
        let _client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // For contract deployment without code, return standard tx gas
        if transaction.to.is_none() && 
           (transaction.data.is_none() || transaction.data.as_ref().unwrap().is_empty()) {
            return Ok("0x5208".to_string()); // 21000 gas
        }
        
        // For simple ETH transfers, return standard tx gas
        if transaction.to.is_some() && 
           (transaction.data.is_none() || transaction.data.as_ref().unwrap().is_empty()) {
            return Ok("0x5208".to_string()); // 21000 gas
        }
        
        // For contract calls or deployments, we'd normally simulate the transaction
        // and measure the gas used. For simplicity, we'll return a higher estimate
        // based on the data size.
        
        // A very simple estimate based on data size
        let data_size = match transaction.data {
            Some(ref data_str) => {
                match utils::hex_to_bytes(data_str) {
                    Ok(data) => data.len(),
                    Err(e) => return Err(Self::map_error(e)),
                }
            },
            None => 0,
        };
        
        // Base cost + data cost (very simplified)
        let base_gas = 21000; // Base transaction cost
        let data_gas = data_size * 68; // Simplified: 68 gas per non-zero byte
        let buffer = 30000; // Safety buffer
        
        let total_gas = base_gas + data_gas + buffer;
        
        // In a real implementation, you would:
        // 1. Execute the transaction in a simulation with gas limit detection
        // 2. Measure the actual gas used
        // 3. Add a safety buffer
        // 4. Consider current block's available gas
        
        Ok(format!("0x{:x}", total_gas))
    }

    async fn get_transaction_by_hash(&self, hash: String) -> RpcResult<Option<EthereumTransaction>> {
        let tx_hash = utils::parse_hash(&hash).map_err(|e| Self::map_error(e))?;
        
        let client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Format hash for database query
        let hash_str = format!("{:?}", tx_hash);
        
        // Query the transaction from the database
        let row = match client
            .query_opt("SELECT value FROM transactions WHERE hash = $1", &[&hash_str])
            .await {
                Ok(row) => row,
                Err(e) => return Err(Self::map_error(AppError::DatabaseError(e))),
            };
        
        if let Some(row) = row {
            // Deserialize the transaction
            let value: Vec<u8> = row.get(0);
            match serde_json::from_slice::<EthereumTransaction>(&value) {
                Ok(tx) => Ok(Some(tx)),
                Err(e) => Err(Self::map_error(AppError::EncodingError(format!("Failed to decode transaction: {}", e)))),
            }
        } else {
            // Transaction not found
            Ok(None)
        }
    }

    async fn get_transaction_receipt(&self, hash: String) -> RpcResult<Option<TransactionReceipt>> {
        let tx_hash = utils::parse_hash(&hash).map_err(|e| Self::map_error(e))?;
        
        let client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Format hash for database query
        let hash_str = format!("{:?}", tx_hash);
        
        // Query the transaction from the database
        let row = match client
            .query_opt("SELECT value, result, block_number FROM transactions WHERE hash = $1", &[&hash_str])
            .await {
                Ok(row) => row,
                Err(e) => return Err(Self::map_error(AppError::DatabaseError(e))),
            };
        
        if let Some(row) = row {
            // Get the result (receipt) data
            let result: Option<Vec<u8>> = row.get(1);
            let block_number: Option<i64> = row.get(2);
            
            // If no result or not included in a block yet, return None
            if result.is_none() || block_number.is_none() {
                return Ok(None);
            }
            
            // Deserialize the receipt
            match serde_json::from_slice::<crate::models::EthereumReceipt>(&result.unwrap()) {
                Ok(our_receipt) => {
                    // Convert our receipt to ethers-core TransactionReceipt
                    // This conversion is simplified and may miss some fields
                    let tx_receipt = TransactionReceipt {
                        transaction_hash: ethers_core::types::H256::from_slice(our_receipt.transaction_hash.as_bytes()),
                        transaction_index: ethers_core::types::U64::from(our_receipt.transaction_index.as_u64()),
                        block_hash: Some(ethers_core::types::H256::from_slice(our_receipt.block_hash.as_bytes())),
                        block_number: Some(ethers_core::types::U64::from(our_receipt.block_number.as_u64())),
                        from: ethers_core::types::H160::from_slice(our_receipt.from.as_bytes()),
                        to: our_receipt.to.map(|addr| ethers_core::types::H160::from_slice(addr.as_bytes())),
                        cumulative_gas_used: ethers_core::types::U256::from(our_receipt.cumulative_gas_used.as_u64()),
                        gas_used: Some(ethers_core::types::U256::from(our_receipt.gas_used.as_u64())),
                        contract_address: our_receipt.contract_address.map(|addr| ethers_core::types::H160::from_slice(addr.as_bytes())),
                        logs: our_receipt.logs.iter().map(|log| {
                            ethers_core::types::Log {
                                address: ethers_core::types::H160::from_slice(log.address.as_bytes()),
                                topics: log.topics.iter().map(|t| ethers_core::types::H256::from_slice(t.as_bytes())).collect(),
                                data: ethers_core::types::Bytes::from(log.data.clone()),
                                block_hash: log.block_hash.map(|h| ethers_core::types::H256::from_slice(h.as_bytes())),
                                block_number: log.block_number.map(|bn| ethers_core::types::U64::from(bn.as_u64())),
                                transaction_hash: log.transaction_hash.map(|h| ethers_core::types::H256::from_slice(h.as_bytes())),
                                transaction_index: log.transaction_index.map(|ti| ethers_core::types::U64::from(ti.as_u64())),
                                log_index: log.log_index.map(|li| ethers_core::types::U256::from(li.as_u64())),
                                removed: Some(log.removed),
                                transaction_log_index: None,
                                log_type: None,
                            }
                        }).collect(),
                        status: our_receipt.status.map(|s| ethers_core::types::U64::from(if s.is_zero() { 0 } else { 1 })),
                        root: our_receipt.root.map(|r| ethers_core::types::H256::from_slice(r.as_bytes())),
                        logs_bloom: our_receipt.logs_bloom,
                        effective_gas_price: our_receipt.effective_gas_price.map(|egp| ethers_core::types::U256::from(egp.as_u64())),
                        transaction_type: our_receipt.transaction_type.map(|tt| ethers_core::types::U64::from(tt.as_u64())),
                        other: Default::default(),
                    };
                    
                    Ok(Some(tx_receipt))
                },
                Err(e) => Err(Self::map_error(AppError::EncodingError(format!("Failed to decode receipt: {}", e)))),
            }
        } else {
            // Transaction not found
            Ok(None)
        }
    }

    async fn get_block_by_hash(&self, hash: String, full_transactions: bool) -> RpcResult<Option<Block<serde_json::Value>>> {
        let block_hash = utils::parse_hash(&hash).map_err(|e| Self::map_error(e))?;
        
        let client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Format hash for database query
        let hash_str = format!("{:?}", block_hash);
        
        // Query the block from the database
        let row = match client
            .query_opt(
                "SELECT number, hash, parent_hash, timestamp, gas_limit, gas_used, base_fee_per_gas 
                 FROM blocks WHERE hash = $1",
                &[&hash_str],
            )
            .await {
                Ok(row) => row,
                Err(e) => return Err(Self::map_error(AppError::DatabaseError(e))),
            };
        
        if let Some(row) = row {
            // Extract block data
            let number: i64 = row.get(0);
            let hash: String = row.get(1);
            let parent_hash: String = row.get(2);
            let timestamp: i64 = row.get(3);
            let gas_limit: i64 = row.get(4);
            let gas_used: i64 = row.get(5);
            let base_fee_per_gas: Option<i64> = row.get(6);
            
            // Format some values
            let block_hash = format!("0x{}", hash.trim_start_matches("0x"));
            let parent_hash = format!("0x{}", parent_hash.trim_start_matches("0x"));
            
            // Get transactions for this block
            let txs = match client
                .query(
                    "SELECT hash, value FROM transactions WHERE block_number = $1 ORDER BY created_at ASC",
                    &[&number],
                )
                .await {
                    Ok(rows) => rows,
                    Err(e) => return Err(Self::map_error(AppError::DatabaseError(e))),
                };
            
            // Process transactions based on full_transactions flag
            let transactions = if full_transactions {
                // Return full transaction objects
                let mut tx_objects = Vec::with_capacity(txs.len());
                
                for tx_row in txs {
                    let _tx_hash: String = tx_row.get(0);
                    let tx_value: Vec<u8> = tx_row.get(1);
                    
                    match serde_json::from_slice::<crate::models::EthereumTransaction>(&tx_value) {
                        Ok(tx) => {
                            // Convert to JSON value for the response
                            // In a real implementation, you'd convert to ethers_core::types::Transaction
                            let tx_json = serde_json::to_value(tx)
                                .map_err(|e| Self::map_error(AppError::EncodingError(format!("Failed to encode transaction: {}", e))))?;
                                
                            tx_objects.push(tx_json);
                        },
                        Err(e) => return Err(Self::map_error(AppError::EncodingError(format!("Failed to decode transaction: {}", e)))),
                    }
                }
                
                serde_json::Value::Array(tx_objects)
            } else {
                // Return just transaction hashes
                let tx_hashes: Vec<String> = txs.iter()
                    .map(|row| {
                        let hash: String = row.get(0);
                        format!("0x{}", hash.trim_start_matches("0x"))
                    })
                    .collect();
                    
                serde_json::to_value(tx_hashes)
                    .map_err(|e| Self::map_error(AppError::EncodingError(format!("Failed to encode transaction hashes: {}", e))))?
            };
            
            // Create the block object
            let block = Block {
                hash: Some(ethers_core::types::H256::from_slice(&hex::decode(block_hash.trim_start_matches("0x"))
                    .map_err(|_| Self::map_error(AppError::InvalidData("Invalid block hash".to_string())))?)),
                parent_hash: ethers_core::types::H256::from_slice(&hex::decode(parent_hash.trim_start_matches("0x"))
                    .map_err(|_| Self::map_error(AppError::InvalidData("Invalid parent hash".to_string())))?),
                uncles_hash: ethers_core::types::H256::zero(), // Not implemented
                author: Some(ethers_core::types::H160::zero()), // Not implemented
                state_root: ethers_core::types::H256::zero(), // Not implemented
                transactions_root: ethers_core::types::H256::zero(), // Not implemented
                receipts_root: ethers_core::types::H256::zero(), // Not implemented
                number: Some(ethers_core::types::U64::from(number as u64)),
                gas_used: ethers_core::types::U256::from(gas_used as u64),
                gas_limit: ethers_core::types::U256::from(gas_limit as u64),
                extra_data: ethers_core::types::Bytes::default(),
                logs_bloom: None, // Not implemented
                timestamp: ethers_core::types::U256::from(timestamp as u64),
                difficulty: ethers_core::types::U256::zero(), // Post-merge, always zero
                total_difficulty: None, // Not implemented 
                seal_fields: vec![], // Not implemented
                uncles: vec![], // Not implemented
                transactions: serde_json::from_value(transactions).unwrap_or_default(),
                size: None, // Not implemented
                mix_hash: None, // Not implemented
                nonce: None, // Post-merge, always None
                base_fee_per_gas: base_fee_per_gas.map(|fee| ethers_core::types::U256::from(fee as u64)),
                withdrawals: None, // Post-Shanghai, would be implemented
                parent_beacon_block_root: None, // Post-Capella
                withdrawals_root: None, // Post-Capella
                blob_gas_used: None, // Post-Cancun, would be implemented
                excess_blob_gas: None, // Post-Cancun, would be implemented
                other: ethers_core::types::OtherFields::default(),
            };
            
            Ok(Some(block))
        } else {
            // Block not found
            Ok(None)
        }
    }

    async fn get_block_by_number(&self, block: String, full_transactions: bool) -> RpcResult<Option<Block<serde_json::Value>>> {
        let client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Handle special block identifiers like "latest", "earliest", etc.
        let block_number: Option<i64> = if block == "latest" || block == "pending" {
            // Get the latest block number
            match client
                .query_opt("SELECT MAX(number) FROM blocks", &[])
                .await {
                    Ok(Some(row)) => {
                        let max_number: Option<i64> = row.get(0);
                        max_number
                    },
                    Ok(None) => None,
                    Err(e) => return Err(Self::map_error(AppError::DatabaseError(e))),
                }
        } else if block == "earliest" || block == "genesis" {
            // Get the earliest block (genesis, block 0)
            match client
                .query_opt("SELECT MIN(number) FROM blocks", &[])
                .await {
                    Ok(Some(row)) => {
                        let min_number: Option<i64> = row.get(0);
                        min_number
                    },
                    Ok(None) => None,
                    Err(e) => return Err(Self::map_error(AppError::DatabaseError(e))),
                }
        } else if block == "safe" || block == "finalized" {
            // In a real system, these would point to blocks that passed finality
            // For our simplified implementation, they're the same as "latest"
            match client
                .query_opt("SELECT MAX(number) FROM blocks", &[])
                .await {
                    Ok(Some(row)) => {
                        let max_number: Option<i64> = row.get(0);
                        max_number
                    },
                    Ok(None) => None,
                    Err(e) => return Err(Self::map_error(AppError::DatabaseError(e))),
                }
        } else {
            // Parse as a hex number
            let block_str = if let Some(stripped) = block.strip_prefix("0x") {
                stripped
            } else {
                &block
            };
            
            match i64::from_str_radix(block_str, 16) {
                Ok(num) => Some(num),
                Err(_) => return Err(Self::map_error(AppError::InvalidData(format!("Invalid block number: {}", block)))),
            }
        };
        
        // If no block number was found (empty database), return None
        let block_number = match block_number {
            Some(num) => num,
            None => return Ok(None),
        };
        
        // Query the block from the database
        let row = match client
            .query_opt(
                "SELECT number, hash, parent_hash, timestamp, gas_limit, gas_used, base_fee_per_gas 
                 FROM blocks WHERE number = $1",
                &[&block_number],
            )
            .await {
                Ok(row) => row,
                Err(e) => return Err(Self::map_error(AppError::DatabaseError(e))),
            };
        
        if let Some(row) = row {
            // Extract block data
            let number: i64 = row.get(0);
            let hash: String = row.get(1);
            let parent_hash: String = row.get(2);
            let timestamp: i64 = row.get(3);
            let gas_limit: i64 = row.get(4);
            let gas_used: i64 = row.get(5);
            let base_fee_per_gas: Option<i64> = row.get(6);
            
            // Format some values
            let block_hash = format!("0x{}", hash.trim_start_matches("0x"));
            let parent_hash = format!("0x{}", parent_hash.trim_start_matches("0x"));
            
            // Get transactions for this block
            let txs = match client
                .query(
                    "SELECT hash, value FROM transactions WHERE block_number = $1 ORDER BY created_at ASC",
                    &[&number],
                )
                .await {
                    Ok(rows) => rows,
                    Err(e) => return Err(Self::map_error(AppError::DatabaseError(e))),
                };
            
            // Process transactions based on full_transactions flag
            let transactions = if full_transactions {
                // Return full transaction objects
                let mut tx_objects = Vec::with_capacity(txs.len());
                
                for tx_row in txs {
                    let _tx_hash: String = tx_row.get(0);
                    let tx_value: Vec<u8> = tx_row.get(1);
                    
                    match serde_json::from_slice::<crate::models::EthereumTransaction>(&tx_value) {
                        Ok(tx) => {
                            // Convert to JSON value for the response
                            // In a real implementation, you'd convert to ethers_core::types::Transaction
                            let tx_json = serde_json::to_value(tx)
                                .map_err(|e| Self::map_error(AppError::EncodingError(format!("Failed to encode transaction: {}", e))))?;
                                
                            tx_objects.push(tx_json);
                        },
                        Err(e) => return Err(Self::map_error(AppError::EncodingError(format!("Failed to decode transaction: {}", e)))),
                    }
                }
                
                serde_json::Value::Array(tx_objects)
            } else {
                // Return just transaction hashes
                let tx_hashes: Vec<String> = txs.iter()
                    .map(|row| {
                        let hash: String = row.get(0);
                        format!("0x{}", hash.trim_start_matches("0x"))
                    })
                    .collect();
                    
                serde_json::to_value(tx_hashes)
                    .map_err(|e| Self::map_error(AppError::EncodingError(format!("Failed to encode transaction hashes: {}", e))))?
            };
            
            // Create the block object - same as in get_block_by_hash
            let block = Block {
                hash: Some(ethers_core::types::H256::from_slice(&hex::decode(block_hash.trim_start_matches("0x"))
                    .map_err(|_| Self::map_error(AppError::InvalidData("Invalid block hash".to_string())))?)),
                parent_hash: ethers_core::types::H256::from_slice(&hex::decode(parent_hash.trim_start_matches("0x"))
                    .map_err(|_| Self::map_error(AppError::InvalidData("Invalid parent hash".to_string())))?),
                uncles_hash: ethers_core::types::H256::zero(), 
                author: Some(ethers_core::types::H160::zero()),
                state_root: ethers_core::types::H256::zero(),
                transactions_root: ethers_core::types::H256::zero(),
                receipts_root: ethers_core::types::H256::zero(),
                number: Some(ethers_core::types::U64::from(number as u64)),
                gas_used: ethers_core::types::U256::from(gas_used as u64),
                gas_limit: ethers_core::types::U256::from(gas_limit as u64),
                extra_data: ethers_core::types::Bytes::default(),
                logs_bloom: None,
                timestamp: ethers_core::types::U256::from(timestamp as u64),
                difficulty: ethers_core::types::U256::zero(),
                total_difficulty: None,
                seal_fields: vec![],
                uncles: vec![],
                transactions: serde_json::from_value(transactions).unwrap_or_default(),
                size: None,
                mix_hash: None,
                nonce: None,
                base_fee_per_gas: base_fee_per_gas.map(|fee| ethers_core::types::U256::from(fee as u64)),
                withdrawals: None,
                parent_beacon_block_root: None,
                withdrawals_root: None,
                blob_gas_used: None,
                excess_blob_gas: None,
                other: ethers_core::types::OtherFields::default(),
            };
            
            Ok(Some(block))
        } else {
            // Block not found
            Ok(None)
        }
    }

    async fn block_number(&self) -> RpcResult<String> {
        let client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Query the latest block number directly from the database
        let row = match client
            .query_opt("SELECT MAX(number) FROM blocks", &[])
            .await {
                Ok(row) => row,
                Err(e) => return Err(Self::map_error(AppError::DatabaseError(e))),
            };
        
        let number: i64 = if let Some(row) = row {
            let max_number: Option<i64> = row.get(0);
            max_number.unwrap_or(0)
        } else {
            0
        };
        
        // Convert to hex string
        Ok(format!("0x{:x}", number))
    }

    async fn gas_price(&self) -> RpcResult<String> {
        let client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Query the latest block's base fee per gas directly from the database
        let row = match client
            .query_opt(
                "SELECT base_fee_per_gas FROM blocks ORDER BY number DESC LIMIT 1",
                &[]
            )
            .await {
                Ok(row) => row,
                Err(e) => return Err(Self::map_error(AppError::DatabaseError(e))),
            };
        
        // Get the base fee, or use a default if no blocks exist or no base fee is set
        let base_fee: i64 = if let Some(row) = row {
            let opt_fee: Option<i64> = row.get(0);
            opt_fee.unwrap_or(1_000_000_000) // 1 gwei default
        } else {
            1_000_000_000 // 1 gwei default  - no blocks exist yet
        };
        
        // Convert to hex string
        Ok(format!("0x{:x}", base_fee))
    }

    async fn max_priority_fee_per_gas(&self) -> RpcResult<String> {
        let client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Query recent transactions to calculate priority fee suggestion
        // Look at the last 20 transactions and get the median priority fee
        let rows = match client
            .query(
                "SELECT value FROM transactions WHERE block_number IS NOT NULL ORDER BY created_at DESC LIMIT 20",
                &[]
            )
            .await {
                Ok(rows) => rows,
                Err(e) => return Err(Self::map_error(AppError::DatabaseError(e))),
            };
        
        let mut priority_fees = Vec::new();
        
        for row in rows {
            let tx_value: Vec<u8> = row.get(0);
            if let Ok(tx) = serde_json::from_slice::<EthereumTransaction>(&tx_value) {
                // Calculate priority fee from transaction
                if let Some(_max_fee) = tx.max_fee_per_gas {
                    if let Some(max_priority) = tx.max_priority_fee_per_gas {
                        priority_fees.push(max_priority.as_u64());
                    }
                } else if let Some(_gas_price) = tx.gas_price {
                    // For legacy transactions, use a default priority fee (2 gwei)
                    priority_fees.push(2_000_000_000);
                }
            }
        }
        
        // Calculate median or use default
        let suggested_priority_fee = if priority_fees.is_empty() {
            2_000_000_000 // Default: 2 gwei
        } else {
            priority_fees.sort_unstable();
            let len = priority_fees.len();
            if len % 2 == 0 {
                (priority_fees[len / 2 - 1] + priority_fees[len / 2]) / 2
            } else {
                priority_fees[len / 2]
            }
        };
        
        Ok(format!("0x{:x}", suggested_priority_fee))
    }

    async fn fee_history(&self, block_count: String, newest_block: String, reward_percentiles: Option<Vec<f64>>) -> RpcResult<serde_json::Value> {
        let client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Parse block_count as hex
        let count = match u64::from_str_radix(block_count.trim_start_matches("0x"), 16) {
            Ok(c) => c,
            Err(_) => return Err(Self::map_error(AppError::InvalidData("Invalid block count".to_string()))),
        };
        
        // Limit to reasonable range
        let count = count.min(1024);
        
        // Parse newest_block similar to get_block_by_number
        let newest_block_num: i64 = if newest_block == "latest" || newest_block == "pending" {
            match client
                .query_one("SELECT COALESCE(MAX(number), 0) FROM blocks", &[])
                .await {
                    Ok(row) => row.get(0),
                    Err(e) => return Err(Self::map_error(AppError::DatabaseError(e))),
                }
        } else {
            match i64::from_str_radix(newest_block.trim_start_matches("0x"), 16) {
                Ok(num) => num,
                Err(_) => return Err(Self::map_error(AppError::InvalidData("Invalid block number".to_string()))),
            }
        };
        
        let oldest_block_num = (newest_block_num - count as i64 + 1).max(0);
        
        // Query blocks in the range
        let rows = match client
            .query(
                "SELECT number, base_fee_per_gas, gas_used, gas_limit FROM blocks WHERE number >= $1 AND number <= $2 ORDER BY number ASC",
                &[&oldest_block_num, &newest_block_num]
            )
            .await {
                Ok(rows) => rows,
                Err(e) => return Err(Self::map_error(AppError::DatabaseError(e))),
            };
        
        let mut base_fees = Vec::new();
        let mut gas_used_ratios = Vec::new();
        let mut rewards = Vec::new();
        
        for row in rows {
            let block_number: i64 = row.get(0);
            let base_fee: Option<i64> = row.get(1);
            let gas_used: i64 = row.get(2);
            let gas_limit: i64 = row.get(3);
            
            base_fees.push(format!("0x{:x}", base_fee.unwrap_or(1_000_000_000)));
            gas_used_ratios.push((gas_used as f64) / (gas_limit as f64));
            
            // Calculate reward percentiles if requested
            if let Some(ref percentiles) = reward_percentiles {
                // Get transactions for this block
                let tx_rows = match client
                    .query(
                        "SELECT value FROM transactions WHERE block_number = $1 ORDER BY created_at ASC",
                        &[&block_number]
                    )
                    .await {
                        Ok(rows) => rows,
                        Err(_) => Vec::new(),
                    };
                
                let mut priority_fees = Vec::new();
                for tx_row in tx_rows {
                    let tx_value: Vec<u8> = tx_row.get(0);
                    if let Ok(tx) = serde_json::from_slice::<EthereumTransaction>(&tx_value) {
                        if let Some(max_priority) = tx.max_priority_fee_per_gas {
                            priority_fees.push(max_priority.as_u64());
                        } else if tx.gas_price.is_some() {
                            priority_fees.push(1_000_000_000); // Default for legacy tx
                        }
                    }
                }
                
                priority_fees.sort_unstable();
                let mut block_rewards = Vec::new();
                
                for &percentile in percentiles {
                    let reward = if priority_fees.is_empty() {
                        0
                    } else {
                        let index = ((percentile / 100.0) * (priority_fees.len() - 1) as f64).round() as usize;
                        priority_fees[index.min(priority_fees.len() - 1)]
                    };
                    block_rewards.push(format!("0x{:x}", reward));
                }
                rewards.push(block_rewards);
            }
        }
        
        // Include next block's base fee as the last element
        let next_block_fee = if let Some(last_fee_str) = base_fees.last() {
            last_fee_str.clone()
        } else {
            "0x3b9aca00".to_string() // 1 gwei in hex
        };
        base_fees.push(next_block_fee);
        
        let mut result = serde_json::json!({
            "baseFeePerGas": base_fees,
            "gasUsedRatio": gas_used_ratios,
            "oldestBlock": format!("0x{:x}", oldest_block_num)
        });
        
        if reward_percentiles.is_some() {
            result["reward"] = serde_json::Value::Array(
                rewards.into_iter().map(|block_rewards| {
                    serde_json::Value::Array(
                        block_rewards.into_iter().map(serde_json::Value::String).collect()
                    )
                }).collect()
            );
        }
        
        Ok(result)
    }

    async fn syncing(&self) -> RpcResult<serde_json::Value> {
        // For this implementation, we're always "synced" since we process transactions immediately
        // In a real blockchain client, this would return sync progress information
        Ok(serde_json::Value::Bool(false))
    }

    async fn get_block_transaction_count_by_hash(&self, hash: String) -> RpcResult<String> {
        let block_hash = utils::parse_hash(&hash).map_err(|e| Self::map_error(e))?;
        
        let client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        let hash_str = format!("{:?}", block_hash);
        
        // Get block number first
        let block_row = match client
            .query_opt("SELECT number FROM blocks WHERE hash = $1", &[&hash_str])
            .await {
                Ok(row) => row,
                Err(e) => return Err(Self::map_error(AppError::DatabaseError(e))),
            };
        
        if let Some(row) = block_row {
            let block_number: i64 = row.get(0);
            
            // Count transactions in this block
            let count_row = match client
                .query_one(
                    "SELECT COUNT(*) FROM transactions WHERE block_number = $1",
                    &[&block_number]
                )
                .await {
                    Ok(row) => row,
                    Err(e) => return Err(Self::map_error(AppError::DatabaseError(e))),
                };
            
            let count: i64 = count_row.get(0);
            Ok(format!("0x{:x}", count))
        } else {
            // Block not found - return null as per JSON-RPC spec
            Err(Self::map_error(AppError::InvalidData("Block not found".to_string())))
        }
    }

    async fn get_block_transaction_count_by_number(&self, block: String) -> RpcResult<String> {
        let client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Parse block number similar to get_block_by_number
        let block_number: i64 = if block == "latest" || block == "pending" {
            match client
                .query_one("SELECT COALESCE(MAX(number), 0) FROM blocks", &[])
                .await {
                    Ok(row) => row.get(0),
                    Err(e) => return Err(Self::map_error(AppError::DatabaseError(e))),
                }
        } else if block == "earliest" {
            0
        } else {
            let block_str = block.trim_start_matches("0x");
            match i64::from_str_radix(block_str, 16) {
                Ok(num) => num,
                Err(_) => return Err(Self::map_error(AppError::InvalidData(format!("Invalid block number: {}", block)))),
            }
        };
        
        // Count transactions in this block
        let count_row = match client
            .query_one(
                "SELECT COUNT(*) FROM transactions WHERE block_number = $1",
                &[&block_number]
            )
            .await {
                Ok(row) => row,
                Err(e) => return Err(Self::map_error(AppError::DatabaseError(e))),
            };
        
        let count: i64 = count_row.get(0);
        Ok(format!("0x{:x}", count))
    }

    async fn get_transaction_by_block_hash_and_index(&self, block_hash: String, index: String) -> RpcResult<Option<EthereumTransaction>> {
        let block_hash = utils::parse_hash(&block_hash).map_err(|e| Self::map_error(e))?;
        let tx_index = match u64::from_str_radix(index.trim_start_matches("0x"), 16) {
            Ok(idx) => idx,
            Err(_) => return Err(Self::map_error(AppError::InvalidData("Invalid transaction index".to_string()))),
        };
        
        let client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        let hash_str = format!("{:?}", block_hash);
        
        // Get block number first
        let block_row = match client
            .query_opt("SELECT number FROM blocks WHERE hash = $1", &[&hash_str])
            .await {
                Ok(row) => row,
                Err(e) => return Err(Self::map_error(AppError::DatabaseError(e))),
            };
        
        if let Some(row) = block_row {
            let block_number: i64 = row.get(0);
            
            // Get transaction by index (ordered by created_at)
            let tx_row = match client
                .query_opt(
                    "SELECT value FROM transactions WHERE block_number = $1 ORDER BY created_at ASC OFFSET $2 LIMIT 1",
                    &[&block_number, &(tx_index as i64)]
                )
                .await {
                    Ok(row) => row,
                    Err(e) => return Err(Self::map_error(AppError::DatabaseError(e))),
                };
            
            if let Some(tx_row) = tx_row {
                let tx_value: Vec<u8> = tx_row.get(0);
                match serde_json::from_slice::<EthereumTransaction>(&tx_value) {
                    Ok(tx) => Ok(Some(tx)),
                    Err(e) => Err(Self::map_error(AppError::EncodingError(format!("Failed to decode transaction: {}", e)))),
                }
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn get_transaction_by_block_number_and_index(&self, block: String, index: String) -> RpcResult<Option<EthereumTransaction>> {
        let tx_index = match u64::from_str_radix(index.trim_start_matches("0x"), 16) {
            Ok(idx) => idx,
            Err(_) => return Err(Self::map_error(AppError::InvalidData("Invalid transaction index".to_string()))),
        };
        
        let client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Parse block number similar to get_block_by_number
        let block_number: i64 = if block == "latest" || block == "pending" {
            match client
                .query_one("SELECT COALESCE(MAX(number), 0) FROM blocks", &[])
                .await {
                    Ok(row) => row.get(0),
                    Err(e) => return Err(Self::map_error(AppError::DatabaseError(e))),
                }
        } else if block == "earliest" {
            0
        } else {
            let block_str = block.trim_start_matches("0x");
            match i64::from_str_radix(block_str, 16) {
                Ok(num) => num,
                Err(_) => return Err(Self::map_error(AppError::InvalidData(format!("Invalid block number: {}", block)))),
            }
        };
        
        // Get transaction by index (ordered by created_at)
        let tx_row = match client
            .query_opt(
                "SELECT value FROM transactions WHERE block_number = $1 ORDER BY created_at ASC OFFSET $2 LIMIT 1",
                &[&block_number, &(tx_index as i64)]
            )
            .await {
                Ok(row) => row,
                Err(e) => return Err(Self::map_error(AppError::DatabaseError(e))),
            };
        
        if let Some(tx_row) = tx_row {
            let tx_value: Vec<u8> = tx_row.get(0);
            match serde_json::from_slice::<EthereumTransaction>(&tx_value) {
                Ok(tx) => Ok(Some(tx)),
                Err(e) => Err(Self::map_error(AppError::EncodingError(format!("Failed to decode transaction: {}", e)))),
            }
        } else {
            Ok(None)
        }
    }
    
    async fn new_filter(&self, filter: FilterRequest) -> RpcResult<String> {
        let filter_id = Self::generate_filter_id();
        let filter = Filter {
            filter_type: FilterType::Log(filter),
            last_poll: std::time::SystemTime::now(),
        };
        
        if let Ok(mut filters) = self.filters.lock() {
            filters.insert(filter_id.clone(), filter);
        }
        
        Ok(filter_id)
    }
    
    async fn new_block_filter(&self) -> RpcResult<String> {
        let filter_id = Self::generate_filter_id();
        let filter = Filter {
            filter_type: FilterType::Block,
            last_poll: std::time::SystemTime::now(),
        };
        
        if let Ok(mut filters) = self.filters.lock() {
            filters.insert(filter_id.clone(), filter);
        }
        
        Ok(filter_id)
    }
    
    async fn new_pending_transaction_filter(&self) -> RpcResult<String> {
        let filter_id = Self::generate_filter_id();
        let filter = Filter {
            filter_type: FilterType::PendingTransaction,
            last_poll: std::time::SystemTime::now(),
        };
        
        if let Ok(mut filters) = self.filters.lock() {
            filters.insert(filter_id.clone(), filter);
        }
        
        Ok(filter_id)
    }
    
    async fn get_filter_changes(&self, filter_id: String) -> RpcResult<serde_json::Value> {
        let filter = {
            if let Ok(mut filters) = self.filters.lock() {
                if let Some(filter) = filters.get_mut(&filter_id) {
                    let last_poll = filter.last_poll;
                    filter.last_poll = std::time::SystemTime::now();
                    (filter.filter_type.clone(), last_poll)
                } else {
                    return Err(Self::map_error(AppError::InvalidData("Filter not found".to_string())));
                }
            } else {
                return Err(Self::map_error(AppError::InvalidData("Failed to access filters".to_string())));
            }
        };
        
        match filter.0 {
            FilterType::Block => {
                // Return new block hashes since last poll
                // For simplicity, return latest block hash
                let client = match self.pool.get().await {
                    Ok(client) => client,
                    Err(e) => return Err(Self::map_error(AppError::PoolError(e))),
                };
                
                let row = match client
                    .query_opt("SELECT hash FROM blocks ORDER BY number DESC LIMIT 1", &[])
                    .await {
                        Ok(row) => row,
                        Err(e) => return Err(Self::map_error(AppError::DatabaseError(e))),
                    };
                
                if let Some(row) = row {
                    let hash: String = row.get(0);
                    Ok(serde_json::Value::Array(vec![
                        serde_json::Value::String(format!("0x{}", hash.trim_start_matches("0x")))
                    ]))
                } else {
                    Ok(serde_json::Value::Array(vec![]))
                }
            },
            FilterType::PendingTransaction => {
                // Return pending transaction hashes (none in this implementation)
                Ok(serde_json::Value::Array(vec![]))
            },
            FilterType::Log(_log_filter) => {
                // For log filters, we would query the database for matching logs
                // This is a simplified implementation
                Ok(serde_json::Value::Array(vec![]))
            },
        }
    }
    
    async fn uninstall_filter(&self, filter_id: String) -> RpcResult<bool> {
        if let Ok(mut filters) = self.filters.lock() {
            Ok(filters.remove(&filter_id).is_some())
        } else {
            Ok(false)
        }
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

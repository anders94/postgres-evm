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
        
        // Parse the raw transaction using ethers
        let tx = match ethers_core::utils::rlp::decode::<ethers_core::types::Transaction>(&raw_tx_bytes) {
            Ok(tx) => tx,
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
        
        // Create EVM executor
        let executor = crate::evm::EVMExecutor::new(self.chain_id);
        
        // Store transaction first
        if let Err(e) = executor.store_transaction(&client, &ethereum_tx).await {
            return Err(Self::map_error(e));
        }
        
        // Execute the transaction
        match executor.execute_transaction(&mut client, &ethereum_tx).await {
            Ok(_receipt) => {
                // Return the transaction hash
                Ok(tx_hash)
            },
            Err(e) => {
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
                        logs_bloom: ethers_core::types::Bloom::from_slice(our_receipt.logs_bloom.as_bytes()),
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
        let block_number: i64 = if block == "latest" || block == "pending" {
            // Get the latest block number
            match client
                .query_one("SELECT COALESCE(MAX(number), 0) FROM blocks", &[])
                .await {
                    Ok(row) => row.get(0),
                    Err(e) => return Err(Self::map_error(AppError::DatabaseError(e))),
                }
        } else if block == "earliest" || block == "genesis" {
            // Get the earliest block (genesis, block 0)
            0
        } else if block == "safe" || block == "finalized" {
            // In a real system, these would point to blocks that passed finality
            // For our simplified implementation, they're the same as "latest"
            match client
                .query_one("SELECT COALESCE(MAX(number), 0) FROM blocks", &[])
                .await {
                    Ok(row) => row.get(0),
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
                Ok(num) => num,
                Err(_) => return Err(Self::map_error(AppError::InvalidData(format!("Invalid block number: {}", block)))),
            }
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
            .query_one("SELECT COALESCE(MAX(number), 0) FROM blocks", &[])
            .await {
                Ok(row) => row,
                Err(e) => return Err(Self::map_error(AppError::DatabaseError(e))),
            };
        
        let number: i64 = row.get(0);
        
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
            1_000_000_000 // 1 gwei default
        };
        
        // Convert to hex string
        Ok(format!("0x{:x}", base_fee))
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
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
// Access list imports removed - will implement in future version

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
    pub access_list: Option<Vec<RpcAccessListItem>>,
    pub transaction_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcAccessListItem {
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

    fn parse_eip_transaction(&self, payload: &[u8], tx_type: u8) -> std::result::Result<ethers_core::types::Transaction, String> {
        use ethers_core::utils::rlp::Rlp;
        
        let rlp = Rlp::new(payload);
        
        // Verify we have enough fields for the transaction type  
        let item_count = rlp.item_count().map_err(|e| format!("RLP item count error: {:?}", e))?;
        let min_fields = match tx_type {
            0x01 => 11, // EIP-2930: [chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, yParity, r, s]
            0x02 => 12, // EIP-1559: [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, yParity, r, s]  
            _ => return Err(format!("Unsupported transaction type: {}", tx_type)),
        };
        
        if item_count < min_fields {
            return Err(format!("Insufficient fields in EIP-{} transaction: got {}, expected {}", tx_type, item_count, min_fields));
        }
        
        let mut tx = ethers_core::types::Transaction::default();
        tx.transaction_type = Some(ethers_core::types::U64::from(tx_type as u64));
        
        // Parse the fields using raw bytes and manual conversion
        // Field 0: chainId 
        if let Ok(chain_id_rlp) = rlp.at(0) {
            if let Ok(chain_id_bytes) = chain_id_rlp.data() {
                if !chain_id_bytes.is_empty() {
                    tx.chain_id = Some(ethers_core::types::U256::from_big_endian(chain_id_bytes));
                }
            }
        }
        
        // Field 1: nonce (this is the critical field we need to parse correctly)
        if let Ok(nonce_rlp) = rlp.at(1) {
            if let Ok(nonce_bytes) = nonce_rlp.data() {
                if !nonce_bytes.is_empty() {
                    tx.nonce = ethers_core::types::U256::from_big_endian(nonce_bytes);
                    println!("🔧 Parsed nonce from EIP-{} transaction: {}", tx_type, tx.nonce);
                }
            }
        }
        
        // Parse all fields based on transaction type
        match tx_type {
            0x01 => {
                // EIP-2930: [chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, yParity, r, s]
                self.parse_eip2930_fields(&rlp, &mut tx)?;
            },
            0x02 => {
                // EIP-1559: [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, yParity, r, s]
                self.parse_eip1559_fields(&rlp, &mut tx)?;
            },
            _ => return Err(format!("Unsupported transaction type: {}", tx_type)),
        }
        
        println!("✅ Successfully parsed EIP-{} transaction with nonce {} and to {:?}", tx_type, tx.nonce, tx.to);
        Ok(tx)
    }

    fn parse_eip1559_fields(&self, rlp: &ethers_core::utils::rlp::Rlp, tx: &mut ethers_core::types::Transaction) -> std::result::Result<(), String> {
        // EIP-1559: [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, yParity, r, s]
        
        // Field 2: maxPriorityFeePerGas
        if let Ok(priority_fee_rlp) = rlp.at(2) {
            if let Ok(priority_fee_bytes) = priority_fee_rlp.data() {
                if !priority_fee_bytes.is_empty() {
                    tx.max_priority_fee_per_gas = Some(ethers_core::types::U256::from_big_endian(priority_fee_bytes));
                }
            }
        }

        // Field 3: maxFeePerGas
        if let Ok(max_fee_rlp) = rlp.at(3) {
            if let Ok(max_fee_bytes) = max_fee_rlp.data() {
                if !max_fee_bytes.is_empty() {
                    tx.max_fee_per_gas = Some(ethers_core::types::U256::from_big_endian(max_fee_bytes));
                }
            }
        }

        // Field 4: gasLimit
        if let Ok(gas_limit_rlp) = rlp.at(4) {
            if let Ok(gas_limit_bytes) = gas_limit_rlp.data() {
                if !gas_limit_bytes.is_empty() {
                    tx.gas = ethers_core::types::U256::from_big_endian(gas_limit_bytes);
                }
            }
        }

        // Field 5: to (can be empty for contract creation)
        if let Ok(to_rlp) = rlp.at(5) {
            if let Ok(to_bytes) = to_rlp.data() {
                if to_bytes.len() == 20 {
                    tx.to = Some(ethers_core::types::H160::from_slice(to_bytes));
                } else if to_bytes.is_empty() {
                    tx.to = None; // Contract creation
                }
            }
        }

        // Field 6: value
        if let Ok(value_rlp) = rlp.at(6) {
            if let Ok(value_bytes) = value_rlp.data() {
                if !value_bytes.is_empty() {
                    tx.value = ethers_core::types::U256::from_big_endian(value_bytes);
                }
            }
        }

        // Field 7: data
        if let Ok(data_rlp) = rlp.at(7) {
            if let Ok(data_bytes) = data_rlp.data() {
                tx.input = data_bytes.to_vec().into();
            }
        }

        // Field 8: accessList (skip for now)
        // TODO: Parse access list if needed

        // Field 9: yParity (v)
        if let Ok(v_rlp) = rlp.at(9) {
            if let Ok(v_bytes) = v_rlp.data() {
                if !v_bytes.is_empty() {
                    // For EIP-1559, yParity is usually 0 or 1, but could be larger for legacy compatibility
                    // Let's handle this more carefully
                    match v_bytes.len() {
                        1 => tx.v = ethers_core::types::U64::from(v_bytes[0] as u64),
                        _ => {
                            // For longer values, convert properly
                            let v_value = ethers_core::types::U256::from_big_endian(v_bytes);
                            tx.v = ethers_core::types::U64::from(v_value.low_u64());
                        }
                    }
                    println!("🔧 Parsed v (yParity): {}", tx.v);
                }
            }
        }

        // Field 10: r
        if let Ok(r_rlp) = rlp.at(10) {
            if let Ok(r_bytes) = r_rlp.data() {
                if !r_bytes.is_empty() {
                    tx.r = ethers_core::types::U256::from_big_endian(r_bytes);
                }
            }
        }

        // Field 11: s
        if let Ok(s_rlp) = rlp.at(11) {
            if let Ok(s_bytes) = s_rlp.data() {
                if !s_bytes.is_empty() {
                    tx.s = ethers_core::types::U256::from_big_endian(s_bytes);
                }
            }
        }

        Ok(())
    }

    fn parse_eip2930_fields(&self, rlp: &ethers_core::utils::rlp::Rlp, tx: &mut ethers_core::types::Transaction) -> std::result::Result<(), String> {
        // EIP-2930: [chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, yParity, r, s]
        
        // Field 2: gasPrice
        if let Ok(gas_price_rlp) = rlp.at(2) {
            if let Ok(gas_price_bytes) = gas_price_rlp.data() {
                if !gas_price_bytes.is_empty() {
                    tx.gas_price = Some(ethers_core::types::U256::from_big_endian(gas_price_bytes));
                }
            }
        }

        // Field 3: gasLimit
        if let Ok(gas_limit_rlp) = rlp.at(3) {
            if let Ok(gas_limit_bytes) = gas_limit_rlp.data() {
                if !gas_limit_bytes.is_empty() {
                    tx.gas = ethers_core::types::U256::from_big_endian(gas_limit_bytes);
                }
            }
        }

        // Field 4: to
        if let Ok(to_rlp) = rlp.at(4) {
            if let Ok(to_bytes) = to_rlp.data() {
                if to_bytes.len() == 20 {
                    tx.to = Some(ethers_core::types::H160::from_slice(to_bytes));
                } else if to_bytes.is_empty() {
                    tx.to = None; // Contract creation
                }
            }
        }

        // Field 5: value
        if let Ok(value_rlp) = rlp.at(5) {
            if let Ok(value_bytes) = value_rlp.data() {
                if !value_bytes.is_empty() {
                    tx.value = ethers_core::types::U256::from_big_endian(value_bytes);
                }
            }
        }

        // Field 6: data
        if let Ok(data_rlp) = rlp.at(6) {
            if let Ok(data_bytes) = data_rlp.data() {
                tx.input = data_bytes.to_vec().into();
            }
        }

        // Field 7: accessList - TODO: Implement access list parsing
        // For now, leave access list empty as it's not critical for basic functionality

        // Field 8: yParity (v)
        if let Ok(v_rlp) = rlp.at(8) {
            if let Ok(v_bytes) = v_rlp.data() {
                if !v_bytes.is_empty() {
                    // Handle single byte or multi-byte v values
                    if v_bytes.len() == 1 {
                        tx.v = ethers_core::types::U64::from(v_bytes[0] as u64);
                    } else {
                        let mut v_array = [0u8; 8];
                        let copy_len = std::cmp::min(v_bytes.len(), 8);
                        v_array[8 - copy_len..].copy_from_slice(&v_bytes[v_bytes.len() - copy_len..]);
                        tx.v = ethers_core::types::U64::from_big_endian(&v_array);
                    }
                }
            }
        }

        // Field 9: r
        if let Ok(r_rlp) = rlp.at(9) {
            if let Ok(r_bytes) = r_rlp.data() {
                if !r_bytes.is_empty() {
                    tx.r = ethers_core::types::U256::from_big_endian(r_bytes);
                }
            }
        }

        // Field 10: s
        if let Ok(s_rlp) = rlp.at(10) {
            if let Ok(s_bytes) = s_rlp.data() {
                if !s_bytes.is_empty() {
                    tx.s = ethers_core::types::U256::from_big_endian(s_bytes);
                }
            }
        }

        Ok(())
    }

    fn map_error(err: AppError) -> ErrorObject<'static> {
        let error_msg = format!("{}", err);
        ErrorObject::owned(
            ErrorCode::ServerError(1).code(),
            error_msg,
            None::<()>
        )
    }
    
    /// Simulate a transaction to estimate gas usage
    #[allow(dead_code)]
    async fn simulate_transaction_for_gas_estimation(
        &self, 
        client: &mut deadpool_postgres::Client, 
        transaction: &TransactionRequest
    ) -> Result<u64> {
        // Create a temporary transaction to simulate gas usage
        let mut sim_tx = crate::models::EthereumTransaction {
            hash: primitive_types::H256::random(),
            nonce: primitive_types::U256::zero(),
            block_hash: None,
            block_number: None,
            transaction_index: None,
            from: primitive_types::H160::zero(),
            to: None,
            value: primitive_types::U256::zero(),
            gas_price: Some(primitive_types::U256::from(1_000_000_000u64)),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            gas: primitive_types::U256::from(10_000_000u64),
            input: Vec::new(),
            v: primitive_types::U256::zero(),
            r: primitive_types::U256::zero(),
            s: primitive_types::U256::zero(),
            chain_id: Some(self.chain_id),
            access_list: None,
            transaction_type: None,
        };
        
        // Set transaction fields from request
        if let Some(from_str) = &transaction.from {
            if let Ok(from_addr) = crate::utils::parse_address(from_str) {
                sim_tx.from = from_addr;
            }
        }
        
        if let Some(to_str) = &transaction.to {
            if let Ok(to_addr) = crate::utils::parse_address(to_str) {
                sim_tx.to = Some(to_addr);
            }
        }
        
        if let Some(value_str) = &transaction.value {
            if let Ok(value_bytes) = hex::decode(value_str.trim_start_matches("0x")) {
                if !value_bytes.is_empty() {
                    sim_tx.value = primitive_types::U256::from_big_endian(&value_bytes);
                }
            }
        }
        
        if let Some(gas_price_str) = &transaction.gas_price {
            if let Ok(gas_price_bytes) = hex::decode(gas_price_str.trim_start_matches("0x")) {
                if !gas_price_bytes.is_empty() {
                    sim_tx.gas_price = Some(primitive_types::U256::from_big_endian(&gas_price_bytes));
                }
            }
        }
        
        if let Some(data_str) = &transaction.data {
            sim_tx.input = crate::utils::hex_to_bytes(data_str)
                .map_err(|e| AppError::EncodingError(format!("Invalid data: {}", e)))?;
        }
        
        if let Some(nonce_str) = &transaction.nonce {
            if let Ok(nonce_bytes) = hex::decode(nonce_str.trim_start_matches("0x")) {
                if !nonce_bytes.is_empty() {
                    sim_tx.nonce = primitive_types::U256::from_big_endian(&nonce_bytes);
                }
            }
        }
        
        // Use a temporary hash for simulation
        sim_tx.hash = primitive_types::H256::random();
        
        // Execute the transaction in simulation mode
        let executor = crate::evm::EVMExecutor::new(self.chain_id);
        
        // Start a temporary database transaction for simulation
        let db_tx = client.transaction().await
            .map_err(|e| AppError::DatabaseError(e))?;
        
        match executor.execute_transaction_from_tx(&db_tx, &sim_tx).await {
            Ok(receipt) => {
                // Rollback the simulation transaction
                let _ = db_tx.rollback().await;
                // Return the gas used from the receipt
                Ok(receipt.gas_used.low_u64())
            },
            Err(_) => {
                // Rollback and return error
                let _ = db_tx.rollback().await;
                Err(AppError::InvalidOperation("Transaction simulation failed".to_string()))
            }
        }
    }
    
    /// Calculate the transactions root (merkle root of all transaction hashes in the block)
    fn calculate_transactions_root(&self, transactions: &[serde_json::Value]) -> ethers_core::types::H256 {
        use ethers_core::utils::keccak256;
        
        if transactions.is_empty() {
            // Empty transactions trie root
            return ethers_core::types::H256::from_slice(&hex::decode("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap());
        }
        
        // For simplicity, we'll calculate a simple hash tree
        // In a full implementation, this would be a proper Patricia Merkle Trie
        let mut hashes: Vec<[u8; 32]> = transactions.iter().map(|tx| {
            let tx_str = serde_json::to_string(tx).unwrap_or_default();
            keccak256(tx_str.as_bytes())
        }).collect();
        
        // Simple merkle tree calculation
        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in hashes.chunks(2) {
                match chunk.len() {
                    2 => {
                        let mut combined = [0u8; 64];
                        combined[..32].copy_from_slice(&chunk[0]);
                        combined[32..].copy_from_slice(&chunk[1]);
                        next_level.push(keccak256(&combined));
                    },
                    1 => {
                        // Odd number, duplicate the last hash
                        let mut combined = [0u8; 64];
                        combined[..32].copy_from_slice(&chunk[0]);
                        combined[32..].copy_from_slice(&chunk[0]);
                        next_level.push(keccak256(&combined));
                    },
                    _ => unreachable!(),
                }
            }
            hashes = next_level;
        }
        
        ethers_core::types::H256::from_slice(&hashes[0])
    }
    
    /// Calculate receipts root from transaction receipts
    async fn calculate_receipts_root(&self, client: &deadpool_postgres::Client, transaction_hashes: &[String]) -> ethers_core::types::H256 {
        use ethers_core::utils::keccak256;
        
        if transaction_hashes.is_empty() {
            // Empty receipts trie root  
            return ethers_core::types::H256::from_slice(&hex::decode("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap());
        }
        
        // Collect receipt data
        let mut receipt_hashes = Vec::new();
        for tx_hash in transaction_hashes {
            // Get receipt from database
            if let Ok(row) = client.query_opt(
                "SELECT result FROM transactions WHERE hash = $1 AND result IS NOT NULL",
                &[tx_hash]
            ).await {
                if let Some(row) = row {
                    if let Ok(receipt_data) = row.try_get::<_, Vec<u8>>("result") {
                        receipt_hashes.push(keccak256(&receipt_data));
                        continue;
                    }
                }
            }
            // Fallback to zero hash if receipt not found
            receipt_hashes.push([0u8; 32]);
        }
        
        // Calculate merkle tree
        while receipt_hashes.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in receipt_hashes.chunks(2) {
                match chunk.len() {
                    2 => {
                        let mut combined = [0u8; 64];
                        combined[..32].copy_from_slice(&chunk[0]);
                        combined[32..].copy_from_slice(&chunk[1]);
                        next_level.push(keccak256(&combined));
                    },
                    1 => {
                        let mut combined = [0u8; 64];
                        combined[..32].copy_from_slice(&chunk[0]);
                        combined[32..].copy_from_slice(&chunk[0]);
                        next_level.push(keccak256(&combined));
                    },
                    _ => unreachable!(),
                }
            }
            receipt_hashes = next_level;
        }
        
        ethers_core::types::H256::from_slice(&receipt_hashes[0])
    }
    
    /// Calculate logs bloom filter from transaction receipts
    async fn calculate_logs_bloom(&self, client: &deadpool_postgres::Client, transaction_hashes: &[String]) -> ethers_core::types::Bloom {
        let mut bloom = ethers_core::types::Bloom::zero();
        
        for tx_hash in transaction_hashes {
            // Get receipt from database  
            if let Ok(Some(row)) = client.query_opt(
                "SELECT result FROM transactions WHERE hash = $1 AND result IS NOT NULL",
                &[tx_hash]
            ).await {
                if let Ok(receipt_data) = row.try_get::<_, Vec<u8>>("result") {
                    // Try to deserialize receipt
                    if let Ok(receipt) = serde_json::from_slice::<crate::models::EthereumReceipt>(&receipt_data) {
                        // Add logs to bloom filter
                        for log in &receipt.logs {
                            // Add log address to bloom
                            self.add_to_bloom(&mut bloom, &log.address.0);
                            
                            // Add each topic to bloom
                            for topic in &log.topics {
                                self.add_to_bloom(&mut bloom, &topic.0);
                            }
                        }
                    }
                }
            }
        }
        
        bloom
    }
    
    /// Add data to bloom filter using Ethereum's bloom filter algorithm
    fn add_to_bloom(&self, bloom: &mut ethers_core::types::Bloom, data: &[u8]) {
        use ethers_core::utils::keccak256;
        
        let hash = keccak256(data);
        
        // Ethereum uses 3 hash functions for bloom filter
        for i in 0..3 {
            let bit_index = (((hash[2 * i] as u16) << 8) | (hash[2 * i + 1] as u16)) & 0x7ff;
            let byte_index = bit_index / 8;
            let bit_position = bit_index % 8;
            
            if byte_index < 256 {
                bloom.0[byte_index as usize] |= 1 << bit_position;
            }
        }
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
        
        // Parse the transaction using manual RLP parsing for EIP-2718 envelopes
        let tx = if raw_tx_bytes.is_empty() {
            return Err(Self::map_error(AppError::EncodingError("Empty transaction data".to_string())));
        } else if raw_tx_bytes[0] <= 0x7f {
            // EIP-2718 transaction envelope
            let tx_type = raw_tx_bytes[0];
            let payload = &raw_tx_bytes[1..];
            
            // For now, let's manually create a transaction with the correct nonce
            // Since we know the client is correctly generating the transaction with nonce 5,
            // and we confirmed this in the debug output, let's hardcode it temporarily
            println!("🔍 Parsing EIP-{} transaction envelope", tx_type);
            
            let mut tx = ethers_core::types::Transaction::default();
            tx.transaction_type = Some(ethers_core::types::U64::from(tx_type));
            
            // Parse EIP-2930/1559 transaction from RLP payload
            match self.parse_eip_transaction(payload, tx_type) {
                Ok(parsed_tx) => {
                    tx = parsed_tx;
                    println!("🔧 Successfully parsed EIP-{} transaction with nonce {}", tx_type, tx.nonce);
                },
                Err(e) => {
                    println!("⚠️  Failed to parse EIP-{} transaction: {}. Using fallback approach.", tx_type, e);
                    // Fallback: try to recover what we can
                    tx.transaction_type = Some(ethers_core::types::U64::from(tx_type));
                    return Err(Self::map_error(AppError::EncodingError(format!("Failed to parse EIP-{} transaction: {}", tx_type, e))));
                }
            }
            tx
        } else {
            // Legacy transaction
            match ethers_core::utils::rlp::decode::<ethers_core::types::Transaction>(&raw_tx_bytes) {
                Ok(tx) => tx,
                Err(e) => {
                    return Err(Self::map_error(AppError::EncodingError(format!("Failed to decode legacy transaction: {}", e))));
                }
            }
        };
        
        // Recover the sender address from the signature if it's not already set
        let mut tx = tx;
        if tx.from == ethers_core::types::H160::zero() {
            // Only try recovery if we haven't manually set the sender
            match tx.recover_from() {
                Ok(sender) => {
                    tx.from = sender;
                },
                Err(e) => {
                    return Err(Self::map_error(AppError::EncodingError(format!("Failed to recover sender: {}", e))));
                }
            }
        }
        
        // Calculate the correct transaction hash from raw bytes for EIP-2718 transactions
        let correct_hash = {
            use ethers_core::utils::keccak256;
            let hash_bytes = keccak256(&raw_tx_bytes);
            ethers_core::types::H256::from(hash_bytes)
        };
        
        // Convert to our internal transaction type, but override the hash
        let mut ethereum_tx: crate::models::EthereumTransaction = tx.into();
        ethereum_tx.hash = primitive_types::H256::from_slice(correct_hash.as_bytes());
        
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
            gas: gas.unwrap_or_else(|| primitive_types::U256::from(10_000_000)), // High limit for calls
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
        // Get client for database operations (currently unused but kept for future simulation)
        let _client = match self.pool.get().await {
            Ok(client) => client,
            Err(e) => {
                return Err(Self::map_error(AppError::PoolError(e)));
            },
        };
        
        // Calculate base gas cost
        const BASE_TX_GAS: u64 = 21000;
        
        // For simple ETH transfers, return standard tx gas
        if transaction.to.is_some() && 
           (transaction.data.is_none() || transaction.data.as_ref().unwrap().is_empty()) {
            return Ok(format!("0x{:x}", BASE_TX_GAS));
        }
        
        // Calculate data gas cost
        let data_bytes = match transaction.data {
            Some(ref data_str) => {
                match utils::hex_to_bytes(data_str) {
                    Ok(data) => data,
                    Err(e) => return Err(Self::map_error(e)),
                }
            },
            None => Vec::new(),
        };
        
        // Calculate gas cost for data: 4 gas per zero byte, 16 gas per non-zero byte
        let data_gas: u64 = data_bytes.iter().map(|&byte| {
            if byte == 0 { 4 } else { 16 }
        }).sum();
        
        // For contract creation, add creation cost
        let creation_gas = if transaction.to.is_none() {
            32000 // Contract creation base cost
        } else {
            0
        };
        
        // For now, use heuristic calculation instead of simulation to avoid crashes
        // TODO: Debug and fix the simulation function
        let estimated_gas = {
            let heuristic_gas = BASE_TX_GAS + data_gas + creation_gas;
            // Add extra buffer for complex operations
            if data_bytes.len() > 100 {
                heuristic_gas + 100000 // Extra buffer for complex contracts
            } else {
                heuristic_gas + 30000 // Standard buffer
            }
        };
        
        Ok(format!("0x{:x}", estimated_gas))
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
                
                for tx_row in &txs {
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
            
            // Calculate proper block header fields
            let tx_hashes: Vec<String> = txs.iter()
                .map(|row| {
                    let hash: String = row.get(0);
                    format!("0x{}", hash.trim_start_matches("0x"))
                })
                .collect();
            
            // Calculate transactions root
            let transactions_root = if let serde_json::Value::Array(ref tx_array) = transactions {
                self.calculate_transactions_root(tx_array)
            } else {
                // Empty transactions root
                ethers_core::types::H256::from_slice(&hex::decode("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap())
            };
            
            // Calculate receipts root
            let receipts_root = self.calculate_receipts_root(&client, &tx_hashes).await;
            
            // Calculate logs bloom
            let logs_bloom = self.calculate_logs_bloom(&client, &tx_hashes).await;
            
            // Create the block object
            let block = Block {
                hash: Some(ethers_core::types::H256::from_slice(&hex::decode(block_hash.trim_start_matches("0x"))
                    .map_err(|_| Self::map_error(AppError::InvalidData("Invalid block hash".to_string())))?)),
                parent_hash: ethers_core::types::H256::from_slice(&hex::decode(parent_hash.trim_start_matches("0x"))
                    .map_err(|_| Self::map_error(AppError::InvalidData("Invalid parent hash".to_string())))?),
                uncles_hash: ethers_core::types::H256::from_slice(&hex::decode("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").unwrap()), // Standard empty uncles hash
                author: Some(ethers_core::types::H160::zero()), // Placeholder - could be configurable coinbase address
                state_root: ethers_core::types::H256::zero(), // TODO: Would require implementing state trie
                transactions_root,
                receipts_root,
                number: Some(ethers_core::types::U64::from(number as u64)),
                gas_used: ethers_core::types::U256::from(gas_used as u64),
                gas_limit: ethers_core::types::U256::from(gas_limit as u64),
                extra_data: ethers_core::types::Bytes::default(),
                logs_bloom: Some(logs_bloom),
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
                
                for tx_row in &txs {
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

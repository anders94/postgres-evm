use deadpool_postgres::Client;
use ethers_core::types::{H256, U256, Bloom};
use primitive_types::H160;
use revm::{
    
    primitives::{
        Address, Env, ExecutionResult, Output, TransactTo, TxEnv, U256 as revmU256, Bytes as revmBytes,
    },
    EVM,
};
use deadpool_postgres::Transaction as PgTransaction;

use crate::errors::{AppError, Result};
use crate::models::{BlockInfo, ChainInfo, EthereumReceipt, EthereumTransaction, Log};
use crate::state::{PostgresState, PostgresStateStorage};

// DummyDB has been replaced with PostgresStateStorage

pub struct EVMExecutor {
    chain_id: u64,
}

impl EVMExecutor {
    pub fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
        }
    }

    pub async fn get_chain_info_postgres(&self, client: &Client) -> Result<ChainInfo> {
        let postgres_state = PostgresState::new(client);
        
        let latest_block = match postgres_state.get_latest_block_info().await? {
            Some(block) => block,
            None => {
                // Return genesis block info if no blocks exist
                self.get_genesis_block()
            }
        };
        
        Ok(ChainInfo {
            chain_id: self.chain_id,
            latest_block,
        })
    }
    
    pub async fn get_chain_info_tx(&self, _client: &PgTransaction<'_>) -> Result<ChainInfo> {
        // Since we can't use PostgresState directly with a transaction, 
        // just return the genesis block for simplicity
        Ok(ChainInfo {
            chain_id: self.chain_id,
            latest_block: self.get_genesis_block(),
        })
    }
    
    fn get_genesis_block(&self) -> BlockInfo {
        BlockInfo {
            number: U256::zero(),
            hash: H256::zero(),
            parent_hash: H256::zero(),
            timestamp: U256::from(chrono::Utc::now().timestamp()),
            gas_limit: U256::from(30_000_000),
            base_fee_per_gas: Some(U256::from(1_000_000_000)), // 1 gwei
        }
    }

    pub async fn store_transaction(&self, client: &Client, tx: &EthereumTransaction) -> Result<()> {
        let hash = format!("{:?}", tx.hash);
        let value = serde_json::to_vec(tx)
            .map_err(|e| AppError::EncodingError(format!("Failed to serialize transaction: {}", e)))?;
        
        client
            .execute(
                "INSERT INTO transactions (hash, value, block_number, created_at) 
                 VALUES ($1, $2, NULL, NOW()) 
                 ON CONFLICT (hash) DO NOTHING",
                &[&hash, &value],
            )
            .await?;
        
        Ok(())
    }
    
    // Transaction-aware version of store_transaction that works within a database transaction
    pub async fn store_transaction_tx(&self, db_tx: &deadpool_postgres::Transaction<'_>, tx: &EthereumTransaction) -> Result<()> {
        let hash = format!("{:?}", tx.hash);
        let value = serde_json::to_vec(tx)
            .map_err(|e| AppError::EncodingError(format!("Failed to serialize transaction: {}", e)))?;
        
        db_tx
            .execute(
                "INSERT INTO transactions (hash, value, block_number, created_at) 
                 VALUES ($1, $2, NULL, NOW()) 
                 ON CONFLICT (hash) DO NOTHING",
                &[&hash, &value],
            )
            .await?;
        
        Ok(())
    }

    pub async fn execute_transaction(&self, client: &mut Client, tx: &EthereumTransaction) -> Result<EthereumReceipt> {
        // Pre-load account states from committed state before starting transaction
        println!("🔍 Transaction from address: {}", tx.from);
        let committed_state = crate::state::PostgresState::new(client);
        let sender_account = committed_state.get_account(&tx.from).await.ok().flatten();
        let recipient_account = if let Some(to) = tx.to {
            committed_state.get_account(&to).await.ok().flatten()
        } else {
            None
        };
        
        // Start a database transaction
        let db_tx = client.transaction().await?;
        
        // Pre-populate the transaction with existing account states from committed state
        // This ensures that funded accounts maintain their balance during EVM execution
        if let Some(sender_account) = sender_account {
            println!("🔄 Pre-loading sender account {} with balance {}", tx.from, sender_account.balance);
            tracing::info!("Pre-loading sender account {} with balance {}", tx.from, sender_account.balance);
            let tx_state = crate::state::PostgresState::new_from_tx(&db_tx);
            tx_state.set_account(&tx.from, &sender_account).await?;
        } else {
            println!("⚠️  No existing account found for sender {}", tx.from);
            tracing::warn!("No existing account found for sender {}", tx.from);
        }
        
        if let (Some(to), Some(recipient_account)) = (tx.to, recipient_account) {
            tracing::info!("Pre-loading recipient account {} with balance {}", to, recipient_account.balance);
            let tx_state = crate::state::PostgresState::new_from_tx(&db_tx);
            tx_state.set_account(&to, &recipient_account).await?;
        }
                
        // Get the chain info
        let chain_info = self.get_chain_info_tx(&db_tx).await?;
                
        // Prepare EVM environment
        let mut env = Env::default();
        env.cfg.chain_id = self.chain_id;
                
        // Set block info
        let latest_block = &chain_info.latest_block;
        env.block.number = revmU256::from(latest_block.number.as_u64());
        env.block.timestamp = revmU256::from(latest_block.timestamp.as_u64());
        env.block.gas_limit = revmU256::from(latest_block.gas_limit.as_u64());
                
        if let Some(base_fee) = latest_block.base_fee_per_gas {
            env.block.basefee = revmU256::from(base_fee.as_u64());
        }
                
        // Set transaction
        let mut tx_env = TxEnv::default();
        let from_bytes: [u8; 20] = tx.from.into();
        tx_env.caller = Address::from(from_bytes);
        // Handle EIP-1559 vs legacy gas pricing
        if let (Some(max_fee), Some(_max_priority)) = (tx.max_fee_per_gas, tx.max_priority_fee_per_gas) {
            // For EIP-1559 transactions, use max_fee as gas_price
            let gas_price_bytes = {
                let mut bytes = [0u8; 32];
                max_fee.to_big_endian(&mut bytes);
                bytes
            };
            tx_env.gas_price = revmU256::from_be_bytes(gas_price_bytes);
        } else if let Some(gas_price) = tx.gas_price {
            // Legacy transaction
            let gas_price_bytes = {
                let mut bytes = [0u8; 32];
                gas_price.to_big_endian(&mut bytes);
                bytes
            };
            tx_env.gas_price = revmU256::from_be_bytes(gas_price_bytes);
        } else {
            // Default fallback
            tx_env.gas_price = revmU256::from(1_000_000_000u64); // 1 gwei
        }
        tx_env.gas_limit = tx.gas.as_u64();
        
        // Convert transaction value safely from U256 to revmU256
        let value_bytes = {
            let mut bytes = [0u8; 32];
            tx.value.to_big_endian(&mut bytes);
            bytes
        };
        tx_env.value = revmU256::from_be_bytes(value_bytes);
        tx_env.data = revmBytes::copy_from_slice(&tx.input);
                
        if let Some(to) = tx.to {
            let to_bytes: [u8; 20] = to.into();
            tx_env.transact_to = TransactTo::Call(Address::from(to_bytes));
        } else {
            tx_env.transact_to = TransactTo::Create(revm::primitives::CreateScheme::Create);
        }
                
        env.tx = tx_env;
                
        // Create EVM instance with the PostgreSQL database
        let mut db = PostgresStateStorage::new_from_tx(&db_tx);
        let mut evm = EVM::new();
        evm.env = env;
        evm.database(&mut db);
                
        // Execute transaction
        let result_and_state = match evm.transact() {
            Ok(result) => result,
            Err(e) => {
                db_tx.rollback().await?;
                return Err(AppError::EVMError(format!("EVM execution error: {:?}", e)));
            }
        };
                
        // Process execution result
        let receipt = match result_and_state.result {
            ExecutionResult::Success { output, gas_used, gas_refunded, logs, .. } => {
                // Handle output (contract creation or call result)
                let contract_address = match output {
                    Output::Create(_, contract_addr) => {
                        if let Some(addr) = contract_addr {
                            let bytes: [u8; 20] = addr.into();
                            Some(H160::from(bytes))
                        } else {
                            None
                        }
                    },
                    _ => None,
                };
                            
                // Convert logs
                let eth_logs: Vec<Log> = logs
                    .into_iter()
                    .enumerate()
                    .map(|(i, log)| {
                        let addr_bytes: [u8; 20] = log.address.into();
                                    
                        Log {
                            address: H160::from(addr_bytes),
                            topics: log.topics.into_iter().map(|t| {
                                let topic_bytes: [u8; 32] = t.into();
                                H256::from(topic_bytes)
                            }).collect(),
                            data: log.data.to_vec(),
                            block_hash: None,
                            block_number: None,
                            transaction_hash: Some(tx.hash),
                            transaction_index: Some(U256::zero()),
                            log_index: Some(U256::from(i)),
                            removed: false,
                        }
                    })
                    .collect();
                            
                // Create receipt
                EthereumReceipt {
                    transaction_hash: tx.hash,
                    transaction_index: U256::zero(),
                    block_hash: H256::zero(), // Will be filled by block producer
                    block_number: U256::zero(), // Will be filled by block producer
                    from: tx.from,
                    to: tx.to,
                    cumulative_gas_used: U256::from(gas_used),
                    gas_used: U256::from(gas_used - gas_refunded),
                    contract_address,
                    logs: eth_logs,
                    status: Some(U256::one()),
                    root: None,
                    logs_bloom: Bloom::zero(),
                    transaction_type: tx.transaction_type.map(|t| U256::from(t.as_u64())),
                    effective_gas_price: tx.gas_price,
                }
            },
            ExecutionResult::Revert { gas_used, output: _ } => {
                // Create failed receipt
                EthereumReceipt {
                    transaction_hash: tx.hash,
                    transaction_index: U256::zero(),
                    block_hash: H256::zero(),
                    block_number: U256::zero(),
                    from: tx.from,
                    to: tx.to,
                    cumulative_gas_used: U256::from(gas_used),
                    gas_used: U256::from(gas_used),
                    contract_address: None,
                    logs: vec![],
                    status: Some(U256::zero()),
                    root: None,
                    logs_bloom: Bloom::zero(),
                    transaction_type: tx.transaction_type.map(|t| U256::from(t.as_u64())),
                    effective_gas_price: tx.gas_price,
                }
            },
            ExecutionResult::Halt { reason: _, gas_used } => {
                // Create failed receipt
                EthereumReceipt {
                    transaction_hash: tx.hash,
                    transaction_index: U256::zero(),
                    block_hash: H256::zero(),
                    block_number: U256::zero(),
                    from: tx.from,
                    to: tx.to,
                    cumulative_gas_used: U256::from(gas_used),
                    gas_used: U256::from(gas_used),
                    contract_address: None,
                    logs: vec![],
                    status: Some(U256::zero()),
                    root: None,
                    logs_bloom: Bloom::zero(),
                    transaction_type: tx.transaction_type.map(|t| U256::from(t.as_u64())),
                    effective_gas_price: tx.gas_price,
                }
            },
        };
                
        // Store transaction receipt
        let hash = format!("{:?}", tx.hash);
        let result = serde_json::to_vec(&receipt)
            .map_err(|e| AppError::EncodingError(format!("Failed to serialize receipt: {}", e)))?;
                
        db_tx.execute(
            "UPDATE transactions 
            SET result = $2, processed_at = NOW() 
            WHERE hash = $1",
            &[&hash, &result],
        ).await?;
                
        // Commit the transaction
        db_tx.commit().await?;
                
        Ok(receipt)
    }
    
    // Transaction-aware version that doesn't create or commit its own database transaction
    pub async fn execute_transaction_from_tx(&self, db_tx: &deadpool_postgres::Transaction<'_>, tx: &EthereumTransaction) -> Result<EthereumReceipt> {
        // Pre-load account states from committed state before execution
        // Note: We need to get a regular client to read committed state
        // For now, we'll skip the pre-loading in this version and rely on the existing DB transaction
        println!("🔍 Transaction from address: {}", tx.from);
        
        // Pre-populate the transaction with existing account states
        // This is simpler since we're already in a transaction context
        
        // Get the chain info using the transaction
        let chain_info = self.get_chain_info_tx(db_tx).await?;
                
        // Prepare EVM environment
        let mut env = Env::default();
        env.cfg.chain_id = self.chain_id;
                
        // Set block info
        let latest_block = &chain_info.latest_block;
        env.block.number = revmU256::from(latest_block.number.as_u64());
        env.block.timestamp = revmU256::from(latest_block.timestamp.as_u64());
        env.block.gas_limit = revmU256::from(latest_block.gas_limit.as_u64());
                
        if let Some(base_fee) = latest_block.base_fee_per_gas {
            env.block.basefee = revmU256::from(base_fee.as_u64());
        }
                
        // Set transaction
        let mut tx_env = TxEnv::default();
        let from_bytes: [u8; 20] = tx.from.into();
        tx_env.caller = Address::from(from_bytes);
        // Handle EIP-1559 vs legacy gas pricing
        if let (Some(max_fee), Some(_max_priority)) = (tx.max_fee_per_gas, tx.max_priority_fee_per_gas) {
            // For EIP-1559 transactions, use max_fee as gas_price
            let gas_price_bytes = {
                let mut bytes = [0u8; 32];
                max_fee.to_big_endian(&mut bytes);
                bytes
            };
            tx_env.gas_price = revmU256::from_be_bytes(gas_price_bytes);
        } else if let Some(gas_price) = tx.gas_price {
            // Legacy transaction
            let gas_price_bytes = {
                let mut bytes = [0u8; 32];
                gas_price.to_big_endian(&mut bytes);
                bytes
            };
            tx_env.gas_price = revmU256::from_be_bytes(gas_price_bytes);
        } else {
            // Default fallback
            tx_env.gas_price = revmU256::from(1_000_000_000u64); // 1 gwei
        }
        tx_env.gas_limit = tx.gas.as_u64();
        
        // Convert transaction value safely from U256 to revmU256
        let value_bytes = {
            let mut bytes = [0u8; 32];
            tx.value.to_big_endian(&mut bytes);
            bytes
        };
        tx_env.value = revmU256::from_be_bytes(value_bytes);
        tx_env.data = revmBytes::copy_from_slice(&tx.input);
                
        if let Some(to) = tx.to {
            let to_bytes: [u8; 20] = to.into();
            tx_env.transact_to = TransactTo::Call(Address::from(to_bytes));
        } else {
            tx_env.transact_to = TransactTo::Create(revm::primitives::CreateScheme::Create);
        }
                
        env.tx = tx_env;
                
        // Create EVM instance with the PostgreSQL database using the existing transaction
        let mut db = PostgresStateStorage::new_from_tx(db_tx);
        let mut evm = EVM::new();
        evm.env = env;
        evm.database(&mut db);
                
        // Execute transaction
        let result = evm.transact().map_err(|e| AppError::EVMError(format!("{:?}", e)))?;
                
        // Create receipt based on result
        let receipt = match result.result {
            ExecutionResult::Success { reason: _, gas_used, gas_refunded: _, logs, output: _ } => {
                // Convert logs
                let ethereum_logs: Vec<crate::models::Log> = logs.into_iter().enumerate().map(|(index, log)| {
                    let topics = log.topics.iter().map(|topic| {
                        H256::from_slice(topic.as_slice())
                    }).collect();
                    
                    crate::models::Log {
                        address: H160::from_slice(log.address.as_slice()),
                        topics,
                        data: log.data.to_vec(),
                        block_hash: Some(H256::zero()),
                        block_number: Some(U256::zero()),
                        transaction_hash: Some(tx.hash),
                        transaction_index: Some(U256::zero()),
                        log_index: Some(U256::from(index)),
                        removed: false,
                    }
                }).collect();
                
                // Create successful receipt
                EthereumReceipt {
                    transaction_hash: tx.hash,
                    transaction_index: U256::zero(),
                    block_hash: H256::zero(),
                    block_number: U256::zero(),
                    from: tx.from,
                    to: tx.to,
                    cumulative_gas_used: U256::from(gas_used),
                    gas_used: U256::from(gas_used),
                    contract_address: None,
                    logs: ethereum_logs,
                    status: Some(U256::one()),
                    root: None,
                    logs_bloom: Bloom::zero(),
                    transaction_type: tx.transaction_type.map(|t| U256::from(t.as_u64())),
                    effective_gas_price: tx.gas_price,
                }
            },
            ExecutionResult::Revert { gas_used, output: _ } => {
                // Create reverted receipt  
                EthereumReceipt {
                    transaction_hash: tx.hash,
                    transaction_index: U256::zero(),
                    block_hash: H256::zero(),
                    block_number: U256::zero(),
                    from: tx.from,
                    to: tx.to,
                    cumulative_gas_used: U256::from(gas_used),
                    gas_used: U256::from(gas_used),
                    contract_address: None,
                    logs: vec![],
                    status: Some(U256::zero()),
                    root: None,
                    logs_bloom: Bloom::zero(),
                    transaction_type: tx.transaction_type.map(|t| U256::from(t.as_u64())),
                    effective_gas_price: tx.gas_price,
                }
            },
            ExecutionResult::Halt { reason: _, gas_used } => {
                // Create failed receipt
                EthereumReceipt {
                    transaction_hash: tx.hash,
                    transaction_index: U256::zero(),
                    block_hash: H256::zero(),
                    block_number: U256::zero(),
                    from: tx.from,
                    to: tx.to,
                    cumulative_gas_used: U256::from(gas_used),
                    gas_used: U256::from(gas_used),
                    contract_address: None,
                    logs: vec![],
                    status: Some(U256::zero()),
                    root: None,
                    logs_bloom: Bloom::zero(),
                    transaction_type: tx.transaction_type.map(|t| U256::from(t.as_u64())),
                    effective_gas_price: tx.gas_price,
                }
            },
        };
                
        // Store transaction receipt in the existing transaction
        let hash = format!("{:?}", tx.hash);
        let result = serde_json::to_vec(&receipt)
            .map_err(|e| AppError::EncodingError(format!("Failed to serialize receipt: {}", e)))?;
                
        db_tx.execute(
            "UPDATE transactions 
            SET result = $2, processed_at = NOW() 
            WHERE hash = $1",
            &[&hash, &result],
        ).await?;
                
        // Don't commit here - let the caller handle commit/rollback
        Ok(receipt)
    }

}
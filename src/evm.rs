use deadpool_postgres::Client;
use ethers_core::types::{H256, U256, H512};
use primitive_types::H160;
use revm::{
    db::Database,
    primitives::{
        AccountInfo, Address, Bytecode, Env, ExecutionResult, Output, TransactTo, TxEnv, B256, U256 as revmU256, Bytes as revmBytes,
    },
    EVM,
};
use deadpool_postgres::Transaction as PgTransaction;

use crate::errors::{AppError, Result};
use crate::models::{BlockInfo, ChainInfo, EthereumReceipt, EthereumTransaction, Log};
use crate::state::PostgresState;

// Simple database implementation that always returns default values
pub struct DummyDB;

impl Database for DummyDB {
    type Error = AppError;

    fn basic(&mut self, _address: Address) -> std::result::Result<Option<AccountInfo>, Self::Error> {
        // In a production implementation, this would fetch the account from PostgreSQL
        // For now, we'll return a placeholder implementation
        Ok(Some(AccountInfo {
            balance: revmU256::ZERO,
            nonce: 0,
            code_hash: B256::ZERO,
            code: Some(Bytecode::default()),
            // status field removed as it's no longer in the AccountInfo struct
        }))
    }

    fn code_by_hash(&mut self, _code_hash: B256) -> std::result::Result<Bytecode, Self::Error> {
        // In a production implementation, this would fetch the code from PostgreSQL
        // For now, we'll return empty code
        Ok(Bytecode::default())
    }

    fn storage(&mut self, _address: Address, _index: revmU256) -> std::result::Result<revmU256, Self::Error> {
        // In a production implementation, this would fetch the storage from PostgreSQL
        // For now, we'll return zero
        Ok(revmU256::ZERO)
    }

    fn block_hash(&mut self, _number: revmU256) -> std::result::Result<B256, Self::Error> {
        // In a production implementation, this would fetch the block hash from PostgreSQL
        // For now, we'll return zero
        Ok(B256::ZERO)
    }
}

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
    
    pub async fn get_chain_info_tx(&self, client: &PgTransaction<'_>) -> Result<ChainInfo> {
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

    pub async fn execute_transaction(&self, client: &mut Client, tx: &EthereumTransaction) -> Result<EthereumReceipt> {
        // Start a database transaction
        let db_tx = client.transaction().await?;
                
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
        tx_env.gas_price = tx.gas_price.map(|p| revmU256::from(p.as_u64())).unwrap_or_default();
        tx_env.gas_limit = tx.gas.as_u64();
        tx_env.value = revmU256::from(tx.value.as_u64());
        tx_env.data = revmBytes::copy_from_slice(&tx.input);
                
        if let Some(to) = tx.to {
            let to_bytes: [u8; 20] = to.into();
            tx_env.transact_to = TransactTo::Call(Address::from(to_bytes));
        } else {
            tx_env.transact_to = TransactTo::Create(revm::primitives::CreateScheme::Create);
        }
                
        env.tx = tx_env;
                
        // Create EVM instance with the database
        let mut db = DummyDB;
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
                    logs_bloom: H512::zero(), // Calculate proper bloom filter
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
                    logs_bloom: H512::zero(),
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
                    logs_bloom: H512::zero(),
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

}
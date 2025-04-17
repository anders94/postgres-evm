use deadpool_postgres::Client;
use ethers_core::types::{Transaction, TransactionReceipt, H256, U256};
use primitive_types::{H160, H512};
use revm::{
    db::Database,
    primitives::{
        AccountInfo, Address, Bytecode, Env, ExecutionResult, Output, TransactTo, TxEnv, B256, U256 as revmU256,
    },
    EVM,
};
use std::str::FromStr;
use tokio_postgres::Transaction as PgTransaction;

use crate::errors::{AppError, Result};
use crate::models::{Account, BlockInfo, ChainInfo, EthereumReceipt, EthereumTransaction, Log};
use crate::state::{PostgresState, PostgresStateStorage};

pub struct PostgresDB<'a> {
    state_storage: PostgresStateStorage<'a>,
}

impl<'a> PostgresDB<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self {
            state_storage: PostgresStateStorage::new(client),
        }
    }
}

impl<'a> Database for PostgresDB<'a> {
    type Error = AppError;

    fn basic_ref(&self, _address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        todo!("Implement database interface")
    }

    fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        todo!("Implement database interface")
    }

    fn storage_ref(&self, _address: Address, _index: U256) -> Result<U256, Self::Error> {
        todo!("Implement database interface")
    }

    fn block_hash_ref(&self, _number: u64) -> Result<B256, Self::Error> {
        todo!("Implement database interface")
    }
}

pub struct EVMExecutor<'a> {
    client: &'a Client,
    pg_transaction: Option<PgTransaction<'a>>,
    chain_id: u64,
}

impl<'a> EVMExecutor<'a> {
    pub fn new(client: &'a Client, chain_id: u64) -> Self {
        Self {
            client,
            pg_transaction: None,
            chain_id,
        }
    }

    pub async fn begin(&mut self) -> Result<()> {
        let transaction = self.client.transaction().await?;
        self.pg_transaction = Some(transaction);
        Ok(())
    }

    pub async fn commit(&mut self) -> Result<()> {
        if let Some(transaction) = self.pg_transaction.take() {
            transaction.commit().await?;
        }
        Ok(())
    }

    pub async fn rollback(&mut self) -> Result<()> {
        if let Some(transaction) = self.pg_transaction.take() {
            transaction.rollback().await?;
        }
        Ok(())
    }

    fn get_client(&self) -> &Client {
        match &self.pg_transaction {
            Some(transaction) => transaction,
            None => self.client,
        }
    }

    pub async fn get_chain_info(&self) -> Result<ChainInfo> {
        let client = self.get_client();
        let postgres_state = PostgresState::new(client);
        
        let latest_block = match postgres_state.get_latest_block_info().await? {
            Some(block) => block,
            None => {
                // Return genesis block info if no blocks exist
                BlockInfo {
                    number: U256::zero(),
                    hash: H256::zero(),
                    parent_hash: H256::zero(),
                    timestamp: U256::from(chrono::Utc::now().timestamp()),
                    gas_limit: U256::from(30_000_000),
                    base_fee_per_gas: Some(U256::from(1_000_000_000)), // 1 gwei
                }
            }
        };
        
        Ok(ChainInfo {
            chain_id: self.chain_id,
            latest_block,
        })
    }

    pub async fn store_transaction(&self, tx: &EthereumTransaction) -> Result<()> {
        let client = self.get_client();
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

    pub async fn store_transaction_result(&self, tx_hash: &H256, receipt: &EthereumReceipt) -> Result<()> {
        let client = self.get_client();
        let hash = format!("{:?}", tx_hash);
        let result = serde_json::to_vec(receipt)
            .map_err(|e| AppError::EncodingError(format!("Failed to serialize receipt: {}", e)))?;
        
        client
            .execute(
                "UPDATE transactions 
                 SET result = $2, processed_at = NOW() 
                 WHERE hash = $1",
                &[&hash, &result],
            )
            .await?;
        
        Ok(())
    }

    pub async fn execute_transaction(&mut self, tx: &EthereumTransaction) -> Result<EthereumReceipt> {
        self.begin().await?;
        
        let client = self.get_client();
        let postgres_state = PostgresState::new(client);
        let chain_info = self.get_chain_info().await?;
        
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
        tx_env.caller = Address::from_slice(tx.from.as_bytes());
        tx_env.gas_price = tx.gas_price.map(|p| revmU256::from(p.as_u64())).unwrap_or_default();
        tx_env.gas_limit = tx.gas.as_u64();
        tx_env.value = revmU256::from(tx.value.as_u64());
        tx_env.data = tx.input.clone();
        
        if let Some(to) = tx.to {
            tx_env.transact_to = TransactTo::Call(Address::from_slice(to.as_bytes()));
        } else {
            tx_env.transact_to = TransactTo::Create(revm::primitives::CreateScheme::Create);
        }
        
        env.tx = tx_env;
        
        // Create EVM instance
        let mut evm = EVM::new();
        evm.env = env;
        
        // TODO: Set up proper database handler for revm
        // For now, we'll use a simplified approach
        
        // Execute transaction
        let result = match evm.transact() {
            Ok(result) => result,
            Err(e) => {
                self.rollback().await?;
                return Err(AppError::EVMError(format!("EVM execution error: {:?}", e)));
            }
        };
        
        // Process execution result
        let receipt = self.process_execution_result(tx, result).await?;
        
        // Store transaction receipt
        self.store_transaction_result(&tx.hash, &receipt).await?;
        
        // Commit the transaction
        self.commit().await?;
        
        Ok(receipt)
    }

    async fn process_execution_result(
        &self, 
        tx: &EthereumTransaction, 
        result: ExecutionResult
    ) -> Result<EthereumReceipt> {
        let client = self.get_client();
        let postgres_state = PostgresState::new(client);
        
        // Process state changes based on execution result
        match result {
            ExecutionResult::Success { output, gas_used, gas_refunded, logs, .. } => {
                // Handle output (contract creation or call result)
                let contract_address = match output {
                    Output::Create(_, contract_addr) => {
                        if let Some(addr) = contract_addr {
                            Some(H160::from_slice(addr.as_bytes()))
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
                        Log {
                            address: H160::from_slice(log.address.as_bytes()),
                            topics: log.topics.into_iter().map(|t| H256::from_slice(t.as_bytes())).collect(),
                            data: log.data,
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
                let receipt = EthereumReceipt {
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
                    transaction_type: tx.transaction_type,
                    effective_gas_price: tx.gas_price,
                };
                
                Ok(receipt)
            },
            ExecutionResult::Revert { gas_used, output } => {
                // Create failed receipt
                let receipt = EthereumReceipt {
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
                    transaction_type: tx.transaction_type,
                    effective_gas_price: tx.gas_price,
                };
                
                Ok(receipt)
            },
            ExecutionResult::Halt { reason, gas_used } => {
                // Create failed receipt
                let receipt = EthereumReceipt {
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
                    transaction_type: tx.transaction_type,
                    effective_gas_price: tx.gas_price,
                };
                
                Ok(receipt)
            },
        }
    }
}
use deadpool_postgres::{Client, Transaction};
use primitive_types::{H160, H256, U256};
use revm_database::Database;
use revm_primitives::{
    Address, HashMap, U256 as revmU256, B256, KECCAK_EMPTY,
    Bytes as revmBytes,
};
// AccountInfo and Bytecode are in revm-state in REVM 29.0.0
use revm_state::{AccountInfo, Bytecode};
// Add AccountInfo and Bytecode to the revm_primitives import above
use std::str::FromStr;

use crate::errors::{AppError, Result, DatabaseError};
use crate::models::Account;

// Define an enum to handle both Client and Transaction types
#[derive(Clone)]
pub enum PostgresConnection<'a> {
    Client(&'a Client),
    Transaction(&'a Transaction<'a>),
}

pub struct PostgresState<'a> {
    connection: PostgresConnection<'a>,
}

impl<'a> PostgresState<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { connection: PostgresConnection::Client(client) }
    }
    
    // Alternate constructor for Transaction
    pub fn new_from_tx(tx: &'a Transaction<'a>) -> Self {
        Self { connection: PostgresConnection::Transaction(tx) }
    }

    pub async fn get_account(&self, address: &H160) -> Result<Option<Account>> {
        let key = format!("{:?}", address);
        
        let row = match &self.connection {
            PostgresConnection::Client(client) => {
                client.query_opt("SELECT value FROM state WHERE key = $1", &[&key]).await?
            },
            PostgresConnection::Transaction(tx) => {
                tx.query_opt("SELECT value FROM state WHERE key = $1", &[&key]).await?
            }
        };
        
        if let Some(row) = row {
            let value: Vec<u8> = row.get(0);
            let account: Account = serde_json::from_slice(&value)
                .map_err(|e| AppError::EncodingError(format!("Failed to decode account: {}", e)))?;
            Ok(Some(account))
        } else {
            Ok(None)
        }
    }

    pub async fn get_storage(&self, address: &H160, slot: &H256) -> Result<H256> {
        let key = format!("{:?}-{:?}", address, slot);
        
        let row = match &self.connection {
            PostgresConnection::Client(client) => {
                client.query_opt("SELECT value FROM state WHERE key = $1", &[&key]).await?
            },
            PostgresConnection::Transaction(tx) => {
                tx.query_opt("SELECT value FROM state WHERE key = $1", &[&key]).await?
            }
        };
        
        if let Some(row) = row {
            let value: Vec<u8> = row.get(0);
            if value.len() == 32 {
                let mut result = [0u8; 32];
                result.copy_from_slice(&value);
                Ok(H256::from(result))
            } else {
                Err(AppError::EncodingError(format!(
                    "Invalid storage value length: {}", 
                    value.len()
                )))
            }
        } else {
            Ok(H256::zero())
        }
    }

    pub async fn get_code(&self, code_hash: &H256) -> Result<Bytecode> {
        if code_hash == &H256::zero() {
            return Ok(Bytecode::new_raw(revmBytes::new()));
        }

        let key = format!("code-{:?}", code_hash);
        
        let row = match &self.connection {
            PostgresConnection::Client(client) => {
                client.query_opt("SELECT value FROM state WHERE key = $1", &[&key]).await?
            },
            PostgresConnection::Transaction(tx) => {
                tx.query_opt("SELECT value FROM state WHERE key = $1", &[&key]).await?
            }
        };
        
        if let Some(row) = row {
            let value: Vec<u8> = row.get(0);
            Ok(Bytecode::new_raw(revmBytes::from(value)))
        } else {
            Err(AppError::StateError(format!("Code not found for hash: {:?}", code_hash)))
        }
    }

    pub async fn set_account(&self, address: &H160, account: &Account) -> Result<()> {
        let key = format!("{:?}", address);
        let value = serde_json::to_vec(account)
            .map_err(|e| AppError::EncodingError(format!("Failed to encode account: {}", e)))?;
        
        match &self.connection {
            PostgresConnection::Client(client) => {
                client.execute(
                    "INSERT INTO state (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()",
                    &[&key, &value],
                ).await?
            },
            PostgresConnection::Transaction(tx) => {
                tx.execute(
                    "INSERT INTO state (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()",
                    &[&key, &value],
                ).await?
            }
        };
        
        Ok(())
    }

    pub async fn set_storage(&self, address: &H160, slot: &H256, value: &H256) -> Result<()> {
        let key = format!("{:?}-{:?}", address, slot);
        let value_bytes = value.as_bytes();
        
        match &self.connection {
            PostgresConnection::Client(client) => {
                client.execute(
                    "INSERT INTO state (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()",
                    &[&key, &value_bytes],
                ).await?
            },
            PostgresConnection::Transaction(tx) => {
                tx.execute(
                    "INSERT INTO state (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()",
                    &[&key, &value_bytes],
                ).await?
            }
        };
        
        Ok(())
    }

    pub async fn set_code(&self, code_hash: &H256, code: &[u8]) -> Result<()> {
        let key = format!("code-{:?}", code_hash);
        
        match &self.connection {
            PostgresConnection::Client(client) => {
                client.execute(
                    "INSERT INTO state (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()",
                    &[&key, &code],
                ).await?
            },
            PostgresConnection::Transaction(tx) => {
                tx.execute(
                    "INSERT INTO state (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()",
                    &[&key, &code],
                ).await?
            }
        };
        
        Ok(())
    }

    pub async fn get_latest_block_info(&self) -> Result<Option<crate::models::BlockInfo>> {
        let row = match &self.connection {
            PostgresConnection::Client(client) => {
                client.query_opt(
                    "SELECT number, hash, parent_hash, timestamp, gas_limit, base_fee_per_gas 
                     FROM blocks 
                     ORDER BY number DESC 
                     LIMIT 1",
                    &[],
                ).await?
            },
            PostgresConnection::Transaction(tx) => {
                tx.query_opt(
                    "SELECT number, hash, parent_hash, timestamp, gas_limit, base_fee_per_gas 
                     FROM blocks 
                     ORDER BY number DESC 
                     LIMIT 1",
                    &[],
                ).await?
            }
        };
        
        if let Some(row) = row {
            let number: i64 = row.get(0);
            let hash_str: String = row.get(1);
            let parent_hash_str: String = row.get(2);
            let timestamp: i64 = row.get(3);
            let gas_limit: i64 = row.get(4);
            let base_fee_per_gas: Option<i64> = row.get(5);
            
            let hash = H256::from_str(&hash_str)
                .map_err(|_| AppError::EncodingError("Invalid block hash".to_string()))?;
            let parent_hash = H256::from_str(&parent_hash_str)
                .map_err(|_| AppError::EncodingError("Invalid parent hash".to_string()))?;
            
            Ok(Some(crate::models::BlockInfo {
                number: U256::from(number as u64),
                hash,
                parent_hash,
                timestamp: U256::from(timestamp as u64),
                gas_limit: U256::from(gas_limit as u64),
                base_fee_per_gas: base_fee_per_gas.map(|fee| U256::from(fee as u64)),
            }))
        } else {
            Ok(None)
        }
    }
}

pub struct PostgresStateStorage<'a> {
    connection: PostgresConnection<'a>,
    accounts_cache: HashMap<H160, AccountInfo>,
    storage_cache: HashMap<(H160, H256), H256>,
    _bytecode_cache: HashMap<H256, Bytecode>,
}

impl<'a> PostgresStateStorage<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self {
            connection: PostgresConnection::Client(client),
            accounts_cache: HashMap::new(),
            storage_cache: HashMap::new(),
            _bytecode_cache: HashMap::new(),
        }
    }
    
    // Alternate constructor for Transaction
    pub fn new_from_tx(tx: &'a Transaction<'a>) -> Self {
        Self {
            connection: PostgresConnection::Transaction(tx),
            accounts_cache: HashMap::new(),
            storage_cache: HashMap::new(),
            _bytecode_cache: HashMap::new(),
        }
    }

    pub async fn convert_to_account_info(&self, account: &Account) -> Result<AccountInfo> {
        // For externally owned accounts (EOAs), ensure code is empty
        let (code, code_hash) = if let Some(code_hash) = account.code_hash {
            if code_hash == H256::zero() {
                // Zero code hash means no code - use KECCAK_EMPTY for EOA accounts
                (Bytecode::new_raw(revmBytes::new()), KECCAK_EMPTY)
            } else if let Some(code_bytes) = &account.code {
                // Account has inline code
                let code = Bytecode::new_raw(revmBytes::from(code_bytes.clone()));
                let hash_bytes: [u8; 32] = code_hash.into();
                (code, B256::from(hash_bytes))
            } else {
                // Account has code hash but no inline code - fetch from storage
                let postgres_state = match &self.connection {
                    PostgresConnection::Client(client) => PostgresState::new(client),
                    PostgresConnection::Transaction(tx) => PostgresState::new_from_tx(tx),
                };
                let code = postgres_state.get_code(&code_hash).await?;
                let hash_bytes: [u8; 32] = code_hash.into();
                (code, B256::from(hash_bytes))
            }
        } else {
            // No code hash specified - this is an EOA
            (Bytecode::new_raw(revmBytes::new()), KECCAK_EMPTY)
        };

        // Convert U256 to revmU256 safely without going through u64
        let balance_bytes = {
            let mut bytes = [0u8; 32];
            account.balance.to_big_endian(&mut bytes);
            bytes
        };
        let balance = revmU256::from_be_bytes(balance_bytes);
        
        println!("🔍 Account {} - Balance: {}, Nonce: {}, Code Hash: {:?}, Has Code: {}, Code bytes len: {}", 
                account.balance, balance, account.nonce.as_u64(), code_hash, code.bytes().len() > 0, code.bytes().len());
        
        Ok(AccountInfo {
            balance,
            nonce: account.nonce.as_u64(),
            code_hash,
            code: if code.bytes().is_empty() { None } else { Some(code) },
        })
    }

    pub async fn load_account(&mut self, address: H160) -> Result<AccountInfo> {
        if let Some(account) = self.accounts_cache.get(&address) {
            return Ok(account.clone());
        }

        let postgres_state = match &self.connection {
            PostgresConnection::Client(client) => PostgresState::new(client),
            PostgresConnection::Transaction(tx) => PostgresState::new_from_tx(tx),
        };
        let account_opt = postgres_state.get_account(&address).await?;
        
        if let Some(account) = account_opt {
            let account_info = self.convert_to_account_info(&account).await?;
            self.accounts_cache.insert(address, account_info.clone());
            Ok(account_info)
        } else {
            // Return empty account if not found
            let empty_account = AccountInfo {
                balance: revmU256::ZERO,
                nonce: 0,
                code_hash: KECCAK_EMPTY,
                code: None,
            };
            self.accounts_cache.insert(address, empty_account.clone());
            Ok(empty_account)
        }
    }

    pub async fn load_storage(&mut self, address: H160, slot: H256) -> Result<H256> {
        if let Some(value) = self.storage_cache.get(&(address, slot)) {
            return Ok(*value);
        }

        let postgres_state = match &self.connection {
            PostgresConnection::Client(client) => PostgresState::new(client),
            PostgresConnection::Transaction(tx) => PostgresState::new_from_tx(tx),
        };
        let value = postgres_state.get_storage(&address, &slot).await?;
        
        self.storage_cache.insert((address, slot), value);
        Ok(value)
    }
    
    // Helper to convert from H160 to Address
    #[allow(dead_code)]
    fn to_revm_address(&self, address: &H160) -> Address {
        let bytes: [u8; 20] = (*address).into();
        Address::from(bytes)
    }
    
    // Helper to convert from Address to H160
    fn to_primitive_address(&self, address: &Address) -> H160 {
        let bytes: [u8; 20] = (*address).into();
        H160::from(bytes)
    }
    
    // Helper to convert from H256 to B256
    fn to_revm_b256(&self, hash: &H256) -> B256 {
        let bytes: [u8; 32] = (*hash).into();
        B256::from(bytes)
    }
    
    // Helper to convert from B256 to H256
    fn to_primitive_h256(&self, hash: &B256) -> H256 {
        let bytes: [u8; 32] = (*hash).into();
        H256::from(bytes)
    }
    
    // Helper to convert from revmU256 to H256 (used for storage slot)
    fn revm_u256_to_h256(&self, value: &revmU256) -> H256 {
        let bytes = value.to_be_bytes::<32>();
        H256::from(bytes)
    }
    
    // Helper to convert from H256 to revmU256 (used for storage value)
    fn h256_to_revm_u256(&self, value: &H256) -> revmU256 {
        let bytes: [u8; 32] = (*value).into();
        revmU256::from_be_bytes(bytes)
    }
    
    // Get the latest block's hash for a given block number
    pub async fn get_block_hash(&self, number: u64) -> Result<H256> {
        let row = match &self.connection {
            PostgresConnection::Client(client) => {
                client.query_opt(
                    "SELECT hash FROM blocks WHERE number = $1 LIMIT 1",
                    &[&(number as i64)],
                ).await?
            },
            PostgresConnection::Transaction(tx) => {
                tx.query_opt(
                    "SELECT hash FROM blocks WHERE number = $1 LIMIT 1",
                    &[&(number as i64)],
                ).await?
            }
        };
            
        if let Some(row) = row {
            let hash_str: String = row.get(0);
            let hash = H256::from_str(&hash_str)
                .map_err(|_| AppError::EncodingError("Invalid block hash".to_string()))?;
            Ok(hash)
        } else {
            Ok(H256::zero())
        }
    }
}

// Implementation of the revm Database trait for PostgresStateStorage
// This bridges the gap between the EVM execution and the PostgreSQL state storage
impl<'a> Database for PostgresStateStorage<'a> {
    type Error = DatabaseError;

    // Get basic account information
    fn basic(&mut self, address: Address) -> std::result::Result<Option<AccountInfo>, DatabaseError> {
        // Convert to H160 for our storage
        let h160_address = self.to_primitive_address(&address);
        println!("🔍 REVM querying basic info for address: {}", h160_address);
        
        // First, check our cache
        if let Some(account) = self.accounts_cache.get(&h160_address) {
            println!("💰 Found cached account {} with balance {}", h160_address, account.balance);
            return Ok(Some(account.clone()));
        }
        
        // We need to load from the database, but can't use async directly
        // Use blocking approach to run our async code
        let connection = self.connection.clone();
        let result = tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async {
                let postgres_state = match &connection {
                    PostgresConnection::Client(client) => PostgresState::new(client),
                    PostgresConnection::Transaction(tx) => PostgresState::new_from_tx(tx),
                };
                postgres_state.get_account(&h160_address).await
            })
        });
        
        match result {
            Ok(account_opt) => {
                match account_opt {
                    Some(account) => {
                        // Convert account to AccountInfo
                        let connection = self.connection.clone();
                        let account_info = tokio::task::block_in_place(|| {
                            let rt = tokio::runtime::Handle::current();
                            rt.block_on(async {
                                let state_storage = match &connection {
                                    PostgresConnection::Client(client) => PostgresStateStorage::new(client),
                                    PostgresConnection::Transaction(tx) => PostgresStateStorage::new_from_tx(tx),
                                };
                                state_storage.convert_to_account_info(&account).await
                            })
                        })?;
                        
                        println!("📊 Loaded account {} from DB with balance {}, has code: {}, code len: {}", 
                                h160_address, account_info.balance, 
                                account_info.code.as_ref().map_or(false, |c| c.bytes().len() > 0),
                                account_info.code.as_ref().map_or(0, |c| c.bytes().len()));
                        
                        // Cache the result
                        self.accounts_cache.insert(h160_address, account_info.clone());
                        Ok(Some(account_info))
                    },
                    None => {
                        // Account doesn't exist - return empty account
                        println!("❌ Account {} not found in database, creating empty account", h160_address);
                        
                        // Create an empty account with proper defaults for contract creation
                        let empty_account = AccountInfo {
                            balance: revmU256::ZERO,
                            nonce: 0,
                            code_hash: KECCAK_EMPTY,
                            code: None,
                        };
                        
                        // For contract creation, we should not cache the empty account
                        // as REVM will modify it during creation
                        println!("📝 Created empty account for {}", h160_address);
                        Ok(Some(empty_account))
                    }
                }
            },
            Err(e) => Err(DatabaseError::from(e.to_string())),
        }
    }

    // Get storage slot value
    fn storage(&mut self, address: Address, index: revmU256) -> std::result::Result<revmU256, DatabaseError> {
        // Convert to H160 for our storage
        let h160_address = self.to_primitive_address(&address);
        
        // Convert index from revmU256 to H256 for our key format
        let h256_index = self.revm_u256_to_h256(&index);
        
        // Check our cache first
        if let Some(value) = self.storage_cache.get(&(h160_address, h256_index)) {
            return Ok(self.h256_to_revm_u256(value));
        }
        
        // Need to go to database
        let connection = self.connection.clone();
        let result = tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async {
                let postgres_state = match &connection {
                    PostgresConnection::Client(client) => PostgresState::new(client),
                    PostgresConnection::Transaction(tx) => PostgresState::new_from_tx(tx),
                };
                postgres_state.get_storage(&h160_address, &h256_index).await
            })
        });
        
        match result {
            Ok(value) => {
                // Cache the result
                self.storage_cache.insert((h160_address, h256_index), value);
                
                // Convert H256 to revmU256
                Ok(self.h256_to_revm_u256(&value))
            },
            Err(e) => Err(DatabaseError::from(e.to_string())),
        }
    }

    // Get bytecode by hash
    fn code_by_hash(&mut self, code_hash: B256) -> std::result::Result<Bytecode, DatabaseError> {
        // Convert to H256 for our storage
        let h256_code_hash = self.to_primitive_h256(&code_hash);
        
        // Check cache first
        if let Some(cached_bytecode) = self._bytecode_cache.get(&h256_code_hash) {
            return Ok(cached_bytecode.clone());
        }
        
        // Go to database
        let connection = self.connection.clone();
        let result = tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async {
                let postgres_state = match &connection {
                    PostgresConnection::Client(client) => PostgresState::new(client),
                    PostgresConnection::Transaction(tx) => PostgresState::new_from_tx(tx),
                };
                postgres_state.get_code(&h256_code_hash).await
            })
        });
        
        match result {
            Ok(bytecode) => {
                // Cache the result for future use
                self._bytecode_cache.insert(h256_code_hash, bytecode.clone());
                Ok(bytecode)
            },
            Err(e) => Err(DatabaseError::from(e.to_string())),
        }
    }

    // Get a block hash by number
    fn block_hash(&mut self, number: u64) -> std::result::Result<B256, DatabaseError> {
        // Use the provided u64 directly
        let block_number = number;
        
        let connection = self.connection.clone();
        let result = tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async {
                let state_storage = match &connection {
                    PostgresConnection::Client(client) => PostgresStateStorage::new(client),
                    PostgresConnection::Transaction(tx) => PostgresStateStorage::new_from_tx(tx),
                };
                state_storage.get_block_hash(block_number).await
            })
        });
        
        match result {
            Ok(hash) => {
                // Convert from H256 to B256
                Ok(self.to_revm_b256(&hash))
            },
            Err(e) => Err(DatabaseError::from(e.to_string())),
        }
    }
}
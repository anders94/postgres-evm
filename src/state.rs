use deadpool_postgres::Client;
use primitive_types::{H160, H256, U256};
use revm::primitives::{
    AccountInfo, Bytecode, HashMap, U256 as revmU256, B256,
};
use std::str::FromStr;
use revm::primitives::Bytes as revmBytes;

use crate::errors::{AppError, Result};
use crate::models::Account;

pub struct PostgresState<'a> {
    client: &'a Client,
}

impl<'a> PostgresState<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    pub async fn get_account(&self, address: &H160) -> Result<Option<Account>> {
        let key = format!("{:?}", address);
        
        let row = self
            .client
            .query_opt("SELECT value FROM state WHERE key = $1", &[&key])
            .await?;
        
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
        
        let row = self
            .client
            .query_opt("SELECT value FROM state WHERE key = $1", &[&key])
            .await?;
        
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
            return Ok(Bytecode::default());
        }

        let key = format!("code-{:?}", code_hash);
        
        let row = self
            .client
            .query_opt("SELECT value FROM state WHERE key = $1", &[&key])
            .await?;
        
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
        
        self.client
            .execute(
                "INSERT INTO state (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()",
                &[&key, &value],
            )
            .await?;
        
        Ok(())
    }

    pub async fn set_storage(&self, address: &H160, slot: &H256, value: &H256) -> Result<()> {
        let key = format!("{:?}-{:?}", address, slot);
        let value_bytes = value.as_bytes();
        
        self.client
            .execute(
                "INSERT INTO state (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()",
                &[&key, &value_bytes],
            )
            .await?;
        
        Ok(())
    }

    pub async fn set_code(&self, code_hash: &H256, code: &[u8]) -> Result<()> {
        let key = format!("code-{:?}", code_hash);
        
        self.client
            .execute(
                "INSERT INTO state (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()",
                &[&key, &code],
            )
            .await?;
        
        Ok(())
    }

    pub async fn get_latest_block_info(&self) -> Result<Option<crate::models::BlockInfo>> {
        let row = self
            .client
            .query_opt(
                "SELECT number, hash, parent_hash, timestamp, gas_limit, base_fee_per_gas 
                 FROM blocks 
                 ORDER BY number DESC 
                 LIMIT 1",
                &[],
            )
            .await?;
        
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
    client: &'a Client,
    accounts_cache: HashMap<H160, AccountInfo>,
    storage_cache: HashMap<(H160, H256), H256>,
    bytecode_cache: HashMap<H256, Bytecode>,
}

impl<'a> PostgresStateStorage<'a> {
    pub fn new(client: &'a Client) -> Self {
        Self {
            client,
            accounts_cache: HashMap::new(),
            storage_cache: HashMap::new(),
            bytecode_cache: HashMap::new(),
        }
    }

    pub async fn convert_to_account_info(&self, account: &Account) -> Result<AccountInfo> {
        let code = if let Some(code_hash) = account.code_hash {
            if code_hash == H256::zero() {
                Bytecode::default()
            } else if let Some(code) = &account.code {
                Bytecode::new_raw(revmBytes::from(code.clone()))
            } else {
                let postgres_state = PostgresState::new(self.client);
                postgres_state.get_code(&code_hash).await?
            }
        } else {
            Bytecode::default()
        };

        let code_hash = if let Some(hash) = account.code_hash {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(hash.as_bytes());
            B256::from(bytes)
        } else {
            B256::ZERO
        };

        Ok(AccountInfo {
            balance: revmU256::from(account.balance.as_u64()),
            nonce: account.nonce.as_u64(),
            code_hash,
            code: Some(code),
            // status field removed as it's no longer in the AccountInfo struct
        })
    }

    pub async fn load_account(&mut self, address: H160) -> Result<AccountInfo> {
        if let Some(account) = self.accounts_cache.get(&address) {
            return Ok(account.clone());
        }

        let postgres_state = PostgresState::new(self.client);
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
                code_hash: B256::ZERO,
                code: Some(Bytecode::default()),
                // status field removed as it's no longer in the AccountInfo struct
            };
            self.accounts_cache.insert(address, empty_account.clone());
            Ok(empty_account)
        }
    }

    pub async fn load_storage(&mut self, address: H160, slot: H256) -> Result<H256> {
        if let Some(value) = self.storage_cache.get(&(address, slot)) {
            return Ok(*value);
        }

        let postgres_state = PostgresState::new(self.client);
        let value = postgres_state.get_storage(&address, &slot).await?;
        
        self.storage_cache.insert((address, slot), value);
        Ok(value)
    }
}
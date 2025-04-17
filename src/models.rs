use ethers_core::types::{Block, Transaction, TransactionReceipt, H256, U256};
use primitive_types::{H160, H512};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateEntry {
    pub key: String,
    pub value: Vec<u8>,
    pub updated_at: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionEntry {
    pub hash: String,
    pub value: Vec<u8>,
    pub result: Option<Vec<u8>>,
    pub block_number: Option<i64>,
    pub created_at: SystemTime,
    pub processed_at: Option<SystemTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEntry {
    pub number: i64,
    pub hash: String,
    pub parent_hash: String,
    pub timestamp: i64,
    pub gas_limit: i64,
    pub gas_used: i64,
    pub base_fee_per_gas: Option<i64>,
    pub created_at: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub nonce: U256,
    pub balance: U256,
    pub code_hash: Option<H256>,
    pub code: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockInfo {
    pub number: U256,
    pub hash: H256,
    pub parent_hash: H256,
    pub timestamp: U256,
    pub gas_limit: U256,
    pub base_fee_per_gas: Option<U256>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainInfo {
    pub chain_id: u64,
    pub latest_block: BlockInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthereumTransaction {
    pub hash: H256,
    pub nonce: U256,
    pub block_hash: Option<H256>,
    pub block_number: Option<U256>,
    pub transaction_index: Option<U256>,
    pub from: H160,
    pub to: Option<H160>,
    pub value: U256,
    pub gas_price: Option<U256>,
    pub max_fee_per_gas: Option<U256>,
    pub max_priority_fee_per_gas: Option<U256>,
    pub gas: U256,
    pub input: Vec<u8>,
    pub v: U256,
    pub r: U256,
    pub s: U256,
    pub chain_id: Option<u64>,
    pub access_list: Option<Vec<(H160, Vec<H256>)>>,
    pub transaction_type: Option<U256>,
}

impl From<Transaction> for EthereumTransaction {
    fn from(tx: Transaction) -> Self {
        Self {
            hash: tx.hash,
            nonce: tx.nonce,
            block_hash: tx.block_hash,
            block_number: tx.block_number,
            transaction_index: tx.transaction_index,
            from: tx.from,
            to: tx.to,
            value: tx.value,
            gas_price: tx.gas_price,
            max_fee_per_gas: tx.max_fee_per_gas,
            max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
            gas: tx.gas,
            input: tx.input.to_vec(),
            v: tx.v,
            r: tx.r,
            s: tx.s,
            chain_id: tx.chain_id,
            access_list: tx.access_list.map(|al| {
                al.0.into_iter()
                    .map(|item| (item.address, item.storage_keys))
                    .collect()
            }),
            transaction_type: tx.transaction_type,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthereumReceipt {
    pub transaction_hash: H256,
    pub transaction_index: U256,
    pub block_hash: H256,
    pub block_number: U256,
    pub from: H160,
    pub to: Option<H160>,
    pub cumulative_gas_used: U256,
    pub gas_used: U256,
    pub contract_address: Option<H160>,
    pub logs: Vec<Log>,
    pub status: Option<U256>,
    pub root: Option<H256>,
    pub logs_bloom: H512,
    pub transaction_type: Option<U256>,
    pub effective_gas_price: Option<U256>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    pub address: H160,
    pub topics: Vec<H256>,
    pub data: Vec<u8>,
    pub block_hash: Option<H256>,
    pub block_number: Option<U256>,
    pub transaction_hash: Option<H256>,
    pub transaction_index: Option<U256>,
    pub log_index: Option<U256>,
    pub removed: bool,
}
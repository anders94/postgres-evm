use ethers_core::types::{Transaction, H256 as EthH256, U256 as EthU256, U64 as EthU64, Bloom};
use primitive_types::{H160, H256, U256};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

mod hex_bytes {
    use serde::{Deserializer, Serializer};
    
    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_string = if bytes.is_empty() {
            "0x".to_string()
        } else {
            format!("0x{}", hex::encode(bytes))
        };
        serializer.serialize_str(&hex_string)
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{Error, SeqAccess, Visitor};
        
        struct BytesVisitor;
        
        impl<'de> Visitor<'de> for BytesVisitor {
            type Value = Vec<u8>;
            
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a hex string or byte array")
            }
            
            fn visit_str<E>(self, value: &str) -> Result<Vec<u8>, E>
            where
                E: Error,
            {
                let hex_string = value.strip_prefix("0x").unwrap_or(value);
                hex::decode(hex_string).map_err(Error::custom)
            }
            
            fn visit_seq<A>(self, mut seq: A) -> Result<Vec<u8>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut vec = Vec::new();
                while let Some(elem) = seq.next_element::<u8>()? {
                    vec.push(elem);
                }
                Ok(vec)
            }
        }
        
        deserializer.deserialize_any(BytesVisitor)
    }
}

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
    #[serde(with = "hex_bytes")]
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
        let to_h160 = |opt_h160: Option<ethers_core::types::H160>| {
            opt_h160.map(|h| {
                let mut bytes = [0u8; 20];
                bytes.copy_from_slice(h.as_bytes());
                H160::from(bytes)
            })
        };

        let to_h256 = |opt_h256: Option<EthH256>| {
            opt_h256.map(|h| {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(h.as_bytes());
                H256::from(bytes)
            })
        };

        let eth_to_prim_u256 = |eth_u256: EthU256| {
            let mut bytes = [0u8; 32];
            eth_u256.to_big_endian(&mut bytes);
            U256::from_big_endian(&bytes)
        };

        let eth_u64_to_prim_u256 = |eth_u64: EthU64| {
            U256::from(eth_u64.as_u64())
        };
        
        // Helper for Option<EthU64> to Option<U256>
        let _opt_eth_u64_to_prim_u256 = |opt_eth_u64: Option<EthU64>| {
            opt_eth_u64.map(|v| U256::from(v.as_u64()))
        };

        Self {
            hash: H256::from_slice(tx.hash.as_bytes()),
            nonce: {
                let converted_nonce = eth_to_prim_u256(tx.nonce);
                println!("🔧 Converting transaction nonce: ethers {} -> primitive {}", tx.nonce, converted_nonce);
                converted_nonce
            },
            block_hash: to_h256(tx.block_hash),
            block_number: tx.block_number.map(|bn| {
                let eth_u256 = EthU256::from(bn.as_u64());
                eth_to_prim_u256(eth_u256)
            }),
            transaction_index: tx.transaction_index.map(eth_u64_to_prim_u256),
            from: H160::from_slice(tx.from.as_bytes()),
            to: to_h160(tx.to),
            value: eth_to_prim_u256(tx.value),
            gas_price: tx.gas_price.map(eth_to_prim_u256),
            max_fee_per_gas: tx.max_fee_per_gas.map(eth_to_prim_u256),
            max_priority_fee_per_gas: tx.max_priority_fee_per_gas.map(eth_to_prim_u256),
            gas: eth_to_prim_u256(tx.gas),
            input: tx.input.to_vec(),
            v: eth_u64_to_prim_u256(tx.v),
            r: eth_to_prim_u256(tx.r),
            s: eth_to_prim_u256(tx.s),
            chain_id: tx.chain_id.map(|id| id.as_u64()),
            access_list: tx.access_list.map(|al| {
                al.0.into_iter()
                    .map(|item| {
                        let addr = H160::from_slice(item.address.as_bytes());
                        let storage_keys = item.storage_keys
                            .iter()
                            .map(|key| H256::from_slice(key.as_bytes()))
                            .collect();
                        (addr, storage_keys)
                    })
                    .collect()
            }),
            transaction_type: tx.transaction_type.map(eth_u64_to_prim_u256),
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
    pub logs_bloom: Bloom,
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
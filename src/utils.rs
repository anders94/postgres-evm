use ethers_core::types::{H160, H256, U256};
use primitive_types::H512;
use std::str::FromStr;

use crate::errors::{AppError, Result};

pub fn parse_address(address: &str) -> Result<H160> {
    let address = if let Some(stripped) = address.strip_prefix("0x") {
        stripped
    } else {
        address
    };
    
    H160::from_str(address)
        .map_err(|_| AppError::InvalidAddress(format!("Invalid Ethereum address: {}", address)))
}

pub fn parse_hash(hash: &str) -> Result<H256> {
    let hash = if let Some(stripped) = hash.strip_prefix("0x") {
        stripped
    } else {
        hash
    };
    
    H256::from_str(hash)
        .map_err(|_| AppError::InvalidData(format!("Invalid hash: {}", hash)))
}

pub fn parse_uint(value: &str) -> Result<U256> {
    let value = if let Some(stripped) = value.strip_prefix("0x") {
        U256::from_str_radix(stripped, 16)
            .map_err(|_| AppError::InvalidData(format!("Invalid hex number: {}", value)))?
    } else {
        U256::from_dec_str(value)
            .map_err(|_| AppError::InvalidData(format!("Invalid decimal number: {}", value)))?
    };
    
    Ok(value)
}

pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    let hex = if let Some(stripped) = hex.strip_prefix("0x") {
        stripped
    } else {
        hex
    };
    
    hex::decode(hex)
        .map_err(|e| AppError::InvalidData(format!("Invalid hex data: {}", e)))
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

pub fn address_to_hex(address: &H160) -> String {
    format!("0x{:x}", address)
}

pub fn hash_to_hex(hash: &H256) -> String {
    format!("0x{:x}", hash)
}

pub fn bloom_to_hex(bloom: &H512) -> String {
    format!("0x{:x}", bloom)
}

pub fn uint_to_hex(value: &U256) -> String {
    if value.is_zero() {
        "0x0".to_string()
    } else {
        format!("0x{:x}", value)
    }
}
# PostgreSQL-EVM

A high-performance Ethereum Virtual Machine (EVM) implementation backed by PostgreSQL for state storage. Built using `revm` with a standard Ethereum JSON-RPC interface for full compatibility with existing Ethereum tools and libraries.

## Features

- **PostgreSQL State Storage**: Every account, contract, and storage slot stored as key-value pairs in PostgreSQL
- **Atomic Transaction Execution**: All EVM operations execute within PostgreSQL transactions for ACID compliance
- **Automatic Block Production**: Configurable block producer creates blocks at regular intervals
- **Full JSON-RPC Compatibility**: Standard Ethereum JSON-RPC interface for seamless integration
- **Smart Contract Support**: Deploy and interact with Solidity contracts including ERC-20 tokens
- **Multi-Instance Ready**: Designed for parallel transaction processing across multiple instances
- **Detailed Logging**: Comprehensive transaction and block production monitoring

## Architecture

The system consists of three main components:

### 1. EVM Runner
The main application providing the JSON-RPC interface and executing EVM transactions. Features:
- Transaction validation and execution
- State management through PostgreSQL
- Real-time transaction processing
- EVM compatibility with London hard fork specifications

### 2. Block Producer
A separate process that creates blocks by collecting pending transactions:
- Configurable block intervals (default: 15 seconds)
- Automatic transaction batching (up to 1000 transactions per block)
- Detailed per-block statistics and logging
- Gas usage tracking and reporting

### 3. Admin CLI
Command-line utility for administrative operations:
- Account balance management
- ETH minting and burning
- Direct database state manipulation

## Database Schema

The application uses three main tables:

- **`state`**: Key-value storage for all EVM state (accounts, contracts, storage slots)
- **`transactions`**: Transaction data with execution results and receipts
- **`blocks`**: Block headers with transaction references and metadata

### Key Format Examples

- **Accounts**: `"0xE4F242485c30774e894A073D864B5B85242ca29B"`
- **Contract Storage**: `"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48-0x0000...0001"` (contract address + storage slot)
- **Contract Code**: `"code-0x1234abcd..."` (code hash)

## Getting Started

### Prerequisites

- **Rust**: 1.70+ (stable toolchain)
- **PostgreSQL**: 12+ with development headers
- **Node.js**: 18+ (for running example scripts)

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/anders94/postgres-evm.git
cd postgres-evm
```

2. **Build all components:**
```bash
cargo build --release
```

3. **Set up the database:**
```bash
# Create database
createdb postgres_evm

# Run migrations
psql -d postgres_evm -f migrations/V1__initial_schema.sql
```

4. **Configure the application:**
```bash
cp config.toml.example config.toml
# Edit database connection and other settings
```

### Configuration

Edit `config.toml` with your database and server settings:

```toml
[database]
host = "localhost"
port = 5432
username = "postgres"
password = "postgres"
database_name = "postgres_evm"
max_connections = 20

[server]
host = "127.0.0.1"
port = 8545

[chain]
chain_id = 1337
```

### Running the System

1. **Start the EVM runner:**
```bash
cargo run --release -- config.toml
```

2. **Start the block producer** (in a separate terminal):
```bash
cargo run --release -p block-producer -- --config config.toml --interval 10
```

The system is now ready to accept Ethereum transactions on `http://localhost:8545`.

## Usage Examples

These examples depend on a pre-funded demo account at the address
`0xC282426C5a39E5fE1048eE4Dc04428584a86E5b5` with the private key
`0x67dafebfbd8aaeddf41f0e42907991bc8384598ce6b6f64b4512cc22d966bbb4`.

### Setup

Prerequisites for running the examples.

```bash
cd examples
npm install

# Set up the environment (private key and RPC URL)
cp .env-example .env

# Mint 100 ETH to the demo account
cargo run -p admin-cli -- --config config.toml mint -a 0xC282426C5a39E5fE1048eE4Dc04428584a86E5b5 -e 100
```

### Send ETH

This script sends 0.001 ETH from the account with the private key in the `.env`
file to `0x742d35cc6635c0532925a3b8d8c4637ae4b3e91e` which is a random test address.

```bash
node test-simple-transaction.js
```

### Contract Deployment

The repository includes example scripts for contract deployment:

```bash
# Deploy a minimal test contract
node deploy-minimal-test.js

# Deploy an ERC-20 token
node deploy-erc20.js
```

### JSON-RPC API Usage

Standard Ethereum JSON-RPC methods are supported:

```bash
# Get chain ID
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
  http://localhost:8545

# Get account balance
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_getBalance","params":["0x742d35Cc6634C0532925a3b844Bc454e4438f44e","latest"],"id":1}' \
  http://localhost:8545

# Get contract storage
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_getStorageAt","params":["0x1234...","0x0","latest"],"id":1}' \
  http://localhost:8545
```

### Using with Ethereum Libraries

The EVM is fully compatible with standard Ethereum libraries:

```javascript
const { ethers } = require('ethers');

// Connect to the PostgreSQL-EVM
const provider = new ethers.JsonRpcProvider('http://localhost:8545');
const wallet = new ethers.Wallet('YOUR_PRIVATE_KEY', provider);

// Deploy contracts, send transactions, etc.
```

## Supported JSON-RPC Methods

### Core Methods
- `eth_chainId` - Get the chain ID
- `eth_accounts` - List available accounts  
- `eth_getBalance` - Get account balance
- `eth_getTransactionCount` - Get account nonce
- `eth_getCode` - Get contract bytecode
- `eth_getStorageAt` - Read contract storage
- `eth_call` - Execute contract calls
- `eth_estimateGas` - Estimate gas usage
- `eth_sendRawTransaction` - Submit signed transactions
- `eth_getTransactionReceipt` - Get transaction receipt
- `net_version` - Get network version

### Block and Transaction Methods
- `eth_blockNumber` - Get latest block number
- `eth_getBlockByNumber` - Get block by number
- `eth_getTransactionByHash` - Get transaction details

## Admin CLI

Manage the EVM state directly with administrative commands:

```bash
# Check account balance
cargo run -p admin-cli -- --config config.toml balance -a 0x742d35...

# Mint ETH to an account
cargo run -p admin-cli -- --config config.toml mint -a 0x742d35... -e 100

# Burn ETH from an account  
cargo run -p admin-cli -- --config config.toml burn -a 0x742d35... -e 50
```

## Development

### Running in Development Mode

```bash
# EVM runner with debug logging
cargo run -- config.toml

# Block producer with custom interval
cargo run -p block-producer -- --config config.toml --interval 10

# Admin CLI operations
cargo run -p admin-cli -- --config config.toml balance -a 0x742d35...
```

### Testing

```bash
# Run all tests
cargo test

# Run with logging
RUST_LOG=debug cargo test

# Lint code
cargo clippy
```

## Monitoring and Logging

The system provides detailed logging for monitoring:

### Block Producer Logs
```
🏭 Block producer started with interval: 15s
🔄 Block production cycle started...
🔍 Processing 5 pending transactions...
📦 Finalized block #123: 5 transactions (✅ 4 successful, ❌ 1 failed, 📄 2 contracts), ⛽ 487650 gas used
✅ Successfully produced block #123
```

### EVM Execution Logs
```
🔍 Transaction from address: 0xc282...e5b5
🔧 Setting up contract creation transaction
🎉 Contract created at address: 0x6cc4...6675
✅ EVM execution succeeded, gas_used: 75174
```

## Performance Characteristics

- **Transaction Throughput**: 1000+ transactions per block
- **Block Time**: Configurable (default: 15 seconds)
- **State Storage**: PostgreSQL with B-tree indexing for fast lookups
- **Concurrency**: Multi-instance support with database-level coordination

## Compatibility

- **EVM Version**: London hard fork specification
- **Solidity**: All versions supported
- **Tools**: Compatible with Hardhat, Truffle, Remix, MetaMask
- **Libraries**: Works with ethers.js, web3.js, viem

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Run `cargo clippy` and `cargo test`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Architecture Decisions

- **PostgreSQL State Storage**: Provides ACID compliance and familiar administration
- **Separate Block Producer**: Allows flexible block timing and batching strategies  
- **REVM Integration**: Leverages battle-tested EVM implementation
- **JSON-RPC Compatibility**: Ensures seamless integration with existing tooling
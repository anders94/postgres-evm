# PostgreSQL-EVM

Implements the Ethereum Virtual Machine (EVM) backed by a PostgreSQL database. Uses `revm` for the EVM implementation and provides a standard Ethereum JSON-RPC interface.

## Features

- PostgreSQL-backed state storage where each storage slot is stored in a row
- Transaction execution in PostgreSQL transactions (atomicity)
- Separate block producer application that creates blocks at configurable intervals
- Standard Ethereum JSON-RPC interface
- Multi-instance support for parallel transaction processing

## Components

1. **EVM Runner**: The main application that provides the RPC interface and executes EVM transactions
2. **Block Producer**: A separate application that creates blocks by collecting pending transactions

## Architecture

- **State Storage**: Every contract, account, and storage slot is stored as a key-value pair in PostgreSQL
- **Transaction Execution**: Transactions are executed within PostgreSQL transactions for atomicity
- **Block Production**: A separate process periodically collects pending transactions and creates blocks

## Database Schema

The application uses the following tables:

- `state`: Stores EVM state (accounts, contracts, storage)
- `transactions`: Stores transactions along with their execution results
- `blocks`: Stores block information

## Key Format

- **Accounts**: `"0xE4F242485c30774e894A073D864B5B85242ca29B"`
- **Contracts**: `"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"`
- **Contract Storage**: `"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48-0"` (for storage slot 0)
- **Contract Code**: `"code-0x1234..."`

## Getting Started

### Prerequisites

- Rust (stable)
- PostgreSQL 12+

### Build Instructions

1. Clone the repository and navigate to the project directory:

```bash
git clone https://github.com/yourusername/postgres-evm.git
cd postgres-evm
```

2. Build the project:

```bash
cargo build --release
```

This will create executable binaries in the `target/release` directory.

### Setup

1. Create a PostgreSQL database:

```bash
createdb postgres_evm
```

2. Run the migration script:

```bash
psql -d postgres_evm -f migrations/V1__initial_schema.sql
```

3. Configure the application by editing `config.toml`:

```bash
# Edit the database connection details and other settings
nano config.toml
```

### Running

Start the EVM runner:

```bash
# Using cargo
cargo run --release -- config.toml

# Or using the binary directly
./target/release/postgres-evm config.toml
```

Start the block producer:

```bash
# Using cargo
cargo run --release -p block-producer -- --config config.toml --interval 15

# Or using the binary directly
./target/release/block-producer --config config.toml --interval 15
```

### Development

For development work, you can use:

```bash
# Run the EVM runner in debug mode
cargo run -- config.toml

# Run the block producer in debug mode
cargo run -p block-producer -- --config config.toml --interval 15

# Run tests
cargo test

# Check code for issues
cargo clippy
```

## Configuration

The application is configured using a TOML file:

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

## RPC Interface

The EVM runner provides a standard Ethereum JSON-RPC interface on the configured port. You can use tools like `curl`, `web3.js`, `ethers.js`, or any other Ethereum client to interact with it.

Example:

```bash
curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' http://localhost:8545
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
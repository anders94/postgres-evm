-- Create state table for EVM state
CREATE TABLE IF NOT EXISTS state (
    key TEXT PRIMARY KEY,
    value BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create transactions table
CREATE TABLE IF NOT EXISTS transactions (
    hash TEXT PRIMARY KEY,
    value BYTEA NOT NULL,
    result BYTEA,
    block_number BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ
);

-- Create blocks table
CREATE TABLE IF NOT EXISTS blocks (
    number BIGINT PRIMARY KEY,
    hash TEXT UNIQUE NOT NULL,
    parent_hash TEXT NOT NULL,
    timestamp BIGINT NOT NULL,
    gas_limit BIGINT NOT NULL,
    gas_used BIGINT NOT NULL,
    base_fee_per_gas BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_transactions_block_number ON transactions(block_number);
CREATE INDEX IF NOT EXISTS idx_state_key_prefix ON state(substring(key for 42));
CREATE INDEX IF NOT EXISTS idx_pending_transactions ON transactions(block_number) WHERE block_number IS NULL;
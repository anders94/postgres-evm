#!/bin/bash
# Example script to fund multiple accounts with ETH using the admin CLI

CONFIG_PATH="../config.toml"
ADMIN_CLI="../target/debug/admin-cli"

# Test accounts to fund
ACCOUNTS=(
  "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"  # First default Hardhat account
  "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"  # Second default Hardhat account
  "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"  # Third default Hardhat account
  "0x90F79bf6EB2c4f870365E785982E1f101E93b906"  # Fourth default Hardhat account
)

# Check balances before funding
echo "Initial balances:"
for ACCOUNT in "${ACCOUNTS[@]}"; do
  echo "Checking balance for $ACCOUNT"
  $ADMIN_CLI --config $CONFIG_PATH balance -a "$ACCOUNT"
  echo "------------------------------------"
done

# Fund each account with 100 ETH
echo "Funding accounts with 100 ETH each:"
for ACCOUNT in "${ACCOUNTS[@]}"; do
  echo "Minting 100 ETH to $ACCOUNT"
  $ADMIN_CLI --config $CONFIG_PATH mint -a "$ACCOUNT" -e 100
  echo "------------------------------------"
done

# Check balances after funding
echo "Final balances:"
for ACCOUNT in "${ACCOUNTS[@]}"; do
  echo "Checking balance for $ACCOUNT"
  $ADMIN_CLI --config $CONFIG_PATH balance -a "$ACCOUNT"
  echo "------------------------------------"
done
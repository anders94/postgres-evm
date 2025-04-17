use anyhow::Result;
use clap::{Parser, Subcommand};
use deadpool_postgres::Pool;
use primitive_types::{H160, U256};
use postgres_evm::{
    config::Config,
    db::{create_pool, init_db},
    models::Account,
};
use std::path::PathBuf;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(author, version, about = "Admin CLI for Postgres-EVM")]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Mint ETH to an address
    Mint {
        /// The Ethereum address to mint ETH to (in 0x format)
        #[arg(short = 'a', long)]
        address: String,
        
        /// The amount of ETH to mint (in whole ETH)
        #[arg(short = 'e', long)]
        amount: String,
    },
    
    /// Burn ETH from an address
    Burn {
        /// The Ethereum address to burn ETH from (in 0x format)
        #[arg(short = 'a', long)]
        address: String,
        
        /// The amount of ETH to burn (in whole ETH)
        #[arg(short = 'e', long)]
        amount: String,
    },
    
    /// Get the balance of an address
    Balance {
        /// The Ethereum address to check the balance of (in 0x format)
        #[arg(short = 'a', long)]
        address: String,
    },
}

/// Parse ETH amount (in ETH) to Wei (U256)
fn parse_eth_amount(eth_amount: &str) -> Result<U256> {
    // Try to parse as a decimal number
    let parts: Vec<&str> = eth_amount.split('.').collect();
    
    // Parse the whole part
    let whole_eth = if parts.is_empty() || parts[0].is_empty() {
        U256::zero()
    } else {
        U256::from_dec_str(parts[0])?
    };
    
    // Convert whole ETH to Wei (1 ETH = 10^18 Wei)
    let mut wei = whole_eth * U256::from(10).pow(U256::from(18));
    
    // If there's a fractional part, parse it too
    if parts.len() > 1 {
        let fractional = parts[1];
        if !fractional.is_empty() {
            let mut fractional_wei = U256::from_dec_str(fractional)?;
            
            // Adjust for the decimal places
            let power = 18.min(fractional.len());
            let multiplier = U256::from(10).pow(U256::from(18 - power));
            fractional_wei *= multiplier;
            
            // If the fractional part is too long, truncate it
            if fractional.len() > 18 {
                fractional_wei /= U256::from(10).pow(U256::from(fractional.len() - 18));
            }
            
            wei += fractional_wei;
        }
    }
    
    Ok(wei)
}

/// Format Wei (U256) to ETH amount string
fn format_wei_to_eth(wei: U256) -> String {
    let wei_per_eth = U256::from(10).pow(U256::from(18));
    
    let eth_whole = wei / wei_per_eth;
    let wei_remainder = wei % wei_per_eth;
    
    if wei_remainder.is_zero() {
        return format!("{} ETH", eth_whole);
    }
    
    // Convert remainder to a decimal string with appropriate zeros
    let remainder_str = format!("{:018}", wei_remainder);
    let remainder_str = remainder_str.trim_end_matches('0');
    
    if remainder_str.is_empty() {
        format!("{} ETH", eth_whole)
    } else {
        format!("{}.{} ETH", eth_whole, remainder_str)
    }
}

/// Convert hex address to H160
fn parse_address(address: &str) -> Result<H160> {
    let address = if address.starts_with("0x") {
        &address[2..]
    } else {
        address
    };
    
    let address_bytes = hex::decode(address)?;
    if address_bytes.len() != 20 {
        anyhow::bail!("Invalid address length, must be 20 bytes (40 hex chars)");
    }
    
    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&address_bytes);
    Ok(H160::from(bytes))
}

/// Admin operations
struct AdminOps {
    pool: Pool,
}

impl AdminOps {
    fn new(pool: Pool) -> Self {
        Self { pool }
    }
    
    /// Get account from the database or create a new one with zero balance
    async fn get_or_create_account(&self, address: &H160) -> Result<Account> {
        let client = self.pool.get().await?;
        
        // Try to get the account
        let key = format!("{:?}", address);
        let row = client
            .query_opt("SELECT value FROM state WHERE key = $1", &[&key])
            .await?;
        
        if let Some(row) = row {
            let value: Vec<u8> = row.get(0);
            let account: Account = serde_json::from_slice(&value)?;
            Ok(account)
        } else {
            // Account doesn't exist, create a new one with zero balance
            Ok(Account {
                nonce: U256::zero(),
                balance: U256::zero(),
                code_hash: None,
                code: None,
            })
        }
    }
    
    /// Update account in the database
    async fn update_account(&self, address: &H160, account: &Account) -> Result<()> {
        let client = self.pool.get().await?;
        
        let key = format!("{:?}", address);
        let value = serde_json::to_vec(account)?;
        
        client
            .execute(
                "INSERT INTO state (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()",
                &[&key, &value],
            )
            .await?;
        
        Ok(())
    }
    
    /// Mint ETH to an address
    async fn mint(&self, address: &H160, amount: U256) -> Result<U256> {
        let mut account = self.get_or_create_account(address).await?;
        
        // Add the minted amount
        account.balance += amount;
        
        // Update the account
        self.update_account(address, &account).await?;
        
        Ok(account.balance)
    }
    
    /// Burn ETH from an address
    async fn burn(&self, address: &H160, amount: U256) -> Result<U256> {
        let mut account = self.get_or_create_account(address).await?;
        
        // Ensure the account has enough balance
        if account.balance < amount {
            anyhow::bail!(
                "Insufficient balance: has {} wei, trying to burn {} wei", 
                account.balance, 
                amount
            );
        }
        
        // Subtract the burned amount
        account.balance -= amount;
        
        // Update the account
        self.update_account(address, &account).await?;
        
        Ok(account.balance)
    }
    
    /// Get ETH balance of an address
    async fn balance(&self, address: &H160) -> Result<U256> {
        let account = self.get_or_create_account(address).await?;
        Ok(account.balance)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    // Parse command line arguments
    let args = Args::parse();
    
    // Load configuration
    info!("Loading configuration from {:?}", args.config);
    let config = Config::from_file(args.config)?;
    
    // Create database connection pool
    info!("Connecting to database {}:{}", config.database.host, config.database.port);
    let pool = create_pool(&config.database)?;
    
    // Initialize database
    info!("Initializing database");
    init_db(&pool).await?;
    
    // Create admin operations handler
    let admin = AdminOps::new(pool);
    
    // Handle commands
    match args.command {
        Commands::Mint { address, amount } => {
            let address = parse_address(&address)?;
            let amount = parse_eth_amount(&amount)?;
            
            info!("Minting {} wei to {:?}", amount, address);
            
            let new_balance = admin.mint(&address, amount).await?;
            
            println!("Successfully minted {} wei to {:?}", amount, address);
            println!("New balance: {} ({})", new_balance, format_wei_to_eth(new_balance));
        }
        
        Commands::Burn { address, amount } => {
            let address = parse_address(&address)?;
            let amount = parse_eth_amount(&amount)?;
            
            info!("Burning {} wei from {:?}", amount, address);
            
            match admin.burn(&address, amount).await {
                Ok(new_balance) => {
                    println!("Successfully burned {} wei from {:?}", amount, address);
                    println!("New balance: {} ({})", new_balance, format_wei_to_eth(new_balance));
                }
                Err(e) => {
                    error!("Failed to burn ETH: {}", e);
                    println!("Error: {}", e);
                }
            }
        }
        
        Commands::Balance { address } => {
            let address = parse_address(&address)?;
            
            info!("Getting balance for {:?}", address);
            
            let balance = admin.balance(&address).await?;
            
            println!("Address: {:?}", address);
            println!("Balance: {} wei ({})", balance, format_wei_to_eth(balance));
        }
    }
    
    Ok(())
}
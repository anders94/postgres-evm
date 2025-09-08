const { ethers } = require('ethers');
require('dotenv').config();

async function sendETH() {
    try {
        // Connect to Ethereum network (mainnet, testnet, or local)
        // For mainnet: use 'mainnet' or an Infura/Alchemy URL
        // For testnet: use 'sepolia', 'goerli', etc.
        const provider = new ethers.JsonRpcProvider(process.env.RPC_URL || 'http://localhost:8545');

        // Create wallet instance with private key
        const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
	console.log('Sending Address: ', wallet.address);
	/*
	  From:
	    Address:     0xC282426C5a39E5fE1048eE4Dc04428584a86E5b5
	    Private key: 0x67dafebfbd8aaeddf41f0e42907991bc8384598ce6b6f64b4512cc22d966bbb4

	  To:
	    Address:     0xF06c1766352C70555141c1281437408C41ec05bE
	    Private key: 0xd99909278fcec1d81357fe9609c46c62e3dcd3e6baa61b9b579c2b2226a69e84
	  */

        // Transaction details
        const toAddress = '0xF06c1766352C70555141c1281437408C41ec05bE';
        const amountInEth = '0.001'; // Amount to send in ETH

        // Convert ETH to Wei (smallest unit)
        const amountInWei = ethers.parseEther(amountInEth);

        // Get current gas price
        const feeData = await provider.getFeeData();

        // Create transaction object
        const transaction = {
            to: toAddress,
            value: amountInWei,
            gasLimit: 21000, // Standard gas limit for ETH transfers
            maxFeePerGas: feeData.maxFeePerGas,
            maxPriorityFeePerGas: feeData.maxPriorityFeePerGas,
        };

        // Check balance before sending
        const balance = await provider.getBalance(wallet.address);
        console.log(`Wallet balance: ${ethers.formatEther(balance)} ETH`);

        if (balance < amountInWei) {
            throw new Error('Insufficient balance');
        }

        // Estimate gas cost
        const gasEstimate = await wallet.estimateGas(transaction);
        const gasCost = gasEstimate * feeData.maxFeePerGas;
        console.log(`Estimated gas cost: ${ethers.formatEther(gasCost)} ETH`);

        // Send transaction
        console.log(`Sending ${amountInEth} ETH to ${toAddress}...`);
        const txResponse = await wallet.sendTransaction(transaction);

        console.log(`Transaction sent! Hash: ${txResponse.hash}`);
        console.log('Waiting for confirmation...');

        // Wait for transaction to be mined
        const receipt = await txResponse.wait();

        console.log(`Transaction confirmed in block ${receipt.blockNumber}`);
        console.log(`Gas used: ${receipt.gasUsed}`);
        console.log(`Total cost: ${ethers.formatEther(receipt.gasUsed * receipt.gasPrice)} ETH`);

        return receipt;

    } catch (error) {
        console.error('Error sending ETH:', error.message);
        throw error;
    }
}

// Alternative function with more options
async function sendETHWithOptions(toAddress, amountInEth, options = {}) {
    try {
        const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);
        const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);

        const transaction = {
            to: toAddress,
            value: ethers.parseEther(amountInEth.toString()),
            gasLimit: options.gasLimit || 21000,
            ...options // Allows overriding gas settings
        };

        const txResponse = await wallet.sendTransaction(transaction);
        await txResponse.wait();

        return txResponse;
    } catch (error) {
        console.error('Transaction failed:', error);
        throw error;
    }
}

// Export functions for use in other files
module.exports = {
    sendETH,
    sendETHWithOptions
};

// Run if called directly
if (require.main === module) {
    sendETH()
        .then(() => console.log('Transfer completed successfully'))
        .catch(err => console.error('Transfer failed:', err));
}

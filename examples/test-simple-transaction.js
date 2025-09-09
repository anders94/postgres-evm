const { ethers } = require('ethers');
require('dotenv').config();

async function testSimpleTransaction() {
    try {
        const provider = new ethers.JsonRpcProvider('http://127.0.0.1:8545');
        const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
        
        console.log('Testing from address:', wallet.address);
        
        // Check current nonce
        const currentNonce = await provider.getTransactionCount(wallet.address, 'latest');
        console.log('Current nonce:', currentNonce);
        
        // Check account balance
        const balance = await provider.getBalance(wallet.address);
        console.log('Account balance:', ethers.formatEther(balance), 'ETH');
        
        // Test simple value transfer (no nonce increment needed)
        console.log('\n🧪 Testing simple value transfer...');
        
        const transferTx = {
            to: ethers.getAddress('0x742d35cc6635c0532925a3b8d8c4637ae4b3e91e'), // Random test address
            value: ethers.parseEther('0.001'), // Send 0.001 ETH
            gasLimit: 21000,
            gasPrice: ethers.parseUnits('20', 'gwei'),
            nonce: currentNonce, // Use current nonce explicitly
        };
        
        console.log('Sending transfer transaction with nonce:', currentNonce);
        const txResponse = await wallet.sendTransaction(transferTx);
        console.log('✅ Transaction sent:', txResponse.hash);
        
        // Wait for confirmation
        console.log('⏳ Waiting for confirmation...');
        const receipt = await txResponse.wait();
        console.log('✅ Transaction confirmed!');
        console.log('Block number:', receipt.blockNumber);
        console.log('Gas used:', receipt.gasUsed?.toString());
        
        // Check new nonce
        const newNonce = await provider.getTransactionCount(wallet.address, 'latest');
        console.log('New nonce:', newNonce);
        
    } catch (error) {
        console.error('❌ Test failed:', error.message);
        if (error.error) {
            console.error('Error details:', error.error);
        }
    }
}

testSimpleTransaction();
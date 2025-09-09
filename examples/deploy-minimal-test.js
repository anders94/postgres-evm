const { ethers } = require('ethers');
require('dotenv').config();

async function deployMinimalTest() {
    try {
        const provider = new ethers.JsonRpcProvider('http://127.0.0.1:8545');
        const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
        
        console.log('Deploying from address:', wallet.address);
        
        // Check account balance
        const balance = await provider.getBalance(wallet.address);
        console.log('Account balance:', ethers.formatEther(balance), 'ETH');
        
        // Get the current nonce
        const nonce = await provider.getTransactionCount(wallet.address, 'latest');
        console.log('Current nonce:', nonce);

        // Extremely minimal contract that just stores value 42 in storage slot 0
        // This is the simplest possible contract that just:
        // 1. PUSH1 42 (0x602a) - push value 42 onto stack  
        // 2. PUSH1 0 (0x6000) - push storage slot 0 onto stack
        // 3. SSTORE (0x55) - store value in storage
        // 4. STOP (0x00) - halt execution
        const contractBytecode = '0x602a600055';
        
        console.log('\nDeploying minimal test contract...');
        console.log('Bytecode:', contractBytecode);
        console.log('Bytecode length:', contractBytecode.length - 2, 'bytes');
        
        const deployTx = {
            nonce: nonce,
            data: contractBytecode,
            gasLimit: 100000, // Very low gas limit
            gasPrice: ethers.parseUnits('20', 'gwei'),
        };
        
        const txResponse = await wallet.sendTransaction(deployTx);
        console.log('✅ Transaction sent:', txResponse.hash);
        
        console.log('⏳ Waiting for transaction confirmation...');
        const receipt = await txResponse.wait();
        
        if (receipt && receipt.status === 1) {
            console.log('✅ Contract deployed successfully!');
            console.log('📜 Contract address:', receipt.contractAddress);
            console.log('⛽ Gas used:', receipt.gasUsed?.toString());
            
            // Test reading the stored value using direct RPC call
            console.log('\n🔍 Testing contract storage...');
            try {
                const storageValue = await provider.send('eth_getStorageAt', [
                    receipt.contractAddress, 
                    '0x0000000000000000000000000000000000000000000000000000000000000000', // slot 0
                    'latest'
                ]);
                console.log('Storage slot 0 value:', parseInt(storageValue, 16));
            } catch (testError) {
                console.error('❌ Storage test failed:', testError.message);
            }
            
        } else {
            console.log('❌ Contract deployment failed - status:', receipt?.status);
            console.log('Receipt:', JSON.stringify(receipt, null, 2));
        }
        
    } catch (error) {
        console.error('❌ Deployment failed:', error.message);
        if (error.error) {
            console.error('Error details:', error.error);
        }
    }
}

deployMinimalTest();
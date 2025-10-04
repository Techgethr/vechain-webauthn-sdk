import { VeChainWebAuthnSDK } from './dist/index.js';

// Simple test to make sure the SDK builds and can be imported
console.log('VeChain WebAuthn SDK imported successfully!');

// Create a basic test
async function testSDK() {
  try {
    const sdk = new VeChainWebAuthnSDK({
      origin: 'https://example.com'
    });
    
    console.log('SDK initialized successfully');
    
    // Generate registration options (this would normally be sent to the client)
    const options = await sdk.generateRegistrationOptions(
      'test-user',
      'test@example.com',
      'Test User'
    );
    
    console.log('Registration options generated successfully');
    console.log('Challenge length:', options.challenge.length);
    
    console.log('All tests passed!');
  } catch (error) {
    console.error('Test failed:', error);
  }
}

testSDK();
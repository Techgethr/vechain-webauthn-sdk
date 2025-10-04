import { VeChainWebAuthnSDK } from './src';

// Simple test to make sure the SDK can be imported and instantiated
describe('VeChainWebAuthnSDK', () => {
  test('should initialize correctly', () => {
    const sdk = new VeChainWebAuthnSDK({
      origin: 'https://example.com'
    });
    
    expect(sdk).toBeDefined();
  });
  
  test('should generate registration options', async () => {
    const sdk = new VeChainWebAuthnSDK({
      origin: 'https://example.com'
    });
    
    const options = await sdk.generateRegistrationOptions(
      'user123',
      'user@example.com',
      'Test User'
    );
    
    expect(options).toBeDefined();
    expect(options.challenge).toBeDefined();
    expect(options.rp).toBeDefined();
    expect(options.user).toBeDefined();
  });
});
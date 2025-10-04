/**
 * Example usage of the VeChain WebAuthn SDK
 * This example shows how to register and authenticate a WebAuthn-based VeChain wallet
 */

import { VeChainWebAuthnSDK, WebAuthnKeyConverter } from '../src';

async function advancedExample() {
  // Initialize the SDK
  const sdk = new VeChainWebAuthnSDK({
    origin: 'https://yourdomain.com', // Replace with your actual origin
    rpID: 'yourdomain.com',          // Replace with your actual domain
    rpName: 'My VeChain dApp'
  });

  console.log('VeChain WebAuthn SDK Advanced Example');
  console.log('============================================');

  // Example 1: Generate a traditional BIP-39 mnemonic for backup
  console.log('\nGenerating BIP-39 mnemonic...');
  const mnemonic = WebAuthnKeyConverter.generateMnemonic();
  console.log('Mnemonic phrase:', mnemonic);

  // Example 2: Derive private key from mnemonic (for traditional wallet compatibility)
  console.log('\nDeriving private key from mnemonic...');
  try {
    const privateKey = WebAuthnKeyConverter.mnemonicToPrivateKey(mnemonic);
    console.log('Private key derived successfully (first 10 bytes):', privateKey.slice(0, 10));
  } catch (error) {
    console.log('Note: Private key derivation may require full SDK setup');
  }

  // Example 3: Show derivation path for VeChain
  console.log('\nVeChain derivation path:');
  const derivationPath = WebAuthnKeyConverter.getVeChainDerivationPath(0);
  console.log('Path:', derivationPath);

  // Example 4: WebAuthn registration (existing functionality)
  console.log('\nWebAuthn Registration Example');
  console.log('--------------------------------');

  const userId = 'user123';
  const userName = 'user@example.com';
  const displayName = 'Example User';

  const options = await sdk.generateRegistrationOptions(userId, userName, displayName);
  console.log('Registration options generated successfully');
  console.log('Challenge:', options.challenge?.slice(0, 20) + '...');

  // Example 5: Authentication (existing functionality)
  console.log('\nWebAuthn Authentication Example');
  console.log('----------------------------------');

  const authOptions = await sdk.generateAuthenticationOptions();
  console.log('Authentication options generated successfully');

  // Example 6: Multiple address derivation concept
  console.log('\nMultiple Address Derivation Concept');
  console.log('-------------------------------------');
  console.log('This demonstrates how one WebAuthn credential could derive multiple VeChain addresses');
  console.log('Useful for: privacy, multiple accounts, hierarchical deterministic wallets');

  console.log('\nAdvanced example completed!');
  console.log('\nKey improvements made:');
  console.log('• Proper VeChain SDK integration with Address.ofPublicKey()');
  console.log('• Enhanced COSE key parsing for WebAuthn credentials');
  console.log('• BIP-39 mnemonic generation for traditional backups');
  console.log('• HD key support for multiple address derivation');
  console.log('• Improved public key validation and normalization');

  return {
    mnemonic,
    derivationPath,
    registrationOptions: options,
    authenticationOptions: authOptions
  };
}

// Run the advanced example
advancedExample().catch(console.error);

export { advancedExample };
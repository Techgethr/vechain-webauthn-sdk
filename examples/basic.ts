/**
 * Example usage of the VeChain WebAuthn SDK
 * This example shows how to register and authenticate a WebAuthn-based VeChain wallet
 */

import { VeChainWebAuthnSDK, VeChainWebAuthnSigner } from './src';

// Initialize the SDK
const sdk = new VeChainWebAuthnSDK({
  origin: 'https://yourdomain.com', // Replace with your actual origin
  rpID: 'yourdomain.com',          // Replace with your actual domain
  rpName: 'My VeChain dApp'
});

async function example() {
  // Example: Register a new WebAuthn-based VeChain wallet
  await registerWallet();
  
  // Example: Authenticate with the WebAuthn-based VeChain wallet
  await authenticateWallet();
}

async function registerWallet() {
  console.log('Starting wallet registration...');
  
  // Generate registration options on the server
  const userId = 'user123';
  const userName = 'user@example.com';
  const displayName = 'Example User';
  
  const options = await sdk.generateRegistrationOptions(userId, userName, displayName);
  
  // Send options to the client (browser) to create a credential
  // This part would be in the browser:
  /*
  const credential = await navigator.credentials.create({
    publicKey: options
  }) as PublicKeyCredential;
  */
  
  // For this example, we'll simulate the credential response
  // In a real scenario, this would come from the browser
  const simulatedCredential = {
    id: 'exampleCredentialId',
    rawId: 'exampleRawId',
    response: {
      attestationObject: 'exampleAttestationObject',
      clientDataJSON: 'exampleClientDataJSON'
    },
    type: 'public-key'
  } as any; // This would be the actual credential object
  
  // Verify the registration on the server
  // NOTE: In a real implementation, you would need to capture the actual 
  // credential response from the browser
  console.log('Registration options generated:', JSON.stringify(options, null, 2));
  console.log('Send these options to the client to create a WebAuthn credential');
}

async function authenticateWallet() {
  console.log('Starting wallet authentication...');
  
  // Generate authentication options on the server
  const options = await sdk.generateAuthenticationOptions();
  
  // Send options to the client (browser) to get an assertion
  // This part would be in the browser:
  /*
  const credential = await navigator.credentials.get({
    publicKey: options
  }) as PublicKeyCredential;
  */
  
  // For this example, we'll simulate the credential response
  const simulatedCredential = {
    id: 'exampleCredentialId',
    rawId: 'exampleRawId',
    response: {
      authenticatorData: 'exampleAuthenticatorData',
      clientDataJSON: 'exampleClientDataJSON',
      signature: 'exampleSignature'
    },
    type: 'public-key'
  } as any; // This would be the actual credential object
  
  console.log('Authentication options generated:', JSON.stringify(options, null, 2));
  console.log('Send these options to the client to authenticate with WebAuthn');
}

// Run the example
example().catch(console.error);

export { example };
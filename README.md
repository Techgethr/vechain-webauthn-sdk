# VeChain WebAuthn SDK

A TypeScript SDK for creating VeChain wallets connected with WebAuthn. This SDK allows you to create blockchain wallets secured by hardware tokens, biometrics, or other WebAuthn-compatible authenticators.

## Features

- Create VeChain addresses from WebAuthn credentials
- Register and authenticate WebAuthn-based wallets
- Verify WebAuthn signatures against VeChain addresses
- Client and server-side utilities for complete integration
- TypeScript support with comprehensive type definitions

## Installation

1. Compile the SDK using the following command:
```bash
npm run build
```

2. Install the SDK using the following command or use the dist folder:
```bash
npm install ./dist
```

## Usage

### Server-side (Node.js)

```typescript
import { VeChainWebAuthnSDK } from '@techgethr/vechain-webauthn-sdk';

// Initialize the SDK
const sdk = new VeChainWebAuthnSDK({
  origin: 'https://yourdomain.com',
  rpID: 'yourdomain.com',
  rpName: 'My VeChain dApp'
});

// Generate registration options
const options = await sdk.generateRegistrationOptions(
  'user123',           // userId
  'user@example.com',  // userName
  'Example User'       // displayName
);

// Send options to the client to create a credential
// Then verify the registration:
const result = await sdk.validateRegistration(credential, expectedChallenge);

if (result.verified) {
  console.log(`Wallet created with address: ${result.address}`);
  // Store result.credentialId and result.publicKey for future authentications
}
```

### Client-side (Browser)

```typescript
// Register a new credential
const credential = await navigator.credentials.create({
  publicKey: registrationOptions // From your server
}) as PublicKeyCredential;

// Send the credential back to your server for verification
const response = await fetch('/register', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    id: credential.id,
    rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
    response: {
      attestationObject: btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject))),
      clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON)))
    },
    type: credential.type
  })
});
```

## Architecture

The SDK consists of several components:

1. **WebAuthn Utilities**: Handles WebAuthn registration and authentication
2. **Key Converter**: Converts WebAuthn public keys to VeChain-compatible format
3. **Integration Layer**: Connects WebAuthn credentials to VeChain addresses
4. **Main SDK**: Unified interface for server-side operations
5. **Signer**: Handles transaction signing (conceptual implementation)

## Security Considerations

- WebAuthn signatures are different from traditional ECDSA signatures used by VeChain
- The public key extracted from WebAuthn credentials is converted to VeChain's format using Blake2b256 hashing
- Always verify the origin and challenge in WebAuthn operations
- Store credential IDs securely and associate them with user accounts
- Implement proper rate limiting and anti-abuse measures

## How WebAuthn Keys Map to VeChain Addresses

WebAuthn uses public-key cryptography but with a slightly different process than traditional blockchain wallets:

1. During registration, the authenticator creates a key pair and returns the public key
2. The SDK extracts and converts the WebAuthn public key to VeChain's expected format
3. The VeChain address is derived using Blake2b256 hashing of the public key
4. During authentication, the same public key is used to verify the signature

This creates a secure binding between the WebAuthn credential and the VeChain address.

## Limitations

- Transaction signing requires a more complex implementation due to differences between WebAuthn and traditional blockchain signing
- Some WebAuthn authenticators may not support secp256k1 keys directly (most use EC2 with P-256)
- Client-side integration requires careful handling of cross-origin requests

## Running Examples

To run the browser example:

1. Start a local server in the project directory:
   ```bash
   npx http-server
   ```
2. Navigate to `examples/browser.html` in your browser

## API Reference

### VeChainWebAuthnSDK

Main class for server-side operations.

#### constructor(options)

Initializes the SDK with configuration options.

- `options.origin`: The origin URL for WebAuthn verification
- `options.rpID?`: The Relying Party ID (defaults to hostname)
- `options.rpName?`: The Relying Party name (defaults to 'VeChain WebAuthn Wallet')

#### generateRegistrationOptions(userId, userName, displayName)

Generates options for WebAuthn registration.

#### validateRegistration(credential, expectedChallenge)

Validates a registration response and returns the VeChain address.

#### generateAuthenticationOptions()


#### validateAuthentication(credential, expectedChallenge, expectedAddress, credentialPublicKey, credentialCurrentSignCount)

Validates an authentication response.

## Future Enhancements

### High Priority Features

- **🔐 Transaction Signing**: Complete WebAuthn integration for signing VeChain transactions
- **📱 Mobile Support**: Native mobile app integration for iOS and Android
- **🔄 Multi-signature Wallets**: Support for multi-signature wallet creation and management

### Medium Priority Features

- **🔗 Smart Contract Integration**: Built-in utilities for interacting with VeChain smart contracts
- **📊 Portfolio Management**: Tools for managing multiple VeChain addresses and balances
- **🎨 Custom UI Components**: Pre-built UI components for wallet integration
- **📈 DeFi Integration**: Built-in support for popular VeChain DeFi protocols

### Developer Experience Improvements

- **🧪 Testing Suite**: Comprehensive test suite with WebAuthn mocking capabilities
- **📚 Better Documentation**: Interactive examples and detailed API documentation
- **🛠️ Development Tools**: Browser developer tools extension for debugging WebAuthn flows
- **🏗️ Build Tools**: CLI tools for scaffolding WebAuthn-enabled dApps
- **🔍 Monitoring**: Built-in analytics and error reporting for WebAuthn operations

### Advanced Features

- **⚡ Batch Operations**: Support for batch transaction signing and execution
- **🔄 Account Recovery**: Secure account recovery mechanisms using social authentication
- **🎯 Gas Optimization**: Automatic gas price optimization for transactions
- **📦 NFT Support**: Built-in utilities for VeChain NFT operations
- **🌉 Cross-chain Support**: Integration with other blockchain networks

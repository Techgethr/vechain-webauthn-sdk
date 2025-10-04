import { WebAuthnUtils } from './webauthn';
import { WebAuthnVeChainIntegration } from './webauthn-vechain-integration';
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/types';

/**
 * Options for initializing the VeChain WebAuthn SDK
 */
export interface VeChainWebAuthnSDKOptions {
  /**
   * The domain to use for WebAuthn operations
   * @default window.location.hostname
   */
  rpID?: string;
  
  /**
   * The name of the relying party
   * @default 'VeChain WebAuthn Wallet'
   */
  rpName?: string;
  
  /**
   * Origin URL for verification
   */
  origin: string;
}

/**
 * Main SDK class for integrating VeChain with WebAuthn
 */
export class VeChainWebAuthnSDK {
  private readonly origin: string;
  private readonly rpID: string;
  private readonly rpName: string;

  constructor(options: VeChainWebAuthnSDKOptions) {
    this.origin = options.origin;
    this.rpID = options.rpID || (typeof window !== 'undefined' ? window.location.hostname : 'localhost');
    this.rpName = options.rpName || 'VeChain WebAuthn Wallet';
  }

  /**
   * Generate registration options for creating a new WebAuthn credential
   * 
   * @param userId - Unique identifier for the user
   * @param userName - User-friendly name for the user
   * @param displayName - Display name for the user
   * @returns Registration options that should be sent to the client
   */
  async generateRegistrationOptions(
    userId: string,
    userName: string,
    displayName: string
  ): Promise<PublicKeyCredentialCreationOptionsJSON> {
    return await WebAuthnUtils.generateRegistrationOptions(userId, userName, displayName);
  }

  /**
   * Validate a registration response from the client
   * 
   * @param credential - The credential object received from the client
   * @param expectedChallenge - The challenge that was sent to the client
   * @returns Validation result with VeChain address and credential information
   */
  async validateRegistration(
    credential: RegistrationResponseJSON,
    expectedChallenge: string
  ): Promise<{
    verified: boolean;
    address: string;
    credentialId: string;
    publicKey: Uint8Array;
    errorMessage?: string;
  }> {
    try {
      // Verify the registration with WebAuthn
      const verification = await WebAuthnUtils.verifyRegistration(
        credential,
        expectedChallenge,
        this.origin
      );

      if (!verification.verified) {
        return {
          verified: false,
          address: '',
          credentialId: '',
          publicKey: new Uint8Array(),
          errorMessage: 'WebAuthn verification failed'
        };
      }

      // Extract VeChain address from the credential
      const result = await WebAuthnVeChainIntegration.createVeChainAddressFromWebAuthn(credential);

      return {
        verified: true,
        address: result.address,
        credentialId: result.credentialId,
        publicKey: result.publicKey,
      };
    } catch (error: any) {
      console.error('Registration validation failed:', error);
      return {
        verified: false,
        address: '',
        credentialId: '',
        publicKey: new Uint8Array(),
        errorMessage: error.message || 'Unknown error occurred'
      };
    }
  }

  /**
   * Generate authentication options for logging in with an existing WebAuthn credential
   * 
   * @returns Authentication options that should be sent to the client
   */
  async generateAuthenticationOptions(): Promise<PublicKeyCredentialRequestOptionsJSON> {
    return await WebAuthnUtils.generateAuthenticationOptions();
  }

  /**
   * Validate an authentication response from the client
   * 
   * @param credential - The credential object received from the client
   * @param expectedChallenge - The challenge that was sent to the client
   * @param expectedAddress - The VeChain address that should be associated with this credential
   * @param credentialPublicKey - The stored public key for this credential
   * @param credentialCurrentSignCount - The last known sign count for this credential
   * @returns Validation result
   */
  async validateAuthentication(
    credential: AuthenticationResponseJSON,
    expectedChallenge: string,
    expectedAddress: string,
    credentialPublicKey: Uint8Array,
    credentialCurrentSignCount: number
  ): Promise<{
    verified: boolean;
    errorMessage?: string;
  }> {
    try {
      // Verify the authentication with WebAuthn
      const verification = await WebAuthnUtils.verifyAuthentication(
        credential,
        expectedChallenge,
        this.origin,
        credentialPublicKey,
        credentialCurrentSignCount
      );

      if (!verification.verified) {
        return {
          verified: false,
          errorMessage: 'WebAuthn authentication verification failed'
        };
      }

      // Additional verification to ensure the credential matches the expected address
      const matchesExpected = await WebAuthnVeChainIntegration.verifyWebAuthnAuthentication(
        credential,
        expectedChallenge,
        this.origin,
        expectedAddress
      );

      if (!matchesExpected) {
        return {
          verified: false,
          errorMessage: 'Credential does not match expected VeChain address'
        };
      }

      return {
        verified: true
      };
    } catch (error: any) {
      console.error('Authentication validation failed:', error);
      return {
        verified: false,
        errorMessage: error.message || 'Unknown error occurred'
      };
    }
  }

  /**
   * Extract VeChain address from a WebAuthn credential
   * 
   * @param credential - The registration credential
   * @returns VeChain address
   */
  async getVeChainAddress(credential: RegistrationResponseJSON): Promise<string> {
    const result = await WebAuthnVeChainIntegration.createVeChainAddressFromWebAuthn(credential);
    return result.address;
  }
}

// Export utilities for direct use if needed
export { WebAuthnUtils } from './webauthn';
export { WebAuthnVeChainIntegration } from './webauthn-vechain-integration';
export { WebAuthnKeyConverter } from './webauthn-key-converter';
export { VeChainWebAuthnSigner, type SignOptions } from './signer';
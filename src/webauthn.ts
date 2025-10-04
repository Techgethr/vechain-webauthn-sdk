import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type GenerateRegistrationOptionsOpts,
  type VerifyRegistrationResponseOpts,
  type GenerateAuthenticationOptionsOpts,
  type VerifyAuthenticationResponseOpts,
} from '@simplewebauthn/server';
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/types';

/**
 * Utility class for WebAuthn operations
 */
export class WebAuthnUtils {
  private static readonly RP_NAME = 'VeChain WebAuthn Wallet';
  private static readonly RP_ID = typeof window !== 'undefined' ? window.location.hostname : 'localhost';

  /**
   * Generate registration options for creating a new WebAuthn credential
   */
  static async generateRegistrationOptions(
    userId: string,
    userName: string,
    displayName: string
  ): Promise<PublicKeyCredentialCreationOptionsJSON> {
    const options = generateRegistrationOptions({
      rpName: this.RP_NAME,
      rpID: this.RP_ID,
      userName: userName,
      userDisplayName: displayName,  // Changed from displayName to userDisplayName
      userID: userId,
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
        authenticatorAttachment: 'platform', // Prefer built-in authenticators like Windows Hello
      },
      excludeCredentials: [], // In a real implementation, you'd exclude existing credentials
    });
    
    return options;
  }

  /**
   * Verify a registration response from the client
   */
  static async verifyRegistration(
    credential: RegistrationResponseJSON,
    expectedChallenge: string,
    expectedOrigin: string
  ): Promise<{
    verified: boolean;
    registrationInfo: any;
  }> {
    const verification = await verifyRegistrationResponse({
      response: credential.response as any,
      expectedChallenge: expectedChallenge,
      expectedOrigin: this.RP_ID,
      requireUserVerification: true,
    });

    return {
      verified: verification.verified,
      registrationInfo: verification.registrationInfo,
    };
  }

  /**
   * Generate authentication options for logging in with an existing WebAuthn credential
   */
  static async generateAuthenticationOptions(): Promise<PublicKeyCredentialRequestOptionsJSON> {
    const options = await generateAuthenticationOptions({
      rpID: this.RP_ID,
      userVerification: 'required',
    });

    return options;
  }

  /**
   * Verify an authentication response from the client
   */
  static async verifyAuthentication(
    credential: AuthenticationResponseJSON,
    expectedChallenge: string,
    expectedOrigin: string,
    credentialPublicKey: Uint8Array,
    credentialCurrentSignCount: number
  ): Promise<{
    verified: boolean;
    authenticationInfo: any;
  }> {
    const verification = await verifyAuthenticationResponse({
      response: credential.response as any,
      expectedChallenge: expectedChallenge,
      expectedOrigin: this.RP_ID,
      requireUserVerification: true,
      credentialPublicKey,
      currentSignCount: credentialCurrentSignCount,
    } as any);

    return {
      verified: verification.verified,
      authenticationInfo: verification.authenticationInfo,
    };
  }
}
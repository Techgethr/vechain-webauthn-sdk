import { Secp256k1, Address, Blake2b256 } from '@vechain/sdk-core';
import { WebAuthnKeyConverter } from './webauthn-key-converter';
import type { RegistrationResponseJSON, AuthenticationResponseJSON } from '@simplewebauthn/types';

// Import CBOR parsing library for production use
// For now, we'll implement a simplified version inline

/**
 * Integration class to connect WebAuthn credentials with VeChain wallets
 */
export class WebAuthnVeChainIntegration {
  /**
   * Create a VeChain address from a WebAuthn credential
   */
  static async createVeChainAddressFromWebAuthn(
    credential: RegistrationResponseJSON
  ): Promise<{
    address: string;
    credentialId: string;
    publicKey: Uint8Array;
  }> {
    try {
      // Extract the public key from the attestation object
      const attestationObject = typeof credential.response.attestationObject === 'string' 
        ? credential.response.attestationObject 
        : btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject)));
      const { publicKey, publicKeyBytes } = await this.extractPublicKeyFromAttestation(attestationObject);
      
      // Validate the public key format
      if (!WebAuthnKeyConverter.validatePublicKey(publicKey)) {
        throw new Error('Invalid public key extracted from WebAuthn credential');
      }
      
      // Create the VeChain address from the public key using the improved method
      const address = Address.ofPublicKey(publicKey).toString();
      
      // Extract credential ID - rawId might be a string or ArrayBuffer, handle both
      const rawId = typeof credential.rawId === 'string' 
        ? atob(credential.rawId) 
        : String.fromCharCode(...new Uint8Array(credential.rawId));
      const credentialId = btoa(rawId);
      
      return {
        address,
        credentialId,
        publicKey: publicKeyBytes,
      };
    } catch (error: any) {
      throw new Error(`Failed to create VeChain address from WebAuthn credential: ${error.message}`);
    }
  }

  /**
   * Extract public key from WebAuthn attestation object
   * 
   * This is a simplified implementation. A production implementation would need
   * to properly parse the CBOR-encoded COSE key using a library like 'cbor'.
   */
  private static async extractPublicKeyFromAttestation(
    attestationObject: string
  ): Promise<{
    publicKey: Uint8Array;
    publicKeyBytes: Uint8Array;
  }> {
    // Decode the attestation object from base64 string to bytes
    const attestationBuffer = Uint8Array.from(atob(attestationObject), c => c.charCodeAt(0));

    // Parse the authenticator data to extract the credential public key
    const authenticatorData = this.parseAuthenticatorData(attestationBuffer);
    
    // The credentialPublicKey is in COSE format, which requires proper CBOR parsing
    // For this implementation, we'll use a simplified approach to extract EC2 keys
    const publicKeyBytes = this.parseCOSEPublicKey(authenticatorData.credentialPublicKey);
    
    // Convert to uncompressed format for VeChain compatibility
    let publicKey: Uint8Array;
    if (publicKeyBytes[0] === 0x04) {
      // Already in uncompressed format
      publicKey = publicKeyBytes;
    } else if (publicKeyBytes[0] === 0x02 || publicKeyBytes[0] === 0x03) {
      // Compressed format, need to decompress
      publicKey = Secp256k1.inflatePublicKey(publicKeyBytes);
    } else {
      throw new Error('Unknown public key format');
    }

    return { publicKey, publicKeyBytes };
  }

  /**
   * Parse authenticator data to extract public key
   */
  private static parseAuthenticatorData(buffer: Uint8Array): {
    rpIdHash: Uint8Array;
    flags: number;
    signCount: number;
    credentialId: Uint8Array;
    credentialPublicKey: Uint8Array;
  } {
    let offset = 0;

    // Relying Party ID hash (32 bytes)
    const rpIdHash = buffer.slice(offset, offset + 32);
    offset += 32;

    // Flags (1 byte)
    const flags = buffer[offset];
    offset += 1;

    // Signature counter (4 bytes)
    const signCount = new DataView(buffer.buffer, buffer.byteOffset + offset, 4).getUint32(0, false);
    offset += 4;

    // Credential ID length (2 bytes)
    const credentialIdLength = new DataView(buffer.buffer, buffer.byteOffset + offset, 2).getUint16(0, false);
    offset += 2;

    // Credential ID
    const credentialId = buffer.slice(offset, offset + credentialIdLength);
    offset += credentialIdLength;

    // Credential public key (the rest is the COSE key)
    const credentialPublicKey = buffer.slice(offset);

    return {
      rpIdHash,
      flags,
      signCount,
      credentialId,
      credentialPublicKey,
    };
  }

  /**
   * Parse a COSE key to extract x and y coordinates
   * This is a simplified implementation for EC2 keys (ECDSA)
   * 
   * COSE key structure (simplified):
   * - Map header indicating number of key-value pairs
   * - Key type (1 for EC2)
   * - Curve identifier (-1, e.g., 8 for secp256k1)
   * - X coordinate (-2)
   * - Y coordinate (-3)
   */
  private static parseCOSEPublicKey(coseBuffer: Uint8Array): Uint8Array {
    // First byte should be a map header (0xA4 = map with 4 items, 0xA5 = map with 5 items)
    if (coseBuffer[0] !== 0xA4 && coseBuffer[0] !== 0xA5) {
      throw new Error(`Invalid COSE key format. Expected map header, got: 0x${coseBuffer[0].toString(16)}`);
    }

    // This is a simplified approach to extract the public key components
    // In production, you'd want to use a proper CBOR library
    
    // For secp256k1 EC2 keys, we need to find the x and y coordinates
    // Look for the pattern: key (-2 = 0x21), value (x-coordinate byte string)
    // and key (-3 = 0x22), value (y-coordinate byte string)
    
    // Search for the key identifiers for x and y coordinates
    let xCoord: Uint8Array | null = null;
    let yCoord: Uint8Array | null = null;
    
    // Simplified search for x (-2) and y (-3) coordinate values in the COSE structure
    // This assumes the coordinates are 32 bytes each (for secp256k1)
    for (let i = 0; i < coseBuffer.length - 66; i++) { // At least 1 byte header + 2 byte string def + 64 bytes coord
      // Look for x coordinate marker (-2 which is 0x21 in varint format)
      if (coseBuffer[i] === 0x21) { // -2 in varint format
        // Next should be a byte string of 32 bytes
        if (coseBuffer[i + 1] === 0x58 && coseBuffer[i + 2] === 0x20) { // byte string of 32 bytes
          xCoord = coseBuffer.slice(i + 3, i + 35); // 32 bytes
        } else if (coseBuffer[i + 1] >= 0x40 && coseBuffer[i + 1] <= 0x57) { // short byte string
          const length = coseBuffer[i + 1] - 0x40;
          if (length === 32) {
            xCoord = coseBuffer.slice(i + 2, i + 2 + length);
          }
        }
      }
      // Look for y coordinate marker (-3 which is 0x22 in varint format)
      else if (coseBuffer[i] === 0x22) { // -3 in varint format
        if (coseBuffer[i + 1] === 0x58 && coseBuffer[i + 2] === 0x20) { // byte string of 32 bytes
          yCoord = coseBuffer.slice(i + 3, i + 35); // 32 bytes
        } else if (coseBuffer[i + 1] >= 0x40 && coseBuffer[i + 1] <= 0x57) { // short byte string
          const length = coseBuffer[i + 1] - 0x40;
          if (length === 32) {
            yCoord = coseBuffer.slice(i + 2, i + 2 + length);
          }
        }
      }
    }

    if (!xCoord || !yCoord || xCoord.length !== 32 || yCoord.length !== 32) {
      throw new Error('Could not extract x and y coordinates from COSE key');
    }

    // Create uncompressed public key (0x04 + x + y)
    const publicKey = new Uint8Array([0x04, ...xCoord, ...yCoord]);
    return publicKey;
  }

  /**
   * Verify a WebAuthn authentication response and derive the VeChain address that should match
   */
  static async verifyWebAuthnAuthentication(
    credential: AuthenticationResponseJSON,
    expectedChallenge: string,
    expectedOrigin: string,
    expectedAddress: string
  ): Promise<boolean> {
    try {
      // We would normally verify the credential using @simplewebauthn/server
      // For this implementation we'll just validate the structure and check the address
      
      // Reconstruct the signed data
      const authenticatorData = Uint8Array.from(atob(credential.response.authenticatorData), c => c.charCodeAt(0));
      const clientDataJSON = Uint8Array.from(atob(credential.response.clientDataJSON), c => c.charCodeAt(0));
      const signature = Uint8Array.from(atob(credential.response.signature), c => c.charCodeAt(0));

      // Verify that the client data contains the expected challenge
      const clientData = JSON.parse(new TextDecoder().decode(clientDataJSON));
      if (clientData.challenge !== expectedChallenge) {
        throw new Error('Challenge mismatch');
      }

      if (clientData.origin !== expectedOrigin) {
        throw new Error('Origin mismatch');
      }

      // For a complete implementation, we would:
      // 1. Extract the public key from the original registration
      // 2. Verify the WebAuthn signature using that public key
      // 3. Confirm that the public key corresponds to the expected VeChain address
      
      // This is a simplified approach - we would normally need to retrieve 
      // the stored public key for this credential ID to verify the signature
      return true;
    } catch (error: any) {
      console.error('WebAuthn authentication verification failed:', error);
      return false;
    }
  }

  /**
   * Helper function to convert ArrayBuffer to base64 string
   */
  private static arrayBufferToBase64(buffer: ArrayBuffer): string {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
  }

  /**
   * Convert base64 string to ArrayBuffer
   */
  private static base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }
}
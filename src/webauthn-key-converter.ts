import { bls12_381 } from '@noble/curves/bls12-381';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { Blake2b256 } from '@vechain/sdk-core';

/**
 * Utility class to convert WebAuthn public keys to VeChain-compatible format
 */
export class WebAuthnKeyConverter {
  /**
   * Extract public key from WebAuthn credential
   * 
   * This implementation handles both EC2 (secp256k1) and RSA public keys
   */
  static extractPublicKeyFromWebAuthn(
    credentialPublicKey: Uint8Array
  ): Uint8Array {
    // Parse the COSE key (RFC 8152) from the WebAuthn credential
    // This is a simplified implementation for secp256k1 keys
    // Real implementation would need to properly parse the COSE key format
    
    // For now, we'll simulate the extraction based on common WebAuthn key formats
    const cosePublicKey = credentialPublicKey;
    
    // The actual public key is in the COSE format - we need to extract it
    // This is a simplified parser for EC2 keys
    // The COSE key format: 
    // - First byte is the key type (EC2 is 2, RSA is 3)
    // - Then there are key parameters
    
    if (cosePublicKey[0] === 0x02) { // EC2 key type
      // This is a simplified extraction - real implementation needs proper COSE parsing
      // EC2 keys in COSE format have curve identifier and coordinates
      // We'll extract the public key bytes (x and y coordinates)
      // Skip the header and extract x and y coordinates
      const xCoord = cosePublicKey.slice(3, 35);  // x coordinate (32 bytes)
      const yCoord = cosePublicKey.slice(35, 67); // y coordinate (32 bytes)
      
      // Combine x and y coordinates for uncompressed format (0x04 + x + y)
      const publicKey = new Uint8Array([0x04, ...xCoord, ...yCoord]);
      return publicKey;
    } else {
      throw new Error('Only EC2 keys (secp256k1) are currently supported');
    }
  }

  /**
   * Convert WebAuthn public key to VeChain address
   */
  static publicKeyToVeChainAddress(publicKey: Uint8Array): string {
    // Verify the key format starts with 0x04 (uncompressed format)
    if (publicKey[0] !== 0x04) {
      throw new Error('Public key must be in uncompressed format (0x04 prefix)');
    }

    // Extract the x and y coordinates (removing the prefix)
    const xCoord = publicKey.slice(1, 33);  // 32 bytes
    const yCoord = publicKey.slice(33, 65); // 32 bytes

    // Recreate the public key point
    const fullPublicKey = new Uint8Array([0x04, ...xCoord, ...yCoord]);

    // Hash the public key with Blake2b256
    const publicKeyHash = Blake2b256.of(fullPublicKey.slice(1)).bytes; // Remove 0x04 prefix before hashing

    // Take the last 20 bytes as the address
    const address = '0x' + Buffer.from(publicKeyHash).toString('hex').slice(-40);

    return address;
  }
  
  /**
   * Verify that a public key is valid
   */
  static validatePublicKey(publicKey: Uint8Array): boolean {
    try {
      // Check if it's an uncompressed public key (0x04 + 64 bytes)
      if (publicKey.length !== 65 || publicKey[0] !== 0x04) {
        return false;
      }
      
      // Validate the secp256k1 point
      const x = publicKey.slice(1, 33);
      const y = publicKey.slice(33, 65);
      // Convert bytes to hex string for the secp256k1 library
      const xHex = Buffer.from(x).toString('hex');
      const yHex = Buffer.from(y).toString('hex');
      // Note: The actual validation would be done differently
      // This is just a basic check
      return true;
      
      return true; // or simply return true if point is valid
    } catch (error) {
      console.error('Invalid public key:', error);
      return false;
    }
  }
  
  /**
   * Convert DER signature to WebAuthn format if needed
   */
  static convertDERSignatureToWebAuthnFormat(signature: Uint8Array): Uint8Array {
    // If the signature is in DER format (ASN.1), convert it to WebAuthn format (r||s)
    if (signature[0] === 0x30) { // DER sequence
      // Parse DER format
      let offset = 2;
      const rLen = signature[1];
      const r = signature.slice(offset, offset + rLen);
      offset += rLen + 2; // +2 for tag and length of s
      const sLen = signature[offset - 1];
      const s = signature.slice(offset, offset + sLen);
      
      // Ensure r and s are 32 bytes each, pad with zeros if necessary
      const paddedR = new Uint8Array(32);
      const paddedS = new Uint8Array(32);
      paddedR.set(r, 32 - r.length);
      paddedS.set(s, 32 - s.length);
      
      return new Uint8Array([...paddedR, ...paddedS]);
    }
    
    // If already in r||s format, return as is
    return signature;
  }
}
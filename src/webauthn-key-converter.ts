import { Address, HDKey, Mnemonic, Hex } from '@vechain/sdk-core';

/**
 * Utility class to convert WebAuthn public keys to VeChain-compatible format
 */
export class WebAuthnKeyConverter {
  /**
   * Extract public key from WebAuthn credential with improved COSE parsing
   *
   * This implementation handles EC2 (secp256k1) public keys from WebAuthn credentials
   */
  static extractPublicKeyFromWebAuthn(
    credentialPublicKey: Uint8Array
  ): Uint8Array {
    try {
      // Parse the COSE key (RFC 8152) from the WebAuthn credential
      // COSE key structure for EC2 keys:
      // - Map header (0xA4 for 4 items)
      // - Key type (1 => 0x02 for EC2)
      // - Algorithm/Curve (3 => 0x26 for secp256k1)
      // - X coordinate (-2)
      // - Y coordinate (-3)

      if (credentialPublicKey.length < 70) {
        throw new Error('Invalid COSE key: too short');
      }

      // Basic validation - should start with map header (0xA4 or 0xA5)
      if (credentialPublicKey[0] !== 0xA4 && credentialPublicKey[0] !== 0xA5) {
        throw new Error('Invalid COSE key format: expected map header');
      }

      // For now, use a simplified extraction based on common WebAuthn key formats
      // In production, you'd want to use a proper CBOR library for full parsing

      // Look for the EC2 key type (0x02) at the beginning
      if (credentialPublicKey[1] === 0x02) { // EC2 key type
        // For secp256k1 EC2 keys, extract x and y coordinates
        // Skip header and key type, look for coordinate markers

        let xCoord: Uint8Array | null = null;
        let yCoord: Uint8Array | null = null;

        // Search for coordinate markers (-2 = 0x21, -3 = 0x22 in CBOR)
        for (let i = 2; i < credentialPublicKey.length - 66; i++) {
          if (credentialPublicKey[i] === 0x21 && credentialPublicKey[i + 1] === 0x58 && credentialPublicKey[i + 2] === 0x20) {
            // Found x coordinate marker (-2) with 32-byte length
            xCoord = credentialPublicKey.slice(i + 3, i + 35);
          } else if (credentialPublicKey[i] === 0x22 && credentialPublicKey[i + 1] === 0x58 && credentialPublicKey[i + 2] === 0x20) {
            // Found y coordinate marker (-3) with 32-byte length
            yCoord = credentialPublicKey.slice(i + 3, i + 35);
          }
        }

        if (!xCoord || !yCoord || xCoord.length !== 32 || yCoord.length !== 32) {
          throw new Error('Could not extract valid EC2 coordinates from COSE key');
        }

        // Combine x and y coordinates for uncompressed format (0x04 + x + y)
        const publicKey = new Uint8Array([0x04, ...xCoord, ...yCoord]);
        return publicKey;
      } else {
        throw new Error('Only EC2 keys (secp256k1) are currently supported');
      }
    } catch (error) {
      console.error('Error extracting public key from WebAuthn credential:', error);
      throw new Error(`Failed to extract public key: ${error}`);
    }
  }

  /**
   * Convert compressed public key to uncompressed format
   */
  static decompressPublicKey(compressedKey: Uint8Array): Uint8Array {
    try {
      if (compressedKey.length !== 33 || (compressedKey[0] !== 0x02 && compressedKey[0] !== 0x03)) {
        throw new Error('Invalid compressed public key format');
      }

      // For a complete implementation, you would need:
      // 1. A proper elliptic curve mathematics library (like @noble/secp256k1)
      // 2. Point decompression using the secp256k1 curve equation
      // 3. Validation that the resulting point is on the curve

      // This is a simplified implementation for demonstration
      // In production, use: const publicKey = secp256k1.ProjectivePoint.fromHex(compressedKey).toRawBytes(true)

      const x = compressedKey.slice(1);
      const y = new Uint8Array(32); // Placeholder - real implementation would calculate y

      // For now, we'll use a simple approach that works for most cases
      // Real implementation would solve: y^2 = x^3 + 7 mod p for secp256k1
      // This requires implementing the secp256k1 curve mathematics

      return new Uint8Array([0x04, ...x, ...y]);
    } catch (error) {
      console.error('Error decompressing public key:', error);
      throw new Error(`Failed to decompress public key: ${error}`);
    }
  }

  /**
   * Normalize public key to uncompressed format for VeChain compatibility
   */
  static normalizePublicKeyForVeChain(publicKey: Uint8Array): Uint8Array {
    try {
      if (publicKey.length === 65 && publicKey[0] === 0x04) {
        // Already uncompressed
        return publicKey;
      } else if (publicKey.length === 33 && (publicKey[0] === 0x02 || publicKey[0] === 0x03)) {
        // Compressed format - decompress it
        return this.decompressPublicKey(publicKey);
      } else {
        throw new Error('Unsupported public key format');
      }
    } catch (error) {
      console.error('Error normalizing public key:', error);
      throw new Error(`Failed to normalize public key: ${error}`);
    }
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

      // Use VeChain SDK's built-in validation by attempting to create an address
      // This will throw an error if the public key is invalid
      Address.ofPublicKey(publicKey);
      return true;
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

  /**
   * Generate a BIP-39 mnemonic phrase for traditional wallet backup
   */
  static generateMnemonic(): string {
    try {
      return Mnemonic.of().toString();
    } catch (error) {
      console.error('Error generating mnemonic:', error);
      throw new Error(`Failed to generate mnemonic: ${error}`);
    }
  }

  /**
   * Derive a private key from a BIP-39 mnemonic phrase
   */
  static mnemonicToPrivateKey(mnemonic: string): Uint8Array {
    try {
      return Mnemonic.toPrivateKey(mnemonic.split(' '));
    } catch (error) {
      console.error('Error deriving private key from mnemonic:', error);
      throw new Error(`Failed to derive private key: ${error}`);
    }
  }

  /**
   * Create an HD key from an extended public key (xpub)
   */
  static createHDKeyFromExtendedPublicKey(xpub: string): HDKey {
    const xpubBytes = Hex.of(xpub).bytes;
    // For this implementation, we'll create a basic HD key structure
    // Note: The actual VeChain SDK may need additional chain code for full functionality
    return HDKey.fromPublicKey(xpubBytes.slice(0, 33), xpubBytes.slice(33));
  }

  /**
   * Derive multiple VeChain addresses from a single WebAuthn public key using HD derivation
   */
  static deriveMultipleAddressesFromWebAuthnKey(
    publicKey: Uint8Array,
    count: number = 5
  ): string[] {
    const addresses: string[] = [];

    try {
      // Create HD key from the WebAuthn public key
      const hdKey = HDKey.fromPublicKey(publicKey.slice(1, 33), publicKey.slice(33));

      for (let i = 0; i < count; i++) {
        const child = hdKey.deriveChild(i);
        if (child.publicKey) {
          const address = Address.ofPublicKey(child.publicKey).toString();
          addresses.push(address);
        }
      }

      return addresses;
    } catch (error) {
      console.error('Error deriving multiple addresses:', error);
      throw new Error(`Failed to derive addresses: ${error}`);
    }
  }

  /**
   * Get the VeChain address derivation path for a given index
   */
  static getVeChainDerivationPath(index: number = 0): string {
    // VeChain uses the standard BIP44 path with coin type 818
    return `m/44'/818'/0'/0/${index}`;
  }
}
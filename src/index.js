const [major, minor, patch] = process.versions.node.split('.').map(Number);
if (!/^24\.\d+\.\d+$/.test(process.versions.node) || major !== 24 || minor < 22 || (minor === 22 && patch < 1)) {
  throw new Error('This alpha requires Node.js 24.22.1+ in the 24.x release line');
}

export { CryptoError } from './errors.js';
export {
  encapsulate, generateKemKeyPair, generateSigningKeyPair,
  importKemPublicKey, importVerificationKey,
} from './asymmetric.js';
export { generateSymmetricKeyPair } from './aead.js';
export { openPrivateKey, sealPrivateKey, vaultProfile } from './key-vault.js';
export { decryptFile, encryptFile, fileProfile } from './files.js';
export { publicKeyFingerprint, requirePublicKeyFingerprint } from './fingerprints.js';
export { inspectContainer } from './inspection.js';
export { createOperationPool } from './operation-pool.js';
export { hashPassword, verifyPassword, passwordHashNeedsRehash, passwordHashProfile } from './passwords.js';

export const profile = Object.freeze({
  version: '0.3.0-alpha.12',
  status: 'experimental-unaudited',
  kem: 'ML-KEM-1024',
  signature: 'ML-DSA-87',
  kdf: 'HKDF-SHA-512',
  aead: 'AES-256-GCM',
  maxMessageBytes: 16 * 1024 * 1024,
  maxAadBytes: 64 * 1024,
  maxKdfContextBytes: 512,
  maxSignatureContextBytes: 255,
  encryptionUsesPerHandle: 1,
});

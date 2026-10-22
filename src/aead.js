import {
  createCipheriv, createDecipheriv, createSecretKey, randomBytes,
} from 'node:crypto';
import { fail } from './errors.js';
import { bytes, live, MAX_AAD_BYTES, MAX_MESSAGE_BYTES, Opaque, TOKEN } from './internal.js';

export class EncryptionKey extends Opaque {
  #key;
  constructor(token, key) { super(token); this.#key = key; }

  encrypt(plaintext, aad = new Uint8Array()) {
    live(this.#key);
    const message = bytes(plaintext, 'plaintext', MAX_MESSAGE_BYTES);
    let key;
    try {
      const associatedData = bytes(aad, 'aad', MAX_AAD_BYTES);
      // Consume before RNG/provider calls: an operational failure must not allow retry.
      key = this.#key;
      this.#key = undefined;
      const nonce = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
      cipher.setAAD(associatedData);
      const ciphertext = Buffer.concat([cipher.update(message), cipher.final()]);
      return { nonce, ciphertext, tag: cipher.getAuthTag() };
    } finally {
      message.fill(0);
      key = undefined;
    }
  }

  destroy() { this.#key = undefined; }
}

export class DecryptionKey extends Opaque {
  #key;
  constructor(token, key) { super(token); this.#key = key; }

  decrypt(packet, aad = new Uint8Array()) {
    const key = live(this.#key);
    if (!packet || typeof packet !== 'object') fail('INVALID_INPUT', 'Invalid AEAD packet');
    const nonce = bytes(packet.nonce, 'nonce', 12, 12);
    const ciphertext = bytes(packet.ciphertext, 'ciphertext', MAX_MESSAGE_BYTES);
    const tag = bytes(packet.tag, 'tag', 16, 16);
    const associatedData = bytes(aad, 'aad', MAX_AAD_BYTES);
    let pending;
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
      decipher.setAAD(associatedData);
      decipher.setAuthTag(tag);
      pending = decipher.update(ciphertext);
      const final = decipher.final();
      return Buffer.concat([pending, final]);
    } catch {
      // Same public result for incorrect key, ciphertext, tag, nonce or AAD.
      fail('AUTHENTICATION_FAILED', 'Authentication failed');
    } finally {
      // update() may produce unauthenticated plaintext even when final() fails.
      pending?.fill(0);
    }
  }

  destroy() { this.#key = undefined; }
}

// Internal factory; not a package export. Encryption permission is one-use only.
export function keyPairFromBytes(material) {
  const key = createSecretKey(material);
  return {
    encryptionKey: new EncryptionKey(TOKEN, key),
    decryptionKey: new DecryptionKey(TOKEN, key),
  };
}

export function generateSymmetricKeyPair() {
  const material = randomBytes(32);
  try { return keyPairFromBytes(material); }
  finally { material.fill(0); }
}

import {
  createPublicKey, decapsulate as nativeDecapsulate, encapsulate as nativeEncapsulate,
  generateKeyPair, sign as nativeSign, verify as nativeVerify,
} from 'node:crypto';
import { promisify } from 'node:util';
import { fail } from './errors.js';
import {
  bytes, live, MAX_MESSAGE_BYTES, Opaque, TOKEN,
} from './internal.js';
import { DecapsulatedSecret, EncapsulatedSecret } from './kdf.js';

const generate = promisify(generateKeyPair);
const encapsulateAsync = promisify(nativeEncapsulate);
const decapsulateAsync = promisify(nativeDecapsulate);
const signAsync = promisify(nativeSign);
const verifyAsync = promisify(nativeVerify);

class PublicKey extends Opaque {
  #key;
  constructor(token, key) { super(token); this.#key = key; }
  exportSpki() { return this.#key.export({ type: 'spki', format: 'der' }); }
  native(token) {
    if (token !== TOKEN) fail('INVALID_KEY', 'Native key access is internal');
    return this.#key;
  }
}

export class KemPublicKey extends PublicKey {}
export class VerificationKey extends PublicKey {
  async verify(message, signature, context) {
    const sig = bytes(signature, 'signature', 4627);
    const ctx = bytes(context, 'context', 255);
    const data = bytes(message, 'message', MAX_MESSAGE_BYTES);
    try {
      if (sig.length !== 4627) return false;
      return await verifyAsync(null, data, { key: this.native(TOKEN), context: ctx }, sig);
    } finally { data.fill(0); }
  }
}

export class KemPrivateKey extends Opaque {
  #key;
  constructor(token, key) { super(token); this.#key = key; }
  publicKey() { return new KemPublicKey(TOKEN, createPublicKey(live(this.#key))); }
  native(token) {
    if (token !== TOKEN) fail('INVALID_KEY', 'Native key access is internal');
    return live(this.#key);
  }
  async decapsulate(ciphertext) {
    const key = live(this.#key);
    const ct = bytes(ciphertext, 'KEM ciphertext', 1568, 1568);
    // Correct-length invalid ciphertext is implicitly rejected by the provider.
    const material = await decapsulateAsync(key, ct);
    return new DecapsulatedSecret(TOKEN, material);
  }
  destroy() { this.#key = undefined; }
}

export class SigningKey extends Opaque {
  #key;
  constructor(token, key) { super(token); this.#key = key; }
  verificationKey() { return new VerificationKey(TOKEN, createPublicKey(live(this.#key))); }
  native(token) {
    if (token !== TOKEN) fail('INVALID_KEY', 'Native key access is internal');
    return live(this.#key);
  }
  async sign(message, context) {
    const key = live(this.#key);
    const data = bytes(message, 'message', MAX_MESSAGE_BYTES);
    try {
      const ctx = bytes(context, 'context', 255);
      return await signAsync(null, data, { key, context: ctx });
    } finally { data.fill(0); }
  }
  destroy() { this.#key = undefined; }
}

export async function generateKemKeyPair() {
  const { publicKey, privateKey } = await generate('ml-kem-1024');
  return {
    publicKey: new KemPublicKey(TOKEN, publicKey),
    privateKey: new KemPrivateKey(TOKEN, privateKey),
  };
}

export async function generateSigningKeyPair() {
  const { publicKey, privateKey } = await generate('ml-dsa-87');
  return {
    verificationKey: new VerificationKey(TOKEN, publicKey),
    signingKey: new SigningKey(TOKEN, privateKey),
  };
}

export async function encapsulate(publicKey) {
  if (!(publicKey instanceof KemPublicKey)) fail('INVALID_KEY', 'Expected an ML-KEM public key');
  const { ciphertext, sharedKey } = await encapsulateAsync(publicKey.native(TOKEN));
  return { ciphertext, secret: new EncapsulatedSecret(TOKEN, sharedKey) };
}

function importSpki(encoded, algorithm, Wrapper) {
  const der = bytes(encoded, 'SPKI', 4096);
  let key;
  try { key = createPublicKey({ key: der, type: 'spki', format: 'der' }); }
  catch { fail('INVALID_KEY', 'Invalid public key encoding'); }
  if (key.asymmetricKeyType !== algorithm || !der.equals(key.export({ type: 'spki', format: 'der' }))) {
    fail('INVALID_KEY', 'Incorrect algorithm or noncanonical SPKI');
  }
  return new Wrapper(TOKEN, key);
}

export function importKemPublicKey(spki) { return importSpki(spki, 'ml-kem-1024', KemPublicKey); }
export function importVerificationKey(spki) { return importSpki(spki, 'ml-dsa-87', VerificationKey); }

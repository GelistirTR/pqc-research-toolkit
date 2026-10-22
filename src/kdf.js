import { createSecretKey, hkdfSync, randomBytes } from 'node:crypto';
import { DecryptionKey, EncryptionKey } from './aead.js';
import { fail } from './errors.js';
import { bytes, contextBytes, frame, live, Opaque, TOKEN } from './internal.js';

const LABEL = 'pqc-research-core/alpha1/ml-kem-1024/hkdf-sha512/aes256gcm\0';

// The alpha composition is documented in docs/CORE-SPEC.md; not HPKE or a hybrid KEM.
function derive(material, salt, context) {
  const output = Buffer.from(hkdfSync('sha512', material, salt, frame(LABEL, context), 32));
  try { return createSecretKey(output); }
  finally { output.fill(0); }
}

class SharedSecret extends Opaque {
  #material;
  constructor(token, material) { super(token); this.#material = material; }
  use(token, salt, context) {
    if (token !== TOKEN) fail('INVALID_KEY', 'Shared secret access is internal');
    const material = live(this.#material);
    this.#material = undefined;
    try { return derive(material, salt, context); }
    finally { material.fill(0); }
  }
  destroy() { this.#material?.fill(0); this.#material = undefined; }
}

export class EncapsulatedSecret extends SharedSecret {
  deriveEncryptionKey(context) {
    const checkedContext = contextBytes(context);
    const salt = randomBytes(32);
    return { salt, key: new EncryptionKey(TOKEN, this.use(TOKEN, salt, checkedContext)) };
  }
}

export class DecapsulatedSecret extends SharedSecret {
  deriveDecryptionKey(salt, context) {
    const checkedSalt = bytes(salt, 'salt', 32, 32);
    const checkedContext = contextBytes(context);
    return new DecryptionKey(TOKEN, this.use(TOKEN, checkedSalt, checkedContext));
  }
}

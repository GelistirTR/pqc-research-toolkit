import { createHash, timingSafeEqual } from 'node:crypto';
import { KemPublicKey, VerificationKey } from './asymmetric.js';
import { fail } from './errors.js';

export function publicKeyFingerprint(key) {
  if (!(key instanceof KemPublicKey) && !(key instanceof VerificationKey)) {
    fail('INVALID_KEY', 'Expected a KEM public key or signature verification key');
  }
  return `SHA256:${createHash('sha256').update(key.exportSpki()).digest('hex')}`;
}

// expected must come from an independently trusted source. Comparing a key to
// its own freshly calculated digest does not establish identity or trust.
export function requirePublicKeyFingerprint(key, expected) {
  if (typeof expected !== 'string' || expected.length !== 71 || !/^SHA256:[0-9a-fA-F]{64}$/.test(expected)) {
    fail('INVALID_FINGERPRINT', 'Supply the trusted SHA256 fingerprint (64 hexadecimal digits)');
  }
  const actual = publicKeyFingerprint(key);
  if (!timingSafeEqual(Buffer.from(actual.slice(7), 'hex'), Buffer.from(expected.slice(7), 'hex'))) {
    fail('FINGERPRINT_MISMATCH', 'Public key does not match the expected fingerprint');
  }
  return actual;
}

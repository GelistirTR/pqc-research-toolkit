import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  generateKemKeyPair, generateSigningKeyPair, generateSymmetricKeyPair,
  importKemPublicKey, importVerificationKey, publicKeyFingerprint, requirePublicKeyFingerprint,
} from '../src/index.js';

const [kem, signer] = await Promise.all([generateKemKeyPair(), generateSigningKeyPair()]);
const error = (code) => (value) => value.code === code;
test.after(() => { kem.privateKey.destroy(); signer.signingKey.destroy(); });

test('SPKI fingerprint matches a pinned digest of the existing public NIST ACVP vector', () => {
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/nist-acvp.json', import.meta.url), 'utf8'));
  const vector = fixture.dsaVerification.find((item) => item.tcId === 61);
  const key = importVerificationKey(Buffer.concat([
    Buffer.from('30820a32300b060960864801650304031303820a2100', 'hex'), Buffer.from(vector.pk, 'hex'),
  ]));
  // Independently computed with PowerShell Get-FileHash / .NET SHA-256 on
  // the existing published public-key fixture's DER SPKI, not raw key bytes.
  assert.equal(publicKeyFingerprint(key), 'SHA256:c32f0a46f467f2d87b1ba9874e8ab28514c2fd09f6f758dd8e3a223b5d905bb3');
});

for (const [name, key, importKey] of [
  ['KEM', kem.publicKey, importKemPublicKey],
  ['signature', signer.verificationKey, importVerificationKey],
]) {
  test(`${name} pin survives SPKI import and accepts hex case while returning canonical lowercase`, () => {
    const pin = publicKeyFingerprint(key);
    assert.match(pin, /^SHA256:[0-9a-f]{64}$/);
    assert.equal(pin.length, 71);
    assert.equal(publicKeyFingerprint(importKey(key.exportSpki())), pin);
    assert.equal(requirePublicKeyFingerprint(key, pin), pin);
    assert.equal(requirePublicKeyFingerprint(key, `SHA256:${pin.slice(7).toUpperCase()}`), pin);
  });
}

test('valid but different key pins are rejected without disclosing either pin', () => {
  const expected = publicKeyFingerprint(kem.publicKey);
  assert.throws(() => requirePublicKeyFingerprint(signer.verificationKey, expected), (failure) =>
    failure.code === 'FINGERPRINT_MISMATCH' && !failure.message.includes(expected));
});

test('pin parsing rejects missing, shortened, whitespace, newline and non-hex inputs', () => {
  const pin = publicKeyFingerprint(kem.publicKey);
  for (const expected of [undefined, null, {}, new String(pin), Buffer.from(pin), '', pin.slice(0, -1),
    `${pin}0`, `${pin}\n`, `${pin}\r\n`, `${pin}\u2028`, ` ${pin}`, `${pin} `,
    `sha256:${pin.slice(7)}`, `SHA256:${'g'.repeat(64)}`, `SHA256:${'0'.repeat(63)}`, `SHA256:${'0'.repeat(65)}`]) {
    assert.throws(() => requirePublicKeyFingerprint(kem.publicKey, expected), error('INVALID_FINGERPRINT'));
  }
});

test('fingerprints reject private, symmetric and duck-typed handles without using export hooks', () => {
  const symmetric = generateSymmetricKeyPair();
  let invoked = false;
  try {
    for (const key of [null, undefined, {}, kem.privateKey, signer.signingKey, symmetric.encryptionKey,
      symmetric.decryptionKey, Buffer.alloc(32), { exportSpki() { invoked = true; throw new Error('must not run'); } }]) {
      assert.throws(() => publicKeyFingerprint(key), error('INVALID_KEY'));
      assert.throws(() => requirePublicKeyFingerprint(key, publicKeyFingerprint(kem.publicKey)), error('INVALID_KEY'));
    }
    assert.equal(invoked, false);
  } finally { symmetric.encryptionKey.destroy(); symmetric.decryptionKey.destroy(); }
});

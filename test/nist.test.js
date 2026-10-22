import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createCipheriv, createPrivateKey, decapsulate, hkdfSync } from 'node:crypto';
import test from 'node:test';
import { importVerificationKey } from '../src/index.js';
import { KemPrivateKey } from '../src/asymmetric.js';
import { TOKEN } from '../src/internal.js';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/nist-acvp.json', import.meta.url), 'utf8'));
const hex = (value) => Buffer.from(value, 'hex');

// Test-only DER wrapping for the published, expanded ACVP private key.
// Private-key import/serialization is deliberately not part of the public alpha API.
function tlv(tag, value) {
  const n = value.length;
  const length = n < 128 ? Buffer.from([n]) : Buffer.from([0x82, n >> 8, n & 255]);
  return Buffer.concat([Buffer.from([tag]), length, value]);
}
function nativeFixtureKey(dk) {
  const algorithm = hex('300b0609608648016503040403');
  const der = tlv(0x30, Buffer.concat([hex('020100'), algorithm, tlv(4, tlv(4, hex(dk)))]));
  return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
}

for (const vector of fixture.kemDecapsulation) {
  test(`NIST ACVP ML-KEM-1024 decapsulation tcId=${vector.tcId}`, async () => {
    const nativeKey = nativeFixtureKey(vector.dk);
    const actual = decapsulate(nativeKey, hex(vector.c));
    assert.deepEqual(actual, hex(vector.k));
    actual.fill(0);

    // Also exercise the actual wrapper's secret handling and KDF/decryption path.
    const privateKey = new KemPrivateKey(TOKEN, nativeKey);
    const secret = await privateKey.decapsulate(hex(vector.c));
    const salt = Buffer.alloc(32, 7);
    const context = Buffer.from('acvp/v1');
    const size = Buffer.alloc(4);
    size.writeUInt32BE(context.length);
    const info = Buffer.concat([
      Buffer.from('pqc-research-core/alpha1/ml-kem-1024/hkdf-sha512/aes256gcm\0'), size, context,
    ]);
    const expectedKey = Buffer.from(hkdfSync('sha512', hex(vector.k), salt, info, 32));
    const nonce = Buffer.alloc(12, 3);
    const plaintext = Buffer.from('ACVP wrapper path');
    const cipher = createCipheriv('aes-256-gcm', expectedKey, nonce);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const key = secret.deriveDecryptionKey(salt, context);
    assert.deepEqual(key.decrypt({ nonce, ciphertext, tag: cipher.getAuthTag() }), plaintext);
    expectedKey.fill(0); key.destroy(); privateKey.destroy();
  });
}

const dsaPrefix = hex('30820a32300b060960864801650304031303820a2100');
for (const vector of fixture.dsaVerification) {
  test(`NIST ACVP ML-DSA-87 pure verification tcId=${vector.tcId} expected=${vector.testPassed}`, async () => {
    const key = importVerificationKey(Buffer.concat([dsaPrefix, hex(vector.pk)]));
    assert.equal(await key.verify(hex(vector.message), hex(vector.signature), hex(vector.context)), vector.testPassed);
  });
}

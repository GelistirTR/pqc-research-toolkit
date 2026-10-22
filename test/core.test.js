import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import {
  encapsulate, generateKemKeyPair, generateSigningKeyPair, generateSymmetricKeyPair,
  importKemPublicKey, importVerificationKey, profile,
} from '../src/index.js';

const b = (s) => Buffer.from(s);
const ctx = b('tests/context/v1');
const message = b('private document');
const aad = b('record:123');
const error = (code) => (e) => e.code === code;

async function exchange() {
  const recipient = await generateKemKeyPair();
  const sent = await encapsulate(recipient.publicKey);
  const derived = sent.secret.deriveEncryptionKey(ctx);
  const packet = derived.key.encrypt(message, aad);
  const secret = await recipient.privateKey.decapsulate(sent.ciphertext);
  const key = secret.deriveDecryptionKey(derived.salt, ctx);
  return { recipient, sent, derived, packet, secret, key };
}

test('complete KEM/KDF/AEAD exchange; shared secrets and encryption permission are consumed', async () => {
  const e = await exchange();
  assert.equal(e.sent.ciphertext.length, 1568);
  assert.equal(e.derived.salt.length, 32);
  assert.deepEqual(e.key.decrypt(e.packet, aad), message);
  assert.throws(() => e.sent.secret.deriveEncryptionKey(ctx), error('KEY_UNAVAILABLE'));
  assert.throws(() => e.secret.deriveDecryptionKey(e.derived.salt, ctx), error('KEY_UNAVAILABLE'));
  assert.throws(() => e.derived.key.encrypt(message, aad), error('KEY_UNAVAILABLE'));
});

test('independent encapsulations produce different ciphertext and salt', async () => {
  const recipient = await generateKemKeyPair();
  const first = await encapsulate(recipient.publicKey);
  const second = await encapsulate(recipient.publicKey);
  assert.notDeepEqual(first.ciphertext, second.ciphertext);
  assert.notDeepEqual(first.secret.deriveEncryptionKey(ctx).salt, second.secret.deriveEncryptionKey(ctx).salt);
});

for (const field of ['nonce', 'ciphertext', 'tag']) {
  test(`changed ${field} fails authentication`, async () => {
    const e = await exchange();
    const modified = { ...e.packet, [field]: Buffer.from(e.packet[field]) };
    modified[field][0] ^= 1;
    assert.throws(() => e.key.decrypt(modified, aad), error('AUTHENTICATION_FAILED'));
    assert.deepEqual(e.key.decrypt(e.packet, aad), message);
  });
}

test('wrong AAD, context, salt and recipient do not decrypt', async () => {
  const e = await exchange();
  assert.throws(() => e.key.decrypt(e.packet, b('other')), error('AUTHENTICATION_FAILED'));
  for (const [salt, context] of [[randomBytes(32), ctx], [e.derived.salt, b('other')]]) {
    const secret = await e.recipient.privateKey.decapsulate(e.sent.ciphertext);
    const key = secret.deriveDecryptionKey(salt, context);
    assert.throws(() => key.decrypt(e.packet, aad), error('AUTHENTICATION_FAILED'));
  }
  const other = await generateKemKeyPair();
  const secret = await other.privateKey.decapsulate(e.sent.ciphertext);
  assert.throws(
    () => secret.deriveDecryptionKey(e.derived.salt, ctx).decrypt(e.packet, aad),
    error('AUTHENTICATION_FAILED'),
  );
});

test('correct-length corrupted KEM ciphertext preserves implicit rejection', async () => {
  const e = await exchange();
  const corrupted = Buffer.from(e.sent.ciphertext);
  corrupted[corrupted.length >> 1] ^= 1;
  const secret = await e.recipient.privateKey.decapsulate(corrupted);
  const key = secret.deriveDecryptionKey(e.derived.salt, ctx);
  assert.throws(() => key.decrypt(e.packet, aad), error('AUTHENTICATION_FAILED'));
});

test('invalid KEM ciphertext lengths are rejected before provider', async () => {
  const recipient = await generateKemKeyPair();
  for (const length of [0, 1, 1567, 1569, 4096]) {
    await assert.rejects(recipient.privateKey.decapsulate(Buffer.alloc(length)), error('INVALID_INPUT'));
  }
});

test('empty message and AAD are valid; nonce and tag retain fixed sizes', () => {
  const keys = generateSymmetricKeyPair();
  const packet = keys.encryptionKey.encrypt(Buffer.alloc(0));
  assert.equal(packet.nonce.length, 12);
  assert.equal(packet.tag.length, 16);
  assert.deepEqual(keys.decryptionKey.decrypt(packet), Buffer.alloc(0));
});

test('all packet byte mutations fail authentication (bounded mutation corpus)', () => {
  const keys = generateSymmetricKeyPair();
  const packet = keys.encryptionKey.encrypt(Buffer.alloc(64, 0x42), aad);
  let mutations = 0;
  for (const field of ['nonce', 'ciphertext', 'tag']) {
    for (let i = 0; i < packet[field].length; i++) {
      const modified = { ...packet, [field]: Buffer.from(packet[field]) };
      modified[field][i] ^= 1;
      assert.throws(() => keys.decryptionKey.decrypt(modified, aad), error('AUTHENTICATION_FAILED'));
      mutations++;
    }
  }
  assert.equal(mutations, 92);
});

test('packet structural errors and truncated tags never return plaintext', () => {
  const keys = generateSymmetricKeyPair();
  const packet = keys.encryptionKey.encrypt(message);
  for (const value of [null, {}, { ...packet, tag: Buffer.alloc(15) },
    { ...packet, nonce: Buffer.alloc(11) }, { ...packet, ciphertext: 'text' }]) {
    assert.throws(() => keys.decryptionKey.decrypt(value), error('INVALID_INPUT'));
  }
});

test('input limits are enforced without consuming a key on validation failure', async () => {
  const keys = generateSymmetricKeyPair();
  assert.throws(() => keys.encryptionKey.encrypt('text'), error('INVALID_INPUT'));
  assert.throws(() => keys.encryptionKey.encrypt(Buffer.alloc(profile.maxMessageBytes + 1)), error('INVALID_INPUT'));
  assert.throws(() => keys.encryptionKey.encrypt(message, Buffer.alloc(profile.maxAadBytes + 1)), error('INVALID_INPUT'));
  const packet = keys.encryptionKey.encrypt(message);
  assert.deepEqual(keys.decryptionKey.decrypt(packet), message);
  const recipient = await generateKemKeyPair();
  const sent = await encapsulate(recipient.publicKey);
  assert.throws(() => sent.secret.deriveEncryptionKey(Buffer.alloc(profile.maxKdfContextBytes + 1)), error('INVALID_INPUT'));
  const { salt, key } = sent.secret.deriveEncryptionKey(Buffer.alloc(profile.maxKdfContextBytes));
  const secret = await recipient.privateKey.decapsulate(sent.ciphertext);
  assert.throws(() => secret.deriveDecryptionKey(Buffer.alloc(31), ctx), error('INVALID_INPUT'));
  const receiver = secret.deriveDecryptionKey(salt, Buffer.alloc(profile.maxKdfContextBytes));
  assert.deepEqual(receiver.decrypt(key.encrypt(message)), message);
});

test('shared backing memory is rejected', async () => {
  const shared = new Uint8Array(new SharedArrayBuffer(32));
  const keys = generateSymmetricKeyPair();
  assert.throws(() => keys.encryptionKey.encrypt(shared), error('INVALID_INPUT'));
  assert.throws(() => importKemPublicKey(shared), error('INVALID_INPUT'));
  const recipient = await generateKemKeyPair();
  await assert.rejects(recipient.privateKey.decapsulate(shared), error('INVALID_INPUT'));
});

test('destroy disables future private-key, AEAD and secret operations', async () => {
  const e = await exchange();
  const sent = await encapsulate(e.recipient.publicKey);
  sent.secret.destroy();
  sent.secret.destroy();
  assert.throws(() => sent.secret.deriveEncryptionKey(ctx), error('KEY_UNAVAILABLE'));
  const received = await e.recipient.privateKey.decapsulate(e.sent.ciphertext);
  received.destroy();
  assert.throws(() => received.deriveDecryptionKey(e.derived.salt, ctx), error('KEY_UNAVAILABLE'));
  e.recipient.privateKey.destroy();
  await assert.rejects(e.recipient.privateKey.decapsulate(e.sent.ciphertext), error('KEY_UNAVAILABLE'));
  e.key.destroy();
  assert.throws(() => e.key.decrypt(e.packet, aad), error('KEY_UNAVAILABLE'));
  const symmetric = generateSymmetricKeyPair();
  symmetric.encryptionKey.destroy();
  assert.throws(() => symmetric.encryptionKey.encrypt(message), error('KEY_UNAVAILABLE'));
  const signer = await generateSigningKeyPair();
  signer.signingKey.destroy();
  await assert.rejects(signer.signingKey.sign(message, ctx), error('KEY_UNAVAILABLE'));
});

test('KEM operations copy ciphertext before async work', async () => {
  const e = await exchange();
  const ciphertext = Buffer.from(e.sent.ciphertext);
  const pending = e.recipient.privateKey.decapsulate(ciphertext);
  ciphertext.fill(0);
  const secret = await pending;
  const key = secret.deriveDecryptionKey(e.derived.salt, ctx);
  assert.deepEqual(key.decrypt(e.packet, aad), message);
});

test('ML-DSA signs with native context; altered message/signature/context fail', async () => {
  const keys = await generateSigningKeyPair();
  const signature = await keys.signingKey.sign(message, ctx);
  assert.equal(signature.length, 4627);
  assert.equal(await keys.verificationKey.verify(message, signature, ctx), true);
  assert.equal(await keys.verificationKey.verify(b('altered'), signature, ctx), false);
  assert.equal(await keys.verificationKey.verify(message, signature, b('other')), false);
  const altered = Buffer.from(signature);
  altered[0] ^= 1;
  assert.equal(await keys.verificationKey.verify(message, altered, ctx), false);
  assert.equal(await keys.verificationKey.verify(message, signature.subarray(1), ctx), false);
  const other = await generateSigningKeyPair();
  assert.equal(await other.verificationKey.verify(message, signature, ctx), false);
});

test('signature context required; boundary 255 bytes works and 256 fails', async () => {
  const keys = await generateSigningKeyPair();
  const boundary = Buffer.alloc(255);
  const signature = await keys.signingKey.sign(message, boundary);
  assert.equal(await keys.verificationKey.verify(message, signature, boundary), true);
  await assert.rejects(keys.signingKey.sign(message), error('INVALID_INPUT'));
  await assert.rejects(keys.signingKey.sign(message, Buffer.alloc(256)), error('INVALID_INPUT'));
  await assert.rejects(keys.verificationKey.verify(message, signature, Buffer.alloc(256)), error('INVALID_INPUT'));
});

test('signing copies caller message and context before awaiting provider', async () => {
  const keys = await generateSigningKeyPair();
  const data = Buffer.from(message);
  const context = Buffer.from(ctx);
  const pending = keys.signingKey.sign(data, context);
  data.fill(0);
  context.fill(0);
  assert.equal(await keys.verificationKey.verify(message, await pending, ctx), true);
});

test('SPKI roundtrip and wrong algorithm / trailing garbage rejection', async () => {
  const kem = await generateKemKeyPair();
  const dsa = await generateSigningKeyPair();
  assert.deepEqual(importKemPublicKey(kem.publicKey.exportSpki()).exportSpki(), kem.publicKey.exportSpki());
  const imported = importVerificationKey(dsa.verificationKey.exportSpki());
  const signature = await dsa.signingKey.sign(message, ctx);
  assert.equal(await imported.verify(message, signature, ctx), true);
  assert.throws(() => importKemPublicKey(dsa.verificationKey.exportSpki()), error('INVALID_KEY'));
  assert.throws(() => importVerificationKey(kem.publicKey.exportSpki()), error('INVALID_KEY'));
  assert.throws(() => importKemPublicKey(Buffer.concat([kem.publicKey.exportSpki(), b('garbage')])), error('INVALID_KEY'));
  assert.throws(() => importKemPublicKey(randomBytes(100)), error('INVALID_KEY'));
  await assert.rejects(encapsulate(dsa.verificationKey), error('INVALID_KEY'));
});

test('public/private handles cannot be reconstructed, dumped or read via internal accessors', async () => {
  const keys = await generateKemKeyPair();
  const e = await encapsulate(keys.publicKey);
  const symmetric = generateSymmetricKeyPair();
  for (const handle of [keys.publicKey, keys.privateKey, e.secret, symmetric.encryptionKey, symmetric.decryptionKey]) {
    assert.equal(JSON.stringify(handle), '"[Opaque cryptographic handle]"');
    assert.equal(inspect(handle), '[Opaque cryptographic handle]');
    assert.throws(() => new handle.constructor(), error('INVALID_KEY'));
  }
  assert.throws(() => keys.publicKey.native(), error('INVALID_KEY'));
  assert.throws(() => e.secret.use(), error('INVALID_KEY'));
});

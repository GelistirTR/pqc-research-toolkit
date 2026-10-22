import assert from 'node:assert/strict';
import { argon2, createDecipheriv, createPrivateKey, createPublicKey, randomBytes } from 'node:crypto';
import { promisify } from 'node:util';
import test from 'node:test';
import { argon2idAsync } from '@noble/hashes/argon2.js';
import {
  encapsulate, generateKemKeyPair, generateSigningKeyPair, generateSymmetricKeyPair,
  openPrivateKey, sealPrivateKey, vaultProfile,
} from '../src/index.js';

const passphrase = Buffer.from('correct horse battery staple example');
const context = Buffer.from('vault/roundtrip');
const argon = promisify(argon2);
const error = (code) => (e) => e.code === code;

test('password-protected KEM key survives destruction and unlocks actual encrypted data', async () => {
  const recipient = await generateKemKeyPair();
  const spki = recipient.publicKey.exportSpki();
  const e = await encapsulate(recipient.publicKey);
  const { salt, key } = e.secret.deriveEncryptionKey(context);
  const packet = key.encrypt(Buffer.from('keep this after restart'));
  const vault = await sealPrivateKey(recipient.privateKey, passphrase);
  recipient.privateKey.destroy();
  const restored = await openPrivateKey(vault, passphrase);
  assert.equal(restored.kind, 'kem');
  assert.deepEqual(restored.publicKey.exportSpki(), spki);
  assert.deepEqual(restored.privateKey.publicKey().exportSpki(), spki);
  const secret = await restored.privateKey.decapsulate(e.ciphertext);
  assert.equal(secret.deriveDecryptionKey(salt, context).decrypt(packet).toString(), 'keep this after restart');
  restored.privateKey.destroy();
});

test('password-protected signing key retains identity and signs after restore', async () => {
  const pair = await generateSigningKeyPair();
  const spki = pair.verificationKey.exportSpki();
  const vault = await sealPrivateKey(pair.signingKey, passphrase);
  pair.signingKey.destroy();
  const restored = await openPrivateKey(vault, passphrase);
  assert.equal(restored.kind, 'signature');
  assert.deepEqual(restored.verificationKey.exportSpki(), spki);
  const message = Buffer.from('restored signer');
  const signature = await restored.signingKey.sign(message, context);
  assert.equal(await pair.verificationKey.verify(message, signature, context), true);
  restored.signingKey.destroy();
});

test('wrong password and authenticated vault field mutations have the same public authentication error', async () => {
  const pair = await generateKemKeyPair();
  const vault = await sealPrivateKey(pair.privateKey, passphrase);
  await assert.rejects(openPrivateKey(vault, Buffer.from('another valid-length password')), error('AUTHENTICATION_FAILED'));
  // kind, salt, nonce, ciphertext and tag are all protected by GCM.
  for (const offset of [9, 24, 40, 56, vault.length - 1]) {
    const changed = Buffer.from(vault);
    if (offset === 9) changed[offset] = 2;
    else changed[offset] ^= 1;
    await assert.rejects(openPrivateKey(changed, passphrase), error('AUTHENTICATION_FAILED'));
  }
});

test('malformed/truncated vault and malicious KDF work factors are rejected before derivation', async () => {
  const pair = await generateKemKeyPair();
  const vault = await sealPrivateKey(pair.privateKey, passphrase);
  for (const offset of [0, 8, 10, 11, 12, 16, 20, 52]) {
    const changed = Buffer.from(vault);
    changed[offset] ^= 1;
    await assert.rejects(openPrivateKey(changed, passphrase), error('INVALID_VAULT'));
  }
  for (const data of [Buffer.alloc(0), vault.subarray(0, 20), vault.subarray(0, -1), Buffer.concat([vault, Buffer.alloc(1)])]) {
    await assert.rejects(openPrivateKey(data, passphrase), error('INVALID_VAULT'));
  }
  await assert.rejects(openPrivateKey(Buffer.alloc(vaultProfile.maxVaultBytes + 1), passphrase), error('INVALID_INPUT'));
});

test('vault uses fresh salt/nonce and enforces passphrase and key type limits', async () => {
  const pair = await generateKemKeyPair();
  const first = await sealPrivateKey(pair.privateKey, passphrase);
  const second = await sealPrivateKey(pair.privateKey, passphrase);
  assert.notDeepEqual(first, second);
  assert.notDeepEqual(first.subarray(24, 40), second.subarray(24, 40));
  await assert.rejects(sealPrivateKey(pair.privateKey, 'a string is not a byte passphrase'), error('INVALID_INPUT'));
  await assert.rejects(sealPrivateKey(pair.privateKey, Buffer.alloc(15)), error('INVALID_INPUT'));
  await assert.rejects(sealPrivateKey(pair.privateKey, Buffer.alloc(1025)), error('INVALID_INPUT'));
  await assert.rejects(sealPrivateKey(generateSymmetricKeyPair().encryptionKey, passphrase), error('INVALID_KEY'));
  pair.privateKey.destroy();
  await assert.rejects(sealPrivateKey(pair.privateKey, passphrase), error('KEY_UNAVAILABLE'));
  assert.throws(() => pair.privateKey.publicKey(), error('KEY_UNAVAILABLE'));
  assert.throws(() => pair.privateKey.native(), error('INVALID_KEY'));
});

test('vault copies passphrase and input before async KDF work', async () => {
  const pair = await generateKemKeyPair();
  const password = Buffer.from(passphrase);
  const pendingSeal = sealPrivateKey(pair.privateKey, password);
  password.fill(0);
  const vault = await pendingSeal;
  const inputCopy = Buffer.from(vault);
  const pendingOpen = openPrivateKey(inputCopy, passphrase);
  inputCopy.fill(0);
  const restored = await pendingOpen;
  assert.equal(restored.kind, 'kem');
});

test('Node Argon2id matches the fixed RFC 9106 section 5.3 vector', async () => {
  const tag = await argon('argon2id', {
    message: Buffer.alloc(32, 1), nonce: Buffer.alloc(16, 2), secret: Buffer.alloc(8, 3),
    associatedData: Buffer.alloc(12, 4), memory: 32, passes: 3, parallelism: 4, tagLength: 32,
  });
  assert.equal(tag.toString('hex'), '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659');
  tag.fill(0);
});

test('independent Noble Argon2id decrypts the real fixed-profile vault', { timeout: 60000 }, async () => {
  const pair = await generateKemKeyPair();
  const vault = await sealPrivateKey(pair.privateKey, passphrase);
  const material = await argon2idAsync(passphrase, vault.subarray(24, 40), {
    m: 65536, t: 3, p: 4, dkLen: 32,
    personalization: Buffer.from('pqc-research-core/vault/v1\0'),
  });
  const decipher = createDecipheriv('aes-256-gcm', material, vault.subarray(40, 52));
  decipher.setAAD(vault.subarray(0, 56));
  decipher.setAuthTag(vault.subarray(-16));
  const der = Buffer.concat([decipher.update(vault.subarray(56, -16)), decipher.final()]);
  const native = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  assert.equal(native.asymmetricKeyType, 'ml-kem-1024');
  assert.deepEqual(createPublicKey(native).export({ format: 'der', type: 'spki' }), pair.publicKey.exportSpki());
  der.fill(0); material.fill(0);
});

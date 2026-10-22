import assert from 'node:assert/strict';
import { argon2, createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { mkdtemp, open, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';
import {
  decryptFile, encryptFile, generateKemKeyPair, generateSigningKeyPair,
  openPrivateKey, sealPrivateKey,
} from '../src/index.js';

const argon = promisify(argon2);
const passphrase = Buffer.from('canonical vault passphrase for hardening');
const context = Buffer.from('hardening/files/context');
const aad = Buffer.from('document-id:hardening-test');
const hasCode = (code) => (error) => error.code === code;

async function workspace(t) {
  const directory = await mkdtemp(join(tmpdir(), 'pqc-hardening-test-'));
  t.after(async () => {
    const target = resolve(directory);
    assert.equal(dirname(target), resolve(tmpdir()));
    assert.ok(basename(target).startsWith('pqc-hardening-test-'));
    await rm(target, { recursive: true, force: true });
  });
  return {
    directory, inputPath: join(directory, 'input.bin'),
    encryptedPath: join(directory, 'encrypted.pqc'), outputPath: join(directory, 'output.bin'),
  };
}

// Build a correctly authenticated container with malformed plaintext. This
// exercises the post-authentication parser, not GCM corruption rejection.
async function appendAuthenticatedVaultContent(vault) {
  const key = await argon('argon2id', {
    message: passphrase, nonce: vault.subarray(24, 40),
    memory: 65536, passes: 3, parallelism: 4, tagLength: 32,
    associatedData: Buffer.from('pqc-research-core/vault/v1\0'),
  });
  let der;
  let changed;
  let pending;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, vault.subarray(40, 52));
    decipher.setAAD(vault.subarray(0, 56));
    decipher.setAuthTag(vault.subarray(-16));
    pending = decipher.update(vault.subarray(56, -16));
    der = Buffer.concat([pending, decipher.final()]);
    changed = Buffer.concat([der, Buffer.from('unexpected trailing DER content')]);
    const prefix = Buffer.from(vault.subarray(0, 56));
    prefix.writeUInt32BE(changed.length, 52);
    // A fresh nonce is used even in this deliberately malformed test fixture.
    randomBytes(12).copy(prefix, 40);
    const cipher = createCipheriv('aes-256-gcm', key, prefix.subarray(40, 52));
    cipher.setAAD(prefix);
    return Buffer.concat([prefix, cipher.update(changed), cipher.final(), cipher.getAuthTag()]);
  } finally { key.fill(0); pending?.fill(0); der?.fill(0); changed?.fill(0); }
}

for (const kind of ['kem', 'signature']) {
  test(`authenticated ${kind} vault rejects trailing PKCS#8 plaintext`, async () => {
    const pair = kind === 'kem' ? await generateKemKeyPair() : await generateSigningKeyPair();
    const key = pair.privateKey ?? pair.signingKey;
    try {
      const vault = await sealPrivateKey(key, passphrase);
      const malformed = await appendAuthenticatedVaultContent(vault);
      await assert.rejects(openPrivateKey(malformed, passphrase), hasCode('INVALID_VAULT'));
      const restored = await openPrivateKey(vault, passphrase);
      assert.equal(restored.kind, kind);
      (restored.privateKey ?? restored.signingKey).destroy();
    } finally { key.destroy(); }
  });
}

test('file API snapshots caller context and AAD before asynchronous I/O', async (t) => {
  const w = await workspace(t);
  const pair = await generateKemKeyPair();
  t.after(() => pair.privateKey.destroy());
  const plaintext = randomBytes(65537);
  await writeFile(w.inputPath, plaintext);
  const callerContext = Buffer.from(context);
  const callerAad = Buffer.from(aad);
  const encryption = encryptFile({
    inputPath: w.inputPath, outputPath: w.encryptedPath, recipient: pair.publicKey,
    context: callerContext, aad: callerAad, chunkSize: 65536,
  });
  callerContext.fill(0); callerAad.fill(0);
  await encryption;
  const decryptContext = Buffer.from(context);
  const decryptAad = Buffer.from(aad);
  const decryption = decryptFile({
    inputPath: w.encryptedPath, outputPath: w.outputPath, privateKey: pair.privateKey,
    context: decryptContext, aad: decryptAad,
  });
  decryptContext.fill(0); decryptAad.fill(0);
  // destroy() blocks later operations; it does not cancel already captured work.
  pair.privateKey.destroy();
  await decryption;
  assert.deepEqual(await readFile(w.outputPath), plaintext);
});

test('disk-full failure after a staged plaintext chunk leaves no output or staging files', async (t) => {
  const w = await workspace(t);
  const pair = await generateKemKeyPair();
  t.after(() => pair.privateKey.destroy());
  const plaintext = randomBytes(65536 * 2 + 1);
  await writeFile(w.inputPath, plaintext);
  await encryptFile({
    inputPath: w.inputPath, outputPath: w.encryptedPath, recipient: pair.publicKey,
    context, aad, chunkSize: 65536,
  });
  const probe = await open(w.inputPath, 'r');
  const prototype = Object.getPrototypeOf(probe);
  await probe.close();
  const originalWrite = prototype.write;
  let writes = 0;
  const failure = Object.assign(new Error('simulated disk full'), { code: 'ENOSPC' });
  const mocked = t.mock.method(prototype, 'write', async function (...args) {
    if (++writes === 2) throw failure;
    return originalWrite.apply(this, args);
  });
  try {
    await assert.rejects(decryptFile({
      inputPath: w.encryptedPath, outputPath: w.outputPath,
      privateKey: pair.privateKey, context, aad,
    }), (error) => error === failure);
  } finally { mocked.mock.restore(); }
  assert.equal(writes, 2);
  assert.deepEqual(await readdir(w.directory), ['encrypted.pqc', 'input.bin']);
  assert.deepEqual(await readFile(w.inputPath), plaintext);
});

test('vault sealing captures a key before asynchronous work when its handle is destroyed', async () => {
  const pair = await generateKemKeyPair();
  const spki = pair.publicKey.exportSpki();
  const sealing = sealPrivateKey(pair.privateKey, passphrase);
  pair.privateKey.destroy();
  const vault = await sealing;
  const restored = await openPrivateKey(vault, passphrase);
  try { assert.deepEqual(restored.publicKey.exportSpki(), spki); }
  finally { restored.privateKey.destroy(); }
});

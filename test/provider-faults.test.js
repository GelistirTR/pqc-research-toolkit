import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, resolve } from 'node:path';
import test from 'node:test';

const probe = `
  import assert from 'node:assert/strict';
  import crypto from 'node:crypto';
  import { syncBuiltinESMExports } from 'node:module';
  import { writeFile, readdir } from 'node:fs/promises';
  import { join } from 'node:path';
  const [sdkUrl, mode, directory] = process.argv.slice(1);
  const failure = Object.assign(new Error('Synthetic provider failure'), { code: 'TEST_PROVIDER_FAILURE' });
  let failNow = false; let capturedMaterial;
  const names = {
    'rng-factory': 'randomBytes', 'rng-aead': 'randomBytes', hkdf: 'hkdfSync',
    'kem-keygen': 'generateKeyPair', 'signature-keygen': 'generateKeyPair', encapsulate: 'encapsulate',
    decapsulate: 'decapsulate', sign: 'sign', verify: 'verify', argon: 'argon2',
    'file-rng': 'randomBytes', 'file-kem': 'encapsulate', 'file-cipher': 'createCipheriv',
    'password-rng': 'randomBytes', 'password-argon': 'argon2', 'password-verify-argon': 'argon2',
  };
  const name = names[mode];
  const original = crypto[name];
  crypto[name] = function(...args) {
    if (!failNow) return original.apply(this, args);
    if (name === 'hkdfSync') capturedMaterial = args[1];
    if (typeof args.at(-1) === 'function') { queueMicrotask(() => args.at(-1)(failure)); return; }
    throw failure;
  };
  for (const symbol of Object.getOwnPropertySymbols(original)) {
    Object.defineProperty(crypto[name], symbol, Object.getOwnPropertyDescriptor(original, symbol));
  }
  syncBuiltinESMExports();
  const sdk = await import(sdkUrl);
  const context = Buffer.from('provider-faults/v1');
  const message = Buffer.from('synthetic test plaintext');
  const password = Buffer.from('synthetic vault password only');
  const pair = await sdk.generateKemKeyPair();
  const signer = await sdk.generateSigningKeyPair();
  try {
    if (mode === 'rng-factory') {
      failNow = true; assert.throws(() => sdk.generateSymmetricKeyPair(), error => error === failure);
    } else if (mode === 'rng-aead') {
      const keys = sdk.generateSymmetricKeyPair(); failNow = true;
      assert.throws(() => keys.encryptionKey.encrypt(message), error => error === failure);
      assert.throws(() => keys.encryptionKey.encrypt(message), error => error.code === 'KEY_UNAVAILABLE');
      keys.decryptionKey.destroy();
    } else if (mode === 'hkdf') {
      const exchange = await sdk.encapsulate(pair.publicKey); failNow = true;
      assert.throws(() => exchange.secret.deriveEncryptionKey(context), error => error === failure);
      assert.ok(capturedMaterial.every(byte => byte === 0), 'Owned shared secret must be wiped on KDF failure');
      failNow = false;
      assert.throws(() => exchange.secret.deriveEncryptionKey(context), error => error.code === 'KEY_UNAVAILABLE');
    } else if (mode.startsWith('file-')) {
      const inputPath = join(directory, 'source.bin');
      await writeFile(inputPath, message, { flag: 'wx' }); failNow = true;
      await assert.rejects(sdk.encryptFile({ inputPath, outputPath: join(directory, 'target.pqc'),
        recipient: pair.publicKey, context }), error => error === failure);
      assert.deepEqual(await readdir(directory), ['source.bin']);
    } else {
      let operation;
      if (mode === 'kem-keygen') operation = () => sdk.generateKemKeyPair();
      if (mode === 'signature-keygen') operation = () => sdk.generateSigningKeyPair();
      if (mode === 'encapsulate') operation = () => sdk.encapsulate(pair.publicKey);
      if (mode === 'decapsulate') {
        const exchange = await sdk.encapsulate(pair.publicKey); exchange.secret.destroy();
        operation = () => pair.privateKey.decapsulate(exchange.ciphertext);
      }
      if (mode === 'sign') operation = () => signer.signingKey.sign(message, context);
      if (mode === 'verify') {
        const signature = await signer.signingKey.sign(message, context);
        operation = () => signer.verificationKey.verify(message, signature, context);
      }
      if (mode === 'argon') operation = () => sdk.sealPrivateKey(pair.privateKey, password);
      if (mode === 'password-rng' || mode === 'password-argon') operation = () => sdk.hashPassword(password);
      if (mode === 'password-verify-argon') {
        const record = await sdk.hashPassword(password);
        operation = () => sdk.verifyPassword(record, password);
      }
      failNow = true; await assert.rejects(operation(), error => error === failure);
      failNow = false;
      if (mode === 'argon') {
        const vault = await operation();
        const restored = await sdk.openPrivateKey(vault, password); restored.privateKey.destroy();
      }
      if (mode === 'password-rng' || mode === 'password-argon' || mode === 'password-verify-argon') await operation();
    }
    assert.deepEqual(message, Buffer.from('synthetic test plaintext'), 'Caller-owned input must remain intact');
  } finally { pair.privateKey.destroy(); signer.signingKey.destroy(); password.fill(0); }
`;

for (const mode of ['rng-factory', 'rng-aead', 'hkdf', 'kem-keygen', 'signature-keygen',
  'encapsulate', 'decapsulate', 'sign', 'verify', 'argon', 'file-rng', 'file-kem', 'file-cipher',
  'password-rng', 'password-argon', 'password-verify-argon']) {
  test(`provider fault ${mode} rejects without a successful result`, async (t) => {
    const directory = await mkdtemp(resolve(tmpdir(), 'pqc-provider-fault-'));
    t.after(() => {
      const target = resolve(directory);
      assert.equal(dirname(target), resolve(tmpdir()));
      assert.ok(basename(target).startsWith('pqc-provider-fault-'));
      return rm(target, { recursive: true, force: true });
    });
    const result = spawnSync(process.execPath, ['--input-type=module', '--eval', probe,
      new URL('../src/index.js', import.meta.url).href, mode, directory],
    { encoding: 'utf8', windowsHide: true, timeout: 20000 });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, '');
  });
}

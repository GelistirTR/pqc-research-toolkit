import assert from 'node:assert/strict';
import { argon2, createCipheriv, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes } from 'node:crypto';
import { promisify } from 'node:util';
import test from 'node:test';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { exportVaultPkcs8, importVaultPkcs8 } from '../src/vault-pkcs8.js';
import { KemPrivateKey, SigningKey } from '../src/asymmetric.js';
import { TOKEN } from '../src/internal.js';
import { encapsulate, openPrivateKey, sealPrivateKey } from '../src/index.js';

function tlv(tag, value) {
  const n = value.length;
  const length = n < 128 ? [n] : n < 256 ? [0x81, n] : [0x82, n >> 8, n & 255];
  return Buffer.concat([Buffer.from([tag, ...length]), value]);
}
const sequence = (...values) => tlv(0x30, Buffer.concat(values));
function pkcs8(oid, choice) {
  return sequence(Buffer.from([2, 1, 0]), sequence(tlv(6, oid)), tlv(4, choice));
}
const invalid = (error) => error.code === 'INVALID_VAULT';
const derive = promisify(argon2);

for (const [kind, name, algorithm, seedBytes, oidHex] of [
  [1, 'ML-KEM-1024', ml_kem1024, 64, '608648016503040403'],
  [2, 'ML-DSA-87', ml_dsa87, 32, '608648016503040313'],
]) {
  test(`${name} vault output uses a stable native-readable seed-only encoding`, () => {
    const { privateKey, publicKey } = generateKeyPairSync(kind === 1 ? 'ml-kem-1024' : 'ml-dsa-87');
    const der = exportVaultPkcs8(privateKey, kind);
    try {
      assert.equal(der.length, seedBytes + 22);
      const restored = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
      assert.deepEqual(createPublicKey(restored).export({ format: 'der', type: 'spki' }), publicKey.export({ format: 'der', type: 'spki' }));
    } finally { der.fill(0); }
  });

  test(`${name} expanded-only key survives a real encrypted vault roundtrip without a seed`, async () => {
    const pair = algorithm.keygen();
    const der = pkcs8(Buffer.from(oidHex, 'hex'), tlv(4, pair.secretKey));
    const native = importVaultPkcs8(der, kind);
    const handle = kind === 1 ? new KemPrivateKey(TOKEN, native) : new SigningKey(TOKEN, native);
    const password = randomBytes(32);
    const context = Buffer.from('expanded-only/vault/roundtrip');
    const message = Buffer.from('synthetic expanded-only key data');
    let restored;
    try {
      const vault = await sealPrivateKey(handle, password);
      handle.destroy();
      restored = await openPrivateKey(vault, password);
      if (kind === 1) {
        const e = await encapsulate(restored.publicKey);
        const { salt, key } = e.secret.deriveEncryptionKey(context);
        const packet = key.encrypt(message);
        const secret = await restored.privateKey.decapsulate(e.ciphertext);
        const decryption = secret.deriveDecryptionKey(salt, context);
        try { assert.deepEqual(decryption.decrypt(packet), message); }
        finally { decryption.destroy(); }
      } else {
        const signature = await restored.signingKey.sign(message, context);
        assert.equal(algorithm.verify(signature, message, pair.publicKey, { context }), true);
      }
    } finally {
      handle.destroy(); restored?.privateKey?.destroy(); restored?.signingKey?.destroy();
      der.fill(0); pair.secretKey.fill(0); password.fill(0);
    }
  });

  test(`${name} seed-only, expanded-only and legacy both restore the same independently derived public key`, () => {
    const seed = randomBytes(seedBytes);
    const pair = algorithm.keygen(seed);
    const oid = Buffer.from(oidHex, 'hex');
    const choices = [tlv(0x80, seed), sequence(tlv(4, seed), tlv(4, pair.secretKey)), tlv(4, pair.secretKey)];
    try {
      for (const choice of choices) {
        const der = pkcs8(oid, choice);
        try {
          const native = importVaultPkcs8(der, kind, 'seed-authoritative');
          const rawPublic = createPublicKey(native).export({ format: 'raw-public' });
          assert.deepEqual(rawPublic, Buffer.from(pair.publicKey));
          const resealedDer = exportVaultPkcs8(native, kind);
          try { assert.deepEqual(createPublicKey(importVaultPkcs8(resealedDer, kind)).export({ format: 'raw-public' }), rawPublic); }
          finally { resealedDer.fill(0); }
        } finally { der.fill(0); }
      }
    } finally { seed.fill(0); pair.secretKey.fill(0); choices.forEach((choice) => choice.fill(0)); }
  });

  test(`${name} vault DER rejects truncation, trailing data, unknown fields and nonminimal lengths`, () => {
    const seed = randomBytes(seedBytes);
    const oid = Buffer.from(oidHex, 'hex');
    const seedChoice = tlv(0x80, seed);
    const canonical = pkcs8(oid, seedChoice);
    const malformed = [
      Buffer.concat([canonical, Buffer.from([0])]),
      Buffer.concat([Buffer.from([0x30, 0x80]), canonical.subarray(2), Buffer.from([0, 0])]),
      Buffer.concat([Buffer.from([0x30, 0x81, canonical[1]]), canonical.subarray(2)]),
      Buffer.concat([Buffer.from([0x30, 0x82, 0, canonical[1]]), canonical.subarray(2)]),
      sequence(Buffer.from([2, 1, 1]), sequence(tlv(6, oid)), tlv(4, seedChoice)),
      sequence(Buffer.from([2, 1, 0]), sequence(tlv(6, oid), Buffer.from([5, 0])), tlv(4, seedChoice)),
      sequence(Buffer.from([2, 1, 0]), sequence(tlv(6, oid)), tlv(4, seedChoice), Buffer.from([0xa0, 0])),
      pkcs8(oid, Buffer.concat([seedChoice, Buffer.from([0])])),
      pkcs8(oid, tlv(0x80, seed.subarray(1))),
      pkcs8(oid, tlv(4, seed)),
      pkcs8(oid, sequence(tlv(4, seed), tlv(4, Buffer.alloc(1)))),
      pkcs8(oid, sequence(tlv(4, seed.subarray(1)), tlv(4, Buffer.alloc(kind === 1 ? 3168 : 4896)))),
      pkcs8(oid, sequence(tlv(4, seed), tlv(4, Buffer.alloc(kind === 1 ? 3168 : 4896)), Buffer.from([5, 0]))),
    ];
    try {
      for (let n = 0; n < canonical.length; n++) assert.throws(() => importVaultPkcs8(canonical.subarray(0, n), kind), invalid);
      for (const der of malformed) assert.throws(() => importVaultPkcs8(der, kind), invalid);
      assert.throws(() => importVaultPkcs8(canonical, kind === 1 ? 2 : 1), invalid);
      assert.throws(() => importVaultPkcs8(canonical, 99), invalid);
    } finally { seed.fill(0); seedChoice.fill(0); canonical.fill(0); malformed.forEach((der) => der.fill(0)); }
  });

  test(`${name} combined representation requires explicit migration, including conflicting expanded companion`, () => {
    const seed = randomBytes(seedBytes);
    const pair = algorithm.keygen(seed);
    const conflicting = Buffer.from(pair.secretKey);
    conflicting[conflicting.length - 1] ^= 1;
    const choice = sequence(tlv(4, seed), tlv(4, conflicting));
    const der = pkcs8(Buffer.from(oidHex, 'hex'), choice);
    try {
      assert.throws(() => importVaultPkcs8(der, kind), (error) => error.code === 'LEGACY_KEY_REQUIRES_MIGRATION');
      const restored = importVaultPkcs8(der, kind, 'seed-authoritative');
      assert.deepEqual(createPublicKey(restored).export({ format: 'raw-public' }), Buffer.from(pair.publicKey));
    } finally { seed.fill(0); pair.secretKey.fill(0); conflicting.fill(0); choice.fill(0); der.fill(0); }
  });

  test(`${name} encrypted legacy vault requires authenticated explicit migration and reseals to strict-readable form`, async () => {
    const seed = randomBytes(seedBytes);
    const pair = algorithm.keygen(seed);
    const der = pkcs8(Buffer.from(oidHex, 'hex'), sequence(tlv(4, seed), tlv(4, pair.secretKey)));
    const password = Buffer.from('synthetic legacy migration password');
    const prefix = Buffer.alloc(56);
    prefix.write('PQCVAULT'); prefix[8] = 1; prefix[9] = kind; prefix[10] = 1; prefix[11] = 1;
    prefix.writeUInt32BE(65536, 12); prefix.writeUInt32BE(3, 16); prefix.writeUInt32BE(4, 20);
    randomBytes(16).copy(prefix, 24); randomBytes(12).copy(prefix, 40); prefix.writeUInt32BE(der.length, 52);
    const material = await derive('argon2id', { message: password, nonce: prefix.subarray(24, 40),
      memory: 65536, passes: 3, parallelism: 4, tagLength: 32,
      associatedData: Buffer.from('pqc-research-core/vault/v1\0') });
    let restored; let migrated;
    try {
      const cipher = createCipheriv('aes-256-gcm', material, prefix.subarray(40, 52));
      cipher.setAAD(prefix);
      const vault = Buffer.concat([prefix, cipher.update(der), cipher.final(), cipher.getAuthTag()]);
      await assert.rejects(openPrivateKey(vault, password), (error) => error.code === 'LEGACY_KEY_REQUIRES_MIGRATION');
      await assert.rejects(openPrivateKey(vault, Buffer.alloc(32)), (error) => error.code === 'AUTHENTICATION_FAILED');
      for (const legacyKeyPolicy of [null, false, 'allow', {}]) {
        await assert.rejects(openPrivateKey(vault, password, { legacyKeyPolicy }), (error) => error.code === 'INVALID_INPUT');
      }
      restored = await openPrivateKey(vault, password, { legacyKeyPolicy: 'seed-authoritative' });
      const publicPart = restored.publicKey ?? restored.verificationKey;
      assert.deepEqual(publicPart.exportSpki().subarray(-pair.publicKey.length), Buffer.from(pair.publicKey));
      const newVault = await sealPrivateKey(restored.privateKey ?? restored.signingKey, password);
      migrated = await openPrivateKey(newVault, password);
      assert.deepEqual((migrated.publicKey ?? migrated.verificationKey).exportSpki(), publicPart.exportSpki());
    } finally {
      restored?.privateKey?.destroy(); restored?.signingKey?.destroy();
      migrated?.privateKey?.destroy(); migrated?.signingKey?.destroy();
      seed.fill(0); pair.secretKey.fill(0); der.fill(0); material.fill(0); password.fill(0);
    }
  });
}

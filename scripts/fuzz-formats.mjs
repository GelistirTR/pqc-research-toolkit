// A bounded, deterministic mutation schedule, not an adaptive or coverage-guided fuzzer.
// All keys/containers are generated locally for this run; no user input is opened.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, unlink, writeFile } from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';

let phase = 'setup';
let structuralArgonCalls = 0;
let structuralDecapsulationCalls = 0;
let totalArgonCalls = 0;
let totalDecapsulationCalls = 0;
const nativeArgon2 = crypto.argon2;
const nativeDecapsulate = crypto.decapsulate;
// Install instrumentation before importing wrappers that capture promisified APIs.
crypto.argon2 = (...args) => {
  totalArgonCalls++;
  if (phase === 'vault-structural') structuralArgonCalls++;
  return nativeArgon2(...args);
};
crypto.decapsulate = (...args) => {
  totalDecapsulationCalls++;
  if (phase === 'file-structural') structuralDecapsulationCalls++;
  return nativeDecapsulate(...args);
};
syncBuiltinESMExports();
const {
  CryptoError, decryptFile, encryptFile, fileProfile, generateKemKeyPair,
  openPrivateKey, profile, sealPrivateKey, vaultProfile,
} = await import('../src/index.js');

const started = performance.now();
const temporary = await mkdtemp(join(tmpdir(), 'pqc-format-corpus-'));
const inputPath = join(temporary, 'input.bin');
const candidatePath = join(temporary, 'candidate.pqc');
const outputPath = join(temporary, 'must-not-exist.bin');
const context = Buffer.from('format-corpus/context/v1');
const aad = Buffer.from('test-only aad');
const password = Buffer.from('TEST ONLY bounded corpus password, not a user password');
const count = { fileStructural: 0, fileAuthentication: 0, lateFileAuthentication: 0,
  vaultStructural: 0, vaultAuthentication: 0 };
let pair;
let vault;

function* changedBytes(original, offsets, exhaustive = false) {
  for (const offset of offsets) {
    const changes = exhaustive ? Array.from({ length: 256 }, (_, value) => value) :
      Array.from({ length: 8 }, (_, bit) => original[offset] ^ (1 << bit));
    for (const value of changes) {
      if (value === original[offset]) continue;
      const data = Buffer.from(original);
      data[offset] = value;
      yield { id: `byte-${offset}-${value}`, data };
    }
  }
}
const interval = (start, end) => Array.from({ length: end - start }, (_, i) => start + i);

async function directoryIsClean(id) {
  const names = await readdir(temporary);
  assert.ok(!names.includes(basename(outputPath)), `${id}: published output after rejection`);
  assert.ok(!names.some((name) => name.startsWith('.pqc-stage-')), `${id}: staging file left behind`);
}

async function rejectFile({ id, data }, counter) {
  await writeFile(candidatePath, data);
  await assert.rejects(decryptFile({ inputPath: candidatePath, outputPath,
    privateKey: pair.privateKey, context, aad }), (error) => {
    assert.ok(error instanceof CryptoError, `${id}: unexpected exception ${error?.name}`);
    assert.ok(['INVALID_FILE', 'AUTHENTICATION_FAILED'].includes(error.code), `${id}: ${error.code}`);
    return true;
  }, id);
  await directoryIsClean(id);
  count[counter]++;
}

async function rejectVault({ id, data }, counter, expected = 'INVALID_VAULT') {
  await assert.rejects(openPrivateKey(data, password), (error) => {
    assert.ok(error instanceof CryptoError, `${id}: unexpected exception ${error?.name}`);
    assert.equal(error.code, expected, id);
    return true;
  }, id);
  count[counter]++;
}

async function validFileControl(encoded, expected) {
  await writeFile(candidatePath, encoded);
  await decryptFile({ inputPath: candidatePath, outputPath, privateKey: pair.privateKey, context, aad });
  assert.deepEqual(await readFile(outputPath), expected);
  await unlink(outputPath);
  await directoryIsClean('valid control');
}

try {
  pair = await generateKemKeyPair();
  const message = Buffer.from('format corpus plaintext');
  await writeFile(inputPath, message);
  await encryptFile({ inputPath, outputPath: candidatePath, recipient: pair.publicKey,
    context, aad, chunkSize: fileProfile.minChunkBytes });
  const encoded = await readFile(candidatePath);
  await validFileControl(encoded, message);
  phase = 'file-structural';
  // Magic, version, suite and reserved bytes have only one valid value each.
  for (const candidate of changedBytes(encoded, interval(0, 12), true)) await rejectFile(candidate, 'fileStructural');
  for (const value of [0, 1, 65535, 65537, 4194305, 8388608, 0xffffffff]) {
    const data = Buffer.from(encoded); data.writeUInt32BE(value, 12);
    await rejectFile({ id: `chunk-${value}`, data }, 'fileStructural');
  }
  for (const value of [BigInt(fileProfile.maxFileBytes) + 1n, 0xffffffffffffffffn]) {
    const data = Buffer.from(encoded); data.writeBigUInt64BE(value, 16);
    await rejectFile({ id: `size-${value}`, data }, 'fileStructural');
  }
  for (let length = 0; length < fileProfile.headerBytes + 16; length++) {
    await rejectFile({ id: `truncated-${length}`, data: encoded.subarray(0, length) }, 'fileStructural');
  }
  assert.equal(structuralDecapsulationCalls, 0, 'Malformed structure reached ML-KEM decapsulation');
  phase = 'file-authentication';
  // One bit in every fingerprint, KEM, salt, header tag, record and final tag byte.
  for (const offset of interval(24, encoded.length)) {
    const data = Buffer.from(encoded); data[offset] ^= 1;
    await rejectFile({ id: `auth-byte-${offset}`, data }, 'fileAuthentication');
  }
  for (const chunkSize of [131072, 262144, 524288, 1048576, 2097152, 4194304]) {
    const data = Buffer.from(encoded); data.writeUInt32BE(chunkSize, 12);
    await rejectFile({ id: `valid-but-unauthenticated-chunk-${chunkSize}`, data }, 'fileAuthentication');
  }
  phase = 'setup';
  const largeMessage = Buffer.alloc(65536 + 17, 0x5a);
  await writeFile(inputPath, largeMessage); await unlink(candidatePath);
  await encryptFile({ inputPath, outputPath: candidatePath, recipient: pair.publicKey,
    context, aad, chunkSize: 65536 });
  const largeEncoded = await readFile(candidatePath);
  phase = 'late-file-authentication';
  const secondRecord = fileProfile.headerBytes + 16 + 4 + 65536 + 16;
  for (const candidate of changedBytes(largeEncoded,
    [...interval(secondRecord, secondRecord + 4 + 17 + 16), ...interval(largeEncoded.length - 20, largeEncoded.length)])) {
    await rejectFile(candidate, 'lateFileAuthentication');
  }
  await validFileControl(largeEncoded, largeMessage);
  phase = 'setup';
  vault = await sealPrivateKey(pair.privateKey, password);
  const restored = await openPrivateKey(vault, password); restored.privateKey.destroy();
  phase = 'vault-structural';
  for (const candidate of changedBytes(vault, [...interval(0, 9), ...interval(10, 24), ...interval(52, 56)], true)) {
    await rejectVault(candidate, 'vaultStructural');
  }
  for (let kind = 0; kind < 256; kind++) {
    if (kind === 1 || kind === 2) continue;
    const data = Buffer.from(vault); data[9] = kind;
    await rejectVault({ id: `kind-${kind}`, data }, 'vaultStructural');
  }
  for (let length = 0; length < vault.length; length++) {
    await rejectVault({ id: `vault-truncated-${length}`, data: vault.subarray(0, length) }, 'vaultStructural');
  }
  await rejectVault({ id: 'vault-appended', data: Buffer.concat([vault, Buffer.alloc(1)]) }, 'vaultStructural');
  await rejectVault({ id: 'vault-oversized', data: Buffer.alloc(vaultProfile.maxVaultBytes + 1) }, 'vaultStructural', 'INVALID_INPUT');
  assert.equal(structuralArgonCalls, 0, 'Malformed structure reached Argon2');
  phase = 'vault-authentication';
  for (const offset of [...interval(24, 52).filter((value) => value % 2 === 0), 56,
    Math.floor(vault.length / 2), vault.length - 17, ...interval(vault.length - 16, vault.length)]) {
    const data = Buffer.from(vault); data[offset] ^= 1;
    await rejectVault({ id: `vault-auth-${offset}`, data }, 'vaultAuthentication', 'AUTHENTICATION_FAILED');
  }
  const changedKind = Buffer.from(vault); changedKind[9] = 2;
  await rejectVault({ id: 'authenticated-kind', data: changedKind }, 'vaultAuthentication', 'AUTHENTICATION_FAILED');
  phase = 'control';
  const finalControl = await openPrivateKey(vault, password);
  assert.deepEqual(finalControl.publicKey.exportSpki(), pair.publicKey.exportSpki());
  finalControl.privateKey.destroy();
  await directoryIsClean('completed corpus');
  console.log(JSON.stringify({ version: profile.version, node: process.versions.node,
    openssl: process.versions.openssl, schedule: 'all-byte-values in structural fields; fixed bit mutations elsewhere',
    cases: count, totalCases: Object.values(count).reduce((a, b) => a + b, 0),
    structuralArgonCalls, structuralDecapsulationCalls, totalArgonCalls, totalDecapsulationCalls,
    elapsedMs: Math.round(performance.now() - started),
    limits: 'Bounded mutation corpus with fresh local containers; not coverage-guided fuzzing, cryptanalysis or a security audit' }, null, 2));
} finally {
  pair?.privateKey.destroy(); password.fill(0); vault?.fill(0);
  crypto.argon2 = nativeArgon2; crypto.decapsulate = nativeDecapsulate; syncBuiltinESMExports();
  const target = resolve(temporary);
  assert.equal(dirname(target), resolve(tmpdir()));
  assert.ok(basename(target).startsWith('pqc-format-corpus-'));
  await rm(target, { recursive: true, force: true });
}

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, open, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';
import {
  decryptFile, encryptFile, fileProfile, generateKemKeyPair, generateSigningKeyPair,
} from '../src/index.js';

const CHUNK = 65536;
const context = Buffer.from('files/test/v1');
const aad = Buffer.from('archive:42');
const error = (code) => (e) => e.code === code;

async function workspace(t) {
  const directory = await mkdtemp(join(tmpdir(), 'pqc-files-test-'));
  t.after(() => {
    const target = resolve(directory);
    assert.equal(dirname(target), resolve(tmpdir()));
    assert.ok(basename(target).startsWith('pqc-files-test-'));
    return rm(target, { recursive: true, force: true });
  });
  return { directory, input: join(directory, 'input.bin'), encrypted: join(directory, 'encrypted.pqc'), output: join(directory, 'output.bin') };
}
async function prepared(t, size = CHUNK * 2 + 17) {
  const w = await workspace(t);
  const pair = await generateKemKeyPair();
  const plaintext = randomBytes(size);
  await writeFile(w.input, plaintext);
  await encryptFile({ inputPath: w.input, outputPath: w.encrypted, recipient: pair.publicKey, context, aad, chunkSize: CHUNK });
  return { ...w, pair, plaintext };
}
async function decrypt(w, overrides = {}) {
  return decryptFile({ inputPath: w.encrypted, outputPath: w.output, privateKey: w.pair.privateKey, context, aad, ...overrides });
}
async function noOutputOrStages(w) {
  assert.equal(existsSync(w.output), false);
  assert.deepEqual((await readdir(w.directory)).filter((name) => name.startsWith('.pqc-stage-')), []);
}

for (const size of [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, CHUNK * 3 + 17]) {
  test(`file roundtrip at boundary length ${size}`, async (t) => {
    const w = await prepared(t, size);
    const result = await decrypt(w);
    assert.deepEqual(result, { bytes: size, chunks: Math.ceil(size / CHUNK) });
    assert.deepEqual(await readFile(w.output), w.plaintext);
    assert.deepEqual(await readFile(w.input), w.plaintext);
    assert.deepEqual((await readdir(w.directory)).filter((name) => name.startsWith('.pqc-stage-')), []);
  });
}

test('file larger than the in-memory API limit is processed in bounded chunks', async (t) => {
  const w = await prepared(t, 17 * 1024 * 1024 + 31);
  await decrypt(w);
  assert.deepEqual(await readFile(w.output), w.plaintext);
});

for (const [name, offset] of [
  ['recipient fingerprint', 24], ['KEM ciphertext', 56], ['KDF salt', 1624],
  ['header authentication tag', 1656], ['first record ciphertext', 1676],
  ['second record ciphertext', 1676 + CHUNK + 20],
]) {
  test(`changed ${name} is rejected without output or leftover staging files`, async (t) => {
    const w = await prepared(t);
    const data = await readFile(w.encrypted);
    data[offset] ^= 1;
    await writeFile(w.encrypted, data);
    await assert.rejects(decrypt(w), error('AUTHENTICATION_FAILED'));
    await noOutputOrStages(w);
  });
}

test('invalid mandatory final tag discards already decrypted staged chunks', async (t) => {
  const w = await prepared(t);
  const data = await readFile(w.encrypted);
  data[data.length - 1] ^= 1;
  await writeFile(w.encrypted, data);
  await assert.rejects(decrypt(w), error('AUTHENTICATION_FAILED'));
  await noOutputOrStages(w);
});

for (const alteration of ['truncate-byte', 'truncate-final-record', 'append-byte', 'reorder', 'duplicate', 'splice']) {
  test(`${alteration} attack is rejected`, async (t) => {
    const w = await prepared(t, CHUNK * 3);
    const data = await readFile(w.encrypted);
    const start = fileProfile.headerBytes + 16;
    const length = CHUNK + 20;
    let changed;
    if (alteration === 'truncate-byte') changed = data.subarray(0, -1);
    if (alteration === 'truncate-final-record') changed = data.subarray(0, -20);
    if (alteration === 'append-byte') changed = Buffer.concat([data, Buffer.alloc(1)]);
    if (alteration === 'reorder') {
      changed = Buffer.concat([data.subarray(0, start), data.subarray(start + length, start + length * 2),
        data.subarray(start, start + length), data.subarray(start + length * 2)]);
    }
    if (alteration === 'duplicate') {
      changed = Buffer.concat([data.subarray(0, start + length), data.subarray(start, start + length),
        data.subarray(start + length * 2)]);
    }
    if (alteration === 'splice') {
      const another = join(w.directory, 'another.pqc');
      await encryptFile({ inputPath: w.input, outputPath: another, recipient: w.pair.publicKey, context, aad, chunkSize: CHUNK });
      const otherData = await readFile(another);
      changed = Buffer.from(data);
      otherData.copy(changed, start, start, start + length);
    }
    await writeFile(w.encrypted, changed);
    await assert.rejects(decrypt(w), error('AUTHENTICATION_FAILED'));
    await noOutputOrStages(w);
  });
}

test('wrong recipient, context and external AAD fail before output', async (t) => {
  const w = await prepared(t);
  const other = await generateKemKeyPair();
  for (const options of [{ privateKey: other.privateKey }, { context: Buffer.from('other') }, { aad: Buffer.from('other') }]) {
    await assert.rejects(decrypt(w, options), error('AUTHENTICATION_FAILED'));
    await noOutputOrStages(w);
  }
});

test('malformed header, invalid chunk length and early final marker fail', async (t) => {
  const w = await prepared(t);
  const original = await readFile(w.encrypted);
  for (const offset of [0, 8, 9, 10, 12]) {
    const data = Buffer.from(original);
    data[offset] ^= 1;
    await writeFile(w.encrypted, data);
    await assert.rejects(decrypt(w), error('INVALID_FILE'));
    await noOutputOrStages(w);
  }
  const oversized = Buffer.from(original);
  oversized.writeBigUInt64BE(BigInt(fileProfile.maxFileBytes) + 1n, 16);
  await writeFile(w.encrypted, oversized);
  await assert.rejects(decrypt(w), error('INVALID_FILE'));
  for (const length of [0, 1, CHUNK + 1, 0xffffffff]) {
    const changed = Buffer.from(original);
    changed.writeUInt32BE(length, fileProfile.headerBytes + 16);
    await writeFile(w.encrypted, changed);
    await assert.rejects(decrypt(w), error('AUTHENTICATION_FAILED'));
    await noOutputOrStages(w);
  }
});

test('existing outputs are never overwritten; input/output identity is rejected', async (t) => {
  const w = await prepared(t);
  await writeFile(w.output, 'keep existing output');
  await assert.rejects(decrypt(w), error('OUTPUT_EXISTS'));
  assert.equal((await readFile(w.output)).toString(), 'keep existing output');
  await assert.rejects(encryptFile({ inputPath: w.input, outputPath: w.encrypted, recipient: w.pair.publicKey, context }), error('OUTPUT_EXISTS'));
  await assert.rejects(decrypt(w, { outputPath: w.encrypted }), error('INVALID_INPUT'));
});

test('concurrent publication to the same target has exactly one winner', async (t) => {
  const w = await prepared(t);
  const results = await Promise.allSettled([decrypt(w), decrypt(w)]);
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
  const failure = results.find((r) => r.status === 'rejected');
  assert.equal(failure.reason.code, 'OUTPUT_EXISTS');
  assert.deepEqual(await readFile(w.output), w.plaintext);
  assert.deepEqual((await readdir(w.directory)).filter((name) => name.startsWith('.pqc-stage-')), []);
});

test('pre-aborted operation creates no output', async (t) => {
  const w = await prepared(t);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(decrypt(w, { signal: controller.signal }), error('ABORTED'));
  await noOutputOrStages(w);
});

test('late cancellation cleans up already written private staging plaintext', async (t) => {
  const w = await prepared(t);
  const controller = new AbortController();
  const probe = await open(w.input, 'r');
  const prototype = Object.getPrototypeOf(probe);
  await probe.close();
  const originalWrite = prototype.write;
  const mocked = t.mock.method(prototype, 'write', async function (...args) {
    const result = await originalWrite.apply(this, args);
    controller.abort();
    return result;
  });
  try { await assert.rejects(decrypt(w, { signal: controller.signal }), error('ABORTED')); }
  finally { mocked.mock.restore(); }
  await noOutputOrStages(w);
});

test('invalid options are rejected without writes', async (t) => {
  const w = await prepared(t);
  await assert.rejects(encryptFile(null), error('INVALID_INPUT'));
  for (const chunkSize of [0, 65535, 65537, 8 * 1024 * 1024]) {
    await assert.rejects(encryptFile({ inputPath: w.input, outputPath: w.output,
      recipient: w.pair.publicKey, context, chunkSize }), error('INVALID_INPUT'));
  }
  const signer = await generateSigningKeyPair();
  await assert.rejects(decrypt(w, { privateKey: signer.signingKey }), error('INVALID_KEY'));
  await assert.rejects(decrypt(w, { signal: {} }), error('INVALID_INPUT'));
  await assert.rejects(decrypt(w, { inputPath: '' }), error('INVALID_INPUT'));
  await noOutputOrStages(w);
});

test('source modification during encryption prevents publication and removes staging output', async (t) => {
  const w = await prepared(t);
  const probe = await open(w.input, 'r');
  const prototype = Object.getPrototypeOf(probe);
  await probe.close();
  const originalRead = prototype.read;
  let changed = false;
  const mocked = t.mock.method(prototype, 'read', async function (...args) {
    const result = await originalRead.apply(this, args);
    if (!changed) {
      changed = true;
      await writeFile(w.input, Buffer.alloc(w.plaintext.length, 0x17));
    }
    return result;
  });
  try {
    await assert.rejects(encryptFile({ inputPath: w.input, outputPath: w.output,
      recipient: w.pair.publicKey, context, chunkSize: CHUNK }), error('INPUT_CHANGED'));
  } finally { mocked.mock.restore(); }
  assert.equal(changed, true);
  await noOutputOrStages(w);
});

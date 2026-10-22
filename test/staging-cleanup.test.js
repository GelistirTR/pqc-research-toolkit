import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { stageOutput, writeAll } from '../src/file-io.js';
import { decryptFile, encryptFile, generateKemKeyPair } from '../src/index.js';

const plaintext = Buffer.from('Synthetic private staging content, not user data.');

async function workspace(t) {
  const directory = await fs.mkdtemp(join(tmpdir(), 'pqc-cleanup-test-'));
  t.after(async () => {
    const target = resolve(directory);
    assert.equal(dirname(target), resolve(tmpdir()));
    assert.ok(basename(target).startsWith('pqc-cleanup-test-'));
    await fs.rm(target, { recursive: true, force: true });
  });
  const output = join(directory, 'output.bin');
  const stage = await stageOutput(output);
  await writeAll(stage.handle, plaintext);
  const stagingName = (await fs.readdir(directory)).find((name) => name.startsWith('.pqc-stage-'));
  return { directory, output, stage, staging: join(directory, stagingName) };
}

const cleanupFailure = (error) => error.code === 'CLEANUP_FAILED' &&
  error.cause instanceof AggregateError && error.message.includes('staging data');

test('staging close failure still attempts removal and reports controlled cleanup failure', async (t) => {
  const w = await workspace(t);
  const originalClose = w.stage.handle.close.bind(w.stage.handle);
  const failure = Object.assign(new Error('synthetic close failure after close'), { code: 'EIO' });
  w.stage.handle.close = async () => { await originalClose(); throw failure; };
  await assert.rejects(w.stage.cleanup(), (error) => {
    assert.ok(cleanupFailure(error));
    assert.deepEqual(error.cause.errors, [failure]);
    return true;
  });
  assert.equal(existsSync(w.staging), false);
  assert.equal(existsSync(w.output), false);
});

test('failed unlink still attempts directory removal and retains both underlying failures', async (t) => {
  const w = await workspace(t);
  const unlinkFailure = Object.assign(new Error('synthetic unlink failure'), { code: 'EPERM' });
  const originalRmdir = fs.rmdir;
  let attemptedDirectory;
  const unlinkMock = t.mock.method(fs, 'unlink', async () => { throw unlinkFailure; });
  const rmdirMock = t.mock.method(fs, 'rmdir', async (path) => {
    attemptedDirectory = path;
    return originalRmdir(path);
  });
  syncBuiltinESMExports();
  try {
    await assert.rejects(w.stage.cleanup(), (error) => {
      assert.ok(cleanupFailure(error));
      assert.equal(error.cause.errors.length, 2);
      assert.equal(error.cause.errors[0], unlinkFailure);
      return true;
    });
  } finally {
    unlinkMock.mock.restore(); rmdirMock.mock.restore(); syncBuiltinESMExports();
  }
  assert.equal(attemptedDirectory, w.staging);
  assert.equal(existsSync(w.output), false);
  assert.deepEqual(await fs.readFile(join(w.staging, 'output.tmp')), plaintext);
});

test('cleanup error after publication preserves the authenticated published output', async (t) => {
  const w = await workspace(t);
  await w.stage.publish();
  const originalRmdir = fs.rmdir;
  const directoryFailure = Object.assign(new Error('synthetic directory removal failure'), { code: 'EACCES' });
  const mocked = t.mock.method(fs, 'rmdir', async (path) => {
    if (path === w.staging) throw directoryFailure;
    return originalRmdir(path);
  });
  syncBuiltinESMExports();
  try {
    await assert.rejects(w.stage.cleanup(), (error) => {
      assert.ok(cleanupFailure(error));
      assert.deepEqual(error.cause.errors, [directoryFailure]);
      return true;
    });
  } finally { mocked.mock.restore(); syncBuiltinESMExports(); }
  assert.deepEqual(await fs.readFile(w.output), plaintext);
  assert.deepEqual(await fs.readdir(w.staging), []);
});

test('late file authentication failure plus staging close error still removes staged plaintext', async (t) => {
  const w = await workspace(t);
  await w.stage.cleanup();
  const inputPath = join(w.directory, 'input.bin');
  const encryptedPath = join(w.directory, 'encrypted.pqc');
  const message = Buffer.alloc(65536 + 1, 0x57);
  const context = Buffer.from('cleanup/regression/v1');
  const pair = await generateKemKeyPair();
  t.after(() => pair.privateKey.destroy());
  await fs.writeFile(inputPath, message);
  await encryptFile({ inputPath, outputPath: encryptedPath, recipient: pair.publicKey, context, chunkSize: 65536 });
  const changed = await fs.readFile(encryptedPath);
  changed[changed.length - 1] ^= 1; // Final tag fails after authenticated data chunks have been staged.
  await fs.writeFile(encryptedPath, changed);
  const originalOpen = fs.open;
  const closeFailure = Object.assign(new Error('synthetic staging close failure'), { code: 'EIO' });
  let stagingCloses = 0;
  const mocked = t.mock.method(fs, 'open', async (...args) => {
    const handle = await originalOpen(...args);
    if (args[1] === 'wx') {
      const originalClose = handle.close.bind(handle);
      handle.close = async () => { stagingCloses++; await originalClose(); throw closeFailure; };
    }
    return handle;
  });
  syncBuiltinESMExports();
  try {
    await assert.rejects(decryptFile({ inputPath: encryptedPath, outputPath: w.output, privateKey: pair.privateKey, context }),
      cleanupFailure);
  } finally { mocked.mock.restore(); syncBuiltinESMExports(); }
  assert.equal(stagingCloses, 1);
  assert.deepEqual((await fs.readdir(w.directory)).sort(), ['encrypted.pqc', 'input.bin']);
  assert.deepEqual(await fs.readFile(inputPath), message);
});

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { inspectContainer } from '../src/index.js';

const code = (expected) => (error) => error.code === expected;
async function workspace(t) {
  const directory = await mkdtemp(join(tmpdir(), 'pqc-inspection-'));
  t.after(() => {
    const target = resolve(directory);
    assert.equal(dirname(target), resolve(tmpdir()));
    assert.ok(basename(target).startsWith('pqc-inspection-'));
    return rm(target, { recursive: true, force: true });
  });
  return directory;
}

// Deliberately synthetic containers with invalid tags, not cryptographic vectors.
function file(size = 0, chunkSize = 65536) {
  const data = Buffer.alloc(1656 + 16 + size + (Math.ceil(size / chunkSize) + 1) * 20);
  data.write('PQCFILE\0'); data[8] = 1; data[9] = 1;
  data.writeUInt32BE(chunkSize, 12); data.writeBigUInt64BE(BigInt(size), 16);
  data.fill(0xa7, 24, 56);
  return data;
}
function vault(kind = 1) {
  const data = Buffer.alloc(73);
  data.write('PQCVAULT'); data[8] = 1; data[9] = kind; data[10] = 1; data[11] = 1;
  data.writeUInt32BE(65536, 12); data.writeUInt32BE(3, 16); data.writeUInt32BE(4, 20);
  data.writeUInt32BE(1, 52);
  return data;
}

test('inspection reports unauthenticated empty, boundary and multi-chunk file claims', async (t) => {
  const directory = await workspace(t);
  for (const size of [0, 1, 65536, 65537]) {
    const path = join(directory, `${size}.bin`);
    const data = file(size);
    await writeFile(path, data);
    const result = await inspectContainer(path);
    assert.equal(result.kind, 'encrypted-file');
    assert.equal(result.authenticated, false);
    assert.equal(result.declaredPlaintextBytes, size);
    assert.equal(result.chunks, Math.ceil(size / 65536));
    assert.equal(result.containerBytes, data.length);
    assert.equal(result.recipientFingerprint, `SHA256:${'a7'.repeat(32)}`);
    assert.ok(Object.isFrozen(result));
    assert.deepEqual(await readFile(path), data);
  }
  assert.equal((await readdir(directory)).length, 4);
});

test('inspection reports both vault key kinds without testing password or authentication', async (t) => {
  const directory = await workspace(t);
  for (const [kind, name] of [[1, 'kem'], [2, 'signature']]) {
    const path = join(directory, name);
    await writeFile(path, vault(kind));
    const result = await inspectContainer(path);
    assert.equal(result.kind, 'key-vault');
    assert.equal(result.keyKind, name);
    assert.equal(result.authenticated, false);
    assert.equal(result.memoryKiB, 65536);
    assert.equal(result.passes, 3);
    assert.equal(result.parallelism, 4);
    assert.ok(!('recipientFingerprint' in result));
  }
});

test('file header versions, reserved fields, sizes and total lengths are checked', async (t) => {
  const directory = await workspace(t);
  const path = join(directory, 'bad-file');
  const mutations = [
    (data) => { data[8] = 2; }, (data) => { data[9] = 2; }, (data) => { data[10] = 1; },
    (data) => { data[11] = 1; }, (data) => data.writeUInt32BE(0, 12),
    (data) => data.writeUInt32BE(65537, 12), (data) => data.writeUInt32BE(8388608, 12),
    (data) => data.writeBigUInt64BE(64n * 1024n ** 3n + 1n, 16),
  ];
  for (const mutate of mutations) {
    const data = file(); mutate(data); await writeFile(path, data);
    await assert.rejects(inspectContainer(path), code('INVALID_FILE'));
  }
  for (const data of [file().subarray(0, 100), file().subarray(0, -1), Buffer.concat([file(), Buffer.alloc(1)])]) {
    await writeFile(path, data);
    await assert.rejects(inspectContainer(path), code('INVALID_FILE'));
  }
});

test('vault header work factors, key kinds and bounded total lengths are checked', async (t) => {
  const directory = await workspace(t);
  const path = join(directory, 'bad-vault');
  for (const offset of [8, 9, 10, 11, 12, 16, 20, 52]) {
    const data = vault(); data[offset] = 0xff; await writeFile(path, data);
    await assert.rejects(inspectContainer(path), code('INVALID_VAULT'));
  }
  for (const data of [vault().subarray(0, 20), vault().subarray(0, -1), Buffer.concat([vault(), Buffer.alloc(1)]),
    Buffer.concat([vault(), Buffer.alloc(17000)])]) {
    await writeFile(path, data);
    await assert.rejects(inspectContainer(path), code('INVALID_VAULT'));
  }
});

test('unknown formats and short headers are rejected without exposing content', async (t) => {
  const directory = await workspace(t);
  const path = join(directory, 'unknown');
  for (const data of [Buffer.alloc(0), Buffer.from('PQCFILE'), Buffer.from('private-user-content-not-a-container')]) {
    await writeFile(path, data);
    await assert.rejects(inspectContainer(path), (error) => error.code === 'INVALID_CONTAINER' && !error.message.includes('private-user'));
  }
});

test('inspection validates paths, options and pre-aborted signals', async () => {
  for (const path of ['', null, {}, new URL('file:///test'), 'nul\0path']) {
    await assert.rejects(inspectContainer(path), code('INVALID_INPUT'));
  }
  for (const options of [null, [], 1, { signal: {} }]) {
    await assert.rejects(inspectContainer('not-opened', options), code('INVALID_INPUT'));
  }
  await assert.rejects(inspectContainer('not-opened', { signal: AbortSignal.abort('private reason') }), code('ABORTED'));
});

test('inspection reads bounded header bytes and calls no KDF, KEM or key import', async (t) => {
  const directory = await workspace(t);
  const path = join(directory, 'synthetic-file');
  await writeFile(path, file(65537));
  const vaultPath = join(directory, 'synthetic-vault');
  await writeFile(vaultPath, vault());
  const probe = `
    import assert from 'node:assert/strict';
    import crypto from 'node:crypto';
    import fs from 'node:fs/promises';
    import { syncBuiltinESMExports } from 'node:module';
    let bytes = 0;
    let limit = 1656;
    for (const name of ['argon2', 'decapsulate', 'createPrivateKey']) {
      crypto[name] = () => { throw new Error('Unexpected cryptographic operation'); };
    }
    const realOpen = fs.open;
    fs.open = async (...args) => {
      assert.equal(args[1], 'r');
      const handle = await realOpen(...args);
      const realRead = handle.read.bind(handle);
      handle.read = async (...args) => {
        assert.ok(args[3] + args[2] <= limit, 'Must not read ciphertext body');
        const result = await realRead(...args); bytes += result.bytesRead; return result;
      };
      return handle;
    };
    syncBuiltinESMExports();
    const { inspectContainer } = await import(process.argv[1]);
    assert.equal((await inspectContainer(process.argv[2])).authenticated, false);
    assert.equal(bytes, 1664);
    bytes = 0; limit = 56;
    assert.equal((await inspectContainer(process.argv[3])).authenticated, false);
    assert.equal(bytes, 64);
  `;
  const result = spawnSync(process.execPath, ['--input-type=module', '--eval', probe,
    new URL('../src/index.js', import.meta.url).href, path, vaultPath], { encoding: 'utf8', windowsHide: true, timeout: 20000 });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
});

test('changed inputs, mid-read cancellation and read errors close the source handle', async (t) => {
  const directory = await workspace(t);
  const path = join(directory, 'source');
  await writeFile(path, file());
  const probe = `
    import assert from 'node:assert/strict';
    import fs from 'node:fs/promises';
    import { syncBuiltinESMExports } from 'node:module';
    const mode = process.argv[3];
    const controller = new AbortController();
    let closes = 0; let stats = 0;
    const realOpen = fs.open;
    fs.open = async (...args) => {
      const handle = await realOpen(...args);
      const close = handle.close.bind(handle);
      const stat = handle.stat.bind(handle);
      const read = handle.read.bind(handle);
      handle.close = async () => { closes++; return close(); };
      handle.stat = async (...args) => {
        const value = await stat(...args);
        if (mode === 'changed' && ++stats === 2) value.mtimeNs += 1n;
        return value;
      };
      handle.read = async (...args) => {
        if (mode === 'read-failure') throw Object.assign(new Error('Synthetic read failure'), { code: 'EIO' });
        const value = await read(...args);
        if (mode === 'aborted') controller.abort('not disclosed');
        return value;
      };
      return handle;
    };
    syncBuiltinESMExports();
    const { inspectContainer } = await import(process.argv[1]);
    const expected = { changed: 'INPUT_CHANGED', aborted: 'ABORTED', 'read-failure': 'EIO' }[mode];
    await assert.rejects(inspectContainer(process.argv[2], { signal: controller.signal }),
      error => error.code === expected && !error.message.includes('not disclosed'));
    assert.equal(closes, 1);
  `;
  for (const mode of ['changed', 'aborted', 'read-failure']) {
    const result = spawnSync(process.execPath, ['--input-type=module', '--eval', probe,
      new URL('../src/index.js', import.meta.url).href, path, mode], { encoding: 'utf8', windowsHide: true, timeout: 20000 });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
  }
  await assert.rejects(inspectContainer(directory), (error) => ['INVALID_INPUT', 'EISDIR', 'EPERM', 'EACCES'].includes(error.code));
});

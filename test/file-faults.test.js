import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { existsSync } from 'node:fs';
import fs from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { createOperationPool, decryptFile, encryptFile, generateKemKeyPair } from '../src/index.js';

async function workspace(t) {
  const directory = await fs.mkdtemp(join(tmpdir(), 'pqc-file-fault-'));
  t.after(() => {
    const target = resolve(directory);
    assert.equal(dirname(target), resolve(tmpdir()));
    assert.ok(basename(target).startsWith('pqc-file-fault-'));
    return fs.rm(target, { recursive: true, force: true });
  });
  return directory;
}
const context = Buffer.from('file/faults/v1');
for (const fault of ['sync', 'permission', 'link']) {
  test(`decryption ${fault} failure never publishes and cleans staged plaintext`, async (t) => {
    const directory = await workspace(t);
    const inputPath = join(directory, 'input.bin');
    const encryptedPath = join(directory, 'encrypted.pqc');
    const outputPath = join(directory, 'output.bin');
    await fs.writeFile(inputPath, Buffer.alloc(65537, 0x35));
    const pair = await generateKemKeyPair(); t.after(() => pair.privateKey.destroy());
    await encryptFile({ inputPath, outputPath: encryptedPath, recipient: pair.publicKey, context, chunkSize: 65536 });
    const failure = Object.assign(new Error('Synthetic I/O failure'), { code: fault === 'permission' ? 'EACCES' : 'EIO' });
    let mock;
    if (fault === 'sync') {
      const probe = await fs.open(inputPath, 'r'); const prototype = Object.getPrototypeOf(probe); await probe.close();
      mock = t.mock.method(prototype, 'sync', async () => { throw failure; });
    } else if (fault === 'permission') {
      const original = fs.open;
      mock = t.mock.method(fs, 'open', async (...args) => {
        if (args[1] === 'wx') throw failure;
        return original(...args);
      });
    } else mock = t.mock.method(fs, 'link', async () => { throw failure; });
    syncBuiltinESMExports();
    try {
      await assert.rejects(decryptFile({ inputPath: encryptedPath, outputPath, privateKey: pair.privateKey, context }), error => error === failure);
    } finally { mock.mock.restore(); syncBuiltinESMExports(); }
    assert.equal(existsSync(outputPath), false);
    assert.deepEqual((await fs.readdir(directory)).sort(), ['encrypted.pqc', 'input.bin']);
  });
}

test('operation pool integrates with real file encryption and decryption', async (t) => {
  const directory = await workspace(t);
  const inputPath = join(directory, 'input.bin');
  const plaintext = Buffer.alloc(65537, 0x26); await fs.writeFile(inputPath, plaintext);
  const pair = await generateKemKeyPair(); t.after(() => pair.privateKey.destroy());
  const pool = createOperationPool({ maxConcurrent: 1, maxQueued: 2 });
  try {
    await Promise.all([0, 1, 2].map(index => pool.run(signal => encryptFile({ inputPath,
      outputPath: join(directory, `${index}.pqc`), recipient: pair.publicKey, context, signal }))));
    await Promise.all([0, 1, 2].map(index => pool.run(signal => decryptFile({ inputPath: join(directory, `${index}.pqc`),
      outputPath: join(directory, `${index}.bin`), privateKey: pair.privateKey, context, signal }))));
    for (const index of [0, 1, 2]) assert.deepEqual(await fs.readFile(join(directory, `${index}.bin`)), plaintext);
    assert.equal(pool.stats.active, 0); assert.equal(pool.stats.queued, 0);
  } finally { pool.close(); }
});

test('abrupt process termination leaves no final target but can retain staged plaintext', async (t) => {
  const directory = await workspace(t);
  const childCode = `
    import fs from 'node:fs/promises';
    import { syncBuiltinESMExports } from 'node:module';
    import { join } from 'node:path';
    const sdk = await import(process.argv[1]);
    const directory = process.argv[2];
    const pair = await sdk.generateKemKeyPair();
    const inputPath = join(directory, 'source.bin');
    const encryptedPath = join(directory, 'encrypted.pqc');
    const context = Buffer.from('crash-probe/v1');
    await fs.writeFile(inputPath, Buffer.alloc(65537, 0x31));
    await sdk.encryptFile({ inputPath, outputPath: encryptedPath, recipient: pair.publicKey, context, chunkSize: 65536 });
    const originalOpen = fs.open;
    fs.open = async (...args) => {
      const handle = await originalOpen(...args);
      if (args[1] === 'wx') {
        const write = handle.write.bind(handle);
        handle.write = async (...args) => {
          const result = await write(...args);
          process.send({ event: 'staged' });
          await new Promise(() => {});
          return result;
        };
      }
      return handle;
    };
    syncBuiltinESMExports();
    await sdk.decryptFile({ inputPath: encryptedPath, outputPath: join(directory, 'final.bin'), privateKey: pair.privateKey, context });
  `;
  const child = spawn(process.execPath, ['--input-type=module', '--eval', childCode,
    new URL('../src/index.js', import.meta.url).href, directory], { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
  let stderr = ''; child.stderr.on('data', data => { stderr += data; });
  const exit = once(child, 'exit');
  let timer;
  try {
    const reached = await Promise.race([
      once(child, 'message').then(([message]) => message),
      exit.then(() => { throw new Error(`Crash probe exited before staging: ${stderr}`); }),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Crash probe staging timeout')), 15000); }),
    ]);
    assert.equal(reached.event, 'staged');
    assert.equal(child.kill('SIGKILL'), true);
    await exit;
    assert.equal(existsSync(join(directory, 'final.bin')), false);
    const stages = (await fs.readdir(directory)).filter(name => name.startsWith('.pqc-stage-'));
    assert.equal(stages.length, 1);
    assert.deepEqual(await fs.readFile(join(directory, stages[0], 'output.tmp')), Buffer.alloc(65536, 0x31));
  } finally {
    clearTimeout(timer);
    if (child.exitCode === null && child.signalCode === null) { child.kill('SIGKILL'); await exit; }
  }
});

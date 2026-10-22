import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdtemp, open, rm } from 'node:fs/promises';
import { tmpdir, cpus } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import {
  createOperationPool, decryptFile, encryptFile, generateKemKeyPair,
  openPrivateKey, profile, sealPrivateKey,
  hashPassword, verifyPassword,
} from '../src/index.js';

async function digest(path) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path, { highWaterMark: 65536 })) hash.update(chunk);
  return hash.digest('hex');
}
async function settled(jobs) {
  const results = await Promise.allSettled(jobs);
  for (const result of results) if (result.status === 'rejected') throw result.reason;
}
async function phase(operation) {
  const cpuStart = process.cpuUsage(); const start = performance.now();
  await operation();
  const cpu = process.cpuUsage(cpuStart);
  return { elapsedMs: Math.round((performance.now() - start) * 100) / 100,
    cpuUserMs: cpu.user / 1000, cpuSystemMs: cpu.system / 1000 };
}

if (process.argv[2] === '--worker') {
  const mode = process.argv[3];
  const sizeMiB = Number(process.argv[4]); const concurrent = Number(process.argv[5]);
  assert.ok(['files', 'vault', 'passwords'].includes(mode));
  assert.ok([32, 128].includes(sizeMiB) && [1, 2].includes(concurrent));
  const directory = await mkdtemp(join(tmpdir(), 'pqc-resource-measure-'));
  const pool = createOperationPool({ maxConcurrent: concurrent, maxQueued: 16 });
  const pair = await generateKemKeyPair();
  const context = Buffer.from('resource-measure/v1');
  let sampledPeakRssBytes = process.memoryUsage().rss;
  const sampler = setInterval(() => { sampledPeakRssBytes = Math.max(sampledPeakRssBytes, process.memoryUsage().rss); }, 10);
  sampler.unref();
  let password;
  try {
    const baselineRssBytes = process.memoryUsage().rss;
    const phases = {};
    if (mode === 'files') {
      const inputPath = join(directory, 'source.bin');
      const handle = await open(inputPath, 'wx', 0o600);
      const block = Buffer.alloc(1024 * 1024, 0x63);
      try { for (let i = 0; i < sizeMiB; i++) await handle.writeFile(block); }
      finally { block.fill(0); await handle.close(); }
      const expected = await digest(inputPath);
      phases.encrypt = await phase(() => settled(Array.from({ length: concurrent }, (_, index) =>
        pool.run(signal => encryptFile({ inputPath, outputPath: join(directory, `${index}.pqc`), recipient: pair.publicKey, context, signal })))));
      phases.decrypt = await phase(() => settled(Array.from({ length: concurrent }, (_, index) =>
        pool.run(signal => decryptFile({ inputPath: join(directory, `${index}.pqc`), outputPath: join(directory, `${index}.bin`),
          privateKey: pair.privateKey, context, signal })))));
      for (let index = 0; index < concurrent; index++) assert.equal(await digest(join(directory, `${index}.bin`)), expected);
    } else if (mode === 'vault') {
      password = Buffer.from('public synthetic resource benchmark password');
      const vault = await sealPrivateKey(pair.privateKey, password);
      phases.openSixVaults = await phase(() => settled(Array.from({ length: 6 }, () => pool.run(async signal => {
        const restored = await openPrivateKey(vault, password, { signal });
        try { assert.deepEqual(restored.publicKey.exportSpki(), pair.publicKey.exportSpki()); }
        finally { restored.privateKey.destroy(); }
      }))));
    } else {
      password = Buffer.from('public synthetic account benchmark password');
      const record = await hashPassword(password);
      phases.verifySixPasswords = await phase(() => settled(Array.from({ length: 6 }, () => pool.run(async signal => {
        assert.equal(await verifyPassword(record, password, { signal }), true);
      }))));
    }
    sampledPeakRssBytes = Math.max(sampledPeakRssBytes, process.memoryUsage().rss);
    console.log(JSON.stringify({ mode, sizeMiB: mode === 'files' ? sizeMiB : null, concurrent,
      fileChunkBytes: mode === 'files' ? 1048576 : null, baselineRssBytes, sampledPeakRssBytes,
      lifetimeMaxRssKiB: process.resourceUsage().maxRSS, phases, roundtripVerified: true }));
  } finally {
    clearInterval(sampler); pool.close(); pair.privateKey.destroy(); password?.fill(0);
    const target = resolve(directory);
    assert.equal(dirname(target), resolve(tmpdir())); assert.ok(basename(target).startsWith('pqc-resource-measure-'));
    await rm(target, { recursive: true, force: true });
  }
} else {
  const cases = [];
  const script = fileURLToPath(import.meta.url);
  for (const [mode, sizeMiB, concurrent] of [['files', 32, 1], ['files', 128, 1], ['files', 32, 2], ['vault', 32, 2], ['passwords', 32, 2]]) {
    const result = spawnSync(process.execPath, [script, '--worker', mode, String(sizeMiB), String(concurrent)],
      { encoding: 'utf8', windowsHide: true, timeout: 120000, maxBuffer: 1024 * 1024 });
    assert.ifError(result.error); assert.equal(result.status, 0, result.stderr);
    cases.push(JSON.parse(result.stdout));
  }
  console.log(JSON.stringify({ version: profile.version, node: process.versions.node, openssl: process.versions.openssl,
    platform: process.platform, arch: process.arch, cpu: cpus()[0]?.model, samplesPerCase: 1,
    memorySamplingIntervalMs: 10, cases,
    limits: 'Local synthetic smoke measurements in independent child processes; no hard RSS ceiling, percentile estimate, DoS or side-channel assurance. Lifetime maxRSS includes setup/hashing; sampled RSS can miss spikes. CPU and disk cache/load affect results.' }, null, 2));
}

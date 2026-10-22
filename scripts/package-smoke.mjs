import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const npmCli = process.env.npm_execpath;
assert.ok(npmCli && basename(npmCli) === 'npm-cli.js', 'Run with npm run test:package');
const temporary = await mkdtemp(join(tmpdir(), 'pqc-package-smoke-'));
function run(executable, args, cwd) {
  const result = spawnSync(executable, args, { cwd, encoding: 'utf8', windowsHide: true,
    timeout: 60000, maxBuffer: 4 * 1024 * 1024, input: '' });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  return result.stdout;
}
try {
  const [pack] = JSON.parse(run(process.execPath,
    [npmCli, 'pack', '--ignore-scripts', '--pack-destination', temporary, '--json'], root));
  // A tarball must contain the runtime, types and license, and no test keys or workspace data.
  for (const file of pack.files) {
    assert.match(file.path, /^(?:(?:src|bin|docs|examples)\/|(?:README\.md|SECURITY\.md|LICENSE|THIRD-PARTY-NOTICES\.md|CHANGELOG\.md|package\.json)$)/);
    assert.doesNotMatch(file.path, /(?:^|\/)(?:\.env|.*\.(?:key|pem|vault|pqc))$/i);
  }
  for (const expected of ['src/index.js', 'src/index.d.ts', 'src/cli.js', 'src/diagnostics.js', 'bin/pqc.mjs', 'LICENSE']) {
    assert.ok(pack.files.some((file) => file.path === expected), `Missing package artifact: ${expected}`);
  }
  const prefix = join(temporary, 'installed');
  run(process.execPath, [npmCli, 'install', '--prefix', prefix, '--ignore-scripts', '--no-audit', '--no-fund',
    '--package-lock=false', join(temporary, pack.filename)], temporary);
  const installed = join(prefix, 'node_modules', 'pqc-research-core');
  const manifest = JSON.parse(await readFile(join(installed, 'package.json'), 'utf8'));
  assert.deepEqual(Object.keys(manifest.dependencies ?? {}), []);
  const cli = (args) => JSON.parse(run(process.execPath, [join(installed, 'bin', 'pqc.mjs'), ...args, '--json'], temporary));
  const report = cli(['doctor']);
  assert.equal(report.ok, true);
  assert.equal(report.version, manifest.version);
  assert.equal(report.checks.length, 3);
  const path = (name) => join(temporary, name);
  const password = path('ephemeral-password.bin');
  const message = Buffer.from('Installed package roundtrip\0\xff', 'utf8');
  await writeFile(password, 'Package test password; never a user key', { mode: 0o600, flag: 'wx' });
  await writeFile(path('message.bin'), message, { mode: 0o600, flag: 'wx' });
  const key = cli(['keygen', '--vault', path('recipient.vault'), '--public', path('recipient.der'), '--password-file', password]);
  run(process.execPath, ['--input-type=module', '--eval', `
    import assert from 'node:assert/strict';
    import { readFile } from 'node:fs/promises';
    const sdk = await import(process.argv[1]);
    const password = Buffer.from('Synthetic installed SDK account password');
    try {
      const record = await sdk.hashPassword(password);
      assert.equal(await sdk.verifyPassword(record, password), true);
      assert.equal(await sdk.verifyPassword(record, Buffer.from('wrong')), false);
      assert.equal(sdk.passwordHashNeedsRehash(record), false);
    } finally { password.fill(0); }
    const pool = sdk.createOperationPool({ maxConcurrent: 1, maxQueued: 0 });
    assert.equal(await pool.run(() => 42), 42);
    pool.close();
    await assert.rejects(pool.run(() => 1), error => error.code === 'POOL_CLOSED');
    const key = sdk.importKemPublicKey(await readFile(process.argv[2]));
    assert.equal(sdk.requirePublicKeyFingerprint(key, process.argv[3]), sdk.publicKeyFingerprint(key));
    assert.throws(() => sdk.requirePublicKeyFingerprint(key, process.argv[3] + String.fromCharCode(10)),
      (error) => error.code === 'INVALID_FINGERPRINT');
  `, pathToFileURL(join(installed, 'src', 'index.js')).href, path('recipient.der'), key.fingerprint], temporary);
  cli(['encrypt', '--input', path('message.bin'), '--output', path('message.pqc'), '--public', path('recipient.der'),
    '--fingerprint', key.fingerprint, '--context', 'package/smoke/v1']);
  const inspected = cli(['inspect', '--input', path('message.pqc')]);
  assert.equal(inspected.authenticated, false);
  assert.equal(inspected.recipientFingerprint, key.fingerprint);
  assert.equal(inspected.declaredPlaintextBytes, message.length);
  assert.equal(cli(['inspect', '--input', path('recipient.vault')]).keyKind, 'kem');
  run(process.execPath, ['--input-type=module', '--eval', `
    import assert from 'node:assert/strict';
    const sdk = await import(process.argv[1]);
    const result = await sdk.inspectContainer(process.argv[2]);
    assert.equal(result.kind, 'encrypted-file');
    assert.equal(result.authenticated, false);
  `, pathToFileURL(join(installed, 'src', 'index.js')).href, path('message.pqc')], temporary);
  cli(['decrypt', '--input', path('message.pqc'), '--output', path('restored.bin'), '--vault', path('recipient.vault'),
    '--password-file', password, '--context', 'package/smoke/v1']);
  assert.deepEqual(await readFile(path('restored.bin')), message);
  const originalVault = await readFile(path('recipient.vault'));
  await writeFile(path('replacement-password.bin'), 'Replacement test password; not a user secret', { mode: 0o600, flag: 'wx' });
  const changed = cli(['change-password', '--vault', path('recipient.vault'), '--output', path('new-recipient.vault'),
    '--password-file', password, '--new-password-file', path('replacement-password.bin')]);
  assert.equal(changed.fingerprint, key.fingerprint);
  assert.equal(changed.originalRetained, true);
  assert.deepEqual(await readFile(path('recipient.vault')), originalVault);
  cli(['decrypt', '--input', path('message.pqc'), '--output', path('new-password-restored.bin'), '--vault', path('new-recipient.vault'),
    '--password-file', path('replacement-password.bin'), '--context', 'package/smoke/v1']);
  assert.deepEqual(await readFile(path('new-password-restored.bin')), message);
  assert.deepEqual((await readdir(temporary)).filter((name) => name.startsWith('.pqc-stage-')), []);
  console.log(`Packed and installed ${manifest.name}@${manifest.version}: doctor, SDK fingerprints, container inspection, file roundtrip and password change passed (${pack.entryCount} allowlisted entries).`);
} finally {
  const target = resolve(temporary);
  assert.equal(dirname(target), resolve(tmpdir()));
  assert.ok(basename(target).startsWith('pqc-package-smoke-'));
  await rm(target, { recursive: true, force: true });
}

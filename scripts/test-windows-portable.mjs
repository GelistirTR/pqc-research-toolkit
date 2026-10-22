import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { constants } from 'node:fs';
import { copyFile, mkdir, mkdtemp, readFile, readdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { cleanupOwned, hash, listFiles, powershell, root, run } from './portable-utils.mjs';

assert.equal(process.platform, 'win32', 'Portable test runs on Windows');
const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
const sourceTree = run('git', ['write-tree'], { cwd: root }).trim();
const archive = resolve(process.argv[2] ?? join(root, '.artifacts', `pqc-research-core-${pkg.version}-windows-x64-${sourceTree.slice(0, 12)}.zip`));
assert.ok(archive.startsWith(`${resolve(root, '.artifacts')}${sep}`), 'Test only locally built artifacts inside .artifacts');
const provenance = JSON.parse(await readFile(join(root, 'third_party', 'node-v24.22.1', 'provenance.json'), 'utf8'));
const temporary = await mkdtemp(join(tmpdir(), 'pqc-portable-smoke-'));
try {
  const extracted = join(temporary, 'çıkarılan paket & yüzde%');
  powershell('archive.ps1', ['-Mode', 'Extract', '-Source', archive, '-Destination', extracted]);
  const name = `pqc-research-core-${pkg.version}-windows-x64`;
  assert.deepEqual(await readdir(extracted), [name]);
  const kit = join(extracted, name);
  const manifest = JSON.parse(await readFile(join(kit, 'MANIFEST.json'), 'utf8'));
  assert.equal(manifest.name, pkg.name);
  assert.equal(manifest.version, pkg.version);
  const files = (await listFiles(kit)).filter((file) => file !== 'MANIFEST.json');
  assert.deepEqual(files, Object.keys(manifest.files).sort());
  for (const file of files) assert.equal(await hash(join(kit, file)), manifest.files[file], file);
  assert.equal(await hash(join(kit, 'runtime', 'node.exe')), provenance.binarySha256);
  assert.equal(await hash(join(kit, 'runtime', 'LICENSE.txt')), provenance.licenseSha256);
  assert.equal(await hash(join(kit, 'LICENSE')), await hash(join(root, 'LICENSE')));
  const executable = join(kit, 'pqc.exe');
  const data = join(temporary, 'özel dosyalar & %TEST%');
  await mkdir(data);
  const cli = (args) => JSON.parse(run(executable, [...args, '--json'], { cwd: data }));
  assert.equal(run(executable, ['--version'], { cwd: data }).trim(), pkg.version);
  assert.match(run(executable, ['--help'], { cwd: data }), /change-password/);
  const doctor = cli(['doctor']);
  assert.equal(doctor.runtime.node, provenance.version);
  assert.equal(doctor.checks.length, 3);
  const input = 'belge & %PATH% Türkçe.bin';
  const password = 'parola & %.bin';
  const message = Buffer.alloc(1024 * 1024 + 17, 0x73);
  await writeFile(join(data, input), message);
  await writeFile(join(data, password), 'Portable test password; never a user secret');
  const key = cli(['keygen', '--vault', 'alıcı.vault', '--public', 'alıcı.der', '--password-file', password]);
  const context = 'bağlam "quote" \\ %PATH% & | ; 😀';
  cli(['encrypt', '--input', input, '--output', 'şifreli.pqc', '--public', 'alıcı.der', '--context', context, '--fingerprint', key.fingerprint]);
  const inspected = cli(['inspect', '--input', 'şifreli.pqc']);
  assert.equal(inspected.authenticated, false);
  assert.equal(inspected.recipientFingerprint, key.fingerprint);
  assert.equal(inspected.declaredPlaintextBytes, message.length);
  assert.equal(cli(['inspect', '--input', 'alıcı.vault']).keyKind, 'kem');
  cli(['decrypt', '--input', 'şifreli.pqc', '--output', 'çözülen.bin', '--vault', 'alıcı.vault', '--context', context, '--password-file', password]);
  assert.deepEqual(await readFile(join(data, 'çözülen.bin')), message);
  const original = await readFile(join(data, 'alıcı.vault'));
  await writeFile(join(data, 'yeni-parola.bin'), 'Replacement portable test password, not for users');
  assert.equal(cli(['change-password', '--vault', 'alıcı.vault', '--output', 'yeni.vault', '--password-file', password,
    '--new-password-file', 'yeni-parola.bin']).fingerprint, key.fingerprint);
  assert.deepEqual(await readFile(join(data, 'alıcı.vault')), original);
  cli(['decrypt', '--input', 'şifreli.pqc', '--output', 'yeni-parolayla.bin', '--vault', 'yeni.vault', '--context', context,
    '--password-file', 'yeni-parola.bin']);
  assert.deepEqual(await readFile(join(data, 'yeni-parolayla.bin')), message);
  const signer = cli(['keygen', '--vault', 'imza.vault', '--public', 'imza.der', '--type', 'signature', '--password-file', password]);
  cli(['sign', '--input', input, '--output', 'belge.sig', '--vault', 'imza.vault', '--context', context, '--password-file', password]);
  assert.equal(cli(['verify', '--input', input, '--signature', 'belge.sig', '--public', 'imza.der', '--context', context,
    '--fingerprint', signer.fingerprint]).valid, true);
  const failed = spawnSync(executable, ['unknown', '--json'], { cwd: data, encoding: 'utf8', windowsHide: true });
  assert.ifError(failed.error); assert.equal(failed.status, 1);
  assert.equal(JSON.parse(failed.stderr).error.code, 'USAGE_ERROR');
  assert.ok(!(await readdir(data)).some((entry) => entry.startsWith('.pqc-stage-')));

  // Use a separate probe copy, never modify the verified release kit.
  const probe = join(temporary, 'argv probe & %');
  await mkdir(join(probe, 'runtime'), { recursive: true });
  await mkdir(join(probe, 'tool', 'bin'), { recursive: true });
  await copyFile(executable, join(probe, 'pqc.exe'), constants.COPYFILE_EXCL);
  await copyFile(join(kit, 'runtime', 'node.exe'), join(probe, 'runtime', 'node.exe'), constants.COPYFILE_EXCL);
  await writeFile(join(probe, 'tool', 'bin', 'pqc.mjs'), `console.log(JSON.stringify({ args: process.argv.slice(2),
    environment: Object.fromEntries(['NODE_OPTIONS','NODE_PATH','OPENSSL_CONF','OPENSSL_MODULES','OPENSSL_ENGINES'].map(k=>[k,process.env[k]??null])) }));`);
  const argumentsToPreserve = ['', 'a b', 'Türkçe 😀', 'a"b', '\\"', 'trailing\\', 'two\\\\"quotes', '%PATH%', 'a&b|c', ';', '$()', '\t', '\n'];
  const probeExecutable = join(probe, 'pqc.exe');
  assert.deepEqual(JSON.parse(run(probeExecutable, argumentsToPreserve)).args, argumentsToPreserve);
  const marker = join(temporary, 'preload-must-not-run.txt');
  const preload = join(temporary, 'malicious-preload.cjs');
  await writeFile(preload, `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'unexpected preload');`);
  const hostileEnvironment = { ...process.env, NODE_OPTIONS: `--require "${preload}"`, NODE_PATH: temporary,
    OPENSSL_CONF: 'missing-config', OPENSSL_MODULES: temporary, OPENSSL_ENGINES: temporary };
  const environmentReport = JSON.parse(run(probeExecutable, [], { env: hostileEnvironment }));
  assert.ok(Object.values(environmentReport.environment).every((value) => value === null));
  assert.ok(!(await readdir(temporary)).includes('preload-must-not-run.txt'));
  await writeFile(join(probe, 'runtime', 'node.exe'), 'MZ deliberately corrupted test runtime');
  const corrupted = spawnSync(probeExecutable, ['doctor', '--json'], { encoding: 'utf8', windowsHide: true });
  assert.ifError(corrupted.error); assert.equal(corrupted.status, 1);
  assert.equal(corrupted.stdout, '');
  assert.equal(JSON.parse(corrupted.stderr).error.code, 'RUNTIME_INTEGRITY');
  console.log(JSON.stringify({ version: pkg.version, target: 'windows-x64', filesVerified: files.length,
    checks: ['archive file hashes and license provenance', 'bundled runtime doctor', 'unauthenticated container inspection', 'multi-chunk file roundtrip',
      'password change preserves identity and old vault', 'ML-DSA signature roundtrip', 'native argument forwarding',
      'ambient preload/provider variables excluded', 'runtime corruption rejected before launch', 'exit status preserved'],
    runtime: doctor.runtime, launcherSigned: false,
    limits: 'Local Windows x64 smoke tests; not an audit, signed project release or proof on other machines' }, null, 2));
} finally { await cleanupOwned(temporary, tmpdir(), 'pqc-portable-smoke-'); }

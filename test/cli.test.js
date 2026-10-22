import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, createPublicKey, randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import { importVerificationKey, openPrivateKey } from '../src/index.js';
import { promptHidden, runCli } from '../src/cli.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const executable = join(root, 'bin', 'pqc.mjs');
const packageVersion = JSON.parse(await readFile(join(root, 'package.json'), 'utf8')).version;
const passwordMarker = 'PASSWORD_SENTINEL_never_log_this_';
const password = Buffer.from(`  ${passwordMarker}1234567890 \r\n`);
const context = 'cli/roundtrip/v1';
const aad = 'project:example';
const fingerprintPattern = /^SHA256:[0-9a-f]{64}$/;

function cli(args, options = {}) {
  const result = spawnSync(process.execPath, [executable, ...args], {
    cwd: root, encoding: 'utf8', input: '', timeout: 20000,
    windowsHide: true, maxBuffer: 1024 * 1024, ...options,
  });
  assert.ifError(result.error);
  assert.equal(result.signal, null, `CLI was interrupted: ${result.stderr}`);
  assert.ok(!`${result.stdout}\n${result.stderr}`.includes(passwordMarker), 'CLI must never expose a password');
  return result;
}

function success(args) {
  const result = cli([...args, '--json']);
  assert.equal(result.status, 0, result.stderr);
  const lines = result.stdout.trim().split(/\r?\n/);
  assert.equal(lines.length, 1, 'JSON success must occupy exactly one stdout line');
  const value = JSON.parse(lines[0]);
  assert.ok(value && typeof value === 'object' && !Array.isArray(value));
  return value;
}

function failure(args) {
  const result = cli([...args, '--json']);
  assert.notEqual(result.status, 0, 'Invalid operation must fail');
  assert.equal(result.stdout.trim(), '', 'Failed operation must not print a success result');
  const lines = result.stderr.trim().split(/\r?\n/);
  assert.equal(lines.length, 1, 'JSON error must occupy exactly one stderr line');
  const value = JSON.parse(lines[0]);
  assert.ok(value.error && typeof value.error.code === 'string' && value.error.code.length > 0);
  return value.error;
}

async function workspace(t) {
  const directory = await mkdtemp(join(tmpdir(), 'pqc-cli-test-'));
  t.after(() => {
    const target = resolve(directory);
    assert.equal(dirname(target), resolve(tmpdir()));
    assert.ok(basename(target).startsWith('pqc-cli-test-'));
    return rm(target, { recursive: true, force: true });
  });
  return directory;
}

async function noStages(directory) {
  assert.deepEqual((await readdir(directory)).filter((name) => name.startsWith('.pqc-stage-')), []);
}

function fakeTty(t, initiallyRaw = false) {
  const input = new PassThrough();
  input.isTTY = true;
  input.isRaw = initiallyRaw;
  const rawModes = [];
  input.setRawMode = (mode) => { rawModes.push(mode); input.isRaw = mode; return input; };
  const writes = [];
  const output = { isTTY: true, write(value) { writes.push(String(value)); return true; } };
  t.after(() => input.destroy());
  return { input, output, rawModes, writes };
}

function assertPromptClosed(tty, previousRawMode = false) {
  assert.deepEqual(tty.rawModes, [true, previousRawMode]);
  assert.equal(tty.input.isRaw, previousRawMode);
  assert.equal(tty.input.isPaused(), true);
  for (const event of ['keypress', 'end', 'error']) assert.equal(tty.input.listenerCount(event), 0);
}

test('hidden TTY prompt accepts UTF-8, deletes complete characters and never echoes', async (t) => {
  const tty = fakeTty(t, true);
  const pending = promptHidden('Secret: ', tty.input, tty.output);
  // Exercise readline decoding of real UTF-8 input, including a four-byte character.
  tty.input.write(Buffer.from('aş😀\u007fZ\r'));
  const secret = await pending;
  assert.equal(secret.toString(), 'aşZ');
  secret.fill(0);
  assert.equal(tty.writes.join(''), 'Secret: \n');
  assertPromptClosed(tty, true);
});

test('hidden prompt ignores terminal controls and permits the 1024-byte boundary', async (t) => {
  const tty = fakeTty(t);
  const pending = promptHidden('Secret: ', tty.input, tty.output);
  tty.input.emit('keypress', 'escape', { meta: true });
  tty.input.emit('keypress', '\u0001', { ctrl: true, name: 'a' });
  tty.input.emit('keypress', '\u001b[A', { name: 'up' });
  tty.input.emit('keypress', 'é'.repeat(512), {});
  tty.input.emit('keypress', '\r', { name: 'return' });
  const secret = await pending;
  assert.equal(secret.length, 1024);
  assert.equal(secret.toString(), 'é'.repeat(512));
  secret.fill(0);
  assert.equal(tty.writes.join(''), 'Secret: \n');
  assertPromptClosed(tty);
});

test('hidden prompt cancels and cleans up for interrupt, end, error and byte overflow', async (t) => {
  for (const kind of ['interrupt', 'end', 'error', 'overflow']) {
    await t.test(kind, async (subtest) => {
      const tty = fakeTty(subtest);
      const pending = promptHidden('Secret: ', tty.input, tty.output);
      tty.input.emit('keypress', passwordMarker, {});
      if (kind === 'interrupt') tty.input.emit('keypress', '\u0003', { ctrl: true, name: 'c' });
      if (kind === 'end') tty.input.emit('end');
      if (kind === 'error') tty.input.emit('error', new Error(passwordMarker));
      if (kind === 'overflow') tty.input.emit('keypress', 'é'.repeat(513), {});
      const expected = kind === 'error' ? 'IO_ERROR' : kind === 'overflow' ? 'INVALID_INPUT' : 'ABORTED';
      await assert.rejects(pending, (error) => error.code === expected && !error.message.includes(passwordMarker));
      assert.equal(tty.writes.join(''), 'Secret: \n');
      assertPromptClosed(tty);
    });
  }
});

test('hidden prompt rejects unavailable TTYs before changing terminal state', (t) => {
  const tty = fakeTty(t);
  tty.input.isTTY = false;
  assert.throws(() => promptHidden('Secret: ', tty.input, tty.output), (error) => error.code === 'PASSWORD_REQUIRED');
  assert.deepEqual(tty.rawModes, []);
  assert.deepEqual(tty.writes, []);
});

test('hidden prompt settles and removes listeners when terminal setup or cleanup throws', { timeout: 3000 }, async (t) => {
  for (const kind of ['raw-setup', 'resume', 'initial-write', 'raw-restore', 'final-write']) {
    await t.test(kind, async (subtest) => {
      const tty = fakeTty(subtest);
      if (kind.startsWith('raw-')) {
        tty.input.setRawMode = (mode) => {
          tty.rawModes.push(mode);
          if ((kind === 'raw-setup' && mode) || (kind === 'raw-restore' && !mode)) throw new Error(passwordMarker);
          tty.input.isRaw = mode;
        };
      }
      if (kind === 'resume') tty.input.resume = () => { throw new Error(passwordMarker); };
      if (kind.endsWith('write')) tty.output.write = (value) => {
        if ((kind === 'initial-write' && value !== '\n') || (kind === 'final-write' && value === '\n')) throw new Error(passwordMarker);
        tty.writes.push(String(value)); return true;
      };
      const pending = promptHidden('Secret: ', tty.input, tty.output);
      if (kind === 'raw-restore' || kind === 'final-write') {
        tty.input.emit('keypress', passwordMarker, {});
        tty.input.emit('keypress', '\r', { name: 'return' });
      }
      await assert.rejects(pending, (error) => error.code === 'IO_ERROR' && !error.message.includes(passwordMarker));
      assert.equal(tty.rawModes.at(-1), false, 'Restoration was attempted even if setup failed early');
      assert.equal(tty.input.isPaused(), true);
      for (const event of ['keypress', 'end', 'error']) assert.equal(tty.input.listenerCount(event), 0);
      assert.ok(!tty.writes.join('').includes(passwordMarker));
    });
  }
});

test('interactive keygen confirmation mismatch cleans terminal state and creates no keys', async (t) => {
  const directory = await workspace(t);
  const tty = fakeTty(t);
  const first = `${passwordMarker}first-password`;
  const second = `${passwordMarker}second-password`;
  const transcript = [];
  tty.output.write = (value) => {
    transcript.push(String(value));
    if (String(value).startsWith('Passphrase (hidden):')) queueMicrotask(() => tty.input.write(`${first}\r`));
    if (String(value).startsWith('Repeat passphrase (hidden):')) queueMicrotask(() => tty.input.write(`${second}\r`));
    return true;
  };
  const stdout = [];
  const descriptors = new Map(['stdin', 'stderr', 'stdout'].map((name) => [name, Object.getOwnPropertyDescriptor(process, name)]));
  let exitCode;
  try {
    Object.defineProperty(process, 'stdin', { configurable: true, value: tty.input });
    Object.defineProperty(process, 'stderr', { configurable: true, value: tty.output });
    Object.defineProperty(process, 'stdout', { configurable: true, value: { write(value) { stdout.push(String(value)); return true; } } });
    exitCode = await runCli(['keygen', '--vault', join(directory, 'key.vault'), '--public', join(directory, 'key.spki'), '--json']);
  } finally {
    for (const [name, descriptor] of descriptors) Object.defineProperty(process, name, descriptor);
  }
  assert.equal(exitCode, 1);
  assert.deepEqual(stdout, []);
  assert.ok(!transcript.join('').includes(passwordMarker));
  const lastLine = transcript.join('').trim().split('\n').at(-1);
  assert.equal(JSON.parse(lastLine).error.code, 'PASSWORD_MISMATCH');
  assert.deepEqual(tty.rawModes, [true, false, true, false]);
  assert.equal(tty.input.isRaw, false);
  assert.equal(tty.input.isPaused(), true);
  for (const event of ['keypress', 'end', 'error']) assert.equal(tty.input.listenerCount(event), 0);
  assert.deepEqual(await readdir(directory), []);
});

test('interactive password change confirms the new secret and handles mismatch/cancel without publication', { timeout: 15000 }, async (t) => {
  const directory = await workspace(t);
  const vault = join(directory, 'original.vault');
  const oldPassword = `current ${passwordMarker}interactive`;
  const newPassword = `replacement ${passwordMarker}interactive`;
  const passwordFile = join(directory, 'old-password.bin');
  await writeFile(passwordFile, oldPassword);
  success(['keygen', '--vault', vault, '--public', join(directory, 'public.der'), '--password-file', passwordFile]);
  const originalBytes = await readFile(vault);
  for (const kind of ['success', 'mismatch', 'cancel']) {
    await t.test(kind, async (subtest) => {
      const tty = fakeTty(subtest);
      const transcript = [];
      const stdout = [];
      tty.output.write = (value) => {
        transcript.push(String(value));
        let answer;
        if (String(value).startsWith('Current passphrase (hidden):')) answer = `${oldPassword}\r`;
        if (String(value).startsWith('New passphrase (hidden):')) answer = kind === 'cancel' ? `${passwordMarker}\u0003` : `${newPassword}\r`;
        if (String(value).startsWith('Repeat new passphrase (hidden):')) answer = `${kind === 'mismatch' ? 'different secret' : newPassword}\r`;
        if (answer !== undefined) queueMicrotask(() => tty.input.write(answer));
        return true;
      };
      const descriptors = new Map(['stdin', 'stderr', 'stdout'].map((name) => [name, Object.getOwnPropertyDescriptor(process, name)]));
      const output = join(directory, `${kind}.vault`);
      let exitCode;
      try {
        Object.defineProperty(process, 'stdin', { configurable: true, value: tty.input });
        Object.defineProperty(process, 'stderr', { configurable: true, value: tty.output });
        Object.defineProperty(process, 'stdout', { configurable: true, value: { write(value) { stdout.push(String(value)); return true; } } });
        exitCode = await runCli(['change-password', '--vault', vault, '--output', output, '--json']);
      } finally {
        for (const [name, descriptor] of descriptors) Object.defineProperty(process, name, descriptor);
      }
      assert.ok(!transcript.join('').includes(passwordMarker));
      assert.equal(tty.input.isRaw, false);
      assert.equal(tty.input.isPaused(), true);
      for (const event of ['keypress', 'end', 'error']) assert.equal(tty.input.listenerCount(event), 0);
      assert.deepEqual(await readFile(vault), originalBytes);
      if (kind === 'success') {
        assert.equal(exitCode, 0, transcript.join('').trim().split('\n').at(-1));
        assert.equal(JSON.parse(stdout.join('')).originalRetained, true);
        const opened = await openPrivateKey(await readFile(output), Buffer.from(newPassword));
        opened.privateKey.destroy();
      } else {
        assert.equal(exitCode, kind === 'cancel' ? 130 : 1);
        assert.deepEqual(stdout, []);
        const report = JSON.parse(transcript.join('').trim().split('\n').at(-1));
        assert.equal(report.error.code, kind === 'cancel' ? 'ABORTED' : 'PASSWORD_MISMATCH');
        assert.equal(existsSync(output), false);
      }
      await noStages(directory);
    });
  }
});

test('CLI help and version are available without prompts', () => {
  const help = cli(['--help']);
  assert.equal(help.status, 0, help.stderr);
  for (const command of ['doctor', 'keygen', 'change-password', 'fingerprint', 'encrypt', 'decrypt', 'sign', 'verify']) {
    assert.ok(help.stdout.includes(command));
  }
  const version = cli(['--version']);
  assert.equal(version.status, 0, version.stderr);
  assert.equal(version.stdout, `${packageVersion}\n`);
});

test('doctor checks real provider operations without prompting or creating files', async (t) => {
  const directory = await workspace(t);
  const result = cli(['doctor', '--json'], { cwd: directory });
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.ok, true);
  assert.equal(report.checks.length, 3);
  assert.equal(report.filesystem, 'not checked');
  assert.match(report.assurance, /not an audit/);
  assert.equal(report.runtime.node, process.versions.node);
  assert.deepEqual(await readdir(directory), []);
  const human = cli(['doctor']);
  assert.equal(human.status, 0, human.stderr);
  assert.match(human.stdout, /PASS ML-KEM/);
  assert.match(human.stdout, /not checked/);
  assert.equal(failure(['doctor', '--input', 'not-accepted']).code, 'USAGE_ERROR');
});

test('doctor provider failure cannot print a successful self-test or provider details', () => {
  const injection = `import crypto from 'node:crypto';
    import { syncBuiltinESMExports } from 'node:module';
    crypto.generateKeyPair = (...args) => args.at(-1)(Object.assign(new Error(${JSON.stringify(passwordMarker)}), { code: 'ERR_OSSL_EVP_UNSUPPORTED' }));
    syncBuiltinESMExports();
    process.argv = ['node', 'pqc', 'doctor', '--json'];
    await import(${JSON.stringify(new URL('../bin/pqc.mjs', import.meta.url).href)});`;
  const failureResult = spawnSync(process.execPath, ['--input-type=module', '--eval', injection], {
    encoding: 'utf8', windowsHide: true, timeout: 20000,
  });
  assert.ifError(failureResult.error);
  assert.equal(failureResult.status, 1);
  assert.equal(failureResult.stdout, '');
  assert.equal(JSON.parse(failureResult.stderr).ok, false);
  assert.ok(!failureResult.stderr.includes(passwordMarker));
});

test('CLI reports staging cleanup failure without leaking filesystem error details', async (t) => {
  const directory = await workspace(t);
  const passwordFile = join(directory, 'password.bin');
  await writeFile(passwordFile, password);
  const vault = join(directory, 'recipient.vault');
  const publicPath = join(directory, 'recipient.der');
  const injection = `import fs from 'node:fs/promises';
    import { syncBuiltinESMExports } from 'node:module';
    fs.unlink = async () => { throw Object.assign(new Error(${JSON.stringify(passwordMarker)}), { code: 'EACCES' }); };
    syncBuiltinESMExports();
    process.argv = ['node', 'pqc', 'keygen', '--vault', ${JSON.stringify(vault)}, '--public', ${JSON.stringify(publicPath)},
      '--password-file', ${JSON.stringify(passwordFile)}, '--json'];
    await import(${JSON.stringify(new URL('../bin/pqc.mjs', import.meta.url).href)});`;
  const result = spawnSync(process.execPath, ['--input-type=module', '--eval', injection], {
    encoding: 'utf8', windowsHide: true, timeout: 20000,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  const report = JSON.parse(result.stderr);
  assert.equal(report.error.code, 'CLEANUP_FAILED');
  assert.match(report.error.message, /inspect the output directory for staging data/);
  assert.ok(!result.stderr.includes(passwordMarker));
  assert.ok(!result.stderr.includes(directory));
  // Publication completed before cleanup failed. Existing valid targets are retained.
  assert.ok(existsSync(vault)); assert.ok(existsSync(publicPath));
  const restored = await openPrivateKey(await readFile(vault), password);
  try { assert.deepEqual(restored.publicKey.exportSpki(), await readFile(publicPath)); }
  finally { restored.privateKey.destroy(); }
});

for (const abortAt of [1, 2]) {
  test(`doctor SIGINT during vault KDF ${abortAt} returns 130 without further KDF work`, () => {
    const injection = `import crypto from 'node:crypto';
      import { syncBuiltinESMExports } from 'node:module';
      const original = crypto.argon2;
      let calls = 0;
      crypto.argon2 = (...args) => {
        calls++;
        if (calls > ${abortAt}) throw new Error('Unexpected KDF after cancellation');
        if (calls === ${abortAt}) process.emit('SIGINT');
        return original(...args);
      };
      syncBuiltinESMExports();
      process.argv = ['node', 'pqc', 'doctor', '--json'];
      await import(${JSON.stringify(new URL('../bin/pqc.mjs', import.meta.url).href)});`;
    const result = spawnSync(process.execPath, ['--input-type=module', '--eval', injection], {
      encoding: 'utf8', windowsHide: true, timeout: 20000,
    });
    assert.ifError(result.error);
    assert.equal(result.status, 130, result.stderr);
    assert.equal(result.stdout, '');
    assert.equal(JSON.parse(result.stderr).error.code, 'ABORTED');
  });
}

test('unsupported runtimes fail at the launcher before native crypto imports', () => {
  for (const version of ['22.0.0', '24.15.9', '24.16.0', '24.21.0', '24.22.0', '24.22.0-pre', '24.22.1-pre', '25.0.0']) {
    const injection = `Object.defineProperty(process.versions, 'node', { value: ${JSON.stringify(version)} });
      process.argv = ['node', 'pqc', 'doctor', '--json'];
      await import(${JSON.stringify(new URL('../bin/pqc.mjs', import.meta.url).href)});`;
    const result = spawnSync(process.execPath, ['--input-type=module', '--eval', injection], {
      encoding: 'utf8', windowsHide: true, timeout: 10000,
    });
    assert.ifError(result.error);
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.equal(JSON.parse(result.stderr).error.code, 'UNSUPPORTED_RUNTIME');
    assert.doesNotMatch(result.stderr, /SyntaxError|node:crypto|at file:/);
  }
});

test('library imports reject Node releases below the security patch floor', () => {
  for (const version of ['24.16.0', '24.22.0', '25.0.0']) {
    const injection = `Object.defineProperty(process.versions, 'node', { value: ${JSON.stringify(version)} });
      try { await import(${JSON.stringify(new URL('../src/index.js', import.meta.url).href)}); process.exitCode = 99; }
      catch (error) { process.stderr.write(error.message); process.exitCode = 1; }`;
    const result = spawnSync(process.execPath, ['--input-type=module', '--eval', injection], {
      encoding: 'utf8', windowsHide: true, timeout: 20000,
    });
    assert.ifError(result.error);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /24\.22\.1/);
  }
});

test('CLI supports real file encryption and signatures with strict failure behavior', { timeout: 180000 }, async (t) => {
  const directory = await workspace(t);
  const path = (name) => join(directory, name);
  const passwordFile = path('password.bin');
  const kemVault = path('recipient.vault');
  const kemPublic = path('recipient.spki');
  const sigVault = path('signer.vault');
  const sigPublic = path('signer.spki');
  const input = path('message.bin');
  const encrypted = path('message.pqc');
  const decrypted = path('restored.bin');
  const signature = path('message.sig');
  const plaintext = randomBytes(131089);
  await writeFile(passwordFile, password);
  await writeFile(input, plaintext);

  let kemFingerprint;
  let sigFingerprint;
  await t.test('keygen writes a protected KEM vault and canonical DER public key', async () => {
    const result = success(['keygen', '--vault', kemVault, '--public', kemPublic, '--password-file', passwordFile]);
    assert.match(result.fingerprint, fingerprintPattern);
    kemFingerprint = result.fingerprint;
    const spki = await readFile(kemPublic);
    const nativeKey = createPublicKey({ key: spki, type: 'spki', format: 'der' });
    assert.equal(nativeKey.asymmetricKeyType, 'ml-kem-1024');
    assert.deepEqual(nativeKey.export({ type: 'spki', format: 'der' }), spki);
    assert.equal(result.fingerprint, `SHA256:${createHash('sha256').update(spki).digest('hex')}`);
    const opened = await openPrivateKey(await readFile(kemVault), password);
    assert.equal(opened.kind, 'kem');
    assert.deepEqual(opened.publicKey.exportSpki(), spki);
    opened.privateKey.destroy();
    await assert.rejects(openPrivateKey(await readFile(kemVault), Buffer.from(password.toString().trim())),
      (error) => error.code === 'AUTHENTICATION_FAILED');
  });

  await t.test('fingerprint works for KEM and signature public keys', async () => {
    assert.equal(success(['fingerprint', '--public', kemPublic]).fingerprint, kemFingerprint);
    const displayed = cli(['fingerprint', '--public', kemPublic]);
    assert.equal(displayed.status, 0, displayed.stderr);
    assert.ok(displayed.stdout.includes(kemFingerprint));
    const result = success(['keygen', '--vault', sigVault, '--public', sigPublic, '--type', 'signature', '--password-file', passwordFile]);
    assert.match(result.fingerprint, fingerprintPattern);
    sigFingerprint = result.fingerprint;
    const spki = await readFile(sigPublic);
    const nativeKey = createPublicKey({ key: spki, type: 'spki', format: 'der' });
    assert.equal(nativeKey.asymmetricKeyType, 'ml-dsa-87');
    assert.deepEqual(nativeKey.export({ type: 'spki', format: 'der' }), spki);
    assert.equal(sigFingerprint, `SHA256:${createHash('sha256').update(spki).digest('hex')}`);
    assert.equal(success(['fingerprint', '--public', sigPublic]).fingerprint, sigFingerprint);
  });

  const encryptArgs = (output = encrypted) => ['encrypt', '--input', input, '--output', output,
    '--public', kemPublic, '--context', context, '--aad', aad, '--fingerprint', kemFingerprint];
  const decryptArgs = (source = encrypted, output = decrypted, contextValue = context, aadValue = aad) => [
    'decrypt', '--input', source, '--output', output, '--vault', kemVault,
    '--context', contextValue, '--aad', aadValue, '--password-file', passwordFile,
  ];
  const signArgs = (source = input, output = signature, vault = sigVault) => ['sign', '--input', source,
    '--output', output, '--vault', vault, '--context', context, '--password-file', passwordFile];
  const verifyArgs = (source = input, signaturePath = signature, contextValue = context) => ['verify',
    '--input', source, '--signature', signaturePath, '--public', sigPublic, '--context', contextValue,
    '--fingerprint', sigFingerprint];

  await t.test('fingerprint pinning is mandatory for encryption and mismatches produce no output', () => {
    const missing = path('missing-pin.pqc');
    failure(['encrypt', '--input', input, '--output', missing, '--public', kemPublic, '--context', context]);
    assert.equal(existsSync(missing), false);
    const incorrect = path('wrong-pin.pqc');
    const args = encryptArgs(incorrect);
    args[args.length - 1] = `SHA256:${'0'.repeat(64)}`;
    failure(args);
    assert.equal(existsSync(incorrect), false);
    const hiddenSuffix = path('newline-pin.pqc');
    for (const suffix of ['\n', '\r\n', '\u2028']) {
      const changed = encryptArgs(hiddenSuffix);
      changed[changed.length - 1] = kemFingerprint + suffix;
      assert.equal(failure(changed).code, 'INVALID_FINGERPRINT');
      assert.equal(existsSync(hiddenSuffix), false);
    }
  });

  await t.test('encrypt and decrypt roundtrip a binary file spanning multiple chunks', async () => {
    success(encryptArgs());
    success(decryptArgs());
    assert.deepEqual(await readFile(decrypted), plaintext);
    assert.deepEqual(await readFile(input), plaintext);
    await noStages(directory);
  });

  await t.test('inspect reads real file and both vault headers without requesting a password', async () => {
    const before = await readdir(directory);
    const inspected = success(['inspect', '--input', encrypted]);
    assert.equal(inspected.authenticated, false);
    assert.equal(inspected.kind, 'encrypted-file');
    assert.equal(inspected.declaredPlaintextBytes, plaintext.length);
    assert.equal(inspected.recipientFingerprint, kemFingerprint);
    for (const [vault, keyKind] of [[kemVault, 'kem'], [sigVault, 'signature']]) {
      const inspectedVault = success(['inspect', '--input', vault]);
      assert.equal(inspectedVault.authenticated, false);
      assert.equal(inspectedVault.keyKind, keyKind);
    }
    const human = cli(['inspect', '--input', encrypted]);
    assert.equal(human.status, 0, human.stderr);
    assert.match(human.stdout, /UNAUTHENTICATED/);
    assert.ok(human.stdout.includes(kemFingerprint));
    assert.match(cli(['inspect', '--input', kemVault]).stdout, /Claimed key type: kem/);
    assert.equal(failure(['inspect']).code, 'USAGE_ERROR');
    assert.equal(failure(['inspect', '--input', encrypted, '--password-file', passwordFile]).code, 'USAGE_ERROR');
    assert.equal(failure(['inspect', '--input', input]).code, 'INVALID_CONTAINER');
    assert.deepEqual(await readdir(directory), before);
  });

  await t.test('changed ciphertext, wrong context and wrong AAD produce no plaintext', async () => {
    const changed = Buffer.from(await readFile(encrypted));
    changed[changed.length - 1] ^= 1;
    const changedPath = path('tampered.pqc');
    await writeFile(changedPath, changed);
    assert.equal(success(['inspect', '--input', changedPath]).authenticated, false,
      'Header inspection cannot detect a modified authentication tag');
    for (const [source, output, contextValue, aadValue] of [
      [changedPath, path('tampered-output.bin'), context, aad],
      [encrypted, path('wrong-context.bin'), 'cli/wrong-context', aad],
      [encrypted, path('wrong-aad.bin'), context, 'other:aad'],
    ]) {
      failure(decryptArgs(source, output, contextValue, aadValue));
      assert.equal(existsSync(output), false);
      await noStages(directory);
    }
  });

  await t.test('wrong password fails without output or disclosure', async () => {
    const wrongPasswordFile = path('wrong-password.bin');
    await writeFile(wrongPasswordFile, `${passwordMarker}wrong-secret`);
    const output = path('wrong-password-output.bin');
    const args = decryptArgs(encrypted, output);
    args[args.length - 1] = wrongPasswordFile;
    failure(args);
    assert.equal(existsSync(output), false);
    await noStages(directory);
  });

  await t.test('signatures interoperate with the library and verify from the CLI', async () => {
    success(signArgs());
    const bytes = await readFile(signature);
    assert.equal(bytes.length, 4627);
    const verifier = importVerificationKey(await readFile(sigPublic));
    assert.equal(await verifier.verify(plaintext, bytes, Buffer.from(context)), true);
    success(verifyArgs());
    success(['verify', '--input', input, '--signature', signature, '--public', sigPublic, '--context', context]);
  });

  await t.test('changed signature, message and context are rejected', async () => {
    const alteredSignature = Buffer.from(await readFile(signature));
    alteredSignature[17] ^= 1;
    const changedSignature = path('tampered.sig');
    await writeFile(changedSignature, alteredSignature);
    const changedMessage = path('tampered-message.bin');
    const changed = Buffer.from(plaintext);
    changed[0] ^= 1;
    await writeFile(changedMessage, changed);
    failure(verifyArgs(input, changedSignature));
    failure(verifyArgs(changedMessage));
    failure(verifyArgs(input, signature, 'wrong/signature/context'));
    const args = verifyArgs();
    args[args.length - 1] = `SHA256:${'0'.repeat(64)}`;
    failure(args);
  });

  await t.test('keys for the wrong purpose cannot encrypt, sign or verify', () => {
    const wrongEncryptionOutput = path('wrong-kind.pqc');
    const args = encryptArgs(wrongEncryptionOutput);
    args[args.indexOf('--public') + 1] = sigPublic;
    args[args.indexOf('--fingerprint') + 1] = sigFingerprint;
    failure(args);
    assert.equal(existsSync(wrongEncryptionOutput), false);
    const wrongSignature = path('wrong-kind.sig');
    failure(signArgs(input, wrongSignature, kemVault));
    assert.equal(existsSync(wrongSignature), false);
    failure(['verify', '--input', input, '--signature', signature, '--public', kemPublic, '--context', context]);
  });

  await t.test('encryption, decryption and signing never overwrite existing output', async () => {
    const snapshots = await Promise.all([encrypted, decrypted, signature].map((file) => readFile(file)));
    failure(encryptArgs());
    failure(decryptArgs());
    failure(signArgs());
    const current = await Promise.all([encrypted, decrypted, signature].map((file) => readFile(file)));
    assert.deepEqual(current, snapshots);
    await noStages(directory);
  });

  await t.test('key generation refuses either existing target without creating its partner', async () => {
    const snapshots = await Promise.all([kemVault, kemPublic].map((file) => readFile(file)));
    const newPublic = path('must-not-create-public.spki');
    failure(['keygen', '--vault', kemVault, '--public', newPublic, '--password-file', passwordFile]);
    assert.equal(existsSync(newPublic), false);
    const newVault = path('must-not-create-vault.bin');
    failure(['keygen', '--vault', newVault, '--public', kemPublic, '--password-file', passwordFile]);
    assert.equal(existsSync(newVault), false);
    assert.deepEqual(await Promise.all([kemVault, kemPublic].map((file) => readFile(file))), snapshots);
  });

  await t.test('key generation rejects identical vault and public paths', () => {
    const target = path('identical-target.bin');
    failure(['keygen', '--vault', target, '--public', target, '--password-file', passwordFile]);
    assert.equal(existsSync(target), false);
  });

  await t.test('noninteractive password omission fails promptly for all private-key operations', () => {
    for (const args of [
      ['keygen', '--vault', path('no-prompt.vault'), '--public', path('no-prompt.spki')],
      decryptArgs(encrypted, path('no-prompt.bin')).slice(0, -2),
      signArgs(input, path('no-prompt.sig')).slice(0, -2),
    ]) failure(args);
    for (const name of ['no-prompt.vault', 'no-prompt.spki', 'no-prompt.bin', 'no-prompt.sig']) {
      assert.equal(existsSync(path(name)), false);
    }
  });

  await t.test('password files enforce raw byte length boundaries', async () => {
    for (const length of [0, 15, 1025]) {
      const source = path(`password-${length}.bin`);
      const vault = path(`password-${length}.vault`);
      const publicKey = path(`password-${length}.spki`);
      await writeFile(source, Buffer.alloc(length, 0x61));
      failure(['keygen', '--vault', vault, '--public', publicKey, '--password-file', source]);
      assert.equal(existsSync(vault), false);
      assert.equal(existsSync(publicKey), false);
    }
    for (const length of [16, 1024]) {
      const source = path(`password-${length}.bin`);
      const vault = path(`password-${length}.vault`);
      const publicKey = path(`password-${length}.spki`);
      const secret = Buffer.alloc(length, 0x61);
      await writeFile(source, secret);
      success(['keygen', '--vault', vault, '--public', publicKey, '--type', 'kem', '--password-file', source]);
      const restored = await openPrivateKey(await readFile(vault), secret);
      restored.privateKey.destroy();
    }
  });

  await t.test('oversized messages cannot be signed or verified', async () => {
    const maximum = path('maximum-signable.bin');
    await writeFile(maximum, Buffer.alloc(16 * 1024 * 1024));
    const maximumSignature = path('maximum-signable.sig');
    success(signArgs(maximum, maximumSignature));
    success(verifyArgs(maximum, maximumSignature));
    const oversized = path('oversized.bin');
    await writeFile(oversized, Buffer.alloc(16 * 1024 * 1024 + 1));
    const output = path('oversized.sig');
    failure(signArgs(oversized, output));
    assert.equal(existsSync(output), false);
    failure(verifyArgs(oversized));
  });

  await t.test('noncanonical public keys cannot be fingerprinted or used', async () => {
    const extraBytes = path('noncanonical.spki');
    await writeFile(extraBytes, Buffer.concat([await readFile(kemPublic), Buffer.from([0])]));
    failure(['fingerprint', '--public', extraBytes]);
    const output = path('noncanonical.pqc');
    const args = encryptArgs(output);
    args[args.indexOf('--public') + 1] = extraBytes;
    failure(args);
    assert.equal(existsSync(output), false);
  });

  await t.test('unknown, duplicate and inline password options are rejected without disclosure', () => {
    for (const args of [
      ['fingerprint', '--public', kemPublic, '--unknown', 'anything'],
      ['fingerprint', '--public', kemPublic, '--public', kemPublic],
      ['fingerprint', '--public', kemPublic, '--json', '--json'],
      ['fingerprint', '--public'],
      ['fingerprint', '--public', kemPublic, '--password', `${passwordMarker}from-argv`],
      ['fingerprint', '--public', kemPublic, `--password=${passwordMarker}inline`],
      ['unknown-command'],
    ]) failure(args);
  });

  await t.test('password changes preserve KEM and signature identity and retain original vaults', async () => {
    const replacementPassword = Buffer.from(`new ${passwordMarker}replacement password`);
    const replacementFile = path('new-password.bin');
    await writeFile(replacementFile, replacementPassword);
    for (const [kind, original, expectedFingerprint] of [['kem', kemVault, kemFingerprint], ['signature', sigVault, sigFingerprint]]) {
      const changedVault = path(`changed-${kind}.vault`);
      const originalBytes = await readFile(original);
      const report = success(['change-password', '--vault', original, '--output', changedVault,
        '--password-file', passwordFile, '--new-password-file', replacementFile]);
      assert.equal(report.kind, kind);
      assert.equal(report.fingerprint, expectedFingerprint);
      assert.equal(report.originalRetained, true);
      assert.deepEqual(await readFile(original), originalBytes);
      const changedBytes = await readFile(changedVault);
      assert.notDeepEqual(changedBytes, originalBytes);
      await assert.rejects(openPrivateKey(changedBytes, password), (error) => error.code === 'AUTHENTICATION_FAILED');
      const oldKey = await openPrivateKey(originalBytes, password);
      (oldKey.privateKey ?? oldKey.signingKey).destroy();
      if (kind === 'kem') {
        success(['decrypt', '--input', encrypted, '--output', path('changed-password-restored.bin'),
          '--vault', changedVault, '--password-file', replacementFile, '--context', context, '--aad', aad]);
        assert.deepEqual(await readFile(path('changed-password-restored.bin')), plaintext);
      } else {
        success(['sign', '--input', input, '--output', path('changed-password.sig'), '--vault', changedVault,
          '--password-file', replacementFile, '--context', context]);
        success(verifyArgs(input, path('changed-password.sig')));
      }
    }
    replacementPassword.fill(0);
    await noStages(directory);
  });

  await t.test('password-change failures leave original keys intact and publish nothing', async () => {
    const wrongPassword = path('wrong-current-password.bin');
    const shortPassword = path('short-new-password.bin');
    await writeFile(wrongPassword, `wrong ${passwordMarker}current password`);
    await writeFile(shortPassword, Buffer.alloc(15));
    const before = await readFile(kemVault);
    const args = ['change-password', '--vault', kemVault, '--output', path('must-not-change.vault')];
    assert.equal(failure([...args, '--password-file', wrongPassword, '--new-password-file', passwordFile]).code, 'AUTHENTICATION_FAILED');
    assert.equal(failure([...args, '--password-file', passwordFile, '--new-password-file', shortPassword]).code, 'INVALID_INPUT');
    assert.equal(failure([...args, '--password-file', passwordFile]).code, 'PASSWORD_REQUIRED');
    assert.equal(failure([...args, '--new-password-file', passwordFile]).code, 'PASSWORD_REQUIRED');
    assert.equal(existsSync(path('must-not-change.vault')), false);
    assert.equal(failure(['change-password', '--vault', kemVault, '--output', kemVault,
      '--password-file', passwordFile, '--new-password-file', passwordFile]).code, 'INVALID_INPUT');
    const otherVault = await readFile(sigVault);
    assert.equal(failure(['change-password', '--vault', kemVault, '--output', sigVault,
      '--password-file', passwordFile, '--new-password-file', passwordFile]).code, 'OUTPUT_EXISTS');
    assert.deepEqual(await readFile(kemVault), before);
    assert.deepEqual(await readFile(sigVault), otherVault);
    await noStages(directory);
  });
});

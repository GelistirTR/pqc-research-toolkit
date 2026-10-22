import { timingSafeEqual } from 'node:crypto';
import { lstat, open, unlink } from 'node:fs/promises';
import { resolve } from 'node:path';
import { emitKeypressEvents } from 'node:readline';
import {
  CryptoError, decryptFile, encryptFile, generateKemKeyPair, generateSigningKeyPair,
  importKemPublicKey, importVerificationKey, openPrivateKey, profile, sealPrivateKey, vaultProfile,
  publicKeyFingerprint as fingerprint, requirePublicKeyFingerprint,
  inspectContainer,
} from './index.js';
import { checkAbort, ensureOutputAbsent, stageOutput, writeAll } from './file-io.js';
import { diagnose } from './diagnostics.js';

const COMMANDS = Object.freeze({
  doctor: [],
  inspect: ['input'],
  keygen: ['vault', 'public', 'type', 'password-file'],
  'change-password': ['vault', 'output', 'password-file', 'new-password-file'],
  fingerprint: ['public'],
  encrypt: ['input', 'output', 'public', 'context', 'fingerprint', 'aad'],
  decrypt: ['input', 'output', 'vault', 'context', 'aad', 'password-file'],
  sign: ['input', 'output', 'vault', 'context', 'password-file'],
  verify: ['input', 'signature', 'public', 'context', 'fingerprint'],
});

const HELP = `PQC Research Toolkit ${profile.version} — experimental, unaudited

Usage: pqc <command> [options]

  doctor      Run local ephemeral cryptographic self-tests; no files or network
  inspect     --input FILE   Read public container headers without a password; NOT authenticated
  keygen      --vault FILE --public FILE [--type kem|signature] [--password-file FILE]
  change-password --vault OLD --output NEW [--password-file OLD_PASSWORD_FILE] [--new-password-file NEW_PASSWORD_FILE]
  fingerprint --public FILE
  encrypt     --input FILE --output FILE --public FILE --context TEXT --fingerprint SHA256:HEX [--aad TEXT]
  decrypt     --input FILE --output FILE --vault FILE --context TEXT [--aad TEXT] [--password-file FILE]
  sign        --input FILE --output FILE --vault FILE --context TEXT [--password-file FILE]
  verify      --input FILE --signature FILE --public FILE --context TEXT [--fingerprint SHA256:HEX]

Global: --json, --help, --version

Passwords are prompted without echo on an interactive terminal. Key generation
asks twice. Automation: --password-file reads 16–1024 raw bytes, without trimming.
Passwords in arguments or environment variables are not supported.
Compare the complete public-key fingerprint via a trusted independent channel.
Encryption and signatures do not establish the owner's identity by themselves.
Existing outputs are never replaced. Signing is limited to 16 MiB.
See README.md and docs/KULLANIM.md for installation, examples and limitations.
`;

function cliError(code, message) { throw new CryptoError(code, message); }

function parse(argv) {
  const command = argv[0];
  if (!Object.hasOwn(COMMANDS, command)) cliError('USAGE_ERROR', 'Unknown command; use pqc --help');
  const allowed = new Set([...COMMANDS[command], 'json']);
  const options = Object.create(null);
  for (let i = 1; i < argv.length; i++) {
    const argument = argv[i];
    if (!argument.startsWith('--') || argument.includes('=')) cliError('USAGE_ERROR', 'Unsupported argument syntax');
    const name = argument.slice(2);
    if (!allowed.has(name) || Object.hasOwn(options, name)) cliError('USAGE_ERROR', 'Unknown or duplicate option');
    if (name === 'json') { options.json = true; continue; }
    const value = argv[++i];
    if (value === undefined || value.startsWith('--')) cliError('USAGE_ERROR', 'An option value is missing');
    options[name] = value;
  }
  return { command, options };
}

function required(options, names) {
  for (const name of names) {
    if (typeof options[name] !== 'string' || options[name].length === 0) {
      cliError('USAGE_ERROR', `Required option: --${name}`);
    }
  }
}

function context(options, max = 512) {
  required(options, ['context']);
  const data = Buffer.from(options.context, 'utf8');
  if (data.length > max) cliError('INVALID_INPUT', 'Context is too long');
  return data;
}

function aad(options) {
  const data = Buffer.from(options.aad ?? '', 'utf8');
  if (data.length > profile.maxAadBytes) cliError('INVALID_INPUT', 'Additional data is too long');
  return data;
}

// Bounded read even if another process grows the file after stat().
async function readBounded(path, max) {
  const handle = await open(path, 'r');
  let scratch;
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size > BigInt(max)) cliError('INVALID_INPUT', 'Input must be a regular file within the size limit');
    scratch = Buffer.alloc(Math.min(Number(before.size) + 1, max + 1));
    let offset = 0;
    for (;;) {
      const { bytesRead } = await handle.read(scratch, offset, scratch.length - offset, offset);
      if (!bytesRead) break;
      offset += bytesRead;
      if (offset === scratch.length) cliError('INPUT_CHANGED', 'Input changed while being read');
    }
    const after = await handle.stat({ bigint: true });
    if (before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs ||
        offset !== Number(before.size)) cliError('INPUT_CHANGED', 'Input changed while being read');
    return Buffer.from(scratch.subarray(0, offset));
  } finally { scratch?.fill(0); await handle.close(); }
}

function checkFingerprint(key, expected, mandatory) {
  if (expected === undefined && !mandatory) return fingerprint(key);
  return requirePublicKeyFingerprint(key, expected);
}

async function publicKey(path, kind) {
  const data = await readBounded(path, 4096);
  if (kind === 'kem') return importKemPublicKey(data);
  if (kind === 'signature') return importVerificationKey(data);
  try { return importKemPublicKey(data); }
  catch (error) { if (error.code !== 'INVALID_KEY') throw error; }
  return importVerificationKey(data);
}

export function promptHidden(prompt, input = process.stdin, output = process.stderr) {
  if (!input.isTTY || !output.isTTY || typeof input.setRawMode !== 'function') {
    cliError('PASSWORD_REQUIRED', 'Use an interactive terminal or --password-file');
  }
  return new Promise((resolvePassword, reject) => {
    const storage = Buffer.alloc(vaultProfile.maxPassphraseBytes);
    const previousRawMode = Boolean(input.isRaw);
    let length = 0;
    let finished = false;
    const finish = (error) => {
      if (finished) return;
      finished = true;
      input.removeListener('keypress', keypress);
      input.removeListener('end', ended);
      input.removeListener('error', failed);
      let failure = error;
      // A terminal I/O failure must not skip wiping or leave this promise pending.
      for (const cleanup of [() => input.setRawMode(previousRawMode), () => input.pause(), () => output.write('\n')]) {
        try { cleanup(); }
        catch { failure = new CryptoError('IO_ERROR', 'Password terminal cleanup failed'); }
      }
      let result;
      try { if (!failure) result = Buffer.from(storage.subarray(0, length)); }
      catch { failure = new CryptoError('IO_ERROR', 'Unable to finish password entry'); }
      finally { storage.fill(0); }
      if (failure) reject(failure); else resolvePassword(result);
    };
    const ended = () => finish(new CryptoError('ABORTED', 'Password entry cancelled'));
    const failed = () => finish(new CryptoError('IO_ERROR', 'Unable to read password'));
    const keypress = (text, key = {}) => {
      if (key.ctrl && key.name === 'c') return ended();
      if (key.name === 'return' || key.name === 'enter') return finish();
      if (key.name === 'backspace') {
        if (length) {
          let start = length - 1;
          while (start > 0 && (storage[start] & 0xc0) === 0x80) start--;
          storage.fill(0, start, length); length = start;
        }
        return;
      }
      if (key.ctrl || key.meta || typeof text !== 'string' || /[\u0000-\u001f\u007f]/u.test(text)) return;
      const encoded = Buffer.from(text, 'utf8');
      try {
        if (length + encoded.length > storage.length) return finish(new CryptoError('INVALID_INPUT', 'Passphrase exceeds 1024 bytes'));
        encoded.copy(storage, length); length += encoded.length;
      } finally { encoded.fill(0); }
    };
    try {
      emitKeypressEvents(input);
      input.on('keypress', keypress);
      input.once('end', ended);
      input.once('error', failed);
      input.setRawMode(true);
      input.resume();
      output.write(prompt);
    } catch { finish(new CryptoError('IO_ERROR', 'Unable to start hidden password entry')); }
  });
}

async function password(options, confirmation, label = 'Passphrase') {
  let value;
  let repeated;
  try {
    value = options['password-file'] !== undefined
      ? await readBounded(options['password-file'], vaultProfile.maxPassphraseBytes)
      : await promptHidden(`${label} (hidden): `);
    if (value.length < vaultProfile.minPassphraseBytes) cliError('INVALID_INPUT', 'Passphrase must contain at least 16 bytes');
    if (confirmation && options['password-file'] === undefined) {
      repeated = await promptHidden(`Repeat ${label.toLowerCase()} (hidden): `);
      if (value.length !== repeated.length || !timingSafeEqual(value, repeated)) {
        cliError('PASSWORD_MISMATCH', 'Passphrases do not match');
      }
    }
    return value;
  } catch (error) { value?.fill(0); throw error; }
  finally { repeated?.fill(0); }
}

async function writeExclusive(path, value, signal) {
  const stage = await stageOutput(resolve(path));
  try { await writeAll(stage.handle, value); await stage.publish(signal); }
  finally { await stage.cleanup(); }
}

async function rollbackOwned(path, identity) {
  const current = await lstat(path, { bigint: true });
  if (current.dev !== identity.dev || current.ino !== identity.ino) {
    cliError('PARTIAL_OUTPUT', 'Output changed during rollback; inspect generated key files');
  }
  await unlink(path);
}

async function writeKeyPair(vaultPath, vault, publicPath, spki, signal) {
  if (resolve(vaultPath) === resolve(publicPath)) cliError('INVALID_INPUT', 'Vault and public-key paths must differ');
  await ensureOutputAbsent(resolve(vaultPath));
  await ensureOutputAbsent(resolve(publicPath));
  let vaultStage;
  let publicStage;
  let vaultPublished = false;
  let publicPublished = false;
  let identity;
  try {
    vaultStage = await stageOutput(resolve(vaultPath));
    publicStage = await stageOutput(resolve(publicPath));
    await writeAll(vaultStage.handle, vault);
    await writeAll(publicStage.handle, spki);
    identity = await vaultStage.handle.stat({ bigint: true });
    await vaultStage.publish(signal); vaultPublished = true;
    await publicStage.publish(signal); publicPublished = true;
  } catch (error) {
    if (vaultPublished && !publicPublished) await rollbackOwned(vaultPath, identity);
    throw error;
  } finally {
    try { await vaultStage?.cleanup(); }
    finally { await publicStage?.cleanup(); }
  }
}

async function execute(command, options, signal) {
  if (command === 'doctor') return { command, ...await diagnose(signal) };
  if (command === 'inspect') {
    required(options, ['input']);
    return { command, ...await inspectContainer(options.input, { signal }) };
  }
  if (command === 'change-password') {
    required(options, ['vault', 'output']);
    if (resolve(options.vault) === resolve(options.output)) cliError('INVALID_INPUT', 'Original and new vault paths must differ');
    await ensureOutputAbsent(resolve(options.output));
    const original = await readBounded(options.vault, vaultProfile.maxVaultBytes);
    let oldPassword;
    let newPassword;
    let restored;
    try {
      oldPassword = await password(options, false, 'Current passphrase');
      restored = await openPrivateKey(original, oldPassword, { signal });
      oldPassword.fill(0);
      checkAbort(signal);
      newPassword = await password({ 'password-file': options['new-password-file'] }, true, 'New passphrase');
      const key = restored.privateKey ?? restored.signingKey;
      const publicPart = restored.publicKey ?? restored.verificationKey;
      const protectedKey = await sealPrivateKey(key, newPassword, { signal });
      await writeExclusive(options.output, protectedKey, signal);
      return { command, kind: restored.kind, fingerprint: fingerprint(publicPart), originalRetained: true };
    } finally {
      oldPassword?.fill(0); newPassword?.fill(0);
      restored?.privateKey?.destroy(); restored?.signingKey?.destroy();
    }
  }
  if (command === 'keygen') {
    required(options, ['vault', 'public']);
    const kind = options.type ?? 'kem';
    if (!['kem', 'signature'].includes(kind)) cliError('USAGE_ERROR', 'Key type must be kem or signature');
    if (resolve(options.vault) === resolve(options.public)) cliError('INVALID_INPUT', 'Vault and public-key paths must differ');
    await ensureOutputAbsent(resolve(options.vault)); await ensureOutputAbsent(resolve(options.public));
    const secret = await password(options, true);
    let pair;
    try {
      checkAbort(signal);
      pair = kind === 'kem' ? await generateKemKeyPair() : await generateSigningKeyPair();
      const privateKey = pair.privateKey ?? pair.signingKey;
      const publicPart = pair.publicKey ?? pair.verificationKey;
      const vault = await sealPrivateKey(privateKey, secret, { signal });
      await writeKeyPair(options.vault, vault, options.public, publicPart.exportSpki(), signal);
      return { command, kind, fingerprint: fingerprint(publicPart) };
    } finally { secret.fill(0); pair?.privateKey?.destroy(); pair?.signingKey?.destroy(); }
  }
  if (command === 'fingerprint') {
    required(options, ['public']);
    return { command, fingerprint: fingerprint(await publicKey(options.public)) };
  }
  if (command === 'encrypt') {
    required(options, ['input', 'output', 'public', 'fingerprint']);
    const ctx = context(options); const associated = aad(options);
    const key = await publicKey(options.public, 'kem');
    const pin = checkFingerprint(key, options.fingerprint, true);
    const result = await encryptFile({ inputPath: options.input, outputPath: options.output,
      recipient: key, context: ctx, aad: associated, signal });
    return { command, ...result, fingerprint: pin };
  }
  if (command === 'decrypt' || command === 'sign') {
    required(options, ['input', 'output', 'vault']);
    const ctx = context(options, command === 'sign' ? 255 : 512);
    const associated = aad(options);
    await ensureOutputAbsent(resolve(options.output));
    const vault = await readBounded(options.vault, vaultProfile.maxVaultBytes);
    const secret = await password(options, false);
    let restored;
    let message;
    try {
      restored = await openPrivateKey(vault, secret, { signal });
      checkAbort(signal);
      if (command === 'decrypt') {
        if (restored.kind !== 'kem') cliError('INVALID_KEY', 'Decryption requires a KEM key vault');
        const result = await decryptFile({ inputPath: options.input, outputPath: options.output,
          privateKey: restored.privateKey, context: ctx, aad: associated, signal });
        return { command, ...result };
      }
      if (restored.kind !== 'signature') cliError('INVALID_KEY', 'Signing requires a signature key vault');
      message = await readBounded(options.input, profile.maxMessageBytes);
      const signature = await restored.signingKey.sign(message, ctx);
      await writeExclusive(options.output, signature, signal);
      return { command, bytes: message.length, fingerprint: fingerprint(restored.verificationKey) };
    } finally { secret.fill(0); message?.fill(0); restored?.privateKey?.destroy(); restored?.signingKey?.destroy(); }
  }
  if (command === 'verify') {
    required(options, ['input', 'signature', 'public']);
    const ctx = context(options, 255);
    const key = await publicKey(options.public, 'signature');
    const pin = checkFingerprint(key, options.fingerprint, false);
    const signature = await readBounded(options.signature, 4627);
    let message;
    try {
      message = await readBounded(options.input, profile.maxMessageBytes);
      if (!await key.verify(message, signature, ctx)) cliError('SIGNATURE_INVALID', 'Signature verification failed');
      return { command, valid: true, fingerprint: pin };
    } finally { message?.fill(0); }
  }
  cliError('USAGE_ERROR', 'Unknown command');
}

function safeError(error) {
  if (error instanceof CryptoError) return { code: error.code, message: error.message };
  const messages = {
    ENOENT: 'An input file or output directory was not found',
    EACCES: 'Access denied; check file and directory permissions',
    EPERM: 'Operation not permitted; check permissions and hard-link support',
    EEXIST: 'Output already exists',
    ENOSPC: 'Not enough disk space',
    EISDIR: 'Expected a regular file, not a directory',
    ENOTDIR: 'An output directory is invalid',
    EXDEV: 'Output publication requires a hard link on the same filesystem',
    ENOTSUP: 'The filesystem does not support the required operation',
  };
  const code = typeof error?.code === 'string' ? error.code : 'OPERATION_FAILED';
  return { code, message: messages[code] ?? 'Operation failed; no password or provider details were printed' };
}

export async function runCli(argv) {
  const json = argv.includes('--json');
  const controller = new AbortController();
  const interrupt = () => controller.abort();
  process.on('SIGINT', interrupt);
  try {
    if (argv.length === 0 || (argv.length === 1 && ['help', '--help', '-h'].includes(argv[0]))) {
      process.stdout.write(HELP); return 0;
    }
    if (argv.length === 1 && ['version', '--version'].includes(argv[0])) {
      process.stdout.write(`${profile.version}\n`); return 0;
    }
    const { command, options } = parse(argv);
    const result = await execute(command, options, controller.signal);
    if (json) process.stdout.write(`${JSON.stringify({ ok: true, ...result })}\n`);
    else {
      process.stdout.write(`${command}: completed${result.bytes !== undefined ? ` (${result.bytes} bytes)` : ''}\n`);
      if (result.fingerprint) process.stdout.write(`${result.fingerprint}\n`);
      if (result.valid) process.stdout.write('Signature is valid for the supplied public key and context.\n');
      if (command === 'inspect') {
        process.stdout.write('UNAUTHENTICATED: header claims only; no password, ciphertext or key identity was verified.\n');
        process.stdout.write(`${result.kind}, format v${result.formatVersion}, ${result.containerBytes} container bytes\n`);
        if (result.kind === 'encrypted-file') {
          process.stdout.write(`Declared plaintext: ${result.declaredPlaintextBytes} bytes; ${result.chunks} chunks of up to ${result.chunkBytes} bytes\n`);
          process.stdout.write(`Claimed recipient: ${result.recipientFingerprint}\n`);
        } else process.stdout.write(`Claimed key type: ${result.keyKind}; Argon2id ${result.memoryKiB} KiB, passes ${result.passes}, parallelism ${result.parallelism}\n`);
      }
      if (command === 'change-password') process.stdout.write('Original vault retained and still opens with its old password. The key identity did not change.\n');
      if (command === 'doctor') {
        process.stdout.write(`Node ${result.runtime.node}, OpenSSL ${result.runtime.openssl}, ${result.runtime.platform}/${result.runtime.arch}\n`);
        for (const item of result.checks) process.stdout.write(`PASS ${item}\n`);
        process.stdout.write(`${result.assurance}. Filesystem permissions and hard links were not checked.\n`);
      }
    }
    return 0;
  } catch (error) {
    const failure = safeError(error);
    if (json) process.stderr.write(`${JSON.stringify({ ok: false, error: failure })}\n`);
    else process.stderr.write(`PQC [${failure.code}]: ${failure.message}\n`);
    return failure.code === 'ABORTED' ? 130 : 1;
  } finally { process.removeListener('SIGINT', interrupt); }
}

import { open } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fail } from './errors.js';
import { checkAbort, readExact, unchanged } from './file-io.js';
import { encryptedFileBytes, fileProfile, parseFileHeader } from './files.js';
import { parseVaultHeader, vaultProfile } from './key-vault.js';

// Read only public headers. No passwords, private-key import, KDF, KEM or
// authentication: every field in this result remains attacker-controlled.
export async function inspectContainer(inputPath, options = {}) {
  if (typeof inputPath !== 'string' || inputPath.length === 0 || inputPath.includes('\0')) {
    fail('INVALID_INPUT', 'Expected an explicit input file path');
  }
  if (!options || typeof options !== 'object' || Array.isArray(options)) fail('INVALID_INPUT', 'Expected inspection options');
  const signal = options.signal;
  checkAbort(signal);
  const source = await open(resolve(inputPath), 'r');
  try {
    const before = await source.stat({ bigint: true });
    if (!before.isFile()) fail('INVALID_INPUT', 'Input must be a regular file');
    if (before.size < 8n) fail('INVALID_CONTAINER', 'Unknown or truncated container');
    const magic = Buffer.alloc(8);
    await readExact(source, magic, 0, 'INVALID_CONTAINER');
    checkAbort(signal);
    let result;
    if (magic.equals(Buffer.from('PQCFILE\0'))) {
      if (before.size < BigInt(fileProfile.headerBytes)) fail('INVALID_FILE', 'Truncated encrypted file header');
      const header = Buffer.alloc(fileProfile.headerBytes);
      await readExact(source, header, 0, 'INVALID_FILE');
      const { size, chunkSize } = parseFileHeader(header);
      const expectedSize = encryptedFileBytes(size, chunkSize);
      if (before.size !== BigInt(expectedSize)) fail('INVALID_FILE', 'Encrypted file length does not match its header');
      result = {
        kind: 'encrypted-file', formatVersion: 1, authenticated: false,
        containerBytes: expectedSize, declaredPlaintextBytes: size,
        chunkBytes: chunkSize, chunks: Math.ceil(size / chunkSize),
        recipientFingerprint: `SHA256:${header.subarray(24, 56).toString('hex')}`,
        kem: 'ML-KEM-1024', kdf: 'HKDF-SHA-512', aead: 'AES-256-GCM',
      };
    } else if (magic.equals(Buffer.from('PQCVAULT'))) {
      if (before.size > BigInt(vaultProfile.maxVaultBytes) || before.size < 56n) fail('INVALID_VAULT', 'Invalid key vault length');
      const header = Buffer.alloc(56);
      await readExact(source, header, 0, 'INVALID_VAULT');
      const { kind } = parseVaultHeader(header, Number(before.size));
      result = {
        kind: 'key-vault', keyKind: kind, formatVersion: 1, authenticated: false,
        containerBytes: Number(before.size), kdf: vaultProfile.kdf, aead: 'AES-256-GCM',
        memoryKiB: vaultProfile.memoryKiB, passes: vaultProfile.passes, parallelism: vaultProfile.parallelism,
      };
    } else fail('INVALID_CONTAINER', 'Unknown container format');
    checkAbort(signal);
    unchanged(before, await source.stat({ bigint: true }));
    return Object.freeze(result);
  } finally { await source.close(); }
}

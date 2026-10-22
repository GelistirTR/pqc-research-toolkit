import {
  createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes,
} from 'node:crypto';
import { open } from 'node:fs/promises';
import { KemPrivateKey, KemPublicKey, encapsulate } from './asymmetric.js';
import { bytes, contextBytes, frame, MAX_AAD_BYTES, TOKEN } from './internal.js';
import { fail } from './errors.js';
import { checkAbort, filePaths, readExact, stageOutput, unchanged, writeAll } from './file-io.js';

const MAGIC = Buffer.from('PQCFILE\0');
const HEADER_BYTES = 1656;
const MAX_FILE_BYTES = 64 * 1024 ** 3;
const EMPTY = Buffer.alloc(0);
const ZERO_NONCE = Buffer.alloc(12);
const ROOT_LABEL = 'pqc-research-core/file/v1/root\0';
const RECORD_LABEL = Buffer.from('pqc-research-core/file/v1/record\0');

export const fileProfile = Object.freeze({
  version: 1, suite: 1, headerBytes: HEADER_BYTES,
  defaultChunkBytes: 1024 * 1024, minChunkBytes: 65536, maxChunkBytes: 4 * 1024 * 1024,
  maxFileBytes: MAX_FILE_BYTES,
});

function checkedChunkSize(value, code = 'INVALID_INPUT') {
  if (!Number.isInteger(value) || value < fileProfile.minChunkBytes || value > fileProfile.maxChunkBytes ||
      (value & (value - 1)) !== 0) fail(code, 'Chunk size must be a power of two from 64 KiB to 4 MiB');
  return value;
}

function fileSize(size, code = 'INVALID_INPUT') {
  if (size < 0n || size > BigInt(MAX_FILE_BYTES)) fail(code, 'File exceeds the 64 GiB alpha limit');
  return Number(size);
}

function header(publicKey, kemCiphertext, salt, chunkSize, size) {
  const data = Buffer.alloc(HEADER_BYTES);
  MAGIC.copy(data); data[8] = 1; data[9] = 1;
  data.writeUInt32BE(chunkSize, 12);
  data.writeBigUInt64BE(BigInt(size), 16);
  createHash('sha256').update(publicKey.exportSpki()).digest().copy(data, 24);
  kemCiphertext.copy(data, 56);
  salt.copy(data, 1624);
  return data;
}

export function parseFileHeader(data) {
  if (data.length !== HEADER_BYTES || !data.subarray(0, 8).equals(MAGIC) || data[8] !== 1 || data[9] !== 1 || data.readUInt16BE(10) !== 0) {
    fail('INVALID_FILE', 'Unsupported or malformed encrypted file');
  }
  return {
    chunkSize: checkedChunkSize(data.readUInt32BE(12), 'INVALID_FILE'),
    size: fileSize(data.readBigUInt64BE(16), 'INVALID_FILE'),
  };
}

export function encryptedFileBytes(size, chunkSize) {
  return HEADER_BYTES + 16 + size + (Math.ceil(size / chunkSize) + 1) * 20;
}

function binding(headerBytes, context, aad) {
  return createHash('sha512').update(headerBytes)
    .update(frame('context\0', context)).update(frame('aad\0', aad)).digest();
}

function descriptor(index, kind, length) {
  const data = Buffer.alloc(13);
  data.writeBigUInt64BE(BigInt(index), 0);
  data[8] = kind;
  data.writeUInt32BE(length, 9);
  return data;
}

function recordKey(root, index) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(index));
  return Buffer.from(hkdfSync('sha512', root, EMPTY, Buffer.concat([RECORD_LABEL, counter]), 32));
}

// One AES key per record, including header/final records. Nonce zero is never reused under a record key.
function encryptRecord(root, bound, index, kind, plaintext) {
  const key = recordKey(root, index);
  try {
    const cipher = createCipheriv('aes-256-gcm', key, ZERO_NONCE, { authTagLength: 16 });
    cipher.setAAD(Buffer.concat([bound, descriptor(index, kind, plaintext.length)]));
    return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  } finally { key.fill(0); }
}

function decryptRecord(root, bound, index, kind, encrypted, length) {
  const key = recordKey(root, index);
  let pending;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, ZERO_NONCE, { authTagLength: 16 });
    decipher.setAAD(Buffer.concat([bound, descriptor(index, kind, length)]));
    decipher.setAuthTag(encrypted.subarray(-16));
    pending = decipher.update(encrypted.subarray(0, -16));
    return Buffer.concat([pending, decipher.final()]);
  } catch { fail('AUTHENTICATION_FAILED', 'Authentication failed'); }
  finally { key.fill(0); pending?.fill(0); }
}

function options(input) {
  if (!input || typeof input !== 'object') fail('INVALID_INPUT', 'Expected file options');
  const paths = filePaths(input.inputPath, input.outputPath);
  const context = contextBytes(input.context);
  const aad = bytes(input.aad ?? EMPTY, 'aad', MAX_AAD_BYTES);
  const signal = input.signal;
  checkAbort(signal);
  return { ...paths, context, aad, signal };
}

export async function encryptFile(input) {
  const { inputPath, outputPath, context, aad, signal } = options(input);
  const recipient = input.recipient;
  if (!(recipient instanceof KemPublicKey)) fail('INVALID_KEY', 'Expected an ML-KEM public key');
  const chunkSize = checkedChunkSize(input.chunkSize ?? fileProfile.defaultChunkBytes);
  let source;
  let stage;
  let root;
  let secret;
  let chunk;
  try {
    source = await open(inputPath, 'r');
    const before = await source.stat({ bigint: true });
    if (!before.isFile()) fail('INVALID_INPUT', 'Input must be a regular file');
    const size = fileSize(before.size);
    checkAbort(signal);
    stage = await stageOutput(outputPath);
    const exchange = await encapsulate(recipient);
    secret = exchange.secret;
    const salt = randomBytes(32);
    root = secret.use(TOKEN, salt, frame(ROOT_LABEL, context));
    const prefix = header(recipient, exchange.ciphertext, salt, chunkSize, size);
    const bound = binding(prefix, context, aad);
    await writeAll(stage.handle, prefix);
    await writeAll(stage.handle, encryptRecord(root, bound, 0, 0, EMPTY));
    chunk = Buffer.alloc(Math.min(chunkSize, size));
    let offset = 0;
    let index = 1;
    while (offset < size) {
      checkAbort(signal);
      const length = Math.min(chunkSize, size - offset);
      const part = chunk.subarray(0, length);
      await readExact(source, part, offset, 'INPUT_CHANGED');
      const lengthBytes = Buffer.alloc(4);
      lengthBytes.writeUInt32BE(length);
      await writeAll(stage.handle, lengthBytes);
      await writeAll(stage.handle, encryptRecord(root, bound, index++, 1, part));
      part.fill(0);
      offset += length;
    }
    checkAbort(signal);
    await unchangedInput(source, before);
    await writeAll(stage.handle, Buffer.alloc(4));
    await writeAll(stage.handle, encryptRecord(root, bound, index, 2, EMPTY));
    await stage.publish(signal);
    return { bytes: size, chunks: index - 1 };
  } finally {
    chunk?.fill(0); secret?.destroy(); root = undefined;
    try { await source?.close(); }
    finally { await stage?.cleanup(); }
  }
}

async function unchangedInput(source, before) { unchanged(before, await source.stat({ bigint: true })); }

export async function decryptFile(input) {
  const { inputPath, outputPath, context, aad, signal } = options(input);
  const privateKey = input.privateKey;
  if (!(privateKey instanceof KemPrivateKey)) fail('INVALID_KEY', 'Expected an ML-KEM private key');
  // Capture native state before asynchronous I/O; destroy() does not cancel in-flight work.
  const recipient = new KemPrivateKey(TOKEN, privateKey.native(TOKEN));
  let source;
  let stage;
  let root;
  let secret;
  try {
    source = await open(inputPath, 'r');
    const before = await source.stat({ bigint: true });
    if (!before.isFile()) fail('INVALID_INPUT', 'Input must be a regular file');
    const prefix = Buffer.alloc(HEADER_BYTES);
    await readExact(source, prefix, 0);
    const { chunkSize, size } = parseFileHeader(prefix);
    const expectedSize = BigInt(encryptedFileBytes(size, chunkSize));
    if (before.size !== expectedSize) fail('AUTHENTICATION_FAILED', 'Authentication failed');
    const fingerprint = createHash('sha256').update(recipient.publicKey().exportSpki()).digest();
    if (!fingerprint.equals(prefix.subarray(24, 56))) fail('AUTHENTICATION_FAILED', 'Authentication failed');
    secret = await recipient.decapsulate(prefix.subarray(56, 1624));
    root = secret.use(TOKEN, prefix.subarray(1624), frame(ROOT_LABEL, context));
    const bound = binding(prefix, context, aad);
    const headerTag = Buffer.alloc(16);
    await readExact(source, headerTag, HEADER_BYTES);
    decryptRecord(root, bound, 0, 0, headerTag, 0).fill(0);
    checkAbort(signal);
    stage = await stageOutput(outputPath);
    let position = HEADER_BYTES + 16;
    let offset = 0;
    let index = 1;
    const lengthBytes = Buffer.alloc(4);
    while (offset < size) {
      checkAbort(signal);
      await readExact(source, lengthBytes, position);
      position += 4;
      const length = lengthBytes.readUInt32BE(0);
      if (length !== Math.min(chunkSize, size - offset)) fail('AUTHENTICATION_FAILED', 'Authentication failed');
      const encrypted = Buffer.alloc(length + 16);
      await readExact(source, encrypted, position);
      position += encrypted.length;
      const plaintext = decryptRecord(root, bound, index++, 1, encrypted, length);
      try { await writeAll(stage.handle, plaintext); }
      finally { plaintext.fill(0); }
      offset += length;
    }
    checkAbort(signal);
    await readExact(source, lengthBytes, position);
    if (lengthBytes.readUInt32BE(0) !== 0) fail('AUTHENTICATION_FAILED', 'Authentication failed');
    const finalTag = Buffer.alloc(16);
    await readExact(source, finalTag, position + 4);
    decryptRecord(root, bound, index, 2, finalTag, 0).fill(0);
    await unchangedInput(source, before);
    await stage.publish(signal);
    return { bytes: size, chunks: index - 1 };
  } finally {
    secret?.destroy(); recipient.destroy(); root = undefined;
    try { await source?.close(); }
    finally { await stage?.cleanup(); }
  }
}

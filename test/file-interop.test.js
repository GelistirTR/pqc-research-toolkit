import assert from 'node:assert/strict';
import { createDecipheriv, createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { encryptFile, importKemPublicKey } from '../src/index.js';
import { readExact, writeAll } from '../src/file-io.js';

test('file header/KEM/HKDF/records are independently decoded from the documented wire format', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'pqc-interop-test-'));
  const noble = ml_kem1024.keygen();
  const context = Buffer.from('independent-file-format');
  const aad = Buffer.from('expected-metadata');
  const message = Buffer.alloc(65536 + 27, 0x7e);
  const publicKey = importKemPublicKey(Buffer.concat([
    Buffer.from('30820632300b06096086480165030404030382062100', 'hex'), noble.publicKey,
  ]));
  let shared;
  let root;
  try {
    const inputPath = join(directory, 'input.bin');
    const outputPath = join(directory, 'encrypted.pqc');
    await writeFile(inputPath, message);
    await encryptFile({ inputPath, outputPath, recipient: publicKey, context, aad, chunkSize: 65536 });
    const file = await readFile(outputPath);
    const header = file.subarray(0, 1656);
    assert.equal(header.subarray(0, 8).toString('hex'), '50514346494c4500');
    assert.equal(header[8], 1);
    assert.equal(header.readBigUInt64BE(16), BigInt(message.length));
    shared = ml_kem1024.decapsulate(header.subarray(56, 1624), noble.secretKey);
    const frame = (label, value) => {
      const size = Buffer.alloc(4);
      size.writeUInt32BE(value.length);
      return Buffer.concat([Buffer.from(label), size, value]);
    };
    const rootContext = frame('pqc-research-core/file/v1/root\0', context);
    const rootInfo = frame('pqc-research-core/alpha1/ml-kem-1024/hkdf-sha512/aes256gcm\0', rootContext);
    root = hkdf(sha512, shared, header.subarray(1624), rootInfo, 32);
    const bound = createHash('sha512').update(header)
      .update(frame('context\0', context)).update(frame('aad\0', aad)).digest();
    const decoded = [];
    const record = (index, kind, length, encrypted) => {
      const counter = Buffer.alloc(8);
      counter.writeBigUInt64BE(BigInt(index));
      const descriptor = Buffer.alloc(13);
      counter.copy(descriptor); descriptor[8] = kind; descriptor.writeUInt32BE(length, 9);
      const key = hkdf(sha512, root, Buffer.alloc(0), Buffer.concat([
        Buffer.from('pqc-research-core/file/v1/record\0'), counter,
      ]), 32);
      try {
        const decipher = createDecipheriv('aes-256-gcm', key, Buffer.alloc(12));
        decipher.setAAD(Buffer.concat([bound, descriptor]));
        decipher.setAuthTag(encrypted.subarray(-16));
        return Buffer.concat([decipher.update(encrypted.subarray(0, -16)), decipher.final()]);
      } finally { key.fill(0); }
    };
    assert.equal(record(0, 0, 0, file.subarray(1656, 1672)).length, 0);
    let position = 1672;
    let index = 1;
    for (;;) {
      const length = file.readUInt32BE(position);
      position += 4;
      const encrypted = file.subarray(position, position + length + 16);
      position += length + 16;
      const plain = record(index++, length === 0 ? 2 : 1, length, encrypted);
      if (length === 0) break;
      decoded.push(plain);
    }
    assert.equal(position, file.length);
    assert.deepEqual(Buffer.concat(decoded), message);
    decoded.forEach((part) => part.fill(0));
  } finally {
    shared?.fill(0); root?.fill(0); noble.secretKey.fill(0);
    const target = resolve(directory);
    assert.equal(dirname(target), resolve(tmpdir()));
    assert.ok(basename(target).startsWith('pqc-interop-test-'));
    await rm(target, { recursive: true, force: true });
  }
});

test('file I/O handles short reads/writes and rejects early EOF or zero write progress', async () => {
  const source = Buffer.from('partial system calls');
  const output = Buffer.alloc(source.length);
  const reader = {
    async read(buffer, offset, length, position) {
      const size = Math.min(3, length, source.length - position);
      source.copy(buffer, offset, position, position + size);
      return { bytesRead: size };
    },
  };
  await readExact(reader, output, 0);
  assert.deepEqual(output, source);
  const pieces = [];
  await writeAll({ async write(buffer, offset, length) {
    const size = Math.min(2, length);
    pieces.push(Buffer.from(buffer.subarray(offset, offset + size)));
    return { bytesWritten: size };
  } }, source);
  assert.deepEqual(Buffer.concat(pieces), source);
  await assert.rejects(readExact(reader, Buffer.alloc(source.length + 1), 0), { code: 'AUTHENTICATION_FAILED' });
  await assert.rejects(writeAll({ async write() { return { bytesWritten: 0 }; } }, source), { code: 'IO_ERROR' });
});

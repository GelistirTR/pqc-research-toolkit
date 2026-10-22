import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import {
  decryptFile, encryptFile, generateKemKeyPair, openPrivateKey, sealPrivateKey,
} from '../src/index.js';

const directory = await mkdtemp(join(tmpdir(), 'pqc-file-demo-'));
const passphrase = randomBytes(32); // Demo-only; use your own strong passphrase and retain it separately.
const context = Buffer.from('example/archive/v1');
const recipient = await generateKemKeyPair();
let restored;
try {
  const inputPath = join(directory, 'input.bin');
  const encryptedPath = join(directory, 'input.pqc');
  const outputPath = join(directory, 'restored.bin');
  const vaultPath = join(directory, 'recipient.pqvault');
  await writeFile(inputPath, Buffer.alloc(3 * 1024 * 1024 + 17, 0x42), { flag: 'wx', mode: 0o600 });
  const vault = await sealPrivateKey(recipient.privateKey, passphrase);
  await writeFile(vaultPath, vault, { flag: 'wx', mode: 0o600 });
  const result = await encryptFile({ inputPath, outputPath: encryptedPath, recipient: recipient.publicKey, context });
  recipient.privateKey.destroy();

  restored = await openPrivateKey(await readFile(vaultPath), passphrase);
  assert.equal(restored.kind, 'kem');
  await decryptFile({ inputPath: encryptedPath, outputPath, privateKey: restored.privateKey, context });
  assert.deepEqual(await readFile(outputPath), await readFile(inputPath));
  console.log(`${result.bytes} bayt, ${result.chunks} parça şifrelendi ve geri çözüldü.`);
  console.log('Parolalı anahtar kasası diske yazıldı, tekrar açıldı ve kullanıldı.');
  console.log('Demo dosyaları şimdi temizleniyor; kalıcı bir anahtar oluşturulmadı.');
} finally {
  passphrase.fill(0);
  recipient.privateKey.destroy();
  restored?.privateKey?.destroy();
  const target = resolve(directory);
  assert.equal(dirname(target), resolve(tmpdir()));
  assert.ok(basename(target).startsWith('pqc-file-demo-'));
  await rm(target, { recursive: true, force: true });
}

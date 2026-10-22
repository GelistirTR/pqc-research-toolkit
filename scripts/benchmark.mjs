import { performance } from 'node:perf_hooks';
import { cpus, platform, arch } from 'node:os';
import {
  encapsulate, generateKemKeyPair, generateSigningKeyPair, generateSymmetricKeyPair, profile,
} from '../src/index.js';

const samples = 30;
const context = Buffer.from('benchmark/v1');
const message = Buffer.alloc(1024);
const kem = await generateKemKeyPair();
const signer = await generateSigningKeyPair();
const signature = await signer.signingKey.sign(message, context);
const ct = (await encapsulate(kem.publicKey));
ct.secret.destroy();
const results = {};
async function measure(name, operation) {
  for (let i = 0; i < 3; i++) await operation();
  const times = [];
  for (let i = 0; i < samples; i++) {
    const start = performance.now();
    await operation();
    times.push(performance.now() - start);
  }
  times.sort((a, b) => a - b);
  results[name] = {
    samples, medianMs: times[Math.floor(samples / 2)], p95Ms: times[Math.ceil(samples * 0.95) - 1],
  };
}
await measure('ML-KEM-1024.KeyGen', async () => (await generateKemKeyPair()).privateKey.destroy());
await measure('ML-KEM-1024.Encaps', async () => (await encapsulate(kem.publicKey)).secret.destroy());
await measure('ML-KEM-1024.Decaps', async () => (await kem.privateKey.decapsulate(ct.ciphertext)).destroy());
await measure('ML-DSA-87.KeyGen', async () => (await generateSigningKeyPair()).signingKey.destroy());
await measure('ML-DSA-87.Sign-1KiB', () => signer.signingKey.sign(message, context));
await measure('ML-DSA-87.Verify-1KiB', () => signer.verificationKey.verify(message, signature, context));
await measure('AES-256-GCM.OneShot-1KiB-including-keygen', () => {
  const keys = generateSymmetricKeyPair();
  const packet = keys.encryptionKey.encrypt(message);
  keys.decryptionKey.decrypt(packet).fill(0);
  keys.decryptionKey.destroy();
});
kem.privateKey.destroy(); signer.signingKey.destroy();
console.log(JSON.stringify({
  profile, node: process.versions.node, openssl: process.versions.openssl,
  platform: platform(), arch: arch(), cpu: cpus()[0]?.model,
  note: 'Local smoke benchmark, sequential async calls with callback/threadpool overhead; not cryptanalysis.',
  results,
}, null, 2));

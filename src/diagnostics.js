import { randomBytes } from 'node:crypto';
import {
  encapsulate, generateKemKeyPair, generateSigningKeyPair, openPrivateKey, profile, sealPrivateKey,
} from './index.js';
import { checkAbort } from './file-io.js';
import { fail } from './errors.js';

// Ephemeral local functional checks only: no user keys, file writes or network calls.
export async function diagnose(signal) {
  const password = randomBytes(32);
  const context = Buffer.from('pqc-research/doctor/v1');
  const message = Buffer.from('Local functional self-test; not a security certification.');
  let kem;
  let signing;
  let restored;
  let sender;
  let recipient;
  let encryption;
  let decryption;
  let plaintext;
  let vault;
  try {
    checkAbort(signal);
    kem = await generateKemKeyPair();
    vault = await sealPrivateKey(kem.privateKey, password, { signal });
    restored = await openPrivateKey(vault, password, { signal });
    kem.privateKey.destroy();
    if (restored.kind !== 'kem') fail('SELF_TEST_FAILED', 'Key vault self-test failed');
    checkAbort(signal);
    const encapsulated = await encapsulate(kem.publicKey);
    sender = encapsulated.secret;
    recipient = await restored.privateKey.decapsulate(encapsulated.ciphertext);
    const derived = sender.deriveEncryptionKey(context);
    encryption = derived.key;
    decryption = recipient.deriveDecryptionKey(derived.salt, context);
    const packet = encryption.encrypt(message, context);
    plaintext = decryption.decrypt(packet, context);
    if (!plaintext.equals(message)) fail('SELF_TEST_FAILED', 'Encryption self-test failed');
    // A failing authentication check must not be mistaken for a successful roundtrip.
    const changed = { ...packet, tag: Buffer.from(packet.tag) };
    changed.tag[0] ^= 1;
    let rejected = false;
    try { decryption.decrypt(changed, context); }
    catch (error) { if (error.code !== 'AUTHENTICATION_FAILED') throw error; rejected = true; }
    if (!rejected) fail('SELF_TEST_FAILED', 'Authentication self-test failed');
    checkAbort(signal);
    signing = await generateSigningKeyPair();
    const signature = await signing.signingKey.sign(message, context);
    if (!await signing.verificationKey.verify(message, signature, context) ||
        await signing.verificationKey.verify(Buffer.from('changed'), signature, context)) {
      fail('SELF_TEST_FAILED', 'Signature self-test failed');
    }
    checkAbort(signal);
    return {
      version: profile.version,
      runtime: { node: process.versions.node, openssl: process.versions.openssl,
        platform: process.platform, arch: process.arch },
      checks: ['ML-KEM-1024 + HKDF-SHA-512 + AES-256-GCM', 'ML-DSA-87', 'Argon2id vault restore'],
      filesystem: 'not checked',
      assurance: 'Functional self-test only; not an audit or security certification',
    };
  } finally {
    password.fill(0); plaintext?.fill(0); vault?.fill(0);
    kem?.privateKey.destroy(); restored?.privateKey?.destroy(); signing?.signingKey.destroy();
    sender?.destroy(); recipient?.destroy(); encryption?.destroy(); decryption?.destroy();
  }
}

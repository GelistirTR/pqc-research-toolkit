import assert from 'node:assert/strict';
import {
  encapsulate, generateKemKeyPair, publicKeyFingerprint, requirePublicKeyFingerprint,
} from '../src/index.js';

// In-process developer smoke example, not a transport format or chat protocol.
// Production must authenticate the recipient key through an independent channel.
const recipient = await generateKemKeyPair();
const trustedPin = publicKeyFingerprint(recipient.publicKey); // Trusted here only because this self-test generated the key.
const context = Buffer.from('example/app/message/v1');
const aad = Buffer.from('tenant:synthetic;purpose:demo');
const message = Buffer.from('Synthetic application message');
let exchange; let encryption; let decapsulated; let decryption; let plaintext;
try {
  requirePublicKeyFingerprint(recipient.publicKey, trustedPin);
  exchange = await encapsulate(recipient.publicKey);
  const derived = exchange.secret.deriveEncryptionKey(context);
  encryption = derived.key;
  const packet = encryption.encrypt(message, aad);

  // Receiver must use its trusted expected context/AAD, not arbitrary peer claims.
  decapsulated = await recipient.privateKey.decapsulate(exchange.ciphertext);
  decryption = decapsulated.deriveDecryptionKey(derived.salt, context);
  plaintext = decryption.decrypt(packet, aad);
  assert.deepEqual(plaintext, message);
  console.log(JSON.stringify({ roundtripVerified: true, messageBytes: message.length,
    limits: 'No sender identity, replay prevention, ratchet, forward secrecy, transport or stable message serialization' }));
} finally {
  plaintext?.fill(0); message.fill(0); encryption?.destroy(); decryption?.destroy();
  exchange?.secret.destroy(); decapsulated?.destroy(); recipient.privateKey.destroy();
}

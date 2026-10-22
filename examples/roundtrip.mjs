import assert from 'node:assert/strict';
import {
  encapsulate, generateKemKeyPair, generateSigningKeyPair, importKemPublicKey, profile,
} from '../src/index.js';

// In a real application, authenticate the recipient's public key before using it.
const recipient = await generateKemKeyPair();
const sender = await generateSigningKeyPair();
const context = Buffer.from('example/document/v1');
const aad = Buffer.from('document:42');
const message = Buffer.from('Merhaba kuantum sonrası dünya!');

const recipientPublicKey = importKemPublicKey(recipient.publicKey.exportSpki());
const exchange = await encapsulate(recipientPublicKey);
const { salt, key } = exchange.secret.deriveEncryptionKey(context);
const encrypted = key.encrypt(message, aad);
const signature = await sender.signingKey.sign(message, context);

const receivedSecret = await recipient.privateKey.decapsulate(exchange.ciphertext);
const decryptionKey = receivedSecret.deriveDecryptionKey(salt, context);
const plaintext = decryptionKey.decrypt(encrypted, aad);
assert.deepEqual(plaintext, message);
assert.equal(await sender.verificationKey.verify(plaintext, signature, context), true);

console.log('Profil:', profile.status);
console.log('ML-KEM ciphertext:', exchange.ciphertext.length, 'bayt');
console.log('ML-DSA imza:', signature.length, 'bayt');
console.log('Şifre çözüldü ve ayrı imza doğrulandı:', plaintext.toString());

plaintext.fill(0);
message.fill(0);
decryptionKey.destroy();
recipient.privateKey.destroy();
sender.signingKey.destroy();

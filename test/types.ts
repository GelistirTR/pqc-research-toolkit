import {
  generateKemKeyPair, generateSigningKeyPair, encapsulate, generateSymmetricKeyPair,
  encryptFile, decryptFile, sealPrivateKey, openPrivateKey,
  publicKeyFingerprint, requirePublicKeyFingerprint,
  inspectContainer,
  createOperationPool,
  hashPassword, verifyPassword, passwordHashNeedsRehash,
} from 'pqc-research-core';

const context = new Uint8Array([1]);
const message = new Uint8Array([2]);
const accountHash: string = await hashPassword(new Uint8Array([1, 2, 3]));
const passwordMatches: boolean = await verifyPassword(accountHash, new Uint8Array([1, 2, 3]));
passwordHashNeedsRehash(accountHash);
// @ts-expect-error Passwords must be explicit bytes; implicit text encoding is not allowed.
await hashPassword('plain text');
// @ts-expect-error PHC records are strings.
await verifyPassword(new Uint8Array(32), new Uint8Array(32));
const pool = createOperationPool({ maxConcurrent: 2, maxQueued: 4 });
const pooledNumber: number = await pool.run(async (signal) => { signal?.throwIfAborted(); return 42; });
// @ts-expect-error Pool result type follows the task's return type.
const pooledString: string = await pool.run(() => 42);
// @ts-expect-error Pool limits are numbers.
createOperationPool({ maxConcurrent: '2' });
pool.close();
const inspected = await inspectContainer('input.pqc', { signal: new AbortController().signal });
const authenticated: false = inspected.authenticated;
if (inspected.kind === 'encrypted-file') inspected.recipientFingerprint.toLowerCase();
else inspected.keyKind.toLowerCase();
// @ts-expect-error Inspection never establishes cryptographic authentication.
const verified: true = inspected.authenticated;
// @ts-expect-error Inspection accepts explicit paths, not byte arrays.
await inspectContainer(new Uint8Array(32));
const kem = await generateKemKeyPair();
const signer = await generateSigningKeyPair();
requirePublicKeyFingerprint(kem.publicKey, publicKeyFingerprint(kem.publicKey));
publicKeyFingerprint(signer.verificationKey);
// @ts-expect-error Private key handles are not accepted by public-key fingerprint helpers.
publicKeyFingerprint(kem.privateKey);
// @ts-expect-error An expected fingerprint must be supplied explicitly.
requirePublicKeyFingerprint(kem.publicKey);
const e = await encapsulate(kem.publicKey);
const derived = e.secret.deriveEncryptionKey(context);
const packet = derived.key.encrypt(message);
const recovered = await kem.privateKey.decapsulate(e.ciphertext);
recovered.deriveDecryptionKey(derived.salt, context).decrypt(packet);
const signature = await signer.signingKey.sign(message, context);
await signer.verificationKey.verify(message, signature, context);
// @ts-expect-error A verification key is not a KEM key even though both export SPKI.
await encapsulate(signer.verificationKey);
// @ts-expect-error Raw bytes cannot act as a KEM public key.
await encapsulate(new Uint8Array(1568));
// @ts-expect-error Context must be supplied explicitly.
await signer.signingKey.sign(message);
const symmetric = generateSymmetricKeyPair();
// @ts-expect-error A decrypt-only key cannot encrypt.
symmetric.decryptionKey.encrypt(message);

const vault = await sealPrivateKey(kem.privateKey, new Uint8Array(32));
await sealPrivateKey(kem.privateKey, new Uint8Array(32), { signal: new AbortController().signal });
// @ts-expect-error Vault cancellation requires a real AbortSignal type.
await openPrivateKey(vault, new Uint8Array(32), { signal: {} });
const restored = await openPrivateKey(vault, new Uint8Array(32));
await openPrivateKey(vault, new Uint8Array(32), { legacyKeyPolicy: 'reject-combined' });
// @ts-expect-error Only named legacy policies are accepted.
await openPrivateKey(vault, new Uint8Array(32), { legacyKeyPolicy: 'ignore-everything' });
if (restored.kind === 'kem') {
  restored.privateKey.publicKey();
  await decryptFile({ inputPath: 'input.pqc', outputPath: 'restored.bin',
    privateKey: restored.privateKey, context, signal: new AbortController().signal });
} else {
  restored.signingKey.verificationKey();
}
await encryptFile({ inputPath: 'input.bin', outputPath: 'output.pqc', recipient: kem.publicKey, context });
// @ts-expect-error Public keys cannot be sealed as private keys.
await sealPrivateKey(kem.publicKey, new Uint8Array(32));
// @ts-expect-error A signing key cannot decrypt files.
await decryptFile({ inputPath: 'a', outputPath: 'b', privateKey: signer.signingKey, context });

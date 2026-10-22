import {
  createCipheriv, createDecipheriv, createSecretKey, randomBytes,
} from 'node:crypto';
import { KemPrivateKey, SigningKey } from './asymmetric.js';
import { bytes, TOKEN } from './internal.js';
import { CryptoError, fail } from './errors.js';
import { exportVaultPkcs8, importVaultPkcs8 } from './vault-pkcs8.js';
import { argon2Budget, checkKdfSignal, deriveArgon2 } from './argon2-budget.js';

const MAGIC = Buffer.from('PQCVAULT');
const HEADER_BYTES = 56;
const MAX_DER_BYTES = 16 * 1024;
const MIN_PASSPHRASE_BYTES = 16;
const MAX_PASSPHRASE_BYTES = 1024;

export const vaultProfile = Object.freeze({
  version: 1, kdf: 'Argon2id', memoryKiB: 65536, passes: 3, parallelism: 4,
  saltBytes: 16, minPassphraseBytes: MIN_PASSPHRASE_BYTES,
  maxPassphraseBytes: MAX_PASSPHRASE_BYTES, maxVaultBytes: HEADER_BYTES + MAX_DER_BYTES + 16,
  maxConcurrentKdf: argon2Budget.maxConcurrent, maxQueuedKdf: argon2Budget.maxQueued,
});

function checkSignal(signal) {
  try { checkKdfSignal(signal); }
  catch (error) {
    if (error.code === 'ABORTED') throw new CryptoError('ABORTED', 'Key vault operation aborted');
    throw error;
  }
}
function vaultSignal(options) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) fail('INVALID_INPUT', 'Expected vault options');
  const signal = options.signal;
  checkSignal(signal);
  return signal;
}

function passwordBytes(passphrase) {
  const password = bytes(passphrase, 'passphrase', MAX_PASSPHRASE_BYTES);
  if (password.length < MIN_PASSPHRASE_BYTES) {
    password.fill(0);
    fail('INVALID_INPUT', 'Passphrase must contain at least 16 bytes');
  }
  return password;
}

async function wrappingKey(password, salt, signal) {
  let material;
  try {
    material = await deriveArgon2({
      message: password, nonce: salt, memory: 65536, passes: 3, parallelism: 4, tagLength: 32,
      associatedData: Buffer.from('pqc-research-core/vault/v1\0'),
    }, signal);
    checkSignal(signal);
    return createSecretKey(material);
  } catch (error) { checkSignal(signal); throw error; }
  finally { material?.fill(0); }
}

// Only the published fixed profile is accepted; attacker-controlled work factors never reach Argon2.
function header(kind, length) {
  const data = Buffer.alloc(HEADER_BYTES);
  MAGIC.copy(data);
  data[8] = 1; data[9] = kind; data[10] = 1; data[11] = 1;
  data.writeUInt32BE(65536, 12); data.writeUInt32BE(3, 16); data.writeUInt32BE(4, 20);
  randomBytes(16).copy(data, 24);
  randomBytes(12).copy(data, 40);
  data.writeUInt32BE(length, 52);
  return data;
}

export function parseVaultHeader(data, totalBytes = data.length) {
  if (data.length < HEADER_BYTES || totalBytes < HEADER_BYTES + 16 || !data.subarray(0, 8).equals(MAGIC) ||
      data[8] !== 1 || ![1, 2].includes(data[9]) || data[10] !== 1 || data[11] !== 1 ||
      data.readUInt32BE(12) !== 65536 || data.readUInt32BE(16) !== 3 || data.readUInt32BE(20) !== 4) {
    fail('INVALID_VAULT', 'Unsupported or malformed key vault');
  }
  const length = data.readUInt32BE(52);
  if (length < 1 || length > MAX_DER_BYTES || totalBytes !== HEADER_BYTES + length + 16) {
    fail('INVALID_VAULT', 'Invalid key vault length');
  }
  return { kind: data[9] === 1 ? 'kem' : 'signature' };
}

export async function sealPrivateKey(key, passphrase, options = {}) {
  const signal = vaultSignal(options);
  let kind;
  if (key instanceof KemPrivateKey) kind = 1;
  else if (key instanceof SigningKey) kind = 2;
  else fail('INVALID_KEY', 'Expected a KEM private key or signing key');
  const nativeKey = key.native(TOKEN);
  const password = passwordBytes(passphrase);
  let der;
  try {
    der = exportVaultPkcs8(nativeKey, kind);
    if (der.length > MAX_DER_BYTES) fail('INVALID_KEY', 'Unsupported private key encoding');
    const prefix = header(kind, der.length);
    const keyEncryptionKey = await wrappingKey(password, prefix.subarray(24, 40), signal);
    checkSignal(signal);
    const cipher = createCipheriv('aes-256-gcm', keyEncryptionKey, prefix.subarray(40, 52), { authTagLength: 16 });
    cipher.setAAD(prefix);
    const encrypted = Buffer.concat([cipher.update(der), cipher.final()]);
    return Buffer.concat([prefix, encrypted, cipher.getAuthTag()]);
  } finally { password.fill(0); der?.fill(0); }
}

export async function openPrivateKey(vault, passphrase, options = {}) {
  const signal = vaultSignal(options);
  const legacyKeyPolicy = options.legacyKeyPolicy === undefined ? 'reject-combined' : options.legacyKeyPolicy;
  if (!['reject-combined', 'seed-authoritative'].includes(legacyKeyPolicy)) fail('INVALID_INPUT', 'Invalid legacy key policy');
  const data = bytes(vault, 'vault', vaultProfile.maxVaultBytes);
  parseVaultHeader(data);
  const password = passwordBytes(passphrase);
  let pending;
  let der;
  try {
    const keyEncryptionKey = await wrappingKey(password, data.subarray(24, 40), signal);
    checkSignal(signal);
    try {
      const decipher = createDecipheriv('aes-256-gcm', keyEncryptionKey, data.subarray(40, 52), { authTagLength: 16 });
      decipher.setAAD(data.subarray(0, HEADER_BYTES));
      decipher.setAuthTag(data.subarray(-16));
      pending = decipher.update(data.subarray(HEADER_BYTES, -16));
      der = Buffer.concat([pending, decipher.final()]);
    } catch { fail('AUTHENTICATION_FAILED', 'Authentication failed'); }
    const nativeKey = importVaultPkcs8(der, data[9], legacyKeyPolicy);
    if (data[9] === 1 && nativeKey.asymmetricKeyType === 'ml-kem-1024') {
      const privateKey = new KemPrivateKey(TOKEN, nativeKey);
      return { kind: 'kem', privateKey, publicKey: privateKey.publicKey() };
    }
    if (data[9] === 2 && nativeKey.asymmetricKeyType === 'ml-dsa-87') {
      const signingKey = new SigningKey(TOKEN, nativeKey);
      return { kind: 'signature', signingKey, verificationKey: signingKey.verificationKey() };
    }
    fail('INVALID_VAULT', 'Private key type does not match vault type');
  } finally { password.fill(0); pending?.fill(0); der?.fill(0); }
}

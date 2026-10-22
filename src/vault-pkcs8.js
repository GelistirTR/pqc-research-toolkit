import { createPrivateKey } from 'node:crypto';
import { fail } from './errors.js';

const algorithms = {
  1: { name: 'ml-kem-1024', oid: Buffer.from('608648016503040403', 'hex'), seedBytes: 64, expandedBytes: 3168 },
  2: { name: 'ml-dsa-87', oid: Buffer.from('608648016503040313', 'hex'), seedBytes: 32, expandedBytes: 4896 },
};
function invalid() { fail('INVALID_VAULT', 'Unsupported or malformed private key content'); }

export function exportVaultPkcs8(key, kind) {
  const algorithm = algorithms[kind];
  if (!algorithm || key.asymmetricKeyType !== algorithm.name) fail('INVALID_KEY', 'Unsupported private key');
  let seed;
  try {
    try { seed = key.export({ format: 'raw-seed' }); }
    catch {
      // Expanded-only legacy keys have no recoverable seed. Preserve them as
      // PKCS#8 after the same strict schema/native import validation.
      let der;
      try {
        der = key.export({ format: 'der', type: 'pkcs8' });
        importVaultPkcs8(der, kind);
        return der;
      } catch {
        der?.fill(0);
        fail('INVALID_KEY', 'Private key is unavailable for vault export');
      }
    }
    if (seed.length !== algorithm.seedBytes) fail('INVALID_KEY', 'Unsupported private key seed');
    // All lengths are below 128 in the seed-only representation. Use a stable
    // version-0 PKCS#8 encoding instead of provider-selected output formats.
    return Buffer.concat([Buffer.from([0x30, seed.length + 20, 2, 1, 0, 0x30, 11, 6, 9]),
      algorithm.oid, Buffer.from([4, seed.length + 2, 0x80, seed.length]), seed]);
  } finally { seed?.fill(0); }
}

// A bounded, schema-specific DER reader, not a general ASN.1 decoder. Vault v1
// accepts version-0 PKCS#8 with an absent AlgorithmIdentifier parameter and one
// seed-only, expanded-only or legacy seed+expanded CHOICE. No trailing data or attributes.
function element(data, offset, limit, tag) {
  if (offset + 2 > limit || data[offset++] !== tag) invalid();
  let length = data[offset++];
  if (length >= 128) {
    const count = length & 127;
    if (count === 0 || count > 2 || offset + count > limit || data[offset] === 0) invalid();
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + data[offset++];
    if (length < 128) invalid();
  }
  const end = offset + length;
  if (end > limit) invalid();
  return { start: offset, end, value: data.subarray(offset, end) };
}

export function importVaultPkcs8(data, kind, legacyKeyPolicy = 'reject-combined') {
  const algorithm = algorithms[kind];
  if (!algorithm) invalid();
  const outer = element(data, 0, data.length, 0x30);
  if (outer.end !== data.length) invalid();
  const version = element(data, outer.start, outer.end, 0x02);
  if (version.value.length !== 1 || version.value[0] !== 0) invalid();
  const identifier = element(data, version.end, outer.end, 0x30);
  const oid = element(data, identifier.start, identifier.end, 0x06);
  if (oid.end !== identifier.end || !oid.value.equals(algorithm.oid)) invalid();
  const privateKey = element(data, identifier.end, outer.end, 0x04);
  if (privateKey.end !== outer.end) invalid();
  if (data[privateKey.start] === 0x04) {
    const expanded = element(data, privateKey.start, privateKey.end, 0x04);
    if (expanded.end !== privateKey.end || expanded.value.length !== algorithm.expandedBytes) invalid();
    // No seed exists in this representation; native provider import performs
    // the algorithm's supported expanded-key validation.
    try { return createPrivateKey({ key: data, format: 'der', type: 'pkcs8' }); }
    catch { invalid(); }
  }
  let seed;
  if (data[privateKey.start] === 0x80) {
    seed = element(data, privateKey.start, privateKey.end, 0x80);
    if (seed.end !== privateKey.end) invalid();
  } else {
    const both = element(data, privateKey.start, privateKey.end, 0x30);
    if (both.end !== privateKey.end) invalid();
    seed = element(data, both.start, both.end, 0x04);
    const expanded = element(data, seed.end, both.end, 0x04);
    if (expanded.end !== both.end || expanded.value.length !== algorithm.expandedBytes || seed.value.length !== algorithm.seedBytes) invalid();
    // The supported Node API cannot expose the regenerated expanded key for
    // full bytewise consistency testing. Do not silently ignore a companion.
    if (legacyKeyPolicy !== 'seed-authoritative') {
      fail('LEGACY_KEY_REQUIRES_MIGRATION', 'Combined legacy private key requires explicit seed-authoritative migration');
    }
    // Explicit migration only: no seed/expanded consistency assurance. Import
    // the seed to avoid provider-dependent preference for the sibling.
  }
  if (seed.value.length !== algorithm.seedBytes) invalid();
  try { return createPrivateKey({ key: seed.value, format: 'raw-seed', asymmetricKeyType: algorithm.name }); }
  catch { invalid(); }
}

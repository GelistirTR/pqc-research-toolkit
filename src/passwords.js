import { randomBytes, timingSafeEqual } from 'node:crypto';
import { argon2Budget, checkKdfSignal, deriveArgon2 } from './argon2-budget.js';
import { bytes } from './internal.js';
import { fail } from './errors.js';

const current = Object.freeze({ memoryKiB: 65536, passes: 3, parallelism: 4 });
const legacy = Object.freeze({ memoryKiB: 19456, passes: 2, parallelism: 1 });
const prefix = (profile) => `$argon2id$v=19$m=${profile.memoryKiB},t=${profile.passes},p=${profile.parallelism}$`;
const encode = (data) => data.toString('base64').replace(/=+$/, '');
export const passwordHashProfile = Object.freeze({
  algorithm: 'Argon2id', version: 19, ...current, saltBytes: 16, hashBytes: 32,
  minPasswordBytes: 1, maxPasswordBytes: 1024,
  maxConcurrentKdf: argon2Budget.maxConcurrent, maxQueuedKdf: argon2Budget.maxQueued,
  acceptedVerificationProfiles: Object.freeze([current, legacy]),
});
function invalid() { fail('INVALID_PASSWORD_HASH', 'Unsupported or malformed password hash'); }
function parse(record) {
  if (typeof record !== 'string') invalid();
  // Exact length excludes final newlines before regex/base64 processing.
  const profile = [current, legacy].find(value => record.length === prefix(value).length + 66 && record.startsWith(prefix(value)));
  if (!profile) invalid();
  const fields = record.slice(prefix(profile).length).split('$');
  if (fields.length !== 2 || fields[0].length !== 22 || fields[1].length !== 43 ||
      fields.some(value => !/^[A-Za-z0-9+/]+$/.test(value))) invalid();
  const salt = Buffer.from(fields[0], 'base64');
  const expected = Buffer.from(fields[1], 'base64');
  if (salt.length !== 16 || expected.length !== 32 || encode(salt) !== fields[0] || encode(expected) !== fields[1]) invalid();
  return { profile, salt, expected };
}
function optionsSignal(options) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) fail('INVALID_INPUT', 'Expected password hash options');
  const signal = options.signal;
  checkKdfSignal(signal);
  return signal;
}
function copyPassword(input) {
  const password = bytes(input, 'password', passwordHashProfile.maxPasswordBytes);
  if (password.length === 0) { password.fill(0); fail('INVALID_INPUT', 'Password must not be empty'); }
  return password;
}
async function derive(password, salt, profile, signal) {
  // No vault associatedData/pepper: standard unkeyed Argon2id PHC interoperability.
  return deriveArgon2({ message: password, nonce: salt, memory: profile.memoryKiB,
    passes: profile.passes, parallelism: profile.parallelism, tagLength: 32 }, signal);
}
export async function hashPassword(input, options = {}) {
  const signal = optionsSignal(options);
  const password = copyPassword(input);
  let material;
  try {
    const salt = randomBytes(16);
    material = await derive(password, salt, current, signal);
    checkKdfSignal(signal);
    return `${prefix(current)}${encode(salt)}$${encode(material)}`;
  } finally { password.fill(0); material?.fill(0); }
}
export async function verifyPassword(record, input, options = {}) {
  const signal = optionsSignal(options);
  const { profile, salt, expected } = parse(record);
  let password;
  let material;
  try {
    password = copyPassword(input);
    material = await derive(password, salt, profile, signal);
    checkKdfSignal(signal);
    return timingSafeEqual(material, expected);
  } finally { password?.fill(0); material?.fill(0); expected.fill(0); }
}
export function passwordHashNeedsRehash(record) {
  const { profile, expected } = parse(record);
  try { return profile !== current; }
  finally { expected.fill(0); }
}

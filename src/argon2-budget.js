import { argon2 } from 'node:crypto';
import { addAbortListener } from 'node:events';
import { promisify } from 'node:util';
import { CryptoError, fail } from './errors.js';

const nativeArgon2 = promisify(argon2);
export const argon2Budget = Object.freeze({ maxConcurrent: 2, maxQueued: 16 });
let active = 0;
const queue = [];
const aborted = () => new CryptoError('ABORTED', 'Key derivation aborted');
export function checkKdfSignal(signal) {
  if (signal !== undefined && !(signal instanceof AbortSignal)) fail('INVALID_INPUT', 'Invalid AbortSignal');
  if (signal?.aborted) throw aborted();
}
function release() {
  const next = queue.shift();
  if (next) { next.subscription?.[Symbol.dispose](); next.resolve(release); }
  else active--;
}
function acquire(signal) {
  checkKdfSignal(signal);
  if (active < argon2Budget.maxConcurrent) { active++; return Promise.resolve(release); }
  if (queue.length >= argon2Budget.maxQueued) fail('RESOURCE_LIMIT', 'Password derivation queue is full');
  return new Promise((resolve, reject) => {
    const entry = { resolve, subscription: undefined };
    if (signal) entry.subscription = addAbortListener(signal, () => {
      const index = queue.indexOf(entry);
      if (index < 0) return;
      queue.splice(index, 1); entry.subscription[Symbol.dispose](); reject(aborted());
    });
    queue.push(entry);
  });
}

// Vaults and account-password hashes share one module-instance native-work budget.
// A successful caller owns the returned material and must wipe it after use.
export async function deriveArgon2(parameters, signal) {
  const done = await acquire(signal);
  let material;
  try {
    checkKdfSignal(signal);
    material = await nativeArgon2('argon2id', parameters);
    checkKdfSignal(signal);
    if (!Buffer.isBuffer(material) || material.length !== 32) fail('CRYPTO_OPERATION_FAILED', 'Invalid password derivation output');
    const result = material; material = undefined;
    return result;
  } catch (error) { checkKdfSignal(signal); throw error; }
  finally { if (Buffer.isBuffer(material)) material.fill(0); done(); }
}

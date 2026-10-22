import { inspect } from 'node:util';
import { fail } from './errors.js';

export const TOKEN = Symbol('internal-constructor');
export const MAX_MESSAGE_BYTES = 16 * 1024 * 1024;
// Node's HKDF info has a 1024-byte limit, including our fixed label/framing.
export const MAX_CONTEXT_BYTES = 512;
export const MAX_AAD_BYTES = 64 * 1024;

// Reject shared backing memory: another worker could change data during validation.
export function bytes(value, name, max, exact) {
  if (!(value instanceof Uint8Array) || value.buffer instanceof SharedArrayBuffer) {
    fail('INVALID_INPUT', `${name} must be a non-shared Uint8Array`);
  }
  if (value.byteLength > max || (exact !== undefined && value.byteLength !== exact)) {
    fail('INVALID_INPUT', `${name} has an invalid length`);
  }
  return Buffer.from(value);
}

export function contextBytes(context) {
  return bytes(context, 'context', MAX_CONTEXT_BYTES);
}

export class Opaque {
  constructor(token) {
    if (token !== TOKEN) fail('INVALID_KEY', 'Use a key generation or import function');
  }
  toJSON() { return '[Opaque cryptographic handle]'; }
  [inspect.custom]() { return '[Opaque cryptographic handle]'; }
}

export function frame(label, context) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(context.length);
  return Buffer.concat([Buffer.from(label, 'ascii'), length, context]);
}

export function live(key) {
  if (!key) fail('KEY_UNAVAILABLE', 'Key is destroyed or already consumed');
  return key;
}

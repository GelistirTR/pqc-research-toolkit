import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import test from 'node:test';
import { argon2id } from '@noble/hashes/argon2.js';

const original = crypto.argon2;
let calls = 0;
crypto.argon2 = (...args) => { calls++; return original(...args); };
syncBuiltinESMExports();
const { hashPassword, verifyPassword, passwordHashNeedsRehash, passwordHashProfile } = await import('../src/index.js');
test.after(() => { crypto.argon2 = original; syncBuiltinESMExports(); });
const password = Buffer.from('synthetic account password');
const code = expected => error => error.code === expected;
const b64 = value => Buffer.from(value).toString('base64').replace(/=+$/, '');

test('password hash uses fresh salt and verifies against independent Noble Argon2id', async () => {
  const record = await hashPassword(password);
  const second = await hashPassword(password);
  assert.notEqual(record, second);
  assert.equal(record.length, 97);
  assert.ok(record.startsWith('$argon2id$v=19$m=65536,t=3,p=4$'));
  const fields = record.split('$');
  const expected = argon2id(password, Buffer.from(fields[4], 'base64'), { m: 65536, t: 3, p: 4, dkLen: 32 });
  try { assert.equal(b64(expected), fields[5]); }
  finally { expected.fill(0); }
  assert.equal(await verifyPassword(record, password), true);
  assert.equal(await verifyPassword(record, Buffer.from('wrong password')), false);
  assert.equal(passwordHashNeedsRehash(record), false);
  assert.ok(Object.isFrozen(passwordHashProfile));
  assert.ok(Object.isFrozen(passwordHashProfile.acceptedVerificationProfiles));
});

test('bounded legacy 19 MiB record interoperates and requests upgrade', async () => {
  const salt = Buffer.alloc(16, 0x23);
  const digest = argon2id(password, salt, { m: 19456, t: 2, p: 1, dkLen: 32 });
  try {
    const record = `$argon2id$v=19$m=19456,t=2,p=1$${b64(salt)}$${b64(digest)}`;
    assert.equal(passwordHashNeedsRehash(record), true);
    assert.equal(await verifyPassword(record, password), true);
    assert.equal(await verifyPassword(record, Buffer.from('other')), false);
  } finally { digest.fill(0); }
});

test('PHC parser rejects malformed and unbounded profiles before any native work', async () => {
  const record = await hashPassword(password);
  const before = calls;
  const fields = record.split('$');
  const salt = fields[4]; const digest = fields[5];
  const noncanonicalSalt = salt.slice(0, -1) + 'B'; // Last base64 quantum must have zero padding bits.
  const malformed = [undefined, null, {}, Buffer.from(record), '', record + '\n', record + '\r\n', record + '\u2028',
    ' ' + record, record + ' ', record.slice(0, -1), record + '$', record.replace('argon2id', 'argon2i'),
    record.replace('v=19', 'v=16'), record.replace('m=65536', 'm=999999999'), record.replace('m=65536', 'm=065536'),
    record.replace('t=3', 't=999'), record.replace('p=4', 'p=0'), record.replace('m=65536,t=3,p=4', 'p=4,t=3,m=65536'),
    record.replace(salt, salt + '=='), record.replace(digest, digest + '='),
    `$argon2id$v=19$m=65536,t=3,p=4$${noncanonicalSalt}$${digest}`,
    `$argon2id$v=19$m=65536,t=3,p=4$${salt}$${digest.slice(0, -1)}B`,
    `$argon2id$v=19$m=65536,t=3,p=4$${'-'.repeat(22)}$${digest}`, 'x'.repeat(100000)];
  for (const value of malformed) {
    await assert.rejects(verifyPassword(value, password), code('INVALID_PASSWORD_HASH'));
    assert.throws(() => passwordHashNeedsRehash(value), code('INVALID_PASSWORD_HASH'));
  }
  assert.equal(calls, before);
});

test('password bytes are preserved exactly, snapshots are independent and input bounds reject before KDF', async () => {
  const raw = Buffer.from('  şaşırtıcı parola \r\n');
  const expected = Buffer.from(raw);
  const pending = hashPassword(raw); raw.fill(0);
  const record = await pending;
  assert.equal(await verifyPassword(record, expected), true);
  assert.equal(await verifyPassword(record, Buffer.from(expected.toString().trim())), false);
  const before = calls;
  for (const value of [undefined, null, 'password', [], Buffer.alloc(0), Buffer.alloc(1025), new Uint8Array(new SharedArrayBuffer(32))]) {
    await assert.rejects(hashPassword(value), code('INVALID_INPUT'));
    await assert.rejects(verifyPassword(record, value), code('INVALID_INPUT'));
  }
  assert.equal(calls, before);
  for (const value of [Buffer.from('a'), Buffer.alloc(1024, 0x78)]) {
    const hash = await hashPassword(value);
    assert.equal(await verifyPassword(hash, value), true);
  }
});

test('password APIs reject invalid options and pre-aborted work before calling Argon2', async () => {
  const record = await hashPassword(password);
  const before = calls;
  for (const options of [null, [], 1, { signal: {} }]) {
    await assert.rejects(hashPassword(password, options), code('INVALID_INPUT'));
    await assert.rejects(verifyPassword(record, password, options), code('INVALID_INPUT'));
  }
  const signal = AbortSignal.abort('private reason');
  await assert.rejects(hashPassword(password, { signal }), code('ABORTED'));
  await assert.rejects(verifyPassword(record, password, { signal }), code('ABORTED'));
  assert.equal(calls, before);
});

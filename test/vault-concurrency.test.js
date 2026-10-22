import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { getEventListeners } from 'node:events';
import { syncBuiltinESMExports } from 'node:module';
import { setImmediate as nextTurn } from 'node:timers/promises';
import test from 'node:test';

// node:test isolates this file in its own process. Interpose before loading the
// library, allowing deterministic completion order without timing assumptions.
const originalArgon2 = crypto.argon2;
let mode = 'hold';
let active = 0;
let peak = 0;
const calls = [];
crypto.argon2 = (algorithm, parameters, callback) => {
  active++;
  peak = Math.max(peak, active);
  const entry = { parameters, finish(error, material = Buffer.alloc(32, 7)) {
    active--;
    entry.material = material;
    callback(error, error ? undefined : material);
  } };
  calls.push(entry);
  if (mode === 'throw') { active--; throw new Error('synthetic synchronous provider failure'); }
  if (mode === 'error') { queueMicrotask(() => entry.finish(new Error('synthetic callback failure'))); }
  if (mode === 'native') {
    originalArgon2(algorithm, parameters, (error, material) => entry.finish(error, material));
  }
};
syncBuiltinESMExports();
const { generateKemKeyPair, openPrivateKey, sealPrivateKey, vaultProfile,
  hashPassword, verifyPassword } = await import('../src/index.js');
const { privateKey, publicKey } = await generateKemKeyPair();
const password = (n) => Buffer.from(`synthetic-password-${String(n).padStart(4, '0')}`);
const outcome = (promise) => promise.then((value) => ({ value }), (error) => ({ error }));
const hasCode = (code) => (error) => error.code === code;

test('vault and account-password operations share one native admission budget', async () => {
  reset();
  const vaults = Array.from({ length: 2 }, (_, n) => outcome(sealPrivateKey(privateKey, password(n))));
  const hashes = Array.from({ length: 16 }, (_, n) => outcome(hashPassword(password(n + 2))));
  await nextTurn();
  assert.equal(calls.length, 2); assert.equal(active, 2);
  await assert.rejects(hashPassword(password(20)), hasCode('RESOURCE_LIMIT'));
  await assert.rejects(sealPrivateKey(privateKey, password(21)), hasCode('RESOURCE_LIMIT'));
  for (let n = 0; n < 18; n++) { calls[n].finish(); await nextTurn(); assert.ok(active <= 2); }
  for (const vault of vaults) assert.ok((await vault).value);
  for (const hash of hashes) assert.match((await hash).value, /^\$argon2id\$v=19\$/);
  assert.equal(peak, 2);
  assert.ok(calls[0].parameters.associatedData.length > 0);
  assert.equal(calls[2].parameters.associatedData, undefined, 'Account hashes must not use vault domain data');
  for (const call of calls) {
    assert.ok(call.parameters.message.every(byte => byte === 0));
    assert.ok(call.material.every(byte => byte === 0));
  }
});

test('account-password queued and active aborts keep reservation and wipe owned buffers', async () => {
  reset();
  const firstController = new AbortController();
  const queuedController = new AbortController();
  const raw = password(1); const expected = Buffer.from(raw);
  const first = outcome(hashPassword(raw, { signal: firstController.signal })); raw.fill(0);
  const second = outcome(hashPassword(password(2)));
  const record = '$argon2id$v=19$m=65536,t=3,p=4$' + Buffer.alloc(16).toString('base64').replace(/=+$/, '') +
    '$' + Buffer.alloc(32, 7).toString('base64').replace(/=+$/, '');
  const queued = outcome(verifyPassword(record, password(3), { signal: queuedController.signal }));
  await nextTurn();
  assert.deepEqual(calls[0].parameters.message, expected);
  queuedController.abort('private reason');
  assert.equal((await queued).error.code, 'ABORTED');
  firstController.abort('private reason');
  await nextTurn(); assert.equal(active, 2); assert.equal(calls.length, 2);
  calls[0].finish(); calls[1].finish();
  assert.equal((await first).error.code, 'ABORTED'); assert.ok((await second).value);
  for (const call of calls) {
    assert.ok(call.parameters.message.every(byte => byte === 0));
    assert.ok(call.material.every(byte => byte === 0));
  }
  assert.equal(getEventListeners(queuedController.signal, 'abort').length, 0);
});

test('invalid native password material fails closed, wipes it and returns the slot', async () => {
  reset();
  const bad = outcome(hashPassword(password(1)));
  await nextTurn(); calls[0].finish(undefined, Buffer.alloc(31, 0x7f));
  assert.equal((await bad).error.code, 'CRYPTO_OPERATION_FAILED');
  assert.ok(calls[0].material.every(byte => byte === 0));
  reset('native');
  const record = await hashPassword(password(1));
  assert.equal(await verifyPassword(record, password(1)), true);
});

function reset(nextMode = 'hold') {
  assert.equal(active, 0);
  calls.length = 0;
  peak = 0;
  mode = nextMode;
}

test.after(() => {
  privateKey.destroy();
  crypto.argon2 = originalArgon2;
  syncBuiltinESMExports();
});

test('vault admission caps native work and FIFO queue; overflow never reaches the provider', async () => {
  reset();
  assert.equal(vaultProfile.maxConcurrentKdf, 2);
  assert.equal(vaultProfile.maxQueuedKdf, 16);
  assert.ok(Object.isFrozen(vaultProfile));
  const jobs = Array.from({ length: 18 }, (_, n) => outcome(sealPrivateKey(privateKey, password(n))));
  await nextTurn();
  assert.equal(calls.length, 2);
  assert.equal(active, 2);
  await assert.rejects(sealPrivateKey(privateKey, password(18)), hasCode('RESOURCE_LIMIT'));
  await assert.rejects(sealPrivateKey(privateKey, password(19)), hasCode('RESOURCE_LIMIT'));
  // Admission control must not obscure structural/input validation errors.
  await assert.rejects(openPrivateKey(Buffer.alloc(72), password(0)), hasCode('INVALID_VAULT'));
  await assert.rejects(sealPrivateKey(privateKey, Buffer.alloc(15)), hasCode('INVALID_INPUT'));
  assert.equal(calls.length, 2);
  for (let n = 0; n < 18; n++) {
    assert.equal(calls[n].parameters.message.toString(), password(n).toString());
    calls[n].finish();
    await nextTurn();
    assert.ok(active <= 2);
  }
  for (const job of jobs) assert.ok((await job).value);
  assert.equal(peak, 2);
  assert.equal(calls.length, 18);
  assert.equal(active, 0);
  for (const call of calls) {
    assert.ok(call.parameters.message.every((byte) => byte === 0), 'owned password copy wiped');
    assert.ok(call.material.every((byte) => byte === 0), 'derived material wiped');
  }
});

test('seal and open share admission; queued inputs are snapshots and caller buffers are untouched', async () => {
  reset();
  const seed = sealPrivateKey(privateKey, password(0));
  await nextTurn(); calls[0].finish();
  const vault = await seed;
  reset();
  const jobs = [outcome(sealPrivateKey(privateKey, password(1))), outcome(openPrivateKey(vault, password(0)))];
  const sourceVault = Buffer.from(vault);
  const sourcePassword = password(0);
  const queued = outcome(openPrivateKey(sourceVault, sourcePassword));
  sourceVault.fill(0); sourcePassword.fill(0);
  await nextTurn();
  assert.equal(calls.length, 2);
  calls[0].finish();
  await nextTurn();
  assert.equal(calls.length, 3);
  assert.equal(calls[2].parameters.message.toString(), password(0).toString());
  calls[1].finish(); calls[2].finish();
  for (const result of await Promise.all([...jobs, queued])) {
    assert.ifError(result.error);
    if (result.value.kind === 'kem') {
      assert.deepEqual(result.value.publicKey.exportSpki(), publicKey.exportSpki());
      result.value.privateKey.destroy();
    }
  }
  assert.ok(vault.some((byte) => byte !== 0), 'caller vault was not wiped');
  assert.equal(peak, 2);
});

test('provider callback and synchronous failures release every reservation and wipe passwords', async () => {
  for (const nextMode of ['error', 'throw']) {
    reset(nextMode);
    const results = await Promise.all(Array.from({ length: 18 }, (_, n) => outcome(sealPrivateKey(privateKey, password(n)))));
    assert.equal(results.length, 18);
    assert.ok(results.every(({ error }) => error instanceof Error));
    assert.equal(calls.length, 18);
    assert.equal(active, 0);
    assert.ok(peak <= 2);
    assert.ok(calls.every(({ parameters }) => parameters.message.every((byte) => byte === 0)));
  }
  reset();
  const resumed = sealPrivateKey(privateKey, password(0));
  await nextTurn(); calls[0].finish();
  assert.ok(await resumed);
});

test('real native Argon2 concurrent vault operations restore the same key under the cap', async () => {
  reset('native');
  const passwords = Array.from({ length: 4 }, (_, n) => password(n));
  const vaults = await Promise.all(passwords.map((value) => sealPrivateKey(privateKey, value)));
  const restored = await Promise.all(vaults.map((vault, n) => openPrivateKey(vault, passwords[n])));
  for (const result of restored) {
    assert.deepEqual(result.publicKey.exportSpki(), publicKey.exportSpki());
    result.privateKey.destroy();
  }
  assert.equal(calls.length, 8);
  assert.equal(peak, 2);
  assert.equal(active, 0);
  assert.ok(passwords.every((value, n) => value.equals(password(n))));
});

test('pre-aborted and invalid vault signals never reserve native work or leak abort reasons', async () => {
  reset();
  const signal = AbortSignal.abort(new Error('PRIVATE_ABORT_REASON'));
  await assert.rejects(sealPrivateKey(privateKey, password(0), { signal }), (error) =>
    error.code === 'ABORTED' && !error.message.includes('PRIVATE_ABORT_REASON'));
  await assert.rejects(openPrivateKey(Buffer.alloc(72), password(0), { signal }), hasCode('ABORTED'));
  for (const options of [null, [], 'bad', { signal: {} }, { signal: null }]) {
    await assert.rejects(sealPrivateKey(privateKey, password(0), options), hasCode('INVALID_INPUT'));
  }
  assert.equal(calls.length, 0);
});

test('queued cancellation frees admission immediately and preserves the FIFO order of survivors', async () => {
  reset();
  const controllers = Array.from({ length: 18 }, () => new AbortController());
  const jobs = controllers.map(({ signal }, n) => outcome(sealPrivateKey(privateKey, password(n), { signal })));
  await nextTurn();
  assert.equal(calls.length, 2);
  assert.equal(getEventListeners(controllers[2].signal, 'abort').length, 1);
  controllers[2].abort('PRIVATE_ABORT_REASON');
  assert.equal((await jobs[2]).error.code, 'ABORTED');
  assert.equal(getEventListeners(controllers[2].signal, 'abort').length, 0);
  jobs.push(outcome(sealPrivateKey(privateKey, password(18))));
  const order = [0, 1, ...Array.from({ length: 15 }, (_, n) => n + 3), 18];
  for (let n = 0; n < order.length; n++) {
    assert.equal(calls[n].parameters.message.toString(), password(order[n]).toString());
    calls[n].finish();
    await nextTurn();
  }
  const results = await Promise.all(jobs);
  assert.equal(results.filter(({ error }) => error).length, 1);
  assert.equal(peak, 2);
  assert.equal(calls.length, 18);
  for (const { signal } of controllers) assert.equal(getEventListeners(signal, 'abort').length, 0);
});

test('active cancellation holds its reservation until native completion and discards derived output', async () => {
  reset();
  const controller = new AbortController();
  let settled = false;
  const cancelled = outcome(sealPrivateKey(privateKey, password(0), { signal: controller.signal }));
  cancelled.then(() => { settled = true; });
  const second = outcome(sealPrivateKey(privateKey, password(1)));
  const queued = outcome(sealPrivateKey(privateKey, password(2)));
  await nextTurn();
  controller.abort();
  await nextTurn();
  assert.equal(settled, false);
  assert.equal(calls.length, 2);
  assert.equal(active, 2);
  assert.ok(calls[0].parameters.message.some((byte) => byte !== 0), 'native input remains valid until callback');
  calls[0].finish();
  assert.equal((await cancelled).error.code, 'ABORTED');
  assert.ok(calls[0].parameters.message.every((byte) => byte === 0));
  assert.ok(calls[0].material.every((byte) => byte === 0));
  await nextTurn();
  assert.equal(calls.length, 3);
  assert.equal(active, 2);
  calls[1].finish(); calls[2].finish();
  assert.ok((await second).value); assert.ok((await queued).value);
  assert.equal(peak, 2);
});

test('cancellation between handoff and native dispatch returns the reservation without starting work', async () => {
  reset();
  const first = outcome(sealPrivateKey(privateKey, password(0)));
  const second = outcome(sealPrivateKey(privateKey, password(1)));
  const controller = new AbortController();
  const queued = outcome(sealPrivateKey(privateKey, password(2), { signal: controller.signal }));
  await nextTurn();
  calls[0].finish();
  await Promise.resolve(); // wrappingKey transfers the reservation before this turn resumes.
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  controller.abort();
  assert.equal((await queued).error.code, 'ABORTED');
  assert.equal(calls.length, 2);
  calls[1].finish();
  assert.ok((await first).value); assert.ok((await second).value);
  const replacement = sealPrivateKey(privateKey, password(3));
  await nextTurn(); calls[2].finish();
  assert.ok(await replacement);
});

test('active cancellation takes precedence over a provider failure and releases its slot', async () => {
  reset();
  const controller = new AbortController();
  const job = outcome(sealPrivateKey(privateKey, password(0), { signal: controller.signal }));
  await nextTurn();
  controller.abort('PRIVATE_ABORT_REASON');
  calls[0].finish(new Error('PRIVATE_PROVIDER_DETAIL'));
  const { error } = await job;
  assert.equal(error.code, 'ABORTED');
  assert.equal(error.message, 'Key vault operation aborted');
  assert.ok(calls[0].parameters.message.every((byte) => byte === 0));
  const replacement = sealPrivateKey(privateKey, password(1));
  await nextTurn(); calls[1].finish();
  assert.ok(await replacement);
});

test('queued open cancellation survives stopImmediatePropagation and never restores a private key', async () => {
  reset();
  const seed = sealPrivateKey(privateKey, password(0));
  await nextTurn(); calls[0].finish();
  const vault = await seed;
  reset();
  const first = outcome(sealPrivateKey(privateKey, password(1)));
  const second = outcome(sealPrivateKey(privateKey, password(2)));
  const controller = new AbortController();
  controller.signal.addEventListener('abort', (event) => event.stopImmediatePropagation(), { once: true });
  const queued = outcome(openPrivateKey(vault, password(0), { signal: controller.signal }));
  controller.abort();
  assert.equal((await queued).error.code, 'ABORTED');
  await nextTurn();
  assert.equal(calls.length, 2);
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  calls[0].finish(); calls[1].finish();
  assert.ok((await first).value); assert.ok((await second).value);
});

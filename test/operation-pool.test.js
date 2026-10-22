import assert from 'node:assert/strict';
import { getEventListeners } from 'node:events';
import test from 'node:test';
import { createOperationPool } from '../src/index.js';

const code = (expected) => (error) => error.code === expected;
const deferred = () => Promise.withResolvers();
const tick = () => new Promise((resolve) => setImmediate(resolve));

test('operation pool bounds admission, preserves FIFO and releases completed slots', async () => {
  const pool = createOperationPool({ maxConcurrent: 1, maxQueued: 2 });
  const gate = deferred();
  const started = [];
  const first = pool.run(async () => { started.push(1); await gate.promise; return 1; });
  const second = pool.run(() => { started.push(2); return 2; });
  const third = pool.run(() => { started.push(3); return 3; });
  await assert.rejects(pool.run(() => assert.fail('Overflow task started')), code('RESOURCE_LIMIT'));
  assert.deepEqual(started, [1]);
  assert.deepEqual(pool.stats, { active: 1, queued: 2, maxConcurrent: 1, maxQueued: 2, closed: false });
  gate.resolve();
  assert.deepEqual(await Promise.all([first, second, third]), [1, 2, 3]);
  assert.deepEqual(started, [1, 2, 3]);
  assert.equal(pool.stats.active, 0);
  assert.equal(pool.stats.queued, 0);
  assert.ok(Object.isFrozen(pool.stats));
  pool.close();
});

test('zero-length queue allows available slots but refuses waiting work', async () => {
  const pool = createOperationPool({ maxConcurrent: 2, maxQueued: 0 });
  const gate = deferred();
  const a = pool.run(() => gate.promise);
  const b = pool.run(() => gate.promise);
  await assert.rejects(pool.run(() => 0), code('RESOURCE_LIMIT'));
  assert.equal(pool.stats.active, 2);
  gate.resolve('done');
  assert.deepEqual(await Promise.all([a, b]), ['done', 'done']);
  pool.close();
});

test('queued cancellation removes work, cannot be suppressed and disposes listener', async () => {
  const pool = createOperationPool({ maxConcurrent: 1, maxQueued: 1 });
  const gate = deferred();
  const active = pool.run(() => gate.promise);
  const controller = new AbortController();
  controller.signal.addEventListener('abort', (event) => event.stopImmediatePropagation(), { once: true });
  const queued = pool.run(() => assert.fail('Cancelled task started'), { signal: controller.signal });
  const rejected = assert.rejects(queued, code('ABORTED'));
  controller.abort('secret reason');
  await rejected;
  assert.equal(pool.stats.queued, 0);
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  const replacement = pool.run(() => 42);
  gate.resolve(); await active;
  assert.equal(await replacement, 42);
  pool.close();
});

test('active cancellation retains admission slot until actual work settles', async () => {
  const pool = createOperationPool({ maxConcurrent: 1, maxQueued: 1 });
  const gate = deferred();
  const controller = new AbortController();
  let secondStarted = false;
  const first = pool.run((signal) => {
    assert.equal(signal, controller.signal);
    return gate.promise; // Deliberately ignores cancellation, like non-cancellable native work.
  }, { signal: controller.signal });
  const rejected = assert.rejects(first, (error) => error.code === 'ABORTED' && !error.message.includes('secret'));
  const second = pool.run(() => { secondStarted = true; return 5; });
  controller.abort('secret');
  await tick();
  assert.equal(pool.stats.active, 1);
  assert.equal(pool.stats.queued, 1);
  assert.equal(secondStarted, false);
  gate.resolve('must not return');
  await rejected;
  assert.equal(await second, 5);
  pool.close();
});

test('synchronous and asynchronous failures release admission and preserve normal errors', async () => {
  const pool = createOperationPool({ maxConcurrent: 1 });
  const failure = new Error('Synthetic failure');
  await assert.rejects(pool.run(() => { throw failure; }), (error) => error === failure);
  await assert.rejects(pool.run(async () => { throw failure; }), (error) => error === failure);
  assert.equal(await pool.run(() => 7), 7);
  assert.equal(pool.stats.active, 0);
  pool.close();
});

test('active cancellation cannot hide a task cleanup or I/O failure', async () => {
  const pool = createOperationPool({ maxConcurrent: 1 });
  const gate = deferred();
  const controller = new AbortController();
  const failure = Object.assign(new Error('Inspect staging data'), { code: 'CLEANUP_FAILED' });
  const task = pool.run(async () => { await gate.promise; throw failure; }, { signal: controller.signal });
  const rejected = assert.rejects(task, error => error === failure);
  controller.abort(); gate.resolve();
  await rejected;
  assert.equal(pool.stats.active, 0); pool.close();
});

test('close rejects queued and future tasks, disposes listeners and waits for active settlement', async () => {
  const pool = createOperationPool({ maxConcurrent: 1 });
  const gate = deferred();
  const controller = new AbortController();
  const first = pool.run(() => gate.promise);
  const queued = pool.run(() => assert.fail('Closed task started'), { signal: controller.signal });
  const rejected = assert.rejects(queued, code('POOL_CLOSED'));
  pool.close(); pool.close();
  await rejected;
  assert.equal(pool.stats.closed, true);
  assert.equal(pool.stats.active, 1);
  assert.equal(pool.stats.queued, 0);
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  await assert.rejects(pool.run(() => 0), code('POOL_CLOSED'));
  gate.resolve(9); assert.equal(await first, 9);
  assert.equal(pool.stats.active, 0);
});

test('pool validates limits, tasks, signals and pre-aborted calls before execution', async () => {
  for (const options of [null, [], 1, { maxConcurrent: 0 }, { maxConcurrent: 17 }, { maxConcurrent: 1.5 },
    { maxConcurrent: null }, { maxQueued: -1 }, { maxQueued: 65 }, { maxQueued: null }]) {
    assert.throws(() => createOperationPool(options), code('INVALID_INPUT'));
  }
  const pool = createOperationPool();
  for (const task of [undefined, null, {}]) await assert.rejects(pool.run(task), code('INVALID_INPUT'));
  for (const options of [null, [], 1, { signal: {} }]) await assert.rejects(pool.run(() => 0, options), code('INVALID_INPUT'));
  await assert.rejects(pool.run(() => assert.fail('Pre-aborted task started'), { signal: AbortSignal.abort() }), code('ABORTED'));
  assert.equal(pool.stats.active, 0); pool.close();
});

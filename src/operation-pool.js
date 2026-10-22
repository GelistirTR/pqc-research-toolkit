import { addAbortListener } from 'node:events';
import { CryptoError, fail } from './errors.js';
import { checkAbort } from './file-io.js';

// Per-instance admission control, not a process/worker-wide memory budget.
// Tasks own their captured inputs and must forward the signal to SDK calls.
export function createOperationPool(options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) fail('INVALID_INPUT', 'Expected pool options');
  const maxConcurrent = options.maxConcurrent === undefined ? 2 : options.maxConcurrent;
  const maxQueued = options.maxQueued === undefined ? 16 : options.maxQueued;
  if (!Number.isInteger(maxConcurrent) || maxConcurrent < 1 || maxConcurrent > 16 ||
      !Number.isInteger(maxQueued) || maxQueued < 0 || maxQueued > 64) {
    fail('INVALID_INPUT', 'Pool limits must be 1–16 active and 0–64 queued operations');
  }
  let active = 0;
  let closed = false;
  const queue = [];
  const aborted = () => new CryptoError('ABORTED', 'Pooled operation aborted');

  async function execute(entry) {
    try {
      checkAbort(entry.signal);
      const value = await entry.task(entry.signal);
      checkAbort(entry.signal);
      entry.resolve(value);
    // Preserve task failures (especially CLEANUP_FAILED) even after abort.
    // Successful late results are rejected by checkAbort above.
    } catch (error) { entry.reject(error); }
    finally { active--; drain(); }
  }
  function drain() {
    while (active < maxConcurrent && queue.length) {
      const entry = queue.shift();
      entry.subscription?.[Symbol.dispose]();
      active++;
      void execute(entry);
    }
  }
  async function run(task, runOptions = {}) {
    if (typeof task !== 'function' || !runOptions || typeof runOptions !== 'object' || Array.isArray(runOptions)) {
      fail('INVALID_INPUT', 'Expected a task function and operation options');
    }
    const signal = runOptions.signal;
    checkAbort(signal);
    if (closed) fail('POOL_CLOSED', 'Operation pool is closed');
    if (active >= maxConcurrent && queue.length >= maxQueued) fail('RESOURCE_LIMIT', 'Operation pool queue is full');
    return new Promise((resolve, reject) => {
      const entry = { task, signal, resolve, reject, subscription: undefined };
      if (signal) {
        entry.subscription = addAbortListener(signal, () => {
          const index = queue.indexOf(entry);
          if (index < 0) return; // Active work retains its slot until settlement.
          queue.splice(index, 1);
          entry.subscription[Symbol.dispose]();
          reject(aborted());
        });
      }
      queue.push(entry);
      drain();
    });
  }
  function close() {
    closed = true;
    for (const entry of queue.splice(0)) {
      entry.subscription?.[Symbol.dispose]();
      entry.reject(new CryptoError('POOL_CLOSED', 'Operation pool is closed'));
    }
  }
  return Object.freeze({ run, close, get stats() {
    return Object.freeze({ active, queued: queue.length, maxConcurrent, maxQueued, closed });
  } });
}

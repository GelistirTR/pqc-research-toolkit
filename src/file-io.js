import { link, lstat, mkdtemp, open, rmdir, unlink } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { CryptoError, fail } from './errors.js';

export function filePaths(inputPath, outputPath) {
  for (const path of [inputPath, outputPath]) {
    if (typeof path !== 'string' || path.length === 0 || path.includes('\0')) {
      fail('INVALID_INPUT', 'Expected explicit input and output file paths');
    }
  }
  if (resolve(inputPath) === resolve(outputPath)) fail('INVALID_INPUT', 'Input and output must differ');
  return { inputPath: resolve(inputPath), outputPath: resolve(outputPath) };
}

export function checkAbort(signal) {
  if (signal !== undefined && !(signal instanceof AbortSignal)) fail('INVALID_INPUT', 'Invalid AbortSignal');
  if (signal?.aborted) fail('ABORTED', 'File operation aborted');
}

export async function readExact(handle, target, position, code = 'AUTHENTICATION_FAILED') {
  let offset = 0;
  while (offset < target.length) {
    const { bytesRead } = await handle.read(target, offset, target.length - offset, position + offset);
    if (bytesRead === 0) fail(code, code === 'INPUT_CHANGED' ? 'Input changed during encryption' : 'Authentication failed');
    offset += bytesRead;
  }
}

export async function writeAll(handle, value) {
  let offset = 0;
  while (offset < value.length) {
    const { bytesWritten } = await handle.write(value, offset, value.length - offset);
    if (bytesWritten === 0) fail('IO_ERROR', 'File write made no progress');
    offset += bytesWritten;
  }
}

export async function ensureOutputAbsent(path) {
  try { await lstat(path); }
  catch (error) { if (error.code === 'ENOENT') return; throw error; }
  fail('OUTPUT_EXISTS', 'Output already exists');
}

export async function stageOutput(outputPath) {
  await ensureOutputAbsent(outputPath);
  // mkdtemp uses owner-only permissions on POSIX. Windows inherits directory ACLs.
  const directory = await mkdtemp(join(dirname(outputPath), '.pqc-stage-'));
  const path = join(directory, 'output.tmp');
  let handle;
  try { handle = await open(path, 'wx', 0o600); }
  catch (error) { await rmdir(directory); throw error; }
  let closed = false;
  return {
    handle,
    async publish(signal) {
      checkAbort(signal);
      await handle.sync();
      await handle.close();
      closed = true;
      checkAbort(signal);
      try {
        // Hard-link creation is exclusive and same-volume: no overwrite or partial public file.
        await link(path, outputPath);
      } catch (error) {
        if (error.code === 'EEXIST') fail('OUTPUT_EXISTS', 'Output already exists');
        throw error; // No unsafe copy/rename fallback on filesystems without hard links.
      }
    },
    async cleanup() {
      // A close failure must not skip attempts to remove staged plaintext.
      // Keep every cleanup failure for library callers; the CLI prints only
      // the fixed public message, never filesystem/provider error details.
      const failures = [];
      if (!closed) {
        try { await handle.close(); closed = true; }
        catch (error) { failures.push(error); }
      }
      try { await unlink(path); }
      catch (error) { failures.push(error); }
      try { await rmdir(directory); }
      catch (error) { failures.push(error); }
      if (failures.length) {
        const error = new CryptoError('CLEANUP_FAILED',
          'Temporary output cleanup reported an error; inspect the output directory for staging data');
        Object.defineProperty(error, 'cause', { value: new AggregateError(failures, 'Staging cleanup failures') });
        throw error;
      }
    },
  };
}

export function unchanged(before, after) {
  if (before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) {
    fail('INPUT_CHANGED', 'Input changed during file operation');
  }
}

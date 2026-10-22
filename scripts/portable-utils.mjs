import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, readdir, realpath, rm } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const root = fileURLToPath(new URL('../', import.meta.url));
export function run(file, args, options = {}) {
  const result = spawnSync(file, args, { encoding: 'utf8', input: '', windowsHide: true,
    timeout: 120000, maxBuffer: 4 * 1024 * 1024, ...options });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return result.stdout;
}
export function powershell(script, args) {
  const home = join(process.env.SystemRoot, 'System32', 'WindowsPowerShell', 'v1.0');
  // A Node process can inherit PowerShell 7 module paths incompatible with Windows PowerShell 5.
  // Use only the built-in modules for this child, without changing system/user settings.
  const environment = Object.fromEntries(Object.entries(process.env).filter(([key]) => key.toUpperCase() !== 'PSMODULEPATH'));
  environment.PSModulePath = join(home, 'Modules');
  return run(join(home, 'powershell.exe'),
    ['-NoProfile', '-NonInteractive', '-File', join(root, 'packaging', 'windows', script), ...args],
    { env: environment });
}
export async function hash(path) {
  const digest = createHash('sha256');
  for await (const chunk of createReadStream(path)) digest.update(chunk);
  return digest.digest('hex');
}
export async function listFiles(directory, prefix = '') {
  const files = [];
  for (const name of await readdir(directory)) {
    const relative = prefix ? `${prefix}/${name}` : name;
    const absolute = join(directory, name);
    const stat = await lstat(absolute);
    assert.equal(stat.isSymbolicLink(), false, 'Package entries must not be links');
    if (stat.isDirectory()) files.push(...await listFiles(absolute, relative));
    else { assert.ok(stat.isFile()); files.push(relative); }
  }
  return files.sort();
}
export async function cleanupOwned(directory, parent, prefix) {
  const resolved = await realpath(directory);
  assert.equal(dirname(resolved).toLowerCase(), (await realpath(parent)).toLowerCase());
  assert.ok(basename(resolved).startsWith(prefix));
  assert.equal((await lstat(directory)).isSymbolicLink(), false);
  await rm(resolve(resolved), { recursive: true, force: true });
}

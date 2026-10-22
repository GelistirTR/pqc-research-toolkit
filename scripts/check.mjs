import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

for (const directory of ['src', 'test', 'examples', 'scripts', 'bin']) {
  for (const file of readdirSync(directory)) {
    if (!/\.(js|mjs)$/.test(file)) continue;
    const result = spawnSync(process.execPath, ['--check', join(directory, file)], { stdio: 'inherit' });
    if (result.status !== 0) process.exit(result.status ?? 1);
  }
}
console.log('JavaScript syntax checks passed.');

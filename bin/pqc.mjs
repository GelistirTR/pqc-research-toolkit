#!/usr/bin/env node
// Check before importing node:crypto APIs unavailable in older releases.
const [major, minor, patch] = process.versions.node.split('.').map(Number);
if (!/^24\.\d+\.\d+$/.test(process.versions.node) || major !== 24 || minor < 22 || (minor === 22 && patch < 1)) {
  const message = 'This alpha requires Node.js 24.22.1+ in the 24.x release line';
  if (process.argv.includes('--json')) {
    process.stderr.write(`${JSON.stringify({ ok: false, error: { code: 'UNSUPPORTED_RUNTIME', message } })}\n`);
  } else process.stderr.write(`PQC [UNSUPPORTED_RUNTIME]: ${message}\n`);
  process.exitCode = 1;
} else {
  const { runCli } = await import('../src/cli.js');
  process.exitCode = await runCli(process.argv.slice(2));
}

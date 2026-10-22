import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

const git = (...args) => execFileSync('git', args, { maxBuffer: 32 * 1024 * 1024 });
assert.equal(resolve(git('rev-parse', '--absolute-git-dir').toString().trim()), resolve(process.cwd(), '.git'), 'Run inside the project repository');
assert.equal(git('rev-parse', '--is-shallow-repository').toString().trim(), 'false', 'History check requires a complete local history');
const paths = git('log', '--format=', '--name-only', '--no-renames', 'HEAD').toString('utf8').split(/\r?\n/).filter(Boolean);
const rootFiles = new Set(['.gitignore', '.gitattributes', 'package.json', 'package-lock.json', 'tsconfig.json',
  'README.md', 'LICENSE', 'SECURITY.md', 'CHANGELOG.md', 'THIRD-PARTY-NOTICES.md', 'CONTRIBUTING.md']);
const sensitive = /(?:^|\/)(?:\.env(?:\..*)?|.*\.(?:pem|key|p12|pfx|pqvault|vault|pqc|tgz|exe|dll|msi|zip|7z)|\.pqc-stage-[^/]*)(?:$|\/)/i;
for (const path of paths) {
  assert.ok(rootFiles.has(path) || /^(src|bin|test|scripts|docs|examples|assets|packaging|third_party|\.github)\//.test(path), `Unexpected historical path: ${path}`);
  assert.ok(!sensitive.test(path), `Sensitive historical filename: ${path}`);
}
const entries = git('rev-list', '--objects', 'HEAD').toString('utf8').trim().split(/\r?\n/);
const ids = entries.map(line => line.slice(0, 40));
const metadata = execFileSync('git', ['cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)'],
  { input: ids.join('\n') + '\n', encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }).trim().split(/\r?\n/);
let blobs = 0; let bytes = 0;
const patterns = [/-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/, /\bgh[pousr]_[A-Za-z0-9]{30,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{30,}\b/, /\bAKIA[A-Z0-9]{16}\b/];
for (const line of metadata) {
  const [id, type, size] = line.split(' ');
  if (type !== 'blob') continue;
  const data = git('cat-file', 'blob', id);
  assert.equal(data.length, Number(size));
  assert.ok(!patterns.some(pattern => pattern.test(data.toString('utf8'))), `Potential secret in historical blob ${id}`);
  blobs++; bytes += data.length;
}
console.log(JSON.stringify({ head: git('rev-parse', 'HEAD').toString().trim(),
  commits: Number(git('rev-list', '--count', 'HEAD').toString().trim()), uniqueHistoricalPaths: new Set(paths).size, blobs, bytes,
  limits: 'Allowlisted filenames and selected secret patterns across complete HEAD ancestry; not a comprehensive secret scan or security audit. Public NIST test-key provenance remains separately checked.' }, null, 2));

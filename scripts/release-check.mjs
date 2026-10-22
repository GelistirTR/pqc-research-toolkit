import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstatSync } from 'node:fs';
import { resolve } from 'node:path';

// Inspect the explicit Git index, never a recursive snapshot of the user's workspace.
const root = process.cwd();
const gitDirectory = execFileSync('git', ['rev-parse', '--absolute-git-dir'], { encoding: 'utf8' }).trim();
if (resolve(gitDirectory) !== resolve(root, '.git')) throw new Error('Run inside this project repository, not a parent checkout');
const files = execFileSync('git', ['ls-files', '-z'], { encoding: 'utf8' }).split('\0').filter(Boolean);
if (files.length === 0) throw new Error('Stage the reviewed project files first');
// npm pack reads the working tree, while git archive reads committed/indexed blobs.
// Require tracked files to agree so these two deliverables cannot silently differ.
try { execFileSync('git', ['diff', '--quiet', '--exit-code']); }
catch { throw new Error('Unstaged changes exist; review and stage the final source before release checks'); }
const untracked = execFileSync('git', ['ls-files', '--others', '--exclude-standard', '-z', '--',
  'src', 'bin', 'docs', 'examples', 'scripts', 'test', 'assets', '.github', 'packaging', 'third_party'], { encoding: 'utf8' });
if (untracked.length) throw new Error('Untracked project files exist; review and stage or exclude them before release checks');
const stagedData = (file) => execFileSync('git', ['show', `:${file}`], { maxBuffer: 8 * 1024 * 1024 });
const roots = new Set([
  '.gitignore', '.gitattributes', 'package.json', 'package-lock.json', 'tsconfig.json', 'README.md',
  'LICENSE', 'SECURITY.md', 'CHANGELOG.md', 'THIRD-PARTY-NOTICES.md', 'CONTRIBUTING.md',
]);
const directories = /^(?:src|bin|test|scripts|docs|examples|assets|packaging|third_party|\.github)\//;
const sensitiveName = /(?:^|\/)(?:\.env(?:\..*)?|.*\.(?:pem|key|p12|pfx|pqvault|vault|pqc|tgz|exe|dll|msi|zip|7z)|\.pqc-stage-[^/]*)(?:$|\/)/i;
const secretPatterns = [
  /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/,
  /\bgh[pousr]_[A-Za-z0-9]{30,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{30,}\b/,
  /\bAKIA[A-Z0-9]{16}\b/,
];
let totalBytes = 0;
for (const file of files) {
  if ((!roots.has(file) && !directories.test(file)) || sensitiveName.test(file)) throw new Error(`Unexpected release path: ${file}`);
  const absolute = resolve(root, file);
  const stat = lstatSync(absolute);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`Unsupported release entry: ${file}`);
  // Read the staged blob: publication checks must inspect what Git will commit.
  const staged = stagedData(file);
  totalBytes += staged.length;
  const content = staged.toString('utf8');
  if (secretPatterns.some((pattern) => pattern.test(content))) throw new Error(`Potential secret in release file: ${file}`);
}
const licenseHash = createHash('sha256').update(stagedData('LICENSE')).digest('hex');
if (licenseHash !== 'c0ea4a896d2c8c394b29f9427589996db826cd501c512279ff0ed3ef48fabbe5') throw new Error('Official license text changed');
const pkg = JSON.parse(stagedData('package.json').toString('utf8'));
const lock = JSON.parse(stagedData('package-lock.json').toString('utf8'));
if (pkg.version !== lock.version || pkg.version !== lock.packages[''].version) throw new Error('Version mismatch');
if (pkg.license !== 'PolyForm-Noncommercial-1.0.0' || Object.keys(pkg.dependencies ?? {}).length !== 0) throw new Error('Unexpected runtime/license profile');
if (JSON.stringify(pkg.devDependencies) !== JSON.stringify(lock.packages[''].devDependencies)) throw new Error('Lockfile dependencies differ');
for (const file of ['bin/pqc.mjs', 'src/index.js', 'src/index.d.ts', 'SECURITY.md', 'docs/KULLANIM.md']) {
  if (!files.includes(file)) throw new Error(`Required staged artifact missing: ${file}`);
}
const fixtures = JSON.parse(stagedData('test/fixtures/nist-acvp.json').toString('utf8'));
if (fixtures.commit !== '975de31eb83d87039ec88934fdc47d8c312b892d' || !fixtures.description.includes('PUBLIC TEST KEYS ONLY')) {
  throw new Error('Public test-key provenance is missing');
}
console.log(JSON.stringify({ version: pkg.version, files: files.length, totalBytes,
  runtimeDependencies: 0, license: pkg.license, publicTestKeys: 'NIST provenance verified',
  note: 'Pattern scan of allowlisted staged files, with matching working tree; not a comprehensive secret/security audit.' }, null, 2));

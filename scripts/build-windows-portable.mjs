import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { copyFile, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { cleanupOwned, hash, listFiles, powershell, root, run } from './portable-utils.mjs';

assert.equal(process.platform, 'win32', 'This builder targets Windows only');
assert.equal(process.arch, 'x64', 'This builder targets Windows x64 only');
const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
const provenancePath = join(root, 'third_party', 'node-v24.22.1');
const provenance = JSON.parse(await readFile(join(provenancePath, 'provenance.json'), 'utf8'));
assert.equal(process.versions.node, provenance.version, 'Use the pinned runtime version for this build');
assert.equal(await hash(process.execPath), provenance.binarySha256, 'Runtime differs from the pinned official binary');
assert.equal(await hash(join(provenancePath, 'LICENSE.txt')), provenance.licenseSha256);
assert.equal(await hash(join(provenancePath, 'SHASUMS256.txt')), provenance.checksumsSha256);
const checksums = await readFile(join(provenancePath, 'SHASUMS256.txt'), 'utf8');
assert.ok(checksums.includes(`${provenance.binarySha256}  win-x64/node.exe`));
const signature = JSON.parse(powershell('verify-runtime.ps1', ['-Path', process.execPath]));
run(process.execPath, [join(root, 'scripts', 'release-check.mjs')], { cwd: root });
const sourceTree = run('git', ['write-tree'], { cwd: root }).trim();
const npmCli = process.env.npm_execpath;
assert.ok(npmCli, 'Run with npm run build:windows-portable');
const [pack] = JSON.parse(run(process.execPath, [npmCli, 'pack', '--dry-run', '--ignore-scripts', '--json'], { cwd: root }));
const artifacts = join(root, '.artifacts');
await mkdir(artifacts, { recursive: true });
const temporary = await mkdtemp(join(artifacts, 'portable-build-'));
const packageName = `pqc-research-core-${pkg.version}-windows-x64`;
const artifactName = `${packageName}-${sourceTree.slice(0, 12)}`;
const directory = join(temporary, packageName);
const archivePath = join(temporary, `${packageName}.zip`);
try {
  await mkdir(directory);
  for (const file of pack.files) {
    assert.match(file.path, /^(?:(?:src|bin|docs|examples)\/|(?:README\.md|SECURITY\.md|LICENSE|THIRD-PARTY-NOTICES\.md|CHANGELOG\.md|package\.json)$)/);
    const target = join(directory, 'tool', file.path);
    await mkdir(dirname(target), { recursive: true });
    await copyFile(join(root, file.path), target, constants.COPYFILE_EXCL);
  }
  await mkdir(join(directory, 'runtime'));
  await copyFile(process.execPath, join(directory, 'runtime', 'node.exe'), constants.COPYFILE_EXCL);
  for (const file of ['LICENSE.txt', 'SHASUMS256.txt', 'provenance.json']) {
    await copyFile(join(provenancePath, file), join(directory, 'runtime', file), constants.COPYFILE_EXCL);
  }
  await copyFile(join(root, 'LICENSE'), join(directory, 'LICENSE'), constants.COPYFILE_EXCL);
  await copyFile(join(root, 'THIRD-PARTY-NOTICES.md'), join(directory, 'THIRD-PARTY-NOTICES.md'), constants.COPYFILE_EXCL);
  await mkdir(join(directory, 'launcher-source'));
  const launcherSource = join(root, 'packaging', 'windows', 'PqcLauncher.cs');
  assert.ok((await readFile(launcherSource, 'utf8')).includes(`RuntimeSha256 = "${provenance.binarySha256}"`));
  await copyFile(launcherSource, join(directory, 'launcher-source', 'PqcLauncher.cs'), constants.COPYFILE_EXCL);
  const compiler = join(process.env.SystemRoot, 'Microsoft.NET', 'Framework64', 'v4.0.30319', 'csc.exe');
  run(compiler, ['/nologo', '/target:exe', '/platform:x64', '/optimize+', `/out:${join(directory, 'pqc.exe')}`, launcherSource]);
  const readme = `PQC Research Toolkit ${pkg.version} — Windows x64 portable alpha

Extract the entire ZIP to a trusted local folder. Windows x64 and .NET Framework 4.x are required. A separate Node/npm installation is not required.
Open PowerShell in the extracted package folder:
  .\\pqc.exe doctor
  .\\pqc.exe --help
Save the full pqc.exe path before changing to your private data folder. Keep keys, passwords and user documents outside the application folder.

Examples from your chosen private data folder (replace the executable path):
  & 'C:\\path-to-kit\\pqc.exe' keygen --vault recipient.vault --public recipient.public.der
  & 'C:\\path-to-kit\\pqc.exe' fingerprint --public recipient.public.der
  & 'C:\\path-to-kit\\pqc.exe' inspect --input document.pqc
Inspection reports unauthenticated public header claims only. It does not validate ciphertext/tags, passwords or identity; do not use the claimed recipient fingerprint as your trusted pin.
Use the complete independently verified fingerprint with the encrypt command. Full instructions: tool/README.md and tool/docs/KULLANIM.md. Library sources and types are in tool/src/.

The toolkit is experimental, independently unaudited and not FIPS certified. Wire formats remain experimental. Decryption uses staged plaintext; crashes or cleanup errors can leave it behind. Use private directories with appropriate ACLs and protect disks/backups. No recovery for a lost password. Changing a vault password preserves the key and leaves old copies usable with their old password.

pqc.exe is a local unsigned .NET launcher built from launcher-source/PqcLauncher.cs. It launches the bundled, unmodified Node ${provenance.version} binary directly, checks its pinned SHA-256 and waits for its exit code. The launcher is not an Authenticode-signed project release. runtime/node.exe was verified against the official Node HTTPS checksum and a valid OpenJS Foundation signature when built. The detached GPG checksum signature was not verified.
The child ignores inherited NODE_OPTIONS, NODE_PATH, OPENSSL_CONF, OPENSSL_MODULES and OPENSSL_ENGINES. System settings are not changed. No shell is used to forward arguments. Relative input/output paths use your current working directory.

LICENSE applies to project code, including the launcher. Node/OpenSSL and bundled third-party components retain their own licenses: runtime/LICENSE.txt. Their rights are not changed by the project's noncommercial license. See THIRD-PARTY-NOTICES.md.
MANIFEST.json records included-file hashes, source Git tree and runtime provenance. These hashes detect changed bytes; the manifest does not authenticate itself or replace a trusted distribution channel. The complete source archive is a separate local artifact. This archive does not contain npm, tests, user keys or user files.
`;
  await writeFile(join(directory, 'START-HERE.txt'), readme, { flag: 'wx' });
  const files = {};
  for (const file of await listFiles(directory)) files[file] = await hash(join(directory, file));
  const manifest = { name: pkg.name, version: pkg.version, target: 'windows-x64',
    sourceTree,
    runtime: { ...provenance, openssl: process.versions.openssl, authenticode: signature },
    launcherSigned: false, files };
  await writeFile(join(directory, 'MANIFEST.json'), `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'wx' });
  powershell('archive.ps1', ['-Mode', 'Create', '-Source', directory, '-Destination', archivePath]);
  const verified = JSON.parse(run(process.execPath, [join(root, 'scripts', 'test-windows-portable.mjs'), archivePath], { cwd: root }));
  // Publish only the verified archive, without replacing prior artifacts.
  const destination = join(artifacts, `${artifactName}.zip`);
  await copyFile(archivePath, destination, constants.COPYFILE_EXCL);
  const digest = await hash(destination);
  await writeFile(`${destination}.sha256`, `${digest}  ${artifactName}.zip\n`, { flag: 'wx' });
  const report = { ...verified, archive: `${artifactName}.zip`, archiveSha256: digest, sourceTree: manifest.sourceTree };
  await writeFile(join(artifacts, `portable-verification-${pkg.version}-${sourceTree.slice(0, 12)}.json`), `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx' });
  console.log(JSON.stringify(report, null, 2));
} finally { await cleanupOwned(temporary, artifacts, 'portable-build-'); }

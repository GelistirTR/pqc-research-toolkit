# PQC Research Core

**0.3.0-alpha.12 · Experimental and independently unaudited · Node.js 24.22.1+ / 24.x**

A developer-focused, typed JavaScript/TypeScript cryptography library for application integration. It provides experimental post-quantum key establishment, authenticated encryption, signatures, protected private-key vaults and chunked file operations. The CLI is a supporting diagnostic/integration tool; a desktop GUI is not the product target.

The primitives run through Node.js `node:crypto` and its OpenSSL provider: **ML-KEM-1024**, **ML-DSA-87**, **HKDF-SHA-512**, **AES-256-GCM**, and **Argon2id**. There are no third-party npm runtime dependencies. The kit uses the Node 24.22.1 security release; see [runtime and legacy-vault policy](docs/RUNTIME-POLICY.md). The project adds experimental file and vault formats and application safeguards; those formats have not received an independent cryptographic review. Standard algorithms do not make the whole application proven secure or FIPS certified. There is no claim of perfect encryption or guaranteed resistance to future quantum attacks.

[Türkçe kullanım kılavuzu](docs/KULLANIM.md) · [Komut seçimi ve sorun giderme](docs/SORUN-GIDERME.md) · [Security status](SECURITY.md) · [Format specification](docs/FILE-FORMAT.md) · [Validation evidence](docs/DOGRULAMA.md)

Start with the [developer integration contract](docs/GELISTIRICI-SDK.md), [account-password API](docs/ACCOUNT-PASSWORDS.md), [local security review](docs/SECURITY-REVIEW-ALPHA11.md) and [resource/failure measurements](docs/KAYNAK-DAYANIKLILIK.md). Alpha.12 adds account-password hashing/verification and bounded PHC migration. The separate vault API protects private keys. Low-level message encryption is available; the [messaging design gate](docs/MESSAGING-DESIGN.md) records the identity, session, replay and ratchet work needed for a full messaging protocol.

```js
import { hashPassword, verifyPassword, passwordHashNeedsRehash } from 'pqc-research-core';

const password = Buffer.from('synthetic example password', 'utf8');
try {
  const record = await hashPassword(password); // Store this PHC record in your protected database.
  const valid = await verifyPassword(record, password); // On login, load the existing DB record.
  const upgrade = valid && passwordHashNeedsRehash(record);
} finally { password.fill(0); }
```

New hashes use Argon2id v19, 64 MiB, 3 passes, 4 lanes, random 16-byte salt and 32-byte output. Verification also accepts the explicitly bounded 19 MiB/2/1 migration profile. Canonical PHC parsing rejects unsupported work factors before native KDF; vault and account-password operations share 2 active / 16 queued Argon2 requests per loaded module instance. This is not a global worker/process budget or account-policy/login service. See the account API contract before integration.

Alpha.11 changes legacy-vault handling: combined seed+expanded private keys now fail with `LEGACY_KEY_REQUIRES_MIGRATION` by default. Controlled SDK migration may explicitly select `{ legacyKeyPolicy: 'seed-authoritative' }`, verify the resulting public key against an independently trusted fingerprint, and reseal to a seed-only vault. This opt-in does not prove companion consistency. Seed-only and supported expanded-only representations remain accepted by default; see [migration policy](docs/KEY-VAULT.md).

Applications can opt into `createOperationPool({ maxConcurrent: 2, maxQueued: 16 })`. Schedule SDK work with `pool.run(signal => encryptFile({ ...options, signal }), { signal: requestSignal })`; forward the signal to the operation. The pool bounds admitted task count per instance and preserves active reservations until settlement. It does not copy closure inputs, impose a hard memory ceiling, cancel native work forcibly, roll back completed side effects, or replace service-wide rate limits. Do not await a task submitted to the same saturated pool from inside its own task. `pool.close()` rejects queued/future work and leaves active tasks to settle.

## Windows portable package

The existing portable artifact is alpha.10. Alpha.11 is delivered as SDK source and an npm tarball; the Windows helper kit was not rebuilt in this SDK-focused change. The older helper does not include the new strict legacy policy or operation pool.

The locally built Windows x64 ZIP includes the pinned Node runtime and an unsigned Windows .NET launcher, so a separate Node/npm installation is not required. Extract the entire archive, open PowerShell in its folder, and run `.\pqc.exe doctor`. Windows x64 and .NET Framework 4.x are required. Read `START-HERE.txt` in the ZIP and [the portable package guide](docs/PORTABLE-WINDOWS.md). The ZIP is a local alpha artifact; it has not been published as a signed project release.

## Install from this checkout

Install a supported Node.js 24 release, open a terminal in this repository, then run:

```powershell
node --version
npm ci --ignore-scripts
node bin/pqc.mjs help
node bin/pqc.mjs --version
node bin/pqc.mjs doctor
```

For the file commands below, save the absolute CLI path and change to an existing private working folder outside this repository:

```powershell
$pqc = (Resolve-Path .\bin\pqc.mjs).Path
Set-Location (Read-Host 'Existing private working folder outside the repository')
```

Optionally run `npm link` from the checkout to install the local `pqc` command, then replace `node $pqc` with `pqc`. These instructions do not require a published npm package. After dependency installation, cryptographic operations run locally without network access.

`doctor` runs ephemeral KEM, KDF, authenticated-encryption, signature and vault checks without opening user files, writing files or making network requests. It briefly uses the vault's 64 MiB Argon2 profile. It is a functional test; it does not audit the machine, check filesystem ACLs/hard links or certify security. Use `doctor --json` for structured diagnostics.

If you received a `.tgz` package built from reviewed source, install it with `npm install --global <absolute-path-to-package.tgz> --ignore-scripts`, then run `pqc doctor`. A locally packed tarball is not an authenticated upstream release; verify its origin and compare its SHA-256 through an authenticated channel. The project is not published to the npm registry.

Choose a private, trusted local folder for keys and output files. Relative paths below refer to the current folder. On Windows, restrict the folder's ACLs to the intended account; POSIX permission bits alone do not enforce Windows privacy. Keep working files outside the repository so they cannot be committed accidentally.

## Encrypt and decrypt a file

Create the recipient's encryption key pair. The CLI asks for a hidden vault password and confirmation. Use a strong, unique password and back up the vault and password securely: there is no password recovery.

```powershell
node $pqc keygen --type kem --vault recipient.vault --public recipient.public.der
node $pqc fingerprint --public recipient.public.der
```

Share only `recipient.public.der`, the canonical SPKI DER public key. Keep `recipient.vault` private. A fingerprint is `SHA256:` followed by **64 lowercase hexadecimal characters**, computed over that canonical public key.

Before encrypting, compare the **entire fingerprint** with the recipient through an independently authenticated channel, such as an already verified conversation or an in-person comparison. Computing a fingerprint from an untrusted downloaded key does not establish who owns it. For a local self-test, compare it with the fingerprint you just generated yourself. Paste the verified value below:

```powershell
$expectedFingerprint = Read-Host 'Paste the full fingerprint verified with the recipient'
node $pqc encrypt --input document.txt --output document.pqc --public recipient.public.der --fingerprint $expectedFingerprint --context my-app/documents/v1 --aad document:42
```

The recipient restores the file using the same trusted context and AAD:

```powershell
node $pqc decrypt --input document.pqc --output document.restored.txt --vault recipient.vault --context my-app/documents/v1 --aad document:42
```

`--context` identifies your application and purpose. Optional `--aad` is authenticated associated data, for example a document identifier the recipient already expects. These values must match exactly on both sides, including UTF-8 encoding. They are not passwords and should not contain secrets. Losing the context or AAD can prevent decryption. Store their agreed values separately. Reusing an identifier does not prevent replay.

Every operation creates a new output: existing files are never overwritten, and source files are never deleted. Keep backups and test recovery before relying on the tool.

## Inspect a container without a password

```powershell
node $pqc inspect --input document.pqc
node $pqc inspect --input recipient.vault --json
```

`inspect` recognizes the file's magic bytes, validates the supported header/profile and compares the declared length with the current file size. It reads only public headers: at most 1,664 bytes for an encrypted file or 64 bytes for a vault, including the initial format probe. It does not request a password, import a private key, run a KDF, read ciphertext records or create output files.

**Every returned field is an unauthenticated claim.** Even a damaged ciphertext/tag can pass this structural inspection. `authenticated` is always `false`; CLI exit zero means the inspection completed, not that the contents are intact. The claimed recipient fingerprint must never become your trusted pin. This command cannot recover context/AAD, identify the sender, test passwords or recover a lost key. Use `decrypt` for full file authentication with the trusted expected context/AAD, and `verify` for detached signatures.

The SDK exposes the same bounded reader as `await inspectContainer(inputPath, { signal })`. Its readonly result is discriminated by `kind` (`encrypted-file` or `key-vault`) and includes the literal `authenticated: false` in the TypeScript contract. Stat checks detect ordinary changes during inspection; this is not a snapshot against a malicious concurrent writer. Inspection follows paths to regular files; it does not establish path ownership or filesystem permissions.

## Sign and verify

Signing uses a separate key pair and vault. This CLI signs the actual input bytes using pure ML-DSA-87; signing inputs are limited to **16 MiB**.

```powershell
node $pqc keygen --type signature --vault signer.vault --public signer.public.der
node $pqc fingerprint --public signer.public.der
node $pqc sign --input document.txt --output document.sig --vault signer.vault --context my-app/signatures/v1
```

Verify the signer's complete fingerprint through an authenticated channel, then verify the signature:

```powershell
$signerFingerprint = Read-Host 'Paste the full fingerprint verified with the signer'
node $pqc verify --input document.txt --signature document.sig --public signer.public.der --fingerprint $signerFingerprint --context my-app/signatures/v1
```

A valid signature authenticates the bytes and context against the supplied key. The identity behind that key must be established separately. Encryption alone does not authenticate a sender; the CLI does not automatically combine signatures and encryption into a messaging protocol.

## Passwords and automation

Vault passwords must be **16–1024 bytes**. Length alone is not a measure of strength. Interactive entry is hidden, and key generation and new passwords require confirmation. Keep secrets out of command arguments, environment variables, logs, and version control.

To protect the same key with a new password, write a new vault:

```powershell
node $pqc change-password --vault recipient.vault --output recipient-new.vault
```

Enter the current password, then the new password twice. The command supports both KEM and signature vaults, preserves the full public-key fingerprint, and never overwrites the original or an existing output. Verify the new vault in your workflow and back it up before retiring any old copy. **The original vault and its backups remain decryptable with the old password.** This changes password protection; it does not rotate the cryptographic key or recover security after that key was compromised. There is no forgotten-password recovery.

For controlled automation, `keygen`, `decrypt`, and `sign` accept `--password-file PATH`. `change-password` uses `--password-file` for the current secret and `--new-password-file` for the replacement secret. The files are read as **raw bytes**, with no newline trimming or Unicode normalization. An editor-added newline changes the password. Protect and back up those files as carefully as the private key; storing them beside the vault can defeat its protection. Interactive use does not require a password file.

Add `--json` for machine-readable results. Treat a nonzero exit status as failure; inspect the reported error instead of guessing from whether an output path exists. A late I/O failure can occur after a complete output has been created. `node $pqc help` lists supported arguments. Resolve mismatching fingerprints, context/AAD, wrong passwords, and authentication failures; weakening checks is not a recovery mechanism.

## JavaScript and TypeScript library

The library uses opaque, separately typed KEM, signing, encryption, and decryption handles. Import from this checkout, or use the package export when integrating a locally installed package. The caller must authenticate public keys before passing them to the API; the library file API does not enforce the CLI's fingerprint check.

Use `publicKeyFingerprint(key)` to display the complete project-format fingerprint, and `requirePublicKeyFingerprint(key, trustedFingerprint)` to require a match before encryption:

```js
import { readFile } from 'node:fs/promises';
import { encryptFile, importKemPublicKey, requirePublicKeyFingerprint } from './src/index.js';

async function encryptForRecipient({ publicKeyPath, trustedFingerprint, inputPath, outputPath }) {
  const recipient = importKemPublicKey(await readFile(publicKeyPath));
  requirePublicKeyFingerprint(recipient, trustedFingerprint);
  return encryptFile({ inputPath, outputPath, recipient,
    context: Buffer.from('my-app/documents/v1', 'utf8') });
}
```

Obtain `trustedFingerprint` through your application's authenticated configuration or an independently verified channel. Calculating it from the same untrusted public-key file would not establish trust. The format is `SHA256:` plus 64 hexadecimal digits over the full canonical DER SPKI; it is project-specific. The helper accepts either hex case, returns lowercase, and rejects abbreviated values or extra whitespace/newlines. It supports KEM public keys and signature verification keys; private and symmetric handles are rejected. CLI and SDK use the same checks. This does not add certificates, key discovery, revocation, or automatic trust to `encryptFile`.

```js
import { readFile } from 'node:fs/promises';
import { decryptFile, openPrivateKey } from './src/index.js';

// Obtain these bytes from your application's protected password input.
const password = await readFile('/private/location/recipient.password');
let unlocked;
try {
  unlocked = await openPrivateKey(
    await readFile('/private/location/recipient.vault'), password,
  );
  if (unlocked.kind !== 'kem') throw new Error('An encryption vault is required');
  await decryptFile({
    inputPath: '/private/location/document.pqc',
    outputPath: '/private/location/document.restored.txt',
    privateKey: unlocked.privateKey,
    context: Buffer.from('my-app/documents/v1', 'utf8'),
    aad: Buffer.from('document:42', 'utf8'),
  });
} finally {
  password.fill(0);
  if (unlocked?.kind === 'kem') unlocked.privateKey.destroy();
  if (unlocked?.kind === 'signature') unlocked.signingKey.destroy();
}
```

Replace these sample paths with your application's protected paths. For a generated-key example, run `npm run demo:files` or read [examples/file-roundtrip.mjs](examples/file-roundtrip.mjs). Primitive usage is in [examples/roundtrip.mjs](examples/roundtrip.mjs). Type declarations are in [src/index.d.ts](src/index.d.ts).

## Limits that matter

| Operation | Alpha limit or behavior |
|---|---|
| File encryption/decryption | 64 GiB maximum; streaming records, default 1 MiB chunks |
| Signing and low-level message operations | 16 MiB maximum input |
| File/KDF context | Explicit trusted argument, at most 512 bytes |
| Signature context | Required CLI argument, at most 255 bytes |
| AAD | At most 64 KiB |
| Vault KDF | Argon2id, 64 MiB, 3 passes, 4 lanes |
| Vault admission | 2 native KDF requests + 16 FIFO waiters per module instance; overflow rejects with `RESOURCE_LIMIT` |
| Vault cancellation | Optional `{ signal }` removes queued work; active native work completes before `ABORTED` |
| Output publication | No overwrite; requires same-volume hard-link support |

The encrypted file header reveals size, profile, chunk size, and recipient fingerprint. The format does not hide recipients or traffic metadata, provide forward secrecy, detect replay, or provide recovery after a key compromise. Anyone with a recipient's public key can create a valid encrypted file for that recipient.

During decryption, individually authenticated plaintext chunks are written to a staging file before the complete file is verified. The final output name appears only after complete verification. A crash or cleanup failure may leave staged plaintext behind. Use a trusted local output directory and protect disks, backups, swap, and snapshots separately. Hard-link support and inherited permissions can differ on cloud-synced or network filesystems. Read [the disk safety contract](docs/FILE-FORMAT.md#dosyaya-güvenli-yazma) before processing sensitive files.

`CLEANUP_FAILED` means a staging cleanup step reported an error. Remaining cleanup steps are still attempted. Inspect the output directory for staging data; the target may already have been published. Existing published targets are retained. The CLI prints a fixed message; library callers can inspect the underlying cleanup errors in the error's `cause`.

The process, runtime, and local filesystem are trusted. Handle separation does not isolate malicious code in the same JavaScript process. `destroy()` prevents future handle use and performs best-effort cleanup; it cannot guarantee erasure of every native allocation, memory copy, disk copy, or snapshot. Active native operations may complete after destruction or cancellation.

## Development and evidence

Run these commands from the source checkout:

```powershell
npm test
npm run typecheck
npm run check
npm run demo
npm run demo:files
npm run test:package
npm run fuzz:formats
npm run benchmark
```

Tests run offline after installation. They cover selected NIST ACVP vectors, AES-GCM vectors, an RFC 9106 Argon2id vector, cross-implementation checks with Noble, corruption and truncation rejection, key lifecycle behavior, and output handling. [The validation report](docs/DOGRULAMA.md) records actual results and limitations. Tests and benchmarks are not an independent security audit or complete ACVP certification. A configured CI workflow is not evidence of a successful remote run; consult the actual repository checks.

`fuzz:formats` runs a bounded mutation schedule against fresh local test containers. It checks rejection, absence of published/staged plaintext, and whether malformed structural inputs reach costly cryptographic operations. It is not coverage-guided fuzzing or a cryptographic proof; it uses test-only keys and temporary files, not user data.

`fixtures:refresh` is a maintainer-only command that downloads test vectors from a pinned NIST source; installation and tests do not invoke it. Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing format or cryptographic changes.

[Core contract](docs/CORE-SPEC.md) · [Vault specification](docs/KEY-VAULT.md) · [Research notes](docs/ARASTIRMA.md) · [Project comparison](docs/KARSILASTIRMA.md) · [Sources](docs/KAYNAKLAR.md) · [Roadmap](docs/KUTUPHANE-PLANI.md) · [Changelog](CHANGELOG.md)

The Turkish research documents record the initial literature review and its date. Current behavior is described by this README and the format specifications. New algorithms and combiners remain research work.

## License

Project-authored code is offered under [PolyForm Noncommercial License 1.0.0](LICENSE), SPDX identifier `PolyForm-Noncommercial-1.0.0`. Commercial use is not licensed under its general noncommercial-purpose grant. Personal use without an anticipated commercial application and the organizations listed in the license have explicit permitted-purpose provisions; the latter apply regardless of funding source or funding obligations. The license also preserves statutory fair-use rights. Read the [official terms](https://polyformproject.org/licenses/noncommercial/1.0.0) for the precise scope; this paragraph does not add to or replace them.

The source is provided under a noncommercial license. This is **source-available**, rather than [OSI open source](https://opensource.org/osd), because commercial use is restricted. Third-party code, runtime components, and test assets retain their own licenses and notices; see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). No npm registry publication is implied.

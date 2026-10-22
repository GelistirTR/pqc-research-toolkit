# Contributing

PQC Research Core is an experimental, independently unaudited cryptography toolkit. Useful contributions include reproducible bug reports, independent format analysis, interoperability cases, clearer documentation, and narrowly scoped fixes. Do not describe it as perfect, unbreakable, production-ready, FIPS certified, or proven secure against all future quantum attacks.

## License and rights

Project-authored code uses [PolyForm Noncommercial License 1.0.0](LICENSE), SPDX `PolyForm-Noncommercial-1.0.0`. By intentionally submitting a contribution for inclusion, you agree that it may be distributed under the project's existing license. Submit only work you are entitled to contribute under those terms. Identify third-party material and retain its license and notices. This does not replace third-party licenses or grant rights you do not hold.

The repository is source-available. Its noncommercial restrictions do not meet the OSI open source definition. Read the complete license, including its explicitly permitted purposes and organization provisions, before contributing or redistributing.

## Local checks

Use Node.js 24.22.1+ within the 24.x release line:

```powershell
npm ci --ignore-scripts
npm test
npm run typecheck
npm run check
npm run test:package
npm run fuzz:formats
```

Run the relevant demo when changing public usage: `npm run demo` for primitives and `npm run demo:files` for disk/vault behavior. Tests run offline after installation. Do not regenerate fixtures as routine setup. `npm run fixtures:refresh` downloads from the pinned NIST source and is reserved for reviewed fixture maintenance.

Describe the runtime, OS, and checks actually run. Do not claim remote CI passed until its run is available. A benchmark measures an environment, not security.

## Changes around the security contract

Read [SECURITY.md](SECURITY.md), [CORE-SPEC](docs/CORE-SPEC.md), [FILE-FORMAT](docs/FILE-FORMAT.md), and [KEY-VAULT](docs/KEY-VAULT.md) before changing cryptographic or disk behavior.

- Explain the concrete failure or use case and resulting public behavior.
- Preserve no-overwrite outputs, trusted-context requirements, strict key types, bounded parsing, and the CLI's trusted-fingerprint requirement for encryption.
- Treat wire-format, domain-separation, nonce, KDF, and algorithm-profile changes as protocol changes. Document the security argument and compatibility consequences before suggesting stability.
- Add a meaningful regression case for a defect; prefer independent fixtures and adversarial cases over tests that copy the implementation.
- Keep runtime cryptography on the documented provider. Do not add a homemade primitive or extra algorithm layer as an assumed security improvement.
- Update public declarations, examples, and documentation with user-visible changes.

Use synthetic or already-public test data. Never commit a real vault, password, private key, personal document, access token, or working-directory snapshot. Clearly mark public test keys and document their source. Do not include crash dumps or logs that may contain user data.

## Security reports

Follow [SECURITY.md](SECURITY.md). Do not put exploitable vulnerabilities, private keys, or real user data in a public issue or pull request. Use an available private security-reporting channel; if none is configured, contact the maintainer privately before disclosing details. Public issues are appropriate for ordinary non-sensitive bugs with minimal synthetic reproducers.

A contribution does not become independently audited by being merged. Review and passing tests are useful evidence, with the limits in [DOGRULAMA](docs/DOGRULAMA.md).

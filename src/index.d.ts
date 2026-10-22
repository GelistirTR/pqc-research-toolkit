declare const encryptionBrand: unique symbol;
declare const decryptionBrand: unique symbol;
declare const kemPublicBrand: unique symbol;
declare const kemPrivateBrand: unique symbol;
declare const encapsulatedBrand: unique symbol;
declare const decapsulatedBrand: unique symbol;
declare const signingBrand: unique symbol;
declare const verificationBrand: unique symbol;
export class CryptoError extends Error {
  constructor(code: string, message: string);
  readonly code: string;
}
export interface AeadPacket {
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
}
export interface EncryptionKey {
  readonly [encryptionBrand]: true;
  /** One successful attempt consumes the handle. No caller-supplied nonce. */
  encrypt(plaintext: Uint8Array, aad?: Uint8Array): AeadPacket;
  destroy(): void;
}
export interface DecryptionKey {
  readonly [decryptionBrand]: true;
  /** Returns plaintext only after tag verification. Does not prevent replay. */
  decrypt(packet: AeadPacket, aad?: Uint8Array): Uint8Array;
  destroy(): void;
}
export interface KemPublicKey { readonly [kemPublicBrand]: true; exportSpki(): Uint8Array; }
export interface KemPrivateKey {
  readonly [kemPrivateBrand]: true;
  publicKey(): KemPublicKey;
  decapsulate(ciphertext: Uint8Array): Promise<DecapsulatedSecret>;
  /** Releases this handle. In-flight calls may complete; no guaranteed physical erasure. */
  destroy(): void;
}
export interface EncapsulatedSecret {
  readonly [encapsulatedBrand]: true;
  /** Consumes the shared secret. context is required and must be trusted by the application. */
  deriveEncryptionKey(context: Uint8Array): { salt: Uint8Array; key: EncryptionKey };
  destroy(): void;
}
export interface DecapsulatedSecret {
  readonly [decapsulatedBrand]: true;
  deriveDecryptionKey(salt: Uint8Array, context: Uint8Array): DecryptionKey;
  destroy(): void;
}
export interface SigningKey {
  readonly [signingBrand]: true;
  verificationKey(): VerificationKey;
  sign(message: Uint8Array, context: Uint8Array): Promise<Uint8Array>;
  destroy(): void;
}
export interface VerificationKey {
  readonly [verificationBrand]: true;
  verify(message: Uint8Array, signature: Uint8Array, context: Uint8Array): Promise<boolean>;
  exportSpki(): Uint8Array;
}
export function generateKemKeyPair(): Promise<{ publicKey: KemPublicKey; privateKey: KemPrivateKey }>;
export function generateSigningKeyPair(): Promise<{ verificationKey: VerificationKey; signingKey: SigningKey }>;
export function encapsulate(key: KemPublicKey): Promise<{ ciphertext: Uint8Array; secret: EncapsulatedSecret }>;
export function importKemPublicKey(spki: Uint8Array): KemPublicKey;
export function importVerificationKey(spki: Uint8Array): VerificationKey;
/** Project-specific SHA256:lowercase-hex digest of canonical DER SPKI. */
export function publicKeyFingerprint(key: KemPublicKey | VerificationKey): string;
/** Throws on malformed/mismatched expected pin; does not authenticate its source. */
export function requirePublicKeyFingerprint(key: KemPublicKey | VerificationKey, expected: string): string;
export function generateSymmetricKeyPair(): { encryptionKey: EncryptionKey; decryptionKey: DecryptionKey };
export interface PasswordHashOptions { signal?: AbortSignal; }
/** Standard unkeyed Argon2id PHC record, fixed current profile and random salt. Input bytes are not normalized. */
export function hashPassword(password: Uint8Array, options?: PasswordHashOptions): Promise<string>;
/** False for a wrong password; malformed/unsupported records throw before KDF. */
export function verifyPassword(record: string, password: Uint8Array, options?: PasswordHashOptions): Promise<boolean>;
/** Checks only the bounded allowlisted record profile, not the password. */
export function passwordHashNeedsRehash(record: string): boolean;
export const passwordHashProfile: Readonly<{
  algorithm: string; version: number; memoryKiB: number; passes: number; parallelism: number;
  saltBytes: number; hashBytes: number; minPasswordBytes: number; maxPasswordBytes: number;
  maxConcurrentKdf: number; maxQueuedKdf: number;
  acceptedVerificationProfiles: readonly Readonly<{ memoryKiB: number; passes: number; parallelism: number }>[];
}>;
export interface VaultOptions {
  /** Queued work is removed; active native work must finish before rejecting. */
  signal?: AbortSignal;
}
export function sealPrivateKey(key: KemPrivateKey | SigningKey, passphrase: Uint8Array, options?: VaultOptions): Promise<Uint8Array>;
export type UnlockedPrivateKey =
  | { kind: 'kem'; privateKey: KemPrivateKey; publicKey: KemPublicKey }
  | { kind: 'signature'; signingKey: SigningKey; verificationKey: VerificationKey };
export interface OpenVaultOptions extends VaultOptions {
  /** Default rejects combined seed+expanded keys. Migration opt-in does not verify companion consistency. */
  legacyKeyPolicy?: 'reject-combined' | 'seed-authoritative';
}
export function openPrivateKey(vault: Uint8Array, passphrase: Uint8Array, options?: OpenVaultOptions): Promise<UnlockedPrivateKey>;
export const vaultProfile: Readonly<{
  version: number; kdf: string; memoryKiB: number; passes: number; parallelism: number;
  saltBytes: number; minPassphraseBytes: number; maxPassphraseBytes: number; maxVaultBytes: number;
  /** Per loaded module instance; excess work rejects with RESOURCE_LIMIT. */
  maxConcurrentKdf: number; maxQueuedKdf: number;
}>;
export interface FileOptions {
  inputPath: string;
  /** Explicit output path; existing outputs are never replaced. Requires hard-link support. */
  outputPath: string;
  /** Application-supplied, trusted expected context, not read from the encrypted file. */
  context: Uint8Array;
  aad?: Uint8Array;
  signal?: AbortSignal;
}
export interface EncryptFileOptions extends FileOptions {
  recipient: KemPublicKey;
  chunkSize?: number;
}
export interface DecryptFileOptions extends FileOptions { privateKey: KemPrivateKey; }
export interface FileResult { bytes: number; chunks: number; }
export interface InspectionOptions { signal?: AbortSignal; }
export interface OperationPoolOptions { maxConcurrent?: number; maxQueued?: number; }
export interface OperationPool {
  /** Captured inputs belong to the caller. Forward signal to the actual operation. */
  run<T>(task: (signal: AbortSignal | undefined) => T | PromiseLike<T>, options?: { signal?: AbortSignal }): Promise<T>;
  /** Reject queued/future work; active tasks retain their slot until they settle. */
  close(): void;
  readonly stats: Readonly<{ active: number; queued: number; maxConcurrent: number; maxQueued: number; closed: boolean }>;
}
/** Opt-in per-instance admission control. Defaults 2 active / 16 queued; not a global memory budget. */
export function createOperationPool(options?: OperationPoolOptions): OperationPool;
interface ContainerHeaderClaims {
  /** Always false: structural inspection does not authenticate any returned claim. */
  readonly authenticated: false;
  readonly formatVersion: 1;
  readonly containerBytes: number;
  readonly kdf: string;
  readonly aead: 'AES-256-GCM';
}
export type ContainerInspection =
  | Readonly<ContainerHeaderClaims & {
    kind: 'encrypted-file'; declaredPlaintextBytes: number; chunkBytes: number; chunks: number;
    recipientFingerprint: string; kem: 'ML-KEM-1024';
  }>
  | Readonly<ContainerHeaderClaims & {
    kind: 'key-vault'; keyKind: 'kem' | 'signature'; memoryKiB: number; passes: number; parallelism: number;
  }>;
/** Reads bounded public headers only. Success does not verify tags, contents, password or identity. */
export function inspectContainer(inputPath: string, options?: InspectionOptions): Promise<ContainerInspection>;
export function encryptFile(options: EncryptFileOptions): Promise<FileResult>;
export function decryptFile(options: DecryptFileOptions): Promise<FileResult>;
export const fileProfile: Readonly<{
  version: number; suite: number; headerBytes: number; defaultChunkBytes: number;
  minChunkBytes: number; maxChunkBytes: number; maxFileBytes: number;
}>;
export const profile: Readonly<{
  version: string; status: string; kem: string; signature: string; kdf: string; aead: string;
  maxMessageBytes: number; maxAadBytes: number; maxKdfContextBytes: number;
  maxSignatureContextBytes: number; encryptionUsesPerHandle: number;
}>;

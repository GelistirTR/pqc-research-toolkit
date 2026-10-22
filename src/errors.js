export class CryptoError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'CryptoError';
    this.code = code;
  }
}

export function fail(code, message) {
  throw new CryptoError(code, message);
}

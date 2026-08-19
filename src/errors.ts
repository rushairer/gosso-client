/**
 * Base error class for all Gosso SDK errors.
 */
export class GossoError extends Error {
  public readonly code: string;
  public readonly cause?: unknown;

  constructor(message: string, code = 'GOSSO_ERROR', cause?: unknown) {
    super(message);
    this.name = 'GossoError';
    this.code = code;
    this.cause = cause;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when a Gosso or same-envelope application API returns an error.
 */
export class ApiError extends GossoError {
  public readonly status: number;

  constructor(message: string, status: number, code = 'API_ERROR', cause?: unknown) {
    super(message, code, cause);
    this.name = 'ApiError';
    this.status = status;
  }
}

/**
 * Thrown when user authentication fails or credentials are missing/invalid.
 */
export class AuthenticationError extends GossoError {
  constructor(message: string, code = 'AUTH_ERROR', cause?: unknown) {
    super(message, code, cause);
    this.name = 'AuthenticationError';
  }
}

/**
 * Thrown when token or session refresh fails or refresh lock cannot be acquired.
 */
export class TokenRefreshError extends GossoError {
  constructor(message: string, code = 'TOKEN_REFRESH_ERROR', cause?: unknown) {
    super(message, code, cause);
    this.name = 'TokenRefreshError';
  }
}

/**
 * Thrown when OAuth2 state does not match, indicating a potential CSRF attack.
 */
export class CsrfError extends GossoError {
  constructor(message = 'State mismatch. Potential CSRF attack.', code = 'CSRF_MISMATCH') {
    super(message, code);
    this.name = 'CsrfError';
  }
}

/**
 * Thrown when the browser Web Crypto API is unavailable or cryptographic operation fails.
 */
export class CryptoError extends GossoError {
  constructor(message = 'Web Crypto API (crypto.subtle) is required for cryptographic operations.', code = 'CRYPTO_UNAVAILABLE') {
    super(message, code);
    this.name = 'CryptoError';
  }
}

/**
 * Thrown when WebAuthn Passkey registration or authentication is cancelled or fails.
 */
export class PasskeyError extends GossoError {
  constructor(message: string, code = 'PASSKEY_ERROR', cause?: unknown) {
    super(message, code, cause);
    this.name = 'PasskeyError';
  }
}

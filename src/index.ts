export type {
  GossoClientConfig,
  TokenResponse,
  UserProfile,
  SessionSnapshot,
  SessionListener,
  LoginResult,
  MfaStatus,
  MfaEnrollment,
  SessionInfo,
  PasskeyInfo,
  ApiEnvelope,
  RefreshLock,
  BrowserLockManager,
  NavigatorWithLocks,
} from './types.js';

export {
  GossoError,
  AuthenticationError,
  TokenRefreshError,
  CsrfError,
  CryptoError,
  PasskeyError,
} from './errors.js';

export {
  normalizeBaseUrl,
  generateRandomString,
  bufferToBase64URL,
  base64URLToBuffer,
  cookieSecureAttribute,
  getCookieName,
  readCookie,
  CookieSessionRefreshError,
  readClaimsFromAccessToken,
  readRolesFromAccessToken,
  readScopeFromAccessToken,
  hasAdminAccess,
  parseRefreshLock,
  generateRefreshOwner,
  parseJsonEnvelope,
} from './utils.js';

export { generateCodeChallenge } from './pkce.js';

export {
  defaultConfig,
  createGossoClient,
} from './client.js';

export type { GossoClient } from './client.js';

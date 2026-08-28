export interface GossoClientConfig<TProfile = UserProfile> {
  issuer: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  postLoginDefaultPath: string;
  loginPath: string;
  storagePrefix: string;
  /** Use HttpOnly Gosso cookies instead of exposing tokens to JavaScript. */
  sessionMode?: "token" | "cookie";
  /** Additional exact origins that apiFetch may contact. */
  allowedApiOrigins?: readonly string[];
  /** Same-origin endpoint returning {data:{sub,roles,scope}} for UI authorization. */
  sessionProfileEndpoint?: string;
  /** CSRF cookie used by same-origin application API requests in cookie session mode. */
  csrfCookieName?: string;
  /** Refresh a Cookie Session after a 401 from protected GOSSO APIs as well. */
  refreshIdentityRequests?: boolean;
  fetchImpl?: typeof fetch;
  onAuthRequired?: () => void;
  onSessionChanged?: (snapshot: SessionSnapshot<TProfile>) => void;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  id_token?: string;
  expires_in: number;
}

export interface CookieSessionResponse {
  expires_in?: number;
  scope?: string;
}

export type AuthenticationResult = TokenResponse | CookieSessionResponse;

export type AuthCallbackResult =
  | { sessionMode: "cookie"; redirectTo: string }
  | { sessionMode: "token"; redirectTo: string; tokenSet: TokenResponse };

export interface UserProfile {
  sub: string;
  name?: string;
  preferred_username?: string;
  email?: string;
  roles?: string[];
  scope?: string;
  [key: string]: unknown;
}

export interface SessionSnapshot<TProfile = UserProfile> {
  accessToken: string | null;
  refreshToken: string | null;
  profile: TProfile | null;
  loggedIn: boolean;
  isAdmin: boolean;
}

/** Receives the current state after this client changes its local session view. */
export type SessionListener<TProfile = UserProfile> = (
  snapshot: SessionSnapshot<TProfile>,
) => void;

export interface LoginResult {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  requires_mfa?: boolean;
  mfa_token?: string;
  [key: string]: unknown;
}

export interface MfaStatus {
  enabled: boolean;
  types: string[];
}

export interface MfaEnrollment {
  secret: string;
  otpauth_url: string;
}

export interface SessionInfo {
  id: string;
  ip: string;
  user_agent: string;
  created_at: string;
  last_active_at: string;
}

export interface PasskeyInfo {
  id: string;
  name: string;
  created_at?: string;
}

export interface ApiEnvelope<T> {
  data?: T;
  message?: string;
  code?: number | string;
  error?: string;
  error_description?: string;
}

export interface RefreshLock {
  owner: string;
  expiresAt: number;
}

export interface BrowserLockManager {
  request<T>(
    name: string,
    options: { mode: "exclusive" },
    callback: () => T | Promise<T>,
  ): Promise<T>;
}

export type NavigatorWithLocks = Navigator & { locks?: BrowserLockManager };

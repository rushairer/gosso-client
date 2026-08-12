export interface GossoClientConfig {
  issuer: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  postLoginDefaultPath: string;
  loginPath: string;
  storagePrefix: string;
  /** Use HttpOnly Gosso cookies instead of exposing tokens to JavaScript. */
  sessionMode?: 'token' | 'cookie';
  /** Same-origin endpoint returning {data:{sub,roles,scope}} for UI authorization. */
  sessionProfileEndpoint?: string;
  /** CSRF cookie used by same-origin application API requests in cookie session mode. */
  csrfCookieName?: string;
  fetchImpl?: typeof fetch;
  onAuthRequired?: () => void;
  onSessionChanged?: (snapshot: SessionSnapshot) => void;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  id_token?: string;
  expires_in: number;
}

export interface UserProfile {
  sub: string;
  name?: string;
  preferred_username?: string;
  email?: string;
  roles?: string[];
  scope?: string;
}

export interface SessionSnapshot {
  accessToken: string | null;
  refreshToken: string | null;
  profile: UserProfile | null;
  loggedIn: boolean;
  isAdmin: boolean;
}

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

interface ApiEnvelope<T> {
  data?: T;
  message?: string;
}

interface RefreshLock {
  owner: string;
  expiresAt: number;
}

interface BrowserLockManager {
  request<T>(name: string, options: { mode: 'exclusive' }, callback: () => T | Promise<T>): Promise<T>;
}

type NavigatorWithLocks = Navigator & { locks?: BrowserLockManager };

const REFRESH_LOCK_TTL_MS = 15_000;
const REFRESH_WAIT_TIMEOUT_MS = 20_000;
const REFRESH_WAIT_POLL_MS = 100;
const REFRESH_WEB_LOCK_NAME = 'gosso-auth-refresh';

const defaultConfig: Pick<GossoClientConfig, 'scope' | 'postLoginDefaultPath' | 'loginPath' | 'storagePrefix'> = {
  scope: 'openid profile email',
  postLoginDefaultPath: '/',
  loginPath: '/login',
  storagePrefix: 'gosso',
};

function normalizeBaseUrl(url: string): string {
  return url.replace(/\/+$/, '');
}

export function generateRandomString(length: number): string {
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  let text = '';
  const cryptoObj = (typeof window !== 'undefined' ? window.crypto : null) || (typeof globalThis !== 'undefined' ? globalThis.crypto : null);
  if (cryptoObj && cryptoObj.getRandomValues) {
    const array = new Uint8Array(length);
    cryptoObj.getRandomValues(array);
    for (let i = 0; i < length; i += 1) {
      text += possible.charAt(array[i] % possible.length);
    }
  } else {
    // Fallback for environments lacking CSPRNG
    for (let i = 0; i < length; i += 1) {
      text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
  }
  return text;
}

async function generateCodeChallenge(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier);
  const digest = await window.crypto.subtle.digest('SHA-256', data);
  return bufferToBase64URL(digest);
}

function cookieSecureAttribute(): string {
  return typeof location !== 'undefined' && location.protocol === 'https:' ? '; Secure' : '';
}

function getCookieName(baseName: string): string {
  return typeof location !== 'undefined' && location.protocol === 'https:' ? `__Secure-${baseName}` : baseName;
}

function readCSRFToken(preferredName?: string): string | null {
	for (const raw of document.cookie.split(';')) {
		const [name, ...value] = raw.trim().split('=');
		if (name === preferredName || name === '__Host-csrf_token' || name === 'csrf_token' || name === 'blog_csrf_token') return decodeURIComponent(value.join('='));
	}
	return null;
}

function readClaimsFromAccessToken(accessToken: string): Record<string, unknown> | null {
  try {
    const payloadBase64 = accessToken.split('.')[1];
    const base64 = payloadBase64.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
    return JSON.parse(decodeURIComponent(escape(atob(padded))));
  } catch {
    return null;
  }
}

function readRolesFromAccessToken(accessToken: string): string[] | undefined {
  const payload = readClaimsFromAccessToken(accessToken);
  return Array.isArray(payload?.roles) ? (payload.roles as string[]) : undefined;
}

function readScopeFromAccessToken(accessToken: string): string | undefined {
  const payload = readClaimsFromAccessToken(accessToken);
  return typeof payload?.scope === 'string' ? payload.scope : undefined;
}

function hasAdminAccess(profile: UserProfile | null, accessToken: string | null): boolean {
  const hasAdminRole = profile?.roles?.includes('admin') || false;
  const scope = accessToken ? readScopeFromAccessToken(accessToken) : profile?.scope;
  return hasAdminRole && Boolean(scope?.split(/\s+/).includes('admin'));
}

function parseRefreshLock(raw: string | null): RefreshLock | null {
  if (!raw) return null;
  try {
    const lock = JSON.parse(raw) as Partial<RefreshLock>;
    if (typeof lock.owner !== 'string' || typeof lock.expiresAt !== 'number') {
      return null;
    }
    return { owner: lock.owner, expiresAt: lock.expiresAt };
  } catch {
    return null;
  }
}

function generateRefreshOwner(): string {
  if (window.crypto?.randomUUID) {
    return window.crypto.randomUUID();
  }
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

async function parseJsonEnvelope<T>(response: Response, fallbackMessage: string): Promise<T> {
  const body = (await response.json()) as ApiEnvelope<T>;
  if (!response.ok) {
    throw new Error(body.message || fallbackMessage);
  }
  return body.data as T;
}

export function bufferToBase64URL(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64URLToBuffer(base64URLString: string): ArrayBuffer {
  const base64 = base64URLString.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export function createGossoClient(inputConfig: GossoClientConfig) {
  const config = {
    ...defaultConfig,
    ...inputConfig,
    issuer: normalizeBaseUrl(inputConfig.issuer),
  };
  const cookieSession = config.sessionMode === 'cookie';
  const flowStorage = cookieSession ? sessionStorage : localStorage;
  const fetcher = config.fetchImpl || fetch.bind(window);
  const key = (name: string) => `${config.storagePrefix}:${name}`;
  const storageKeys = {
    accessToken: key('access_token'),
    refreshToken: key('refresh_token'),
    userProfile: key('user_profile'),
    pkceVerifier: key('pkce_verifier'),
    authState: key('auth_state'),
    postLoginRedirect: key('post_login_redirect'),
    tokenIssuedAt: key('token_issued_at'),
    tokenExpiresIn: key('token_expires_in'),
    refreshLock: key('auth_refresh_lock'),
  };

  let refreshPromise: Promise<string> | null = null;

  const setCookie = (name: string, value: string, maxAgeSeconds: number) => {
    const cookieName = getCookieName(name);
    document.cookie = `${cookieName}=${value}; path=/; max-age=${maxAgeSeconds}; SameSite=Lax${cookieSecureAttribute()}`;
  };

  const deleteCookie = (name: string) => {
    const cookieName = getCookieName(name);
    document.cookie = `${cookieName}=; path=/; max-age=-1; SameSite=Lax`;
  };

  const readProfile = (): UserProfile | null => {
    const storage = cookieSession ? sessionStorage : localStorage;
    const profile = storage.getItem(storageKeys.userProfile);
    if (!profile) return null;
    try {
      return JSON.parse(profile) as UserProfile;
    } catch {
      return null;
    }
  };

  const getAccessToken = (): string | null => cookieSession ? null : localStorage.getItem(storageKeys.accessToken);
  const getRefreshToken = (): string | null => cookieSession ? null : localStorage.getItem(storageKeys.refreshToken);

  const getSnapshot = (): SessionSnapshot => {
    const accessToken = getAccessToken();
    const refreshToken = getRefreshToken();
    const profile = readProfile();
    return {
      accessToken,
      refreshToken,
      profile,
      loggedIn: cookieSession ? Boolean(profile) : Boolean(accessToken),
      isAdmin: hasAdminAccess(profile, accessToken),
    };
  };

  const emitSessionChanged = () => {
    config.onSessionChanged?.(getSnapshot());
  };

  const saveTokenSet = (data: TokenResponse | { access_token: string; refresh_token?: string; expires_in?: number }) => {
    if (cookieSession) { emitSessionChanged(); return; }
    localStorage.setItem(storageKeys.accessToken, data.access_token);
    if (data.refresh_token) {
      localStorage.setItem(storageKeys.refreshToken, data.refresh_token);
    }
    localStorage.setItem(storageKeys.tokenIssuedAt, String(Date.now()));
    localStorage.setItem(storageKeys.tokenExpiresIn, String(data.expires_in || 900));
    setCookie('access_token', data.access_token, data.expires_in || 900);
    emitSessionChanged();
  };

  const clear = () => {
    Object.values(storageKeys).forEach((storageKey) => localStorage.removeItem(storageKey));
    Object.values(storageKeys).forEach((storageKey) => sessionStorage.removeItem(storageKey));
    deleteCookie('access_token');
    emitSessionChanged();
  };

  const redirectToLogin = () => {
    if (config.onAuthRequired) {
      config.onAuthRequired();
      return;
    }
    window.location.href = config.loginPath;
  };

  const tryAcquireRefreshLock = (owner: string): boolean => {
    const now = Date.now();
    const current = parseRefreshLock(localStorage.getItem(storageKeys.refreshLock));
    if (current && current.expiresAt > now && current.owner !== owner) {
      return false;
    }
    const nextLock: RefreshLock = { owner, expiresAt: now + REFRESH_LOCK_TTL_MS };
    localStorage.setItem(storageKeys.refreshLock, JSON.stringify(nextLock));
    return parseRefreshLock(localStorage.getItem(storageKeys.refreshLock))?.owner === owner;
  };

  const releaseRefreshLock = (owner: string) => {
    const current = parseRefreshLock(localStorage.getItem(storageKeys.refreshLock));
    if (!current || current.owner === owner || current.expiresAt <= Date.now()) {
      localStorage.removeItem(storageKeys.refreshLock);
    }
  };

  const waitForRefreshFromAnotherContext = (previousRefreshToken: string): Promise<string | null> => {
    const startedAt = Date.now();
    return new Promise((resolve) => {
      let settled = false;
      let intervalId: number | undefined;
      let timeoutId: number | undefined;
      const finish = (token: string | null) => {
        if (settled) return;
        settled = true;
        if (intervalId !== undefined) window.clearInterval(intervalId);
        if (timeoutId !== undefined) window.clearTimeout(timeoutId);
        window.removeEventListener('storage', check);
        resolve(token);
      };
      const check = () => {
        const accessToken = getAccessToken();
        const refreshToken = getRefreshToken();
        const issuedAt = Number(localStorage.getItem(storageKeys.tokenIssuedAt));
        if (accessToken && refreshToken && refreshToken !== previousRefreshToken && issuedAt >= startedAt) {
          finish(accessToken);
          return;
        }
        const lock = parseRefreshLock(localStorage.getItem(storageKeys.refreshLock));
        if (!lock || lock.expiresAt <= Date.now()) {
          finish(null);
        }
      };
      window.addEventListener('storage', check);
      intervalId = window.setInterval(check, REFRESH_WAIT_POLL_MS);
      timeoutId = window.setTimeout(() => finish(null), REFRESH_WAIT_TIMEOUT_MS);
      check();
    });
  };

  const requestBrowserRefreshLock = async (callback: () => Promise<string>): Promise<string> => {
    const locks = (navigator as NavigatorWithLocks).locks;
    if (!locks) return callback();
    return locks.request(REFRESH_WEB_LOCK_NAME, { mode: 'exclusive' }, callback);
  };

  const performTokenRefresh = async (previousRefreshToken: string): Promise<string> => {
    const latestRefreshToken = getRefreshToken();
    if (!latestRefreshToken) throw new Error('No refresh token found');
    if (latestRefreshToken !== previousRefreshToken) {
      const latestAccessToken = getAccessToken();
      if (latestAccessToken) return latestAccessToken;
    }
    const response = await fetcher(`${config.issuer}/api/v1/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: latestRefreshToken }),
    });
    const data = await parseJsonEnvelope<TokenResponse>(response, 'Token refresh failed');
    saveTokenSet(data);
    return data.access_token;
  };

  const refreshAccessToken = async (): Promise<string> => {
    if (refreshPromise) return refreshPromise;
    refreshPromise = (async () => {
      const owner = generateRefreshOwner();
      let lockAcquired = false;
      try {
        const refreshToken = getRefreshToken();
        if (!refreshToken) throw new Error('No refresh token found');
        if ((navigator as NavigatorWithLocks).locks) {
          return requestBrowserRefreshLock(() => performTokenRefresh(refreshToken));
        }
        lockAcquired = tryAcquireRefreshLock(owner);
        if (!lockAcquired) {
          const tokenFromPeer = await waitForRefreshFromAnotherContext(refreshToken);
          if (tokenFromPeer) return tokenFromPeer;
          lockAcquired = tryAcquireRefreshLock(owner);
          if (!lockAcquired) throw new Error('Token refresh is already in progress');
        }
        return performTokenRefresh(refreshToken);
      } finally {
        if (lockAcquired) releaseRefreshLock(owner);
        refreshPromise = null;
      }
    })();
    return refreshPromise;
  };

  const fetchUserProfile = async (accessToken = getAccessToken()): Promise<UserProfile> => {
    if (cookieSession) {
      const [identity, session] = await Promise.all([
        fetcher(`${config.issuer}/oidc/userinfo`, { credentials: 'same-origin' }),
        config.sessionProfileEndpoint ? fetcher(config.sessionProfileEndpoint, { credentials: 'same-origin' }) : Promise.resolve(null),
      ]);
      if (!identity.ok || (session && !session.ok)) throw new Error('Failed to fetch user profile');
      const data = await identity.json() as UserProfile;
      if (session) Object.assign(data, (await session.json() as ApiEnvelope<Partial<UserProfile>>).data || {});
      sessionStorage.setItem(storageKeys.userProfile, JSON.stringify(data));
      emitSessionChanged();
      return data;
    }
    if (!accessToken) throw new Error('No access token found');
    const response = await fetcher(`${config.issuer}/oidc/userinfo`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!response.ok) throw new Error('Failed to fetch user profile');
    const data = (await response.json()) as UserProfile;
    const roles = readRolesFromAccessToken(accessToken);
    if (roles) data.roles = roles;
    const scope = readScopeFromAccessToken(accessToken);
    if (scope) data.scope = scope;
    localStorage.setItem(storageKeys.userProfile, JSON.stringify(data));
    emitSessionChanged();
    return data;
  };

  const apiFetch = async (url: string, options: RequestInit = {}): Promise<Response> => {
    if (cookieSession) {
      const headers = new Headers(options.headers || {});
      const issuerRequest = url.startsWith(`${config.issuer}/`);
      if (!['GET', 'HEAD', 'OPTIONS'].includes((options.method || 'GET').toUpperCase()) && !headers.has('X-CSRF-Token')) {
        const csrf = readCSRFToken(issuerRequest ? undefined : config.csrfCookieName);
        if (csrf) headers.set('X-CSRF-Token', csrf);
      }
      let response = await fetcher(url, { ...options, headers, credentials: 'same-origin' });
      if (response.status === 401 && !issuerRequest) {
        const csrf = readCSRFToken();
        const refreshResponse = await fetcher(`${config.issuer}/api/v1/auth/refresh`, {
          method: 'POST',
          headers: csrf ? { 'X-CSRF-Token': csrf, 'X-Gosso-Cookie-Session': '1' } : { 'X-Gosso-Cookie-Session': '1' },
          credentials: 'same-origin',
        });
        if (refreshResponse.ok) response = await fetcher(url, { ...options, headers, credentials: 'same-origin' });
      }
      if (response.status === 401) clear();
      return response;
    }
    let token = getAccessToken();
    if (!token) {
      redirectToLogin();
      return new Response(null, { status: 401 });
    }
    const issuedAt = Number(localStorage.getItem(storageKeys.tokenIssuedAt));
    const expiresIn = Number(localStorage.getItem(storageKeys.tokenExpiresIn)) || 900;
    if (issuedAt && Date.now() - issuedAt > expiresIn * 1000) {
      try {
        token = await refreshAccessToken();
      } catch {
        clear();
        redirectToLogin();
        return new Response(null, { status: 401 });
      }
    }
    const headers = new Headers(options.headers || {});
    if (token && !headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${token}`);
    }
    let response = await fetcher(url, { ...options, headers });
    if (response.status === 401 && getRefreshToken()) {
      try {
        const freshToken = await refreshAccessToken();
        headers.set('Authorization', `Bearer ${freshToken}`);
        response = await fetcher(url, { ...options, headers });
      } catch {
        clear();
        redirectToLogin();
      }
    }
    return response;
  };

  const redirectToAuthorize = async (customRedirectUri?: string) => {
    const verifier = generateRandomString(64);
    const state = generateRandomString(16);
    flowStorage.setItem(storageKeys.pkceVerifier, verifier);
    flowStorage.setItem(storageKeys.authState, state);
    if (customRedirectUri) {
      flowStorage.setItem(storageKeys.postLoginRedirect, customRedirectUri);
    }
    const challenge = await generateCodeChallenge(verifier);
    const authUrl = new URL(`${config.issuer}/oauth2/authorize`);
    authUrl.searchParams.append('client_id', config.clientId);
    authUrl.searchParams.append('response_type', 'code');
    authUrl.searchParams.append('redirect_uri', config.redirectUri);
    authUrl.searchParams.append('scope', config.scope);
    authUrl.searchParams.append('code_challenge', challenge);
    authUrl.searchParams.append('code_challenge_method', 'S256');
    authUrl.searchParams.append('state', state);
    window.location.href = authUrl.toString();
  };

  const exchangeCodeForToken = async (code: string, state: string): Promise<TokenResponse> => {
    const savedState = flowStorage.getItem(storageKeys.authState);
    const verifier = flowStorage.getItem(storageKeys.pkceVerifier);
    if (state !== savedState) throw new Error('State mismatch. Potential CSRF attack.');
    if (!verifier) throw new Error('PKCE verifier not found. Authentication flow expired.');
    const body = new URLSearchParams();
    body.append('grant_type', 'authorization_code');
    body.append('client_id', config.clientId);
    body.append('code', code);
    body.append('code_verifier', verifier);
    body.append('redirect_uri', config.redirectUri);
    const response = await fetcher(`${config.issuer}/oauth2/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...(cookieSession ? { 'X-Gosso-Cookie-Session': '1' } : {}) },
      body: body.toString(),
      credentials: 'same-origin',
    });
    if (!response.ok) {
      throw new Error(`Token exchange failed: ${await response.text()}`);
    }
    const data = (await response.json()) as TokenResponse;
    if (!cookieSession) saveTokenSet(data);
    flowStorage.removeItem(storageKeys.pkceVerifier);
    flowStorage.removeItem(storageKeys.authState);
    return data;
  };

  const handleRedirectCallback = async (code: string, state: string): Promise<{ tokenSet: TokenResponse; redirectTo: string }> => {
    const tokenSet = await exchangeCodeForToken(code, state);
    await fetchUserProfile(cookieSession ? undefined : tokenSet.access_token);
    const redirectTo = flowStorage.getItem(storageKeys.postLoginRedirect) || config.postLoginDefaultPath;
    flowStorage.removeItem(storageKeys.postLoginRedirect);
    return { tokenSet, redirectTo };
  };

  const logout = async (redirectTo = '/') => {
    if (cookieSession) {
      const csrf = readCSRFToken();
      try { await fetcher(`${config.issuer}/api/v1/auth/logout`, { method: 'POST', headers: csrf ? { 'X-CSRF-Token': csrf } : {}, credentials: 'same-origin', keepalive: true }); }
      finally { clear(); window.location.href = redirectTo; }
      return;
    }
    const accessToken = getAccessToken();
    try {
      if (accessToken) {
        await fetcher(`${config.issuer}/api/v1/auth/logout`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${accessToken}` },
          credentials: 'same-origin',
          keepalive: true,
        });
      }
    } finally {
      clear();
      window.location.href = redirectTo;
    }
  };

  const loginWithPassword = async (username: string, password: string): Promise<LoginResult> => {
    const response = await fetcher(`${config.issuer}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(cookieSession ? { 'X-Gosso-Cookie-Session': '1' } : {}) },
      body: JSON.stringify({ username, password }),
      credentials: 'same-origin',
    });
    const result = await parseJsonEnvelope<LoginResult>(response, 'Login failed');
    if (!cookieSession && result.access_token) {
      saveTokenSet(result as TokenResponse);
      await fetchUserProfile(result.access_token);
    } else if (cookieSession && !result.requires_mfa) {
      await fetchUserProfile();
    }
    return result;
  };

  const verifyMfa = async (mfaToken: string, code: string, type: 'totp' | 'passkey' = 'totp'): Promise<TokenResponse> => {
    const response = await fetcher(`${config.issuer}/api/v1/auth/mfa/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(cookieSession ? { 'X-Gosso-Cookie-Session': '1' } : {}) },
      body: JSON.stringify({ mfa_token: mfaToken, code, type }),
      credentials: 'same-origin',
    });
    const data = await parseJsonEnvelope<TokenResponse>(response, 'MFA verification failed');
    if (!cookieSession) saveTokenSet(data);
    await fetchUserProfile(cookieSession ? undefined : data.access_token);
    return data;
  };

  const loginWithPasskey = async (): Promise<TokenResponse> => {
    const beginRes = await fetcher(`${config.issuer}/api/v1/passkey/login/begin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
      credentials: 'same-origin',
    });
    const begin = await parseJsonEnvelope<{ options: PublicKeyCredentialRequestOptions; request_id: string }>(
      beginRes,
      'Failed to begin passkey login'
    );
    const options = {
      ...begin.options,
      challenge: base64URLToBuffer(begin.options.challenge as unknown as string),
      allowCredentials: (begin.options.allowCredentials || []).map((cred) => ({
        ...cred,
        id: base64URLToBuffer(cred.id as unknown as string),
      })),
    };
    const assertion = (await navigator.credentials.get({ publicKey: options })) as PublicKeyCredential | null;
    if (!assertion?.response) throw new Error('Passkey authentication cancelled or failed');
    const assertionResponse = assertion.response as AuthenticatorAssertionResponse;
    const completeRes = await fetcher(`${config.issuer}/api/v1/passkey/login/complete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(cookieSession ? { 'X-Gosso-Cookie-Session': '1' } : {}) },
      body: JSON.stringify({
        request_id: begin.request_id,
        id: assertion.id,
        rawId: bufferToBase64URL(assertion.rawId),
        type: assertion.type,
        response: {
          clientDataJSON: bufferToBase64URL(assertionResponse.clientDataJSON),
          authenticatorData: bufferToBase64URL(assertionResponse.authenticatorData),
          signature: bufferToBase64URL(assertionResponse.signature),
          userHandle: assertionResponse.userHandle ? bufferToBase64URL(assertionResponse.userHandle) : null,
        },
      }),
    });
    const data = await parseJsonEnvelope<TokenResponse>(completeRes, 'Passkey login failed');
    if (!cookieSession) saveTokenSet(data);
    await fetchUserProfile(cookieSession ? undefined : data.access_token);
    return data;
  };

  const updateProfile = async (displayName: string) => {
    const response = await apiFetch(`${config.issuer}/api/v1/auth/profile`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ display_name: displayName }),
    });
    await parseJsonEnvelope<unknown>(response, 'Failed to update profile');
    return fetchUserProfile();
  };

  const changePassword = async (currentPassword: string, newPassword: string) => {
    const response = await apiFetch(`${config.issuer}/api/v1/auth/password/change`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    });
    await parseJsonEnvelope<unknown>(response, 'Failed to change password');
  };

  const requestEmailChange = async (newEmail: string, password: string) => {
    const response = await apiFetch(`${config.issuer}/api/v1/auth/profile/email/change/request`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ new_email: newEmail, password }),
    });
    await parseJsonEnvelope<unknown>(response, 'Failed to request email verification code');
  };

  const confirmEmailChange = async (newEmail: string, code: string) => {
    const response = await apiFetch(`${config.issuer}/api/v1/auth/profile/email/change/confirm`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ new_email: newEmail, code }),
    });
    await parseJsonEnvelope<unknown>(response, 'Failed to confirm email change');
    return fetchUserProfile();
  };

  const getMfaStatus = async (): Promise<MfaStatus> => {
    const response = await apiFetch(`${config.issuer}/api/v1/auth/mfa`);
    return parseJsonEnvelope<MfaStatus>(response, 'Failed to load MFA status');
  };

  const enrollMfa = async (): Promise<MfaEnrollment> => {
    const response = await apiFetch(`${config.issuer}/api/v1/auth/mfa/enroll`, { method: 'POST' });
    return parseJsonEnvelope<MfaEnrollment>(response, 'Failed to enroll MFA');
  };

  const activateMfa = async (code: string): Promise<string[]> => {
    const response = await apiFetch(`${config.issuer}/api/v1/auth/mfa/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
    });
    await parseJsonEnvelope<unknown>(response, 'Failed to activate MFA');
    const codesResponse = await apiFetch(`${config.issuer}/api/v1/auth/mfa/backup-codes`, { method: 'POST' });
    const data = await parseJsonEnvelope<{ backup_codes?: string[] }>(codesResponse, 'Failed to generate backup codes');
    return data.backup_codes || [];
  };

  const disableMfa = async (currentPassword: string) => {
    const response = await apiFetch(`${config.issuer}/api/v1/auth/mfa`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ current_password: currentPassword }),
    });
    await parseJsonEnvelope<unknown>(response, 'Failed to disable MFA');
  };

  const generateBackupCodes = async (): Promise<string[]> => {
    const response = await apiFetch(`${config.issuer}/api/v1/auth/mfa/backup-codes`, { method: 'POST' });
    const data = await parseJsonEnvelope<{ backup_codes?: string[] }>(response, 'Failed to generate backup codes');
    return data.backup_codes || [];
  };

  const listPasskeys = async (): Promise<PasskeyInfo[]> => {
    const response = await apiFetch(`${config.issuer}/api/v1/passkeys`);
    return parseJsonEnvelope<PasskeyInfo[]>(response, 'Failed to load passkeys');
  };

  const registerPasskey = async (name: string): Promise<void> => {
    const beginRes = await apiFetch(`${config.issuer}/api/v1/passkey/register/begin`, { method: 'POST' });
    const begin = await parseJsonEnvelope<{ options: PublicKeyCredentialCreationOptions; request_id: string }>(
      beginRes,
      'Failed to initialize passkey registration'
    );
    const options = {
      ...begin.options,
      challenge: base64URLToBuffer(begin.options.challenge as unknown as string),
      user: {
        ...begin.options.user,
        id: base64URLToBuffer(begin.options.user.id as unknown as string),
      },
      excludeCredentials: (begin.options.excludeCredentials || []).map((cred) => ({
        ...cred,
        id: base64URLToBuffer(cred.id as unknown as string),
      })),
    };
    const credential = (await navigator.credentials.create({ publicKey: options })) as PublicKeyCredential | null;
    if (!credential?.response) throw new Error('Passkey registration cancelled or failed');
    const attestationResponse = credential.response as AuthenticatorAttestationResponse;
    const completeRes = await apiFetch(`${config.issuer}/api/v1/passkey/register/complete?request_id=${begin.request_id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: credential.id,
        rawId: bufferToBase64URL(credential.rawId),
        type: credential.type,
        name,
        response: {
          clientDataJSON: bufferToBase64URL(attestationResponse.clientDataJSON),
          attestationObject: bufferToBase64URL(attestationResponse.attestationObject),
          transports: typeof attestationResponse.getTransports === 'function' ? attestationResponse.getTransports() : [],
        },
      }),
    });
    await parseJsonEnvelope<unknown>(completeRes, 'Failed to verify passkey registration');
  };

  const deletePasskey = async (id: string) => {
    const response = await apiFetch(`${config.issuer}/api/v1/passkeys/${id}`, { method: 'DELETE' });
    await parseJsonEnvelope<unknown>(response, 'Failed to remove passkey');
  };

  const listSessions = async (): Promise<SessionInfo[]> => {
    const response = await apiFetch(`${config.issuer}/api/v1/auth/sessions`);
    const sessions = await parseJsonEnvelope<SessionInfo[]>(response, 'Failed to load sessions');
    return sessions.sort((a, b) => new Date(b.last_active_at).getTime() - new Date(a.last_active_at).getTime());
  };

  const getCurrentSession = async (): Promise<SessionInfo> => {
    const response = await apiFetch(`${config.issuer}/api/v1/auth/session`);
    return parseJsonEnvelope<SessionInfo>(response, 'Failed to load current session');
  };

  const revokeSession = async (id: string) => {
    const response = await apiFetch(`${config.issuer}/api/v1/auth/sessions/${id}`, { method: 'DELETE' });
    await parseJsonEnvelope<unknown>(response, 'Failed to revoke session');
  };

  return {
    config,
    storageKeys,
    getAccessToken,
    getRefreshToken,
    getUserProfile: readProfile,
    getSnapshot,
    isLoggedIn: () => cookieSession ? Boolean(readProfile()) : Boolean(getAccessToken()),
    isAdmin: () => hasAdminAccess(readProfile(), getAccessToken()),
    saveTokenSet,
    clear,
    logout,
    redirectToAuthorize,
    exchangeCodeForToken,
    handleRedirectCallback,
    fetchUserProfile,
    refreshAccessToken,
    apiFetch,
    loginWithPassword,
    verifyMfa,
    loginWithPasskey,
    updateProfile,
    changePassword,
    requestEmailChange,
    confirmEmailChange,
    getMfaStatus,
    enrollMfa,
    activateMfa,
    disableMfa,
    generateBackupCodes,
    listPasskeys,
    registerPasskey,
    deletePasskey,
    listSessions,
    getCurrentSession,
    revokeSession,
  };
}

export type GossoClient = ReturnType<typeof createGossoClient>;

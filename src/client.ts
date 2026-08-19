import type {
  ApiEnvelope,
  GossoClientConfig,
  LoginResult,
  MfaEnrollment,
  MfaStatus,
  NavigatorWithLocks,
  PasskeyInfo,
  RefreshLock,
  SessionInfo,
  SessionListener,
  SessionSnapshot,
  TokenResponse,
  UserProfile,
} from './types.js';
import {
  base64URLToBuffer,
  bufferToBase64URL,
  cookieSecureAttribute,
  CookieSessionRefreshError,
  generateRandomString,
  generateRefreshOwner,
  getCookieName,
  hasAdminAccess,
  normalizeBaseUrl,
  parseJsonEnvelope,
  parseRefreshLock,
  readCookie,
  readRolesFromAccessToken,
  readScopeFromAccessToken,
} from './utils.js';
import {
  AuthenticationError,
  CsrfError,
  PasskeyError,
  TokenRefreshError,
} from './errors.js';
import { generateCodeChallenge } from './pkce.js';

const REFRESH_LOCK_TTL_MS = 15_000;
const REFRESH_WAIT_TIMEOUT_MS = 20_000;
const REFRESH_WAIT_POLL_MS = 100;
const REFRESH_WEB_LOCK_NAME = 'gosso-auth-refresh';
const AUTH_REDIRECT_GUARD_MS = 30_000;

export const defaultConfig: Pick<GossoClientConfig, 'scope' | 'postLoginDefaultPath' | 'loginPath' | 'storagePrefix'> = {
  scope: 'openid profile email',
  postLoginDefaultPath: '/',
  loginPath: '/login',
  storagePrefix: 'gosso',
};

export function createGossoClient(inputConfig: GossoClientConfig) {
  const config = {
    ...defaultConfig,
    ...inputConfig,
    issuer: normalizeBaseUrl(inputConfig.issuer),
  };
  const cookieSession = config.sessionMode === 'cookie';
  const flowStorage = cookieSession ? sessionStorage : localStorage;
  const fetcher = (input: RequestInfo | URL, init?: RequestInit) =>
    (config.fetchImpl || globalThis.fetch)(input, init);
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
    refreshGeneration: key('auth_refresh_generation'),
    authRedirectGuard: key('auth_redirect_guard'),
  };

  let refreshPromise: Promise<string> | null = null;
  const sessionListeners = new Set<SessionListener>();

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
    const snapshot = getSnapshot();
    config.onSessionChanged?.(snapshot);
    sessionListeners.forEach((listener) => listener(snapshot));
  };

  /**
   * Observe profile, login and logout changes without reimplementing a session
   * store in each consuming SPA. Callers receive future changes only and must
   * read getSnapshot() for the initial value.
   */
  const subscribe = (listener: SessionListener) => {
    sessionListeners.add(listener);
    return () => {
      sessionListeners.delete(listener);
    };
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

  const identityCSRFCookieName = new URL(config.issuer).protocol === 'https:'
    ? '__Host-csrf_token'
    : 'csrf_token';

  const isIdentityRequest = (url: string): boolean => {
    if (url.startsWith(`${config.issuer}/`)) return true;
    const path = url.startsWith('/') ? url : new URL(url, window.location.origin).pathname;
    return path.startsWith('/api/v1/') || path.startsWith('/oauth2/') || path.startsWith('/oidc/');
  };

  const readIdentityCSRFToken = (): string | null => readCookie(identityCSRFCookieName);

  const ensureIdentityCSRFToken = async (): Promise<string> => {
    let token = readIdentityCSRFToken();
    if (token) return token;

    // Safe methods are accepted without CSRF validation and the GOSSO middleware
    // reissues its own short-lived double-submit cookie before auth is evaluated.
    await fetcher(`${config.issuer}/api/v1/auth/session`, { credentials: 'same-origin' });
    token = readIdentityCSRFToken();
    if (!token) throw new CookieSessionRefreshError(403, 'GOSSO CSRF recovery failed');
    return token;
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

  const currentRefreshGeneration = (): string | null => localStorage.getItem(storageKeys.refreshGeneration);

  const markCookieRefreshComplete = () => {
    localStorage.setItem(storageKeys.refreshGeneration, `${Date.now()}:${generateRefreshOwner()}`);
  };

  const performCookieRefresh = async (observedGeneration: string | null): Promise<string> => {
    if (currentRefreshGeneration() !== observedGeneration) return '';

    const csrf = await ensureIdentityCSRFToken();
    const response = await fetcher(`${config.issuer}/api/v1/auth/refresh`, {
      method: 'POST',
      headers: { 'X-CSRF-Token': csrf, 'X-Gosso-Cookie-Session': '1' },
      credentials: 'same-origin',
    });
    if (!response.ok) {
      const message = response.status === 401
        ? 'Refresh token is invalid, expired, or revoked'
        : response.status === 403
          ? 'GOSSO CSRF recovery failed'
          : 'Cookie session refresh failed';
      throw new CookieSessionRefreshError(response.status, message);
    }
    markCookieRefreshComplete();
    return '';
  };

  const performTokenRefresh = async (previousRefreshToken: string): Promise<string> => {
    const latestRefreshToken = getRefreshToken();
    if (!latestRefreshToken) throw new TokenRefreshError('No refresh token found', 'NO_REFRESH_TOKEN');
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
    const pending = (async () => {
      const owner = generateRefreshOwner();
      let lockAcquired = false;
      try {
        if (cookieSession) {
          const observedGeneration = currentRefreshGeneration();
          if ((navigator as NavigatorWithLocks).locks) {
            return requestBrowserRefreshLock(() => performCookieRefresh(observedGeneration));
          }
          lockAcquired = tryAcquireRefreshLock(owner);
          if (!lockAcquired) {
            const startedAt = Date.now();
            while (Date.now() - startedAt < REFRESH_WAIT_TIMEOUT_MS) {
              if (currentRefreshGeneration() !== observedGeneration) return '';
              const lock = parseRefreshLock(localStorage.getItem(storageKeys.refreshLock));
              if (!lock || lock.expiresAt <= Date.now()) break;
              await new Promise((resolve) => window.setTimeout(resolve, REFRESH_WAIT_POLL_MS));
            }
            lockAcquired = tryAcquireRefreshLock(owner);
            if (!lockAcquired) throw new TokenRefreshError('Cookie session refresh is already in progress', 'REFRESH_IN_PROGRESS');
          }
          return performCookieRefresh(observedGeneration);
        }
        const refreshToken = getRefreshToken();
        if (!refreshToken) throw new TokenRefreshError('No refresh token found', 'NO_REFRESH_TOKEN');
        if ((navigator as NavigatorWithLocks).locks) {
          return requestBrowserRefreshLock(() => performTokenRefresh(refreshToken));
        }
        lockAcquired = tryAcquireRefreshLock(owner);
        if (!lockAcquired) {
          const tokenFromPeer = await waitForRefreshFromAnotherContext(refreshToken);
          if (tokenFromPeer) return tokenFromPeer;
          lockAcquired = tryAcquireRefreshLock(owner);
          if (!lockAcquired) throw new TokenRefreshError('Token refresh is already in progress', 'REFRESH_IN_PROGRESS');
        }
        return performTokenRefresh(refreshToken);
      } finally {
        if (lockAcquired) releaseRefreshLock(owner);
      }
    })();
    refreshPromise = pending;
    void pending.then(
      () => { if (refreshPromise === pending) refreshPromise = null; },
      () => { if (refreshPromise === pending) refreshPromise = null; },
    );
    return pending;
  };

  const fetchUserProfile = async (accessToken = getAccessToken()): Promise<UserProfile> => {
    if (cookieSession) {
      const [identity, session] = await Promise.all([
        fetcher(`${config.issuer}/oidc/userinfo`, { credentials: 'same-origin' }),
        config.sessionProfileEndpoint ? fetcher(config.sessionProfileEndpoint, { credentials: 'same-origin' }) : Promise.resolve(null),
      ]);
      if (!identity.ok || (session && !session.ok)) throw new AuthenticationError('Failed to fetch user profile', 'USER_PROFILE_FAILED');
      const data = await identity.json() as UserProfile;
      if (session) Object.assign(data, (await session.json() as ApiEnvelope<Partial<UserProfile>>).data || {});
      sessionStorage.setItem(storageKeys.userProfile, JSON.stringify(data));
      sessionStorage.removeItem(storageKeys.authRedirectGuard);
      emitSessionChanged();
      return data;
    }
    if (!accessToken) throw new AuthenticationError('No access token found', 'NO_ACCESS_TOKEN');
    const response = await fetcher(`${config.issuer}/oidc/userinfo`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!response.ok) throw new AuthenticationError('Failed to fetch user profile', 'USER_PROFILE_FAILED');
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
      const issuerRequest = isIdentityRequest(url);
      if (!['GET', 'HEAD', 'OPTIONS'].includes((options.method || 'GET').toUpperCase()) && !headers.has('X-CSRF-Token')) {
        const csrf = issuerRequest
          ? readIdentityCSRFToken()
          : config.csrfCookieName ? readCookie(config.csrfCookieName) : null;
        if (csrf) headers.set('X-CSRF-Token', csrf);
      }
      let response = await fetcher(url, { ...options, headers, credentials: 'same-origin' });
      if (response.status === 401 && (!issuerRequest || config.refreshIdentityRequests)) {
        try {
          await refreshAccessToken();
          response = await fetcher(url, { ...options, headers, credentials: 'same-origin' });
        } catch {
          response = new Response(null, { status: 401, statusText: 'Authentication required' });
        }
      }
      if (response.status === 401) {
        const returnTo = `${window.location.pathname}${window.location.search}${window.location.hash}`;
        const previous = sessionStorage.getItem(storageKeys.authRedirectGuard);
        const now = Date.now();
        let recentlyRedirected = false;
        try {
          const guard = previous ? JSON.parse(previous) as { at?: number; returnTo?: string } : null;
          recentlyRedirected = guard?.returnTo === returnTo && typeof guard.at === 'number' && now - guard.at < AUTH_REDIRECT_GUARD_MS;
        } catch {
          recentlyRedirected = false;
        }
        if (!recentlyRedirected) {
          clear();
          sessionStorage.setItem(storageKeys.authRedirectGuard, JSON.stringify({ at: now, returnTo }));
          await redirectToAuthorize(returnTo);
        } else if (previous) {
          sessionStorage.removeItem(storageKeys.userProfile);
          emitSessionChanged();
          sessionStorage.setItem(storageKeys.authRedirectGuard, previous);
        }
      }
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
    if (state !== savedState) throw new CsrfError('State mismatch. Potential CSRF attack.', 'CSRF_MISMATCH');
    if (!verifier) throw new AuthenticationError('PKCE verifier not found. Authentication flow expired.', 'PKCE_VERIFIER_MISSING');
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
      throw new AuthenticationError(`Token exchange failed: ${await response.text()}`, 'TOKEN_EXCHANGE_FAILED');
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
    sessionStorage.removeItem(storageKeys.authRedirectGuard);
    return { tokenSet, redirectTo };
  };

  const logout = async (redirectTo = '/') => {
    if (cookieSession) {
      const csrf = await ensureIdentityCSRFToken();
      const response = await fetcher(`${config.issuer}/api/v1/auth/logout`, {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf },
        credentials: 'same-origin',
        keepalive: true,
      });
      if (!response.ok) throw new AuthenticationError(`Logout failed (${response.status})`, 'LOGOUT_FAILED');
      clear();
      window.location.href = redirectTo;
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
    if (!assertion?.response) throw new PasskeyError('Passkey authentication cancelled or failed', 'PASSKEY_AUTH_CANCELLED');
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
    if (!credential?.response) throw new PasskeyError('Passkey registration cancelled or failed', 'PASSKEY_REGISTRATION_CANCELLED');
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
    subscribe,
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

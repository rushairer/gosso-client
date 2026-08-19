import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  createGossoClient,
  generateRandomString,
  GossoError,
  CsrfError,
  AuthenticationError,
  TokenRefreshError,
  CryptoError,
  PasskeyError,
} from './index';

function createLocalStorageMock(): Storage {
  let values = new Map<string, string>();
  return {
    get length() {
      return values.size;
    },
    clear() {
      values = new Map<string, string>();
    },
    getItem(key: string) {
      return values.get(key) ?? null;
    },
    key(index: number) {
      return Array.from(values.keys())[index] ?? null;
    },
    removeItem(key: string) {
      values.delete(key);
    },
    setItem(key: string, value: string) {
      values.set(key, value);
    },
  };
}

function createClient(fetchImpl = vi.fn()) {
  return createGossoClient({
    issuer: 'https://sso.example.test',
    clientId: 'blog-spa',
    redirectUri: 'https://app.example.test/callback',
    scope: 'openid profile email',
    postLoginDefaultPath: '/admin',
    loginPath: '/login',
    storagePrefix: 'test',
    fetchImpl: fetchImpl as unknown as typeof fetch,
    onAuthRequired: vi.fn(),
  });
}

function createCookieClient(fetchImpl = vi.fn()) {
  return createGossoClient({
    issuer: 'https://sso.example.test',
    clientId: 'blog-spa',
    redirectUri: 'https://app.example.test/callback',
    scope: 'openid profile email',
    postLoginDefaultPath: '/admin',
    loginPath: '/login',
    storagePrefix: 'cookie-test',
    sessionMode: 'cookie',
    sessionProfileEndpoint: '/api/me/session',
    csrfCookieName: 'blog_csrf_token',
    fetchImpl: fetchImpl as unknown as typeof fetch,
  });
}

function jsonResponse(body: unknown, init: ResponseInit = {}) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    ...init,
  });
}

function tokenWithClaims(claims: Record<string, unknown>) {
  const encode = (value: unknown) => btoa(JSON.stringify(value)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `${encode({ alg: 'none' })}.${encode(claims)}.`;
}

describe('@gosso/client', () => {
  beforeEach(() => {
    Object.defineProperty(globalThis, 'localStorage', { value: createLocalStorageMock(), configurable: true });
    localStorage.clear();
    sessionStorage.clear();
    document.cookie = 'access_token=; path=/; max-age=-1; SameSite=Lax';
    document.cookie = 'blog_csrf_token=; path=/; max-age=0; Secure';
    document.cookie = '__Host-csrf_token=; path=/; max-age=0; Secure';
    document.cookie = 'csrf_token=; path=/; max-age=0';
    Object.defineProperty(navigator, 'locks', { value: undefined, configurable: true });
    vi.restoreAllMocks();
  });

  it('exchanges an authorization code, validates state, stores tokens, and returns the post-login redirect', async () => {
    const accessToken = tokenWithClaims({ roles: ['admin'], scope: 'openid profile email' });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ access_token: accessToken, refresh_token: 'refresh', expires_in: 900 }))
      .mockResolvedValueOnce(jsonResponse({ sub: 'user-1', preferred_username: 'aben' }));
    const client = createClient(fetchMock);
    localStorage.setItem('test:auth_state', 'state-1');
    localStorage.setItem('test:pkce_verifier', 'verifier-1');
    localStorage.setItem('test:post_login_redirect', '/settings');

    const result = await client.handleRedirectCallback('code-1', 'state-1');

    expect(result.redirectTo).toBe('/settings');
    expect(localStorage.getItem('test:access_token')).toBe(accessToken);
    expect(localStorage.getItem('test:refresh_token')).toBe('refresh');
    expect(client.getUserProfile()).toMatchObject({ sub: 'user-1', roles: ['admin'] });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://sso.example.test/oauth2/token',
      expect.objectContaining({
        method: 'POST',
        body: 'grant_type=authorization_code&client_id=blog-spa&code=code-1&code_verifier=verifier-1&redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback',
      })
    );
  });

  it('rejects callback state mismatches before calling the token endpoint', async () => {
    const fetchMock = vi.fn();
    const client = createClient(fetchMock);
    localStorage.setItem('test:auth_state', 'expected-state');
    localStorage.setItem('test:pkce_verifier', 'verifier-1');

    await expect(client.exchangeCodeForToken('code-1', 'wrong-state')).rejects.toThrow('State mismatch');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('refreshes an expired token before apiFetch and attaches the fresh bearer token', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ data: { access_token: 'fresh-access', refresh_token: 'fresh-refresh', expires_in: 900 } }))
      .mockResolvedValueOnce(jsonResponse({ data: { ok: true } }));
    const client = createClient(fetchMock);
    localStorage.setItem('test:access_token', 'old-access');
    localStorage.setItem('test:refresh_token', 'old-refresh');
    localStorage.setItem('test:token_issued_at', String(Date.now() - 1_000_000));
    localStorage.setItem('test:token_expires_in', '1');

    await client.apiFetch('/api/posts');

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      'https://sso.example.test/api/v1/auth/refresh',
      expect.objectContaining({ body: JSON.stringify({ refresh_token: 'old-refresh' }) })
    );
    const headers = fetchMock.mock.calls[1][1].headers as Headers;
    expect(headers.get('Authorization')).toBe('Bearer fresh-access');
  });

  it('refreshes and retries once after a protected request returns 401', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(null, { status: 401 }))
      .mockResolvedValueOnce(jsonResponse({ data: { access_token: 'retry-access', refresh_token: 'retry-refresh', expires_in: 900 } }))
      .mockResolvedValueOnce(jsonResponse({ data: { ok: true } }));
    const client = createClient(fetchMock);
    localStorage.setItem('test:access_token', 'old-access');
    localStorage.setItem('test:refresh_token', 'old-refresh');
    localStorage.setItem('test:token_issued_at', String(Date.now()));
    localStorage.setItem('test:token_expires_in', '900');

    const response = await client.apiFetch('/api/posts');

    expect(response.ok).toBe(true);
    const retryHeaders = fetchMock.mock.calls[2][1].headers as Headers;
    expect(retryHeaders.get('Authorization')).toBe('Bearer retry-access');
  });

  it('sends settings profile updates through the authenticated API helper', async () => {
    const accessToken = tokenWithClaims({ scope: 'openid profile email' });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ data: {} }))
      .mockResolvedValueOnce(jsonResponse({ sub: 'user-1', name: 'New Name' }));
    const client = createClient(fetchMock);
    localStorage.setItem('test:access_token', accessToken);
    localStorage.setItem('test:refresh_token', 'refresh');
    localStorage.setItem('test:token_issued_at', String(Date.now()));
    localStorage.setItem('test:token_expires_in', '900');

    await client.updateProfile('New Name');

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      'https://sso.example.test/api/v1/auth/profile',
      expect.objectContaining({
        method: 'PUT',
        body: JSON.stringify({ display_name: 'New Name' }),
      })
    );
  });

  it('generates secure random strings of specified length', () => {
    const str1 = generateRandomString(32);
    const str2 = generateRandomString(32);

    expect(str1).toHaveLength(32);
    expect(str2).toHaveLength(32);
    expect(str1).not.toBe(str2);
    expect(str1).toMatch(/^[A-Za-z0-9\-._~]+$/);
  });

  it('uses __Secure- prefix for access token cookie on HTTPS', async () => {
    const originalLocation = window.location;
    Object.defineProperty(window, 'location', {
      value: { ...originalLocation, protocol: 'https:' },
      configurable: true,
    });

    const accessToken = tokenWithClaims({ scope: 'openid profile email' });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ access_token: accessToken, refresh_token: 'refresh', expires_in: 900 }))
      .mockResolvedValueOnce(jsonResponse({ sub: 'user-1', preferred_username: 'aben' }));
    const client = createClient(fetchMock);
    localStorage.setItem('test:auth_state', 'state-1');
    localStorage.setItem('test:pkce_verifier', 'verifier-1');

    await client.handleRedirectCallback('code-1', 'state-1');

    expect(document.cookie).toContain('__Secure-access_token=');

    Object.defineProperty(window, 'location', {
      value: originalLocation,
      configurable: true,
    });
  });

  it('keeps tokens out of Web Storage in cookie session mode', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ expires_in: 900 }))
      .mockResolvedValueOnce(jsonResponse({ sub: 'user-1', preferred_username: 'aben' }))
      .mockResolvedValueOnce(jsonResponse({ data: { sub: 'user-1', roles: ['admin'], scope: 'openid profile admin' } }));
    const client = createCookieClient(fetchMock);
    // Cookie mode keeps transient PKCE state in session storage.
    sessionStorage.setItem('cookie-test:auth_state', 'state-1');
    sessionStorage.setItem('cookie-test:pkce_verifier', 'verifier-1');
    await client.handleRedirectCallback('code-1', 'state-1');
    expect(localStorage.getItem('cookie-test:access_token')).toBeNull();
    expect(localStorage.getItem('cookie-test:refresh_token')).toBeNull();
    expect(client.isAdmin()).toBe(true);
    expect(fetchMock.mock.calls[0][1].headers['X-Gosso-Cookie-Session']).toBe('1');
  });

  it.each([
    ['blog-first', ['blog_csrf_token=blog-value', '__Host-csrf_token=gosso-value']],
    ['gosso-first', ['__Host-csrf_token=gosso-value', 'blog_csrf_token=blog-value']],
  ])('selects CSRF cookies by request target regardless of cookie order (%s)', async (_name, cookies) => {
    for (const cookie of cookies) document.cookie = `${cookie}; path=/; Secure`;
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ ok: true }));
    const client = createCookieClient(fetchMock);

    await client.apiFetch('/api/admin/posts', { method: 'POST' });
    await client.apiFetch('https://sso.example.test/api/v1/auth/profile', { method: 'PUT' });

    const blogHeaders = fetchMock.mock.calls[0][1].headers as Headers;
    const identityHeaders = fetchMock.mock.calls[1][1].headers as Headers;
    expect(blogHeaders.get('X-CSRF-Token')).toBe('blog-value');
    expect(identityHeaders.get('X-CSRF-Token')).toBe('gosso-value');
  });

  it('refreshes a cookie session and retries the original request exactly once', async () => {
    document.cookie = '__Host-csrf_token=gosso-value; path=/; Secure';
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(null, { status: 401 }))
      .mockResolvedValueOnce(jsonResponse({ ok: true }))
      .mockResolvedValueOnce(jsonResponse({ data: { ok: true } }));
    const client = createCookieClient(fetchMock);

    const response = await client.apiFetch('/api/admin/posts');

    expect(response.ok).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    const refreshHeaders = fetchMock.mock.calls[1][1].headers as Record<string, string>;
    expect(refreshHeaders['X-CSRF-Token']).toBe('gosso-value');
  });

  it('recovers a missing GOSSO CSRF cookie with a safe GET before refresh', async () => {
    document.cookie = 'blog_csrf_token=blog-value; path=/; Secure';
    const fetchMock = vi.fn(async (url: string) => {
      if (url === '/api/admin/posts') {
        const calls = fetchMock.mock.calls.filter(([value]) => value === '/api/admin/posts').length;
        return calls === 1 ? new Response(null, { status: 401 }) : jsonResponse({ data: { ok: true } });
      }
      if (url.endsWith('/api/v1/auth/session')) {
        document.cookie = '__Host-csrf_token=renewed-gosso; path=/; Secure';
        return new Response(null, { status: 401 });
      }
      return jsonResponse({ ok: true });
    });
    const client = createCookieClient(fetchMock);

    await expect(client.apiFetch('/api/admin/posts')).resolves.toMatchObject({ status: 200 });
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      '/api/admin/posts',
      'https://sso.example.test/api/v1/auth/session',
      'https://sso.example.test/api/v1/auth/refresh',
      '/api/admin/posts',
    ]);
    const refreshHeaders = fetchMock.mock.calls[2][1].headers as Record<string, string>;
    expect(refreshHeaders['X-CSRF-Token']).toBe('renewed-gosso');
  });

  it('coalesces concurrent 401 responses into one refresh in a page', async () => {
    document.cookie = '__Host-csrf_token=gosso-value; path=/; Secure';
    let protectedCalls = 0;
    let refreshCalls = 0;
    let releaseRefresh!: () => void;
    const refreshGate = new Promise<void>((resolve) => { releaseRefresh = resolve; });
    const fetchMock = vi.fn(async (url: string) => {
      if (url === '/api/admin/posts') {
        protectedCalls += 1;
        return protectedCalls <= 2 ? new Response(null, { status: 401 }) : jsonResponse({ ok: true });
      }
      refreshCalls += 1;
      await refreshGate;
      return jsonResponse({ ok: true });
    });
    const client = createCookieClient(fetchMock);

    const first = client.apiFetch('/api/admin/posts');
    const second = client.apiFetch('/api/admin/posts');
    await vi.waitFor(() => expect(refreshCalls).toBe(1));
    releaseRefresh();
    const responses = await Promise.all([first, second]);

    expect(responses.every((response) => response.ok)).toBe(true);
    expect(refreshCalls).toBe(1);
  });

  it('uses Web Locks and a generation marker to avoid refresh-token rotation races across tabs', async () => {
    document.cookie = '__Host-csrf_token=gosso-value; path=/; Secure';
    let queue = Promise.resolve();
    Object.defineProperty(navigator, 'locks', {
      configurable: true,
      value: {
        request: <T>(_name: string, _options: { mode: 'exclusive' }, callback: () => T | Promise<T>): Promise<T> => {
          const result = queue.then(callback);
          queue = result.then(() => undefined, () => undefined);
          return result;
        },
      },
    });
    let refreshCalls = 0;
    const makeFetcher = () => {
      let protectedCalls = 0;
      return vi.fn(async (url: string) => {
        if (url === '/api/admin/posts') {
          protectedCalls += 1;
          return protectedCalls === 1 ? new Response(null, { status: 401 }) : jsonResponse({ ok: true });
        }
        refreshCalls += 1;
        return jsonResponse({ ok: true });
      });
    };
    const tabOne = createCookieClient(makeFetcher());
    const tabTwo = createCookieClient(makeFetcher());

    const responses = await Promise.all([
      tabOne.apiFetch('/api/admin/posts'),
      tabTwo.apiFetch('/api/admin/posts'),
    ]);

    expect(responses.every((response) => response.ok)).toBe(true);
    expect(refreshCalls).toBe(1);
  });

  it('starts PKCE reauthorization once when refresh is invalid and does not recurse', async () => {
    document.cookie = '__Host-csrf_token=gosso-value; path=/; Secure';
    const fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith('/api/v1/auth/refresh')) return jsonResponse({ message: 'invalid or expired token' }, { status: 401 });
      return new Response(null, { status: 401 });
    });
    const client = createCookieClient(fetchMock);

    const response = await client.apiFetch('/api/admin/posts');

    expect(response.status).toBe(401);
    expect(fetchMock.mock.calls.filter(([url]) => String(url).endsWith('/api/v1/auth/refresh'))).toHaveLength(1);
    expect(sessionStorage.getItem('cookie-test:pkce_verifier')).toBeTruthy();
    expect(sessionStorage.getItem('cookie-test:post_login_redirect')).toBe('/');
    expect(sessionStorage.getItem('cookie-test:auth_redirect_guard')).toBeTruthy();
    const firstState = sessionStorage.getItem('cookie-test:auth_state');

    await client.apiFetch('/api/admin/posts');

    expect(sessionStorage.getItem('cookie-test:auth_state')).toBe(firstState);
    expect(fetchMock.mock.calls.filter(([url]) => String(url).endsWith('/api/v1/auth/refresh'))).toHaveLength(2);
  });

  it('does not retry indefinitely when the retried request is still 401', async () => {
    document.cookie = '__Host-csrf_token=gosso-value; path=/; Secure';
    const fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith('/api/v1/auth/refresh')) return jsonResponse({ ok: true });
      return new Response(null, { status: 401 });
    });
    const client = createCookieClient(fetchMock);

    await client.apiFetch('/api/admin/posts');

    expect(fetchMock.mock.calls.filter(([url]) => url === '/api/admin/posts')).toHaveLength(2);
    expect(fetchMock.mock.calls.filter(([url]) => String(url).endsWith('/api/v1/auth/refresh'))).toHaveLength(1);
  });

  it('logs out with only the GOSSO CSRF cookie and clears state only after server success', async () => {
    document.cookie = 'blog_csrf_token=blog-value; path=/; Secure';
    document.cookie = '__Host-csrf_token=gosso-value; path=/; Secure';
    let logoutCalls = 0;
    const fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith('/oidc/userinfo')) return jsonResponse({ sub: 'user-1', roles: ['admin'], scope: 'openid admin' });
      if (url === '/api/me/session') return jsonResponse({ data: { roles: ['admin'], scope: 'openid admin' } });
      logoutCalls += 1;
      return new Response(null, { status: logoutCalls === 1 ? 403 : 204 });
    });
    const client = createCookieClient(fetchMock);
    await client.fetchUserProfile();

    await expect(client.logout('/')).rejects.toThrow('Logout failed (403)');
    expect(client.isLoggedIn()).toBe(true);
    await expect(client.logout('/')).resolves.toBeUndefined();
    expect(client.isLoggedIn()).toBe(false);
    const failedLogoutHeaders = fetchMock.mock.calls[2][1].headers as Record<string, string>;
    expect(failedLogoutHeaders['X-CSRF-Token']).toBe('gosso-value');
  });

  it('notifies subscriptions when the client session changes', () => {
    const client = createClient();
    const listener = vi.fn();
    const unsubscribe = client.subscribe(listener);

    client.saveTokenSet({ access_token: 'access', refresh_token: 'refresh', expires_in: 900 });
    expect(listener).toHaveBeenLastCalledWith(expect.objectContaining({ loggedIn: true, accessToken: 'access' }));

    unsubscribe();
    client.clear();
    expect(listener).toHaveBeenCalledTimes(1);
  });

  describe('Typed Error Hierarchy', () => {
    it('properly instantiates all typed SDK error subclasses with code and name', () => {
      const baseErr = new GossoError('base message', 'BASE_CODE');
      expect(baseErr).toBeInstanceOf(Error);
      expect(baseErr).toBeInstanceOf(GossoError);
      expect(baseErr.name).toBe('GossoError');
      expect(baseErr.code).toBe('BASE_CODE');

      const csrfErr = new CsrfError();
      expect(csrfErr).toBeInstanceOf(GossoError);
      expect(csrfErr).toBeInstanceOf(CsrfError);
      expect(csrfErr.name).toBe('CsrfError');
      expect(csrfErr.code).toBe('CSRF_MISMATCH');

      const authErr = new AuthenticationError('unauthorized', 'AUTH_FAIL');
      expect(authErr).toBeInstanceOf(GossoError);
      expect(authErr).toBeInstanceOf(AuthenticationError);
      expect(authErr.name).toBe('AuthenticationError');

      const refreshErr = new TokenRefreshError('refresh failed', 'REFRESH_FAIL');
      expect(refreshErr).toBeInstanceOf(GossoError);
      expect(refreshErr).toBeInstanceOf(TokenRefreshError);
      expect(refreshErr.name).toBe('TokenRefreshError');

      const cryptoErr = new CryptoError();
      expect(cryptoErr).toBeInstanceOf(GossoError);
      expect(cryptoErr).toBeInstanceOf(CryptoError);
      expect(cryptoErr.name).toBe('CryptoError');

      const passkeyErr = new PasskeyError('passkey cancel', 'PASSKEY_CANCEL');
      expect(passkeyErr).toBeInstanceOf(GossoError);
      expect(passkeyErr).toBeInstanceOf(PasskeyError);
      expect(passkeyErr.name).toBe('PasskeyError');
    });

    it('throws CsrfError on OAuth2 state mismatch', async () => {
      const client = createClient();
      localStorage.setItem('test:auth_state', 'valid-state');
      localStorage.setItem('test:pkce_verifier', 'verifier');

      await expect(client.exchangeCodeForToken('code', 'tampered-state')).rejects.toBeInstanceOf(CsrfError);
    });

    it('throws TokenRefreshError when no refresh token is present', async () => {
      const client = createClient();
      await expect(client.refreshAccessToken()).rejects.toBeInstanceOf(TokenRefreshError);
    });
  });
});


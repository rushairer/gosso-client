import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createGossoClient, generateRandomString } from './index';

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
    document.cookie = 'access_token=; path=/; max-age=-1; SameSite=Lax';
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
});

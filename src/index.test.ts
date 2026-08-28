import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  createGossoClient,
  generateRandomString,
  parseJsonEnvelope,
  GossoError,
  ApiError,
  CsrfError,
  AuthenticationError,
  TokenRefreshError,
  CryptoError,
  PasskeyError,
} from "./index";

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
    issuer: "https://sso.example.test",
    clientId: "blog-spa",
    redirectUri: "https://app.example.test/callback",
    scope: "openid profile email",
    postLoginDefaultPath: "/admin",
    loginPath: "/login",
    storagePrefix: "test",
    sessionMode: "token",
    fetchImpl: fetchImpl as unknown as typeof fetch,
    onAuthRequired: vi.fn(),
  });
}

function createCookieClient(fetchImpl = vi.fn()) {
  return createGossoClient({
    issuer: "https://sso.example.test",
    clientId: "blog-spa",
    redirectUri: "https://app.example.test/callback",
    scope: "openid profile email",
    postLoginDefaultPath: "/admin",
    loginPath: "/login",
    storagePrefix: "cookie-test",
    sessionProfileEndpoint: "/api/me/session",
    csrfCookieName: "blog_csrf_token",
    fetchImpl: fetchImpl as unknown as typeof fetch,
  });
}

function jsonResponse(body: unknown, init: ResponseInit = {}) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
    ...init,
  });
}

function tokenWithClaims(claims: Record<string, unknown>) {
  const encode = (value: unknown) =>
    btoa(JSON.stringify(value))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  return `${encode({ alg: "none" })}.${encode(claims)}.`;
}

describe("@gosso/client", () => {
  beforeEach(() => {
    Object.defineProperty(globalThis, "localStorage", {
      value: createLocalStorageMock(),
      configurable: true,
    });
    localStorage.clear();
    sessionStorage.clear();
    document.cookie = "access_token=; path=/; max-age=-1; SameSite=Lax";
    document.cookie = "blog_csrf_token=; path=/; max-age=0; Secure";
    document.cookie = "__Host-csrf_token=; path=/; max-age=0; Secure";
    document.cookie = "csrf_token=; path=/; max-age=0";
    Object.defineProperty(navigator, "locks", {
      value: undefined,
      configurable: true,
    });
    vi.restoreAllMocks();
  });

  it("exchanges an authorization code, validates state, stores tokens, and returns the post-login redirect", async () => {
    const accessToken = tokenWithClaims({
      roles: ["admin"],
      scope: "openid profile email",
    });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          access_token: accessToken,
          refresh_token: "refresh",
          expires_in: 900,
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({ sub: "user-1", preferred_username: "aben" }),
      );
    const client = createClient(fetchMock);
    sessionStorage.setItem("test:auth_state", "state-1");
    sessionStorage.setItem("test:pkce_verifier", "verifier-1");
    sessionStorage.setItem("test:post_login_redirect", "/settings");

    const result = await client.handleRedirectCallback("code-1", "state-1");

    expect(result.redirectTo).toBe("/settings");
    expect(client.getAccessToken()).toBe(accessToken);
    expect(client.getRefreshToken()).toBe("refresh");
    expect(localStorage.getItem("test:access_token")).toBeNull();
    expect(document.cookie).not.toContain("access_token=");
    expect(client.getUserProfile()).toMatchObject({
      sub: "user-1",
      roles: ["admin"],
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "https://sso.example.test/oauth2/token",
      expect.objectContaining({
        method: "POST",
        body: "grant_type=authorization_code&client_id=blog-spa&code=code-1&code_verifier=verifier-1&redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback",
      }),
    );
  });

  it("rejects callback state mismatches before calling the token endpoint", async () => {
    const fetchMock = vi.fn();
    const client = createClient(fetchMock);
    sessionStorage.setItem("test:auth_state", "expected-state");
    sessionStorage.setItem("test:pkce_verifier", "verifier-1");

    await expect(
      client.exchangeCodeForToken("code-1", "wrong-state"),
    ).rejects.toThrow("State mismatch");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refreshes an expired token before apiFetch and attaches the fresh bearer token", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          data: {
            access_token: "fresh-access",
            refresh_token: "fresh-refresh",
            expires_in: 900,
          },
        }),
      )
      .mockResolvedValueOnce(jsonResponse({ data: { ok: true } }));
    const client = createClient(fetchMock);
    client.saveTokenSet({
      access_token: "old-access",
      refresh_token: "old-refresh",
      expires_in: -1,
    });

    await client.apiFetch("/api/posts");

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "https://sso.example.test/api/v1/auth/refresh",
      expect.objectContaining({
        body: JSON.stringify({ refresh_token: "old-refresh" }),
      }),
    );
    const headers = fetchMock.mock.calls[1][1].headers as Headers;
    expect(headers.get("Authorization")).toBe("Bearer fresh-access");
  });

  it("refreshes and retries once after a protected request returns 401", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(null, { status: 401 }))
      .mockResolvedValueOnce(
        jsonResponse({
          data: {
            access_token: "retry-access",
            refresh_token: "retry-refresh",
            expires_in: 900,
          },
        }),
      )
      .mockResolvedValueOnce(jsonResponse({ data: { ok: true } }));
    const client = createClient(fetchMock);
    client.saveTokenSet({
      access_token: "old-access",
      refresh_token: "old-refresh",
      expires_in: 900,
    });

    const response = await client.apiFetch("/api/posts");

    expect(response.ok).toBe(true);
    const retryHeaders = fetchMock.mock.calls[2][1].headers as Headers;
    expect(retryHeaders.get("Authorization")).toBe("Bearer retry-access");
  });

  it("sends settings profile updates through the authenticated API helper", async () => {
    const accessToken = tokenWithClaims({ scope: "openid profile email" });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ data: {} }))
      .mockResolvedValueOnce(jsonResponse({ sub: "user-1", name: "New Name" }));
    const client = createClient(fetchMock);
    client.saveTokenSet({
      access_token: accessToken,
      refresh_token: "refresh",
      expires_in: 900,
    });

    await client.updateProfile("New Name");

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "https://sso.example.test/api/v1/auth/profile",
      expect.objectContaining({
        method: "PUT",
        body: JSON.stringify({ display_name: "New Name" }),
      }),
    );
  });

  it("generates secure random strings of specified length", () => {
    const str1 = generateRandomString(32);
    const str2 = generateRandomString(32);

    expect(str1).toHaveLength(32);
    expect(str2).toHaveLength(32);
    expect(str1).not.toBe(str2);
    expect(str1).toMatch(/^[A-Za-z0-9\-._~]+$/);
  });

  it("fails closed before storing OAuth state when Web Crypto is unavailable", async () => {
    const cryptoDescriptor = Object.getOwnPropertyDescriptor(
      globalThis,
      "crypto",
    );
    Object.defineProperty(globalThis, "crypto", {
      value: undefined,
      configurable: true,
    });
    try {
      expect(() => generateRandomString(32)).toThrow(CryptoError);
      await expect(
        createClient().redirectToAuthorize("/admin"),
      ).rejects.toBeInstanceOf(CryptoError);
      expect(sessionStorage.getItem("test:pkce_verifier")).toBeNull();
      expect(sessionStorage.getItem("test:auth_state")).toBeNull();
    } finally {
      if (cryptoDescriptor)
        Object.defineProperty(globalThis, "crypto", cryptoDescriptor);
    }
  });

  it("requests and completes password reset through SDK-owned endpoints", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({ code: 200, message: "success", data: "sent" }),
      )
      .mockResolvedValueOnce(
        jsonResponse({ code: 200, message: "success", data: "reset" }),
      );
    const client = createClient(fetchMock);

    await client.requestPasswordReset("reader@example.test");
    await client.resetPassword("reset-token", "correct horse battery staple");

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "https://sso.example.test/api/v1/auth/password/forgot",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ email: "reader@example.test" }),
        credentials: "same-origin",
      }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "https://sso.example.test/api/v1/auth/password/reset",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          token: "reset-token",
          new_password: "correct horse battery staple",
        }),
        credentials: "same-origin",
      }),
    );
  });

  it("normalizes Gouno, OAuth, empty, and invalid API responses", async () => {
    await expect(
      parseJsonEnvelope(
        jsonResponse({ code: 200, message: "success", data: { ok: true } }),
      ),
    ).resolves.toEqual({ ok: true });
    await expect(
      parseJsonEnvelope(new Response(null, { status: 204 })),
    ).resolves.toBeUndefined();

    const oauthError = parseJsonEnvelope(
      new Response(
        JSON.stringify({
          error: "invalid_grant",
          error_description: "Grant rejected",
        }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" },
        },
      ),
    );
    await expect(oauthError).rejects.toMatchObject({
      name: "ApiError",
      code: "invalid_grant",
      status: 400,
      message: "Grant rejected",
    });

    const invalid = parseJsonEnvelope(
      new Response("<html>bad gateway</html>", {
        status: 502,
        headers: { "Content-Type": "text/html" },
      }),
      "Upstream unavailable",
    );
    await expect(invalid).rejects.toBeInstanceOf(ApiError);
    await expect(invalid).rejects.toMatchObject({
      status: 502,
      message: "Upstream unavailable",
    });
  });

  it("never writes legacy tokens to a JavaScript cookie or Web Storage", async () => {
    const originalLocation = window.location;
    Object.defineProperty(window, "location", {
      value: { ...originalLocation, protocol: "https:" },
      configurable: true,
    });

    const accessToken = tokenWithClaims({ scope: "openid profile email" });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          access_token: accessToken,
          refresh_token: "refresh",
          expires_in: 900,
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({ sub: "user-1", preferred_username: "aben" }),
      );
    const client = createClient(fetchMock);
    sessionStorage.setItem("test:auth_state", "state-1");
    sessionStorage.setItem("test:pkce_verifier", "verifier-1");

    await client.handleRedirectCallback("code-1", "state-1");

    expect(document.cookie).not.toContain("__Secure-access_token=");
    expect(localStorage.getItem("test:access_token")).toBeNull();
    expect(sessionStorage.getItem("test:access_token")).toBeNull();

    Object.defineProperty(window, "location", {
      value: originalLocation,
      configurable: true,
    });
  });

  it("keeps tokens out of Web Storage in cookie session mode", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ expires_in: 900 }))
      .mockResolvedValueOnce(
        jsonResponse({ sub: "user-1", preferred_username: "aben" }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          data: {
            sub: "user-1",
            roles: ["admin"],
            scope: "openid profile admin",
          },
        }),
      );
    const client = createCookieClient(fetchMock);
    // Cookie mode keeps transient PKCE state in session storage.
    sessionStorage.setItem("cookie-test:auth_state", "state-1");
    sessionStorage.setItem("cookie-test:pkce_verifier", "verifier-1");
    await client.handleRedirectCallback("code-1", "state-1");
    expect(localStorage.getItem("cookie-test:access_token")).toBeNull();
    expect(localStorage.getItem("cookie-test:refresh_token")).toBeNull();
    expect(client.isAdmin()).toBe(true);
    expect(fetchMock.mock.calls[0][1].headers["X-Gosso-Cookie-Session"]).toBe(
      "1",
    );
  });

  it("uses Cookie Session when sessionMode is omitted", () => {
    const client = createCookieClient();
    expect(client.config.sessionMode).toBe("cookie");
    client.saveTokenSet({
      access_token: "ignored",
      refresh_token: "ignored",
      expires_in: 900,
    });
    expect(client.getAccessToken()).toBeNull();
    expect(client.getRefreshToken()).toBeNull();
  });

  it("rejects untrusted API origins before sending credentials", async () => {
    const fetchMock = vi.fn();
    const client = createCookieClient(fetchMock);
    await expect(
      client.apiFetch("https://evil.example/api/v1/auth/profile"),
    ).rejects.toMatchObject({
      code: "UNTRUSTED_API_ORIGIN",
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("normalizes OAuth return paths and rejects protocol-relative redirects", async () => {
    const client = createCookieClient();
    await client.redirectToAuthorize("//evil.example/steal");
    expect(sessionStorage.getItem("cookie-test:post_login_redirect")).toBe(
      "/admin",
    );
  });

  it.each([
    [
      "blog-first",
      ["blog_csrf_token=blog-value", "__Host-csrf_token=gosso-value"],
    ],
    [
      "gosso-first",
      ["__Host-csrf_token=gosso-value", "blog_csrf_token=blog-value"],
    ],
  ])(
    "selects CSRF cookies by request target regardless of cookie order (%s)",
    async (_name, cookies) => {
      for (const cookie of cookies)
        document.cookie = `${cookie}; path=/; Secure`;
      const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ ok: true }));
      const client = createCookieClient(fetchMock);

      await client.apiFetch("/api/admin/posts", { method: "POST" });
      await client.apiFetch("https://sso.example.test/api/v1/auth/profile", {
        method: "PUT",
      });

      const blogHeaders = fetchMock.mock.calls[0][1].headers as Headers;
      const identityHeaders = fetchMock.mock.calls[1][1].headers as Headers;
      expect(blogHeaders.get("X-CSRF-Token")).toBe("blog-value");
      expect(identityHeaders.get("X-CSRF-Token")).toBe("gosso-value");
    },
  );

  it("refreshes a cookie session and retries the original request exactly once", async () => {
    document.cookie = "__Host-csrf_token=gosso-value; path=/; Secure";
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(null, { status: 401 }))
      .mockResolvedValueOnce(jsonResponse({ ok: true }))
      .mockResolvedValueOnce(jsonResponse({ data: { ok: true } }));
    const client = createCookieClient(fetchMock);

    const response = await client.apiFetch("/api/admin/posts");

    expect(response.ok).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    const refreshHeaders = fetchMock.mock.calls[1][1].headers as Record<
      string,
      string
    >;
    expect(refreshHeaders["X-CSRF-Token"]).toBe("gosso-value");
  });

  it("recovers a missing GOSSO CSRF cookie with a safe GET before refresh", async () => {
    document.cookie = "blog_csrf_token=blog-value; path=/; Secure";
    const fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith("/api/admin/posts")) {
        const calls = fetchMock.mock.calls.filter(([value]) =>
          String(value).endsWith("/api/admin/posts"),
        ).length;
        return calls === 1
          ? new Response(null, { status: 401 })
          : jsonResponse({ data: { ok: true } });
      }
      if (url.endsWith("/api/v1/auth/session")) {
        document.cookie = "__Host-csrf_token=renewed-gosso; path=/; Secure";
        return new Response(null, { status: 401 });
      }
      return jsonResponse({ ok: true });
    });
    const client = createCookieClient(fetchMock);

    await expect(client.apiFetch("/api/admin/posts")).resolves.toMatchObject({
      status: 200,
    });
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "/api/admin/posts",
      "https://sso.example.test/api/v1/auth/session",
      "https://sso.example.test/api/v1/auth/refresh",
      "/api/admin/posts",
    ]);
    const refreshHeaders = fetchMock.mock.calls[2][1].headers as Record<
      string,
      string
    >;
    expect(refreshHeaders["X-CSRF-Token"]).toBe("renewed-gosso");
  });

  it("coalesces concurrent 401 responses into one refresh in a page", async () => {
    document.cookie = "__Host-csrf_token=gosso-value; path=/; Secure";
    let protectedCalls = 0;
    let refreshCalls = 0;
    let releaseRefresh!: () => void;
    const refreshGate = new Promise<void>((resolve) => {
      releaseRefresh = resolve;
    });
    const fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith("/api/admin/posts")) {
        protectedCalls += 1;
        return protectedCalls <= 2
          ? new Response(null, { status: 401 })
          : jsonResponse({ ok: true });
      }
      refreshCalls += 1;
      await refreshGate;
      return jsonResponse({ ok: true });
    });
    const client = createCookieClient(fetchMock);

    const first = client.apiFetch("/api/admin/posts");
    const second = client.apiFetch("/api/admin/posts");
    await vi.waitFor(() => expect(refreshCalls).toBe(1));
    releaseRefresh();
    const responses = await Promise.all([first, second]);

    expect(responses.every((response) => response.ok)).toBe(true);
    expect(refreshCalls).toBe(1);
  });

  it("uses Web Locks and a generation marker to avoid refresh-token rotation races across tabs", async () => {
    document.cookie = "__Host-csrf_token=gosso-value; path=/; Secure";
    let queue = Promise.resolve();
    Object.defineProperty(navigator, "locks", {
      configurable: true,
      value: {
        request: <T>(
          _name: string,
          _options: { mode: "exclusive" },
          callback: () => T | Promise<T>,
        ): Promise<T> => {
          const result = queue.then(callback);
          queue = result.then(
            () => undefined,
            () => undefined,
          );
          return result;
        },
      },
    });
    let refreshCalls = 0;
    const makeFetcher = () => {
      let protectedCalls = 0;
      return vi.fn(async (url: string) => {
        if (url.endsWith("/api/admin/posts")) {
          protectedCalls += 1;
          return protectedCalls === 1
            ? new Response(null, { status: 401 })
            : jsonResponse({ ok: true });
        }
        refreshCalls += 1;
        return jsonResponse({ ok: true });
      });
    };
    const tabOne = createCookieClient(makeFetcher());
    const tabTwo = createCookieClient(makeFetcher());

    const responses = await Promise.all([
      tabOne.apiFetch("/api/admin/posts"),
      tabTwo.apiFetch("/api/admin/posts"),
    ]);

    expect(responses.every((response) => response.ok)).toBe(true);
    expect(refreshCalls).toBe(1);
  });

  it("starts PKCE reauthorization once when refresh is invalid and does not recurse", async () => {
    document.cookie = "__Host-csrf_token=gosso-value; path=/; Secure";
    const fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith("/api/v1/auth/refresh"))
        return jsonResponse(
          { message: "invalid or expired token" },
          { status: 401 },
        );
      return new Response(null, { status: 401 });
    });
    const client = createCookieClient(fetchMock);

    const response = await client.apiFetch("/api/admin/posts");

    expect(response.status).toBe(401);
    expect(
      fetchMock.mock.calls.filter(([url]) =>
        String(url).endsWith("/api/v1/auth/refresh"),
      ),
    ).toHaveLength(1);
    expect(sessionStorage.getItem("cookie-test:pkce_verifier")).toBeTruthy();
    expect(sessionStorage.getItem("cookie-test:post_login_redirect")).toBe("/");
    expect(
      sessionStorage.getItem("cookie-test:auth_redirect_guard"),
    ).toBeTruthy();
    const firstState = sessionStorage.getItem("cookie-test:auth_state");

    await client.apiFetch("/api/admin/posts");

    expect(sessionStorage.getItem("cookie-test:auth_state")).toBe(firstState);
    expect(
      fetchMock.mock.calls.filter(([url]) =>
        String(url).endsWith("/api/v1/auth/refresh"),
      ),
    ).toHaveLength(2);
  });

  it("does not retry indefinitely when the retried request is still 401", async () => {
    document.cookie = "__Host-csrf_token=gosso-value; path=/; Secure";
    const fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith("/api/v1/auth/refresh"))
        return jsonResponse({ ok: true });
      return new Response(null, { status: 401 });
    });
    const client = createCookieClient(fetchMock);

    await client.apiFetch("/api/admin/posts");

    expect(
      fetchMock.mock.calls.filter(([url]) =>
        String(url).endsWith("/api/admin/posts"),
      ),
    ).toHaveLength(2);
    expect(
      fetchMock.mock.calls.filter(([url]) =>
        String(url).endsWith("/api/v1/auth/refresh"),
      ),
    ).toHaveLength(1);
  });

  it("logs out with only the GOSSO CSRF cookie and clears state only after server success", async () => {
    document.cookie = "blog_csrf_token=blog-value; path=/; Secure";
    document.cookie = "__Host-csrf_token=gosso-value; path=/; Secure";
    let logoutCalls = 0;
    const fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith("/oidc/userinfo"))
        return jsonResponse({
          sub: "user-1",
          roles: ["admin"],
          scope: "openid admin",
        });
      if (url.endsWith("/api/me/session"))
        return jsonResponse({
          data: { roles: ["admin"], scope: "openid admin" },
        });
      logoutCalls += 1;
      return new Response(null, { status: logoutCalls === 1 ? 403 : 204 });
    });
    const client = createCookieClient(fetchMock);
    await client.fetchUserProfile();

    await expect(client.logout("/")).rejects.toThrow("Logout failed (403)");
    expect(client.isLoggedIn()).toBe(true);
    await expect(client.logout("/")).resolves.toBeUndefined();
    expect(client.isLoggedIn()).toBe(false);
    const failedLogoutHeaders = fetchMock.mock.calls[2][1].headers as Record<
      string,
      string
    >;
    expect(failedLogoutHeaders["X-CSRF-Token"]).toBe("gosso-value");
  });

  it("notifies subscriptions when the client session changes", () => {
    const client = createClient();
    const listener = vi.fn();
    const unsubscribe = client.subscribe(listener);

    client.saveTokenSet({
      access_token: "access",
      refresh_token: "refresh",
      expires_in: 900,
    });
    expect(listener).toHaveBeenLastCalledWith(
      expect.objectContaining({ loggedIn: true, accessToken: "access" }),
    );

    unsubscribe();
    client.clear();
    expect(listener).toHaveBeenCalledTimes(1);
  });

  describe("Typed Error Hierarchy", () => {
    it("properly instantiates all typed SDK error subclasses with code and name", () => {
      const baseErr = new GossoError("base message", "BASE_CODE");
      expect(baseErr).toBeInstanceOf(Error);
      expect(baseErr).toBeInstanceOf(GossoError);
      expect(baseErr.name).toBe("GossoError");
      expect(baseErr.code).toBe("BASE_CODE");

      const apiErr = new ApiError("bad response", 429, "rate_limited");
      expect(apiErr).toBeInstanceOf(GossoError);
      expect(apiErr.name).toBe("ApiError");
      expect(apiErr.status).toBe(429);

      const csrfErr = new CsrfError();
      expect(csrfErr).toBeInstanceOf(GossoError);
      expect(csrfErr).toBeInstanceOf(CsrfError);
      expect(csrfErr.name).toBe("CsrfError");
      expect(csrfErr.code).toBe("CSRF_MISMATCH");

      const authErr = new AuthenticationError("unauthorized", "AUTH_FAIL");
      expect(authErr).toBeInstanceOf(GossoError);
      expect(authErr).toBeInstanceOf(AuthenticationError);
      expect(authErr.name).toBe("AuthenticationError");

      const refreshErr = new TokenRefreshError(
        "refresh failed",
        "REFRESH_FAIL",
      );
      expect(refreshErr).toBeInstanceOf(GossoError);
      expect(refreshErr).toBeInstanceOf(TokenRefreshError);
      expect(refreshErr.name).toBe("TokenRefreshError");

      const cryptoErr = new CryptoError();
      expect(cryptoErr).toBeInstanceOf(GossoError);
      expect(cryptoErr).toBeInstanceOf(CryptoError);
      expect(cryptoErr.name).toBe("CryptoError");

      const passkeyErr = new PasskeyError("passkey cancel", "PASSKEY_CANCEL");
      expect(passkeyErr).toBeInstanceOf(GossoError);
      expect(passkeyErr).toBeInstanceOf(PasskeyError);
      expect(passkeyErr.name).toBe("PasskeyError");
    });

    it("throws CsrfError on OAuth2 state mismatch", async () => {
      const client = createClient();
      sessionStorage.setItem("test:auth_state", "valid-state");
      sessionStorage.setItem("test:pkce_verifier", "verifier");

      await expect(
        client.exchangeCodeForToken("code", "tampered-state"),
      ).rejects.toBeInstanceOf(CsrfError);
    });

    it("throws TokenRefreshError when no refresh token is present", async () => {
      const client = createClient();
      await expect(client.refreshAccessToken()).rejects.toBeInstanceOf(
        TokenRefreshError,
      );
    });

    it("maintains referential equality of getSnapshot() until session changes", () => {
      const client = createClient();
      const s1 = client.getSnapshot();
      const s2 = client.getSnapshot();
      expect(s1).toBe(s2);

      client.saveTokenSet({ access_token: "token-123", expires_in: 900 });
      const s3 = client.getSnapshot();
      expect(s3).not.toBe(s1);
      expect(client.getSnapshot()).toBe(s3);
    });

    it("completes step-up MFA without access_token in cookie session mode", async () => {
      const fetchImpl = vi.fn().mockResolvedValue(
        jsonResponse({
          code: 200,
          data: {
            auth_time: 1724774400,
            amr: ["pwd", "otp"],
            expires_in: 900,
          },
        }),
      );
      const client = createCookieClient(fetchImpl);
      const res = await client.stepUpMfa("123456", "totp");
      expect(res.auth_time).toBe(1724774400);
      expect(res.amr).toEqual(["pwd", "otp"]);
      expect(res.access_token).toBeUndefined();
    });

    it("performs typed HTTP helper requests (get, post, put, patch, delete)", async () => {
      const fetchImpl = vi.fn().mockImplementation((url, options) => {
        const method = options?.method || "GET";
        return Promise.resolve(
          jsonResponse({
            code: 200,
            data: { method, path: String(url) },
          }),
        );
      });
      const client = createCookieClient(fetchImpl);

      const getRes = await client.get<{ method: string }>("/api/test");
      expect(getRes.method).toBe("GET");

      const postRes = await client.post<{ method: string }>("/api/test", {
        foo: "bar",
      });
      expect(postRes.method).toBe("POST");

      const putRes = await client.put<{ method: string }>("/api/test", {
        foo: "bar",
      });
      expect(putRes.method).toBe("PUT");

      const patchRes = await client.patch<{ method: string }>("/api/test", {
        foo: "bar",
      });
      expect(patchRes.method).toBe("PATCH");

      const delRes = await client.delete<{ method: string }>("/api/test");
      expect(delRes.method).toBe("DELETE");

      const getWithParams = await client.get<{ method: string; path: string }>(
        "/api/items",
        { params: { page: 2, tag: "tech", empty: "" } },
      );
      expect(getWithParams.path).toBe("/api/items?page=2&tag=tech");

      const getWithExistingParams = await client.get<{
        method: string;
        path: string;
      }>("/api/items?filter=active", {
        params: new URLSearchParams({ sort: "desc" }),
      });
      expect(getWithExistingParams.path).toBe(
        "/api/items?filter=active&sort=desc",
      );
    });
  });
});

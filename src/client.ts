import type {
  ApiEnvelope,
  AuthCallbackResult,
  AuthenticationResult,
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
} from "./types.js";
import {
  base64URLToBuffer,
  bufferToBase64URL,
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
  safeLocalPath,
} from "./utils.js";
import {
  AuthenticationError,
  CsrfError,
  PasskeyError,
  TokenRefreshError,
} from "./errors.js";
import { generateCodeChallenge } from "./pkce.js";

const REFRESH_LOCK_TTL_MS = 15_000;
const REFRESH_WAIT_TIMEOUT_MS = 20_000;
const REFRESH_WAIT_POLL_MS = 100;
const REFRESH_WEB_LOCK_NAME = "gosso-auth-refresh";
const AUTH_REDIRECT_GUARD_MS = 30_000;

export const defaultConfig: Pick<
  GossoClientConfig,
  | "scope"
  | "postLoginDefaultPath"
  | "loginPath"
  | "storagePrefix"
  | "sessionMode"
> = {
  scope: "openid profile email",
  postLoginDefaultPath: "/",
  loginPath: "/login",
  storagePrefix: "gosso",
  sessionMode: "cookie",
};

export function createGossoClient<TProfile = UserProfile>(
  inputConfig: GossoClientConfig<TProfile>,
) {
  const config = {
    ...defaultConfig,
    ...inputConfig,
    issuer: normalizeBaseUrl(inputConfig.issuer),
    sessionMode: inputConfig.sessionMode ?? defaultConfig.sessionMode,
  };
  const cookieSession = config.sessionMode === "cookie";
  const flowStorage = sessionStorage;
  const fetcher = (input: RequestInfo | URL, init?: RequestInit) =>
    (config.fetchImpl || globalThis.fetch)(input, init);
  const key = (name: string) => `${config.storagePrefix}:${name}`;
  const storageKeys = {
    accessToken: key("access_token"),
    refreshToken: key("refresh_token"),
    userProfile: key("user_profile"),
    pkceVerifier: key("pkce_verifier"),
    authState: key("auth_state"),
    postLoginRedirect: key("post_login_redirect"),
    tokenIssuedAt: key("token_issued_at"), // legacy cleanup only
    tokenExpiresIn: key("token_expires_in"), // legacy cleanup only
    refreshLock: key("auth_refresh_lock"),
    refreshGeneration: key("auth_refresh_generation"),
    authRedirectGuard: key("auth_redirect_guard"),
  };

  let refreshPromise: Promise<string> | null = null;
  let memoryTokenSet: TokenResponse | null = null;
  let tokenIssuedAt = 0;
  const sessionListeners = new Set<SessionListener<TProfile>>();

  const deleteCookie = (name: string) => {
    const cookieName = getCookieName(name);
    document.cookie = `${cookieName}=; path=/; max-age=-1; SameSite=Lax`;
  };

  const readProfile = (): TProfile | null => {
    const profile = sessionStorage.getItem(storageKeys.userProfile);
    if (!profile) return null;
    try {
      return JSON.parse(profile) as TProfile;
    } catch {
      return null;
    }
  };

  const getAccessToken = (): string | null =>
    cookieSession ? null : memoryTokenSet?.access_token || null;
  const getRefreshToken = (): string | null =>
    cookieSession ? null : memoryTokenSet?.refresh_token || null;

  let cachedSnapshot: SessionSnapshot<TProfile> | null = null;

  const computeSnapshot = (): SessionSnapshot<TProfile> => {
    const accessToken = getAccessToken();
    const refreshToken = getRefreshToken();
    const profile = readProfile();
    return {
      accessToken,
      refreshToken,
      profile,
      loggedIn: cookieSession ? Boolean(profile) : Boolean(accessToken),
      isAdmin: hasAdminAccess(
        profile as unknown as UserProfile | null,
        accessToken,
      ),
    };
  };

  const getSnapshot = (): SessionSnapshot<TProfile> => {
    if (!cachedSnapshot) {
      cachedSnapshot = computeSnapshot();
    }
    return cachedSnapshot;
  };

  const emitSessionChanged = () => {
    cachedSnapshot = computeSnapshot();
    config.onSessionChanged?.(cachedSnapshot);
    sessionListeners.forEach((listener) => listener(cachedSnapshot!));
  };

  /**
   * Observe profile, login and logout changes without reimplementing a session
   * store in each consuming SPA. Callers receive future changes only and must
   * read getSnapshot() for the initial value.
   */
  const subscribe = (listener: SessionListener<TProfile>) => {
    sessionListeners.add(listener);
    return () => {
      sessionListeners.delete(listener);
    };
  };

  const saveTokenSet = (
    data:
      | TokenResponse
      | { access_token: string; refresh_token?: string; expires_in?: number },
  ) => {
    if (cookieSession) {
      emitSessionChanged();
      return;
    }
    memoryTokenSet = {
      access_token: data.access_token,
      refresh_token: data.refresh_token || "",
      expires_in: data.expires_in || 900,
    };
    tokenIssuedAt = Date.now();
    emitSessionChanged();
  };

  const clear = () => {
    memoryTokenSet = null;
    tokenIssuedAt = 0;
    // Remove artifacts written by pre-0.4 releases during migration.
    Object.values(storageKeys).forEach((storageKey) =>
      localStorage.removeItem(storageKey),
    );
    Object.values(storageKeys).forEach((storageKey) =>
      sessionStorage.removeItem(storageKey),
    );
    deleteCookie("access_token");
    emitSessionChanged();
  };

  const redirectToLogin = () => {
    if (config.onAuthRequired) {
      config.onAuthRequired();
      return;
    }
    window.location.href = safeLocalPath(config.loginPath, "/login");
  };

  const identityCSRFCookieName =
    new URL(config.issuer).protocol === "https:"
      ? "__Host-csrf_token"
      : "csrf_token";

  const issuerOrigin = new URL(config.issuer).origin;
  const credentialsFor = (target: URL): RequestCredentials =>
    cookieSession && target.origin !== window.location.origin
      ? "include"
      : "same-origin";
  const identityCredentials = credentialsFor(new URL(config.issuer));
  const allowedApiOrigins = new Set([window.location.origin, issuerOrigin]);
  for (const value of config.allowedApiOrigins || []) {
    const parsed = new URL(value);
    if (parsed.protocol !== "https:" && parsed.hostname !== "localhost") {
      throw new AuthenticationError(
        "Allowed API origins must use HTTPS",
        "INSECURE_API_ORIGIN",
      );
    }
    allowedApiOrigins.add(parsed.origin);
  }
  const resolveRequestURL = (url: string): URL =>
    new URL(url, window.location.origin);
  const isIdentityRequest = (url: string): boolean => {
    const target = resolveRequestURL(url);
    return (
      target.origin === issuerOrigin &&
      ["/api/v1/", "/oauth2/", "/oidc/", "/.well-known/"].some((prefix) =>
        target.pathname.startsWith(prefix),
      )
    );
  };
  const assertAllowedRequest = (url: string): URL => {
    const target = resolveRequestURL(url);
    if (!allowedApiOrigins.has(target.origin)) {
      throw new AuthenticationError(
        `Refusing credentials for untrusted API origin: ${target.origin}`,
        "UNTRUSTED_API_ORIGIN",
      );
    }
    return target;
  };

  const readIdentityCSRFToken = (): string | null =>
    readCookie(identityCSRFCookieName);

  const ensureIdentityCSRFToken = async (): Promise<string> => {
    let token = readIdentityCSRFToken();
    if (token) return token;

    // Safe methods are accepted without CSRF validation and the GOSSO middleware
    // reissues its own short-lived double-submit cookie before auth is evaluated.
    await fetcher(`${config.issuer}/api/v1/auth/session`, {
      credentials: identityCredentials,
    });
    token = readIdentityCSRFToken();
    if (!token)
      throw new CookieSessionRefreshError(403, "GOSSO CSRF recovery failed");
    return token;
  };

  const tryAcquireRefreshLock = (owner: string): boolean => {
    const now = Date.now();
    const current = parseRefreshLock(
      localStorage.getItem(storageKeys.refreshLock),
    );
    if (current && current.expiresAt > now && current.owner !== owner) {
      return false;
    }
    const nextLock: RefreshLock = {
      owner,
      expiresAt: now + REFRESH_LOCK_TTL_MS,
    };
    localStorage.setItem(storageKeys.refreshLock, JSON.stringify(nextLock));
    return (
      parseRefreshLock(localStorage.getItem(storageKeys.refreshLock))?.owner ===
      owner
    );
  };

  const releaseRefreshLock = (owner: string) => {
    const current = parseRefreshLock(
      localStorage.getItem(storageKeys.refreshLock),
    );
    if (
      !current ||
      current.owner === owner ||
      current.expiresAt <= Date.now()
    ) {
      localStorage.removeItem(storageKeys.refreshLock);
    }
  };

  const requestBrowserRefreshLock = async (
    callback: () => Promise<string>,
  ): Promise<string> => {
    const locks = (navigator as NavigatorWithLocks).locks;
    if (!locks) return callback();
    return locks.request(
      REFRESH_WEB_LOCK_NAME,
      { mode: "exclusive" },
      callback,
    );
  };

  const currentRefreshGeneration = (): string | null =>
    localStorage.getItem(storageKeys.refreshGeneration);

  const markCookieRefreshComplete = () => {
    localStorage.setItem(
      storageKeys.refreshGeneration,
      `${Date.now()}:${generateRefreshOwner()}`,
    );
  };

  const performCookieRefresh = async (
    observedGeneration: string | null,
  ): Promise<string> => {
    if (currentRefreshGeneration() !== observedGeneration) return "";

    const csrf = await ensureIdentityCSRFToken();
    const response = await fetcher(`${config.issuer}/api/v1/auth/refresh`, {
      method: "POST",
      headers: { "X-CSRF-Token": csrf, "X-Gosso-Cookie-Session": "1" },
      credentials: identityCredentials,
    });
    if (!response.ok) {
      const message =
        response.status === 401
          ? "Refresh token is invalid, expired, or revoked"
          : response.status === 403
            ? "GOSSO CSRF recovery failed"
            : "Cookie session refresh failed";
      throw new CookieSessionRefreshError(response.status, message);
    }
    markCookieRefreshComplete();
    return "";
  };

  const performTokenRefresh = async (
    previousRefreshToken: string,
  ): Promise<string> => {
    const latestRefreshToken = getRefreshToken();
    if (!latestRefreshToken)
      throw new TokenRefreshError("No refresh token found", "NO_REFRESH_TOKEN");
    if (latestRefreshToken !== previousRefreshToken) {
      const latestAccessToken = getAccessToken();
      if (latestAccessToken) return latestAccessToken;
    }
    const response = await fetcher(`${config.issuer}/api/v1/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: latestRefreshToken }),
    });
    const data = await parseJsonEnvelope<TokenResponse>(
      response,
      "Token refresh failed",
    );
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
            return requestBrowserRefreshLock(() =>
              performCookieRefresh(observedGeneration),
            );
          }
          lockAcquired = tryAcquireRefreshLock(owner);
          if (!lockAcquired) {
            const startedAt = Date.now();
            while (Date.now() - startedAt < REFRESH_WAIT_TIMEOUT_MS) {
              if (currentRefreshGeneration() !== observedGeneration) return "";
              const lock = parseRefreshLock(
                localStorage.getItem(storageKeys.refreshLock),
              );
              if (!lock || lock.expiresAt <= Date.now()) break;
              await new Promise((resolve) =>
                window.setTimeout(resolve, REFRESH_WAIT_POLL_MS),
              );
            }
            lockAcquired = tryAcquireRefreshLock(owner);
            if (!lockAcquired)
              throw new TokenRefreshError(
                "Cookie session refresh is already in progress",
                "REFRESH_IN_PROGRESS",
              );
          }
          return performCookieRefresh(observedGeneration);
        }
        const refreshToken = getRefreshToken();
        if (!refreshToken)
          throw new TokenRefreshError(
            "No refresh token found",
            "NO_REFRESH_TOKEN",
          );
        // Legacy token sessions are intentionally tab-local and in-memory.
        // refreshPromise already coalesces concurrent refreshes in this page.
        return performTokenRefresh(refreshToken);
      } finally {
        if (lockAcquired) releaseRefreshLock(owner);
      }
    })();
    refreshPromise = pending;
    void pending.then(
      () => {
        if (refreshPromise === pending) refreshPromise = null;
      },
      () => {
        if (refreshPromise === pending) refreshPromise = null;
      },
    );
    return pending;
  };

  const fetchUserProfile = async (
    accessToken = getAccessToken(),
  ): Promise<TProfile> => {
    if (cookieSession) {
      const [identity, session] = await Promise.all([
        fetcher(`${config.issuer}/oidc/userinfo`, {
          credentials: identityCredentials,
        }),
        config.sessionProfileEndpoint
          ? fetcher(config.sessionProfileEndpoint, {
              credentials: credentialsFor(
                assertAllowedRequest(config.sessionProfileEndpoint),
              ),
            })
          : Promise.resolve(null),
      ]);
      if (!identity.ok || (session && !session.ok))
        throw new AuthenticationError(
          "Failed to fetch user profile",
          "USER_PROFILE_FAILED",
        );
      const data = (await identity.json()) as TProfile;
      if (session)
        Object.assign(
          data as object,
          ((await session.json()) as ApiEnvelope<Partial<TProfile>>).data || {},
        );
      sessionStorage.setItem(storageKeys.userProfile, JSON.stringify(data));
      sessionStorage.removeItem(storageKeys.authRedirectGuard);
      emitSessionChanged();
      return data;
    }
    if (!accessToken)
      throw new AuthenticationError("No access token found", "NO_ACCESS_TOKEN");
    const response = await fetcher(`${config.issuer}/oidc/userinfo`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!response.ok)
      throw new AuthenticationError(
        "Failed to fetch user profile",
        "USER_PROFILE_FAILED",
      );
    const data = (await response.json()) as TProfile;
    const roles = readRolesFromAccessToken(accessToken);
    if (roles) (data as unknown as UserProfile).roles = roles;
    const scope = readScopeFromAccessToken(accessToken);
    if (scope) (data as unknown as UserProfile).scope = scope;
    sessionStorage.setItem(storageKeys.userProfile, JSON.stringify(data));
    emitSessionChanged();
    return data;
  };

  const apiFetch = async (
    url: string,
    options: RequestInit = {},
  ): Promise<Response> => {
    const target = assertAllowedRequest(url);
    if (cookieSession) {
      const headers = new Headers(options.headers || {});
      const issuerRequest = isIdentityRequest(target.toString());
      if (
        !["GET", "HEAD", "OPTIONS"].includes(
          (options.method || "GET").toUpperCase(),
        ) &&
        !headers.has("X-CSRF-Token")
      ) {
        const csrf = issuerRequest
          ? readIdentityCSRFToken()
          : config.csrfCookieName
            ? readCookie(config.csrfCookieName)
            : null;
        if (csrf) headers.set("X-CSRF-Token", csrf);
      }
      let response = await fetcher(url, {
        ...options,
        headers,
        credentials: credentialsFor(target),
      });
      if (
        response.status === 401 &&
        (!issuerRequest || config.refreshIdentityRequests)
      ) {
        try {
          await refreshAccessToken();
          response = await fetcher(url, {
            ...options,
            headers,
            credentials: credentialsFor(target),
          });
        } catch {
          response = new Response(null, {
            status: 401,
            statusText: "Authentication required",
          });
        }
      }
      if (response.status === 401) {
        const returnTo = `${window.location.pathname}${window.location.search}${window.location.hash}`;
        const previous = sessionStorage.getItem(storageKeys.authRedirectGuard);
        const now = Date.now();
        let recentlyRedirected = false;
        try {
          const guard = previous
            ? (JSON.parse(previous) as { at?: number; returnTo?: string })
            : null;
          recentlyRedirected =
            guard?.returnTo === returnTo &&
            typeof guard.at === "number" &&
            now - guard.at < AUTH_REDIRECT_GUARD_MS;
        } catch {
          recentlyRedirected = false;
        }
        if (!recentlyRedirected) {
          clear();
          sessionStorage.setItem(
            storageKeys.authRedirectGuard,
            JSON.stringify({ at: now, returnTo }),
          );
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
    const expiresIn = memoryTokenSet?.expires_in || 900;
    if (tokenIssuedAt && Date.now() - tokenIssuedAt > expiresIn * 1000) {
      try {
        token = await refreshAccessToken();
      } catch {
        clear();
        redirectToLogin();
        return new Response(null, { status: 401 });
      }
    }
    const headers = new Headers(options.headers || {});
    if (token && !headers.has("Authorization")) {
      headers.set("Authorization", `Bearer ${token}`);
    }
    let response = await fetcher(url, { ...options, headers });
    if (response.status === 401 && getRefreshToken()) {
      try {
        const freshToken = await refreshAccessToken();
        headers.set("Authorization", `Bearer ${freshToken}`);
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
      flowStorage.setItem(
        storageKeys.postLoginRedirect,
        safeLocalPath(customRedirectUri, config.postLoginDefaultPath),
      );
    }
    const challenge = await generateCodeChallenge(verifier);
    const authUrl = new URL(`${config.issuer}/oauth2/authorize`);
    authUrl.searchParams.append("client_id", config.clientId);
    authUrl.searchParams.append("response_type", "code");
    authUrl.searchParams.append("redirect_uri", config.redirectUri);
    authUrl.searchParams.append("scope", config.scope);
    authUrl.searchParams.append("code_challenge", challenge);
    authUrl.searchParams.append("code_challenge_method", "S256");
    authUrl.searchParams.append("state", state);
    window.location.href = authUrl.toString();
  };

  const exchangeCodeForToken = async (
    code: string,
    state: string,
  ): Promise<AuthenticationResult> => {
    const savedState = flowStorage.getItem(storageKeys.authState);
    const verifier = flowStorage.getItem(storageKeys.pkceVerifier);
    if (state !== savedState)
      throw new CsrfError(
        "State mismatch. Potential CSRF attack.",
        "CSRF_MISMATCH",
      );
    if (!verifier)
      throw new AuthenticationError(
        "PKCE verifier not found. Authentication flow expired.",
        "PKCE_VERIFIER_MISSING",
      );
    const body = new URLSearchParams();
    body.append("grant_type", "authorization_code");
    body.append("client_id", config.clientId);
    body.append("code", code);
    body.append("code_verifier", verifier);
    body.append("redirect_uri", config.redirectUri);
    const response = await fetcher(`${config.issuer}/oauth2/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        ...(cookieSession ? { "X-Gosso-Cookie-Session": "1" } : {}),
      },
      body: body.toString(),
      credentials: identityCredentials,
    });
    if (!response.ok) {
      throw new AuthenticationError(
        `Token exchange failed: ${await response.text()}`,
        "TOKEN_EXCHANGE_FAILED",
      );
    }
    const data = (await response.json()) as AuthenticationResult;
    if (!cookieSession) saveTokenSet(data as TokenResponse);
    flowStorage.removeItem(storageKeys.pkceVerifier);
    flowStorage.removeItem(storageKeys.authState);
    return data;
  };

  const handleRedirectCallback = async (
    code: string,
    state: string,
  ): Promise<AuthCallbackResult> => {
    const tokenSet = await exchangeCodeForToken(code, state);
    await fetchUserProfile(
      cookieSession ? undefined : (tokenSet as TokenResponse).access_token,
    );
    const redirectTo = safeLocalPath(
      flowStorage.getItem(storageKeys.postLoginRedirect) || undefined,
      config.postLoginDefaultPath,
    );
    flowStorage.removeItem(storageKeys.postLoginRedirect);
    sessionStorage.removeItem(storageKeys.authRedirectGuard);
    if (cookieSession) return { sessionMode: "cookie", redirectTo };
    return {
      sessionMode: "token",
      tokenSet: tokenSet as TokenResponse,
      redirectTo,
    };
  };

  const logout = async (redirectTo = "/") => {
    if (cookieSession) {
      const csrf = await ensureIdentityCSRFToken();
      const response = await fetcher(`${config.issuer}/api/v1/auth/logout`, {
        method: "POST",
        headers: { "X-CSRF-Token": csrf },
        credentials: identityCredentials,
        keepalive: true,
      });
      if (!response.ok)
        throw new AuthenticationError(
          `Logout failed (${response.status})`,
          "LOGOUT_FAILED",
        );
      clear();
      window.location.href = safeLocalPath(redirectTo, "/");
      return;
    }
    const accessToken = getAccessToken();
    try {
      if (accessToken) {
        await fetcher(`${config.issuer}/api/v1/auth/logout`, {
          method: "POST",
          headers: { Authorization: `Bearer ${accessToken}` },
          credentials: identityCredentials,
          keepalive: true,
        });
      }
    } finally {
      clear();
      window.location.href = safeLocalPath(redirectTo, "/");
    }
  };

  const loginWithPassword = async (
    username: string,
    password: string,
  ): Promise<LoginResult> => {
    const response = await fetcher(`${config.issuer}/api/v1/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(cookieSession ? { "X-Gosso-Cookie-Session": "1" } : {}),
      },
      body: JSON.stringify({ username, password }),
      credentials: identityCredentials,
    });
    const result = await parseJsonEnvelope<LoginResult>(
      response,
      "Login failed",
    );
    if (!cookieSession && result.access_token) {
      saveTokenSet(result as TokenResponse);
      await fetchUserProfile(result.access_token);
    } else if (cookieSession && !result.requires_mfa) {
      await fetchUserProfile();
    }
    return result;
  };

  const requestPasswordReset = async (email: string): Promise<void> => {
    const response = await fetcher(
      `${config.issuer}/api/v1/auth/password/forgot`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
        credentials: identityCredentials,
      },
    );
    await parseJsonEnvelope<unknown>(
      response,
      "Failed to request a password reset",
    );
  };

  const resetPassword = async (
    token: string,
    newPassword: string,
  ): Promise<void> => {
    const response = await fetcher(
      `${config.issuer}/api/v1/auth/password/reset`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, new_password: newPassword }),
        credentials: identityCredentials,
      },
    );
    await parseJsonEnvelope<unknown>(response, "Failed to reset password");
  };

  const verifyMfa = async (
    mfaToken: string,
    code: string,
    type: "totp" | "passkey" = "totp",
  ): Promise<AuthenticationResult> => {
    const response = await fetcher(`${config.issuer}/api/v1/auth/mfa/verify`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(cookieSession ? { "X-Gosso-Cookie-Session": "1" } : {}),
      },
      body: JSON.stringify({ mfa_token: mfaToken, code, type }),
      credentials: identityCredentials,
    });
    const data = await parseJsonEnvelope<AuthenticationResult>(
      response,
      "MFA verification failed",
    );
    if (!cookieSession) saveTokenSet(data as TokenResponse);
    await fetchUserProfile(
      cookieSession ? undefined : (data as TokenResponse).access_token,
    );
    return data;
  };

  const loginWithPasskey = async (): Promise<AuthenticationResult> => {
    const beginRes = await fetcher(
      `${config.issuer}/api/v1/passkey/login/begin`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
        credentials: identityCredentials,
      },
    );
    const begin = await parseJsonEnvelope<{
      options: PublicKeyCredentialRequestOptions;
      request_id: string;
    }>(beginRes, "Failed to begin passkey login");
    const options = {
      ...begin.options,
      challenge: base64URLToBuffer(
        begin.options.challenge as unknown as string,
      ),
      allowCredentials: (begin.options.allowCredentials || []).map((cred) => ({
        ...cred,
        id: base64URLToBuffer(cred.id as unknown as string),
      })),
    };
    const assertion = (await navigator.credentials.get({
      publicKey: options,
    })) as PublicKeyCredential | null;
    if (!assertion?.response)
      throw new PasskeyError(
        "Passkey authentication cancelled or failed",
        "PASSKEY_AUTH_CANCELLED",
      );
    const assertionResponse =
      assertion.response as AuthenticatorAssertionResponse;
    const completeRes = await fetcher(
      `${config.issuer}/api/v1/passkey/login/complete`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(cookieSession ? { "X-Gosso-Cookie-Session": "1" } : {}),
        },
        body: JSON.stringify({
          request_id: begin.request_id,
          id: assertion.id,
          rawId: bufferToBase64URL(assertion.rawId),
          type: assertion.type,
          response: {
            clientDataJSON: bufferToBase64URL(assertionResponse.clientDataJSON),
            authenticatorData: bufferToBase64URL(
              assertionResponse.authenticatorData,
            ),
            signature: bufferToBase64URL(assertionResponse.signature),
            userHandle: assertionResponse.userHandle
              ? bufferToBase64URL(assertionResponse.userHandle)
              : null,
          },
        }),
      },
    );
    const data = await parseJsonEnvelope<AuthenticationResult>(
      completeRes,
      "Passkey login failed",
    );
    if (!cookieSession) saveTokenSet(data as TokenResponse);
    await fetchUserProfile(
      cookieSession ? undefined : (data as TokenResponse).access_token,
    );
    return data;
  };

  const updateProfile = async (displayName: string) => {
    const response = await apiFetch(`${config.issuer}/api/v1/auth/profile`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ display_name: displayName }),
    });
    await parseJsonEnvelope<unknown>(response, "Failed to update profile");
    return fetchUserProfile();
  };

  const changePassword = async (
    currentPassword: string,
    newPassword: string,
  ) => {
    const response = await apiFetch(
      `${config.issuer}/api/v1/auth/password/change`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          current_password: currentPassword,
          new_password: newPassword,
        }),
      },
    );
    await parseJsonEnvelope<unknown>(response, "Failed to change password");
  };

  const requestEmailChange = async (newEmail: string, password: string) => {
    const response = await apiFetch(
      `${config.issuer}/api/v1/auth/profile/email/change/request`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ new_email: newEmail, password }),
      },
    );
    await parseJsonEnvelope<unknown>(
      response,
      "Failed to request email verification code",
    );
  };

  const confirmEmailChange = async (newEmail: string, code: string) => {
    const response = await apiFetch(
      `${config.issuer}/api/v1/auth/profile/email/change/confirm`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ new_email: newEmail, code }),
      },
    );
    await parseJsonEnvelope<unknown>(
      response,
      "Failed to confirm email change",
    );
    return fetchUserProfile();
  };

  const getMfaStatus = async (): Promise<MfaStatus> => {
    const response = await apiFetch(`${config.issuer}/api/v1/auth/mfa`);
    return parseJsonEnvelope<MfaStatus>(response, "Failed to load MFA status");
  };

  const enrollMfa = async (): Promise<MfaEnrollment> => {
    const response = await apiFetch(`${config.issuer}/api/v1/auth/mfa/enroll`, {
      method: "POST",
    });
    return parseJsonEnvelope<MfaEnrollment>(response, "Failed to enroll MFA");
  };

  const activateMfa = async (code: string): Promise<string[]> => {
    const response = await apiFetch(
      `${config.issuer}/api/v1/auth/mfa/activate`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      },
    );
    await parseJsonEnvelope<unknown>(response, "Failed to activate MFA");
    const codesResponse = await apiFetch(
      `${config.issuer}/api/v1/auth/mfa/backup-codes`,
      { method: "POST" },
    );
    const data = await parseJsonEnvelope<{ backup_codes?: string[] }>(
      codesResponse,
      "Failed to generate backup codes",
    );
    return data.backup_codes || [];
  };

  const disableMfa = async (currentPassword: string) => {
    const response = await apiFetch(`${config.issuer}/api/v1/auth/mfa`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ current_password: currentPassword }),
    });
    await parseJsonEnvelope<unknown>(response, "Failed to disable MFA");
  };

  const generateBackupCodes = async (): Promise<string[]> => {
    const response = await apiFetch(
      `${config.issuer}/api/v1/auth/mfa/backup-codes`,
      { method: "POST" },
    );
    const data = await parseJsonEnvelope<{ backup_codes?: string[] }>(
      response,
      "Failed to generate backup codes",
    );
    return data.backup_codes || [];
  };

  const stepUpMfa = async (
    code: string,
    type: "totp" | "backup_code" = "totp",
  ): Promise<{ access_token?: string; auth_time: number; amr: string[] }> => {
    const response = await apiFetch(
      `${config.issuer}/api/v1/auth/mfa/step-up`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code, type }),
      },
    );
    return parseJsonEnvelope<{
      access_token?: string;
      auth_time: number;
      amr: string[];
    }>(response, "Failed to complete step-up MFA");
  };

  const listPasskeys = async (): Promise<PasskeyInfo[]> => {
    const response = await apiFetch(`${config.issuer}/api/v1/passkeys`);
    return parseJsonEnvelope<PasskeyInfo[]>(
      response,
      "Failed to load passkeys",
    );
  };

  const registerPasskey = async (name: string): Promise<void> => {
    const beginRes = await apiFetch(
      `${config.issuer}/api/v1/passkey/register/begin`,
      { method: "POST" },
    );
    const begin = await parseJsonEnvelope<{
      options: PublicKeyCredentialCreationOptions;
      request_id: string;
    }>(beginRes, "Failed to initialize passkey registration");
    const options = {
      ...begin.options,
      challenge: base64URLToBuffer(
        begin.options.challenge as unknown as string,
      ),
      user: {
        ...begin.options.user,
        id: base64URLToBuffer(begin.options.user.id as unknown as string),
      },
      excludeCredentials: (begin.options.excludeCredentials || []).map(
        (cred) => ({
          ...cred,
          id: base64URLToBuffer(cred.id as unknown as string),
        }),
      ),
    };
    const credential = (await navigator.credentials.create({
      publicKey: options,
    })) as PublicKeyCredential | null;
    if (!credential?.response)
      throw new PasskeyError(
        "Passkey registration cancelled or failed",
        "PASSKEY_REGISTRATION_CANCELLED",
      );
    const attestationResponse =
      credential.response as AuthenticatorAttestationResponse;
    const completeRes = await apiFetch(
      `${config.issuer}/api/v1/passkey/register/complete?request_id=${begin.request_id}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: credential.id,
          rawId: bufferToBase64URL(credential.rawId),
          type: credential.type,
          name,
          response: {
            clientDataJSON: bufferToBase64URL(
              attestationResponse.clientDataJSON,
            ),
            attestationObject: bufferToBase64URL(
              attestationResponse.attestationObject,
            ),
            transports:
              typeof attestationResponse.getTransports === "function"
                ? attestationResponse.getTransports()
                : [],
          },
        }),
      },
    );
    await parseJsonEnvelope<unknown>(
      completeRes,
      "Failed to verify passkey registration",
    );
  };

  const deletePasskey = async (id: string) => {
    const response = await apiFetch(`${config.issuer}/api/v1/passkeys/${id}`, {
      method: "DELETE",
    });
    await parseJsonEnvelope<unknown>(response, "Failed to remove passkey");
  };

  const listSessions = async (): Promise<SessionInfo[]> => {
    const response = await apiFetch(`${config.issuer}/api/v1/auth/sessions`);
    const sessions = await parseJsonEnvelope<SessionInfo[]>(
      response,
      "Failed to load sessions",
    );
    return sessions.sort(
      (a, b) =>
        new Date(b.last_active_at).getTime() -
        new Date(a.last_active_at).getTime(),
    );
  };

  const getCurrentSession = async (): Promise<SessionInfo> => {
    const response = await apiFetch(`${config.issuer}/api/v1/auth/session`);
    return parseJsonEnvelope<SessionInfo>(
      response,
      "Failed to load current session",
    );
  };

  const revokeSession = async (id: string) => {
    const response = await apiFetch(
      `${config.issuer}/api/v1/auth/sessions/${id}`,
      { method: "DELETE" },
    );
    await parseJsonEnvelope<unknown>(response, "Failed to revoke session");
  };

  return {
    config,
    storageKeys,
    getAccessToken,
    getRefreshToken,
    getUserProfile: readProfile,
    getSnapshot,
    subscribe,
    isLoggedIn: () =>
      cookieSession ? Boolean(readProfile()) : Boolean(getAccessToken()),
    isAdmin: () =>
      hasAdminAccess(
        readProfile() as unknown as UserProfile | null,
        getAccessToken(),
      ),
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
    requestPasswordReset,
    resetPassword,
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
    stepUpMfa,
    listPasskeys,
    registerPasskey,
    deletePasskey,
    listSessions,
    getCurrentSession,
    revokeSession,
    requestJson: <T = unknown>(
      url: string,
      method: string,
      body?: unknown,
      init: RequestInit = {},
    ): Promise<T> => {
      const headers = new Headers(init.headers || {});
      let payloadBody = init.body;
      if (body !== undefined && payloadBody === undefined) {
        if (
          typeof body === "string" ||
          body instanceof FormData ||
          body instanceof URLSearchParams ||
          body instanceof Blob
        ) {
          payloadBody = body;
        } else {
          if (!headers.has("Content-Type")) {
            headers.set("Content-Type", "application/json");
          }
          payloadBody = JSON.stringify(body);
        }
      }
      return apiFetch(url, {
        ...init,
        method,
        headers,
        body: payloadBody,
      }).then((res) => parseJsonEnvelope<T>(res, `${method} request failed`));
    },
    get: <T = unknown>(url: string, init?: RequestInit): Promise<T> => {
      return apiFetch(url, { ...init, method: "GET" }).then((res) =>
        parseJsonEnvelope<T>(res, "GET request failed"),
      );
    },
    post: <T = unknown>(
      url: string,
      body?: unknown,
      init: RequestInit = {},
    ): Promise<T> => {
      const headers = new Headers(init.headers || {});
      let payloadBody = init.body;
      if (body !== undefined && payloadBody === undefined) {
        if (
          typeof body === "string" ||
          body instanceof FormData ||
          body instanceof URLSearchParams ||
          body instanceof Blob
        ) {
          payloadBody = body;
        } else {
          if (!headers.has("Content-Type")) {
            headers.set("Content-Type", "application/json");
          }
          payloadBody = JSON.stringify(body);
        }
      }
      return apiFetch(url, {
        ...init,
        method: "POST",
        headers,
        body: payloadBody,
      }).then((res) => parseJsonEnvelope<T>(res, "POST request failed"));
    },
    put: <T = unknown>(
      url: string,
      body?: unknown,
      init: RequestInit = {},
    ): Promise<T> => {
      const headers = new Headers(init.headers || {});
      let payloadBody = init.body;
      if (body !== undefined && payloadBody === undefined) {
        if (
          typeof body === "string" ||
          body instanceof FormData ||
          body instanceof URLSearchParams ||
          body instanceof Blob
        ) {
          payloadBody = body;
        } else {
          if (!headers.has("Content-Type")) {
            headers.set("Content-Type", "application/json");
          }
          payloadBody = JSON.stringify(body);
        }
      }
      return apiFetch(url, {
        ...init,
        method: "PUT",
        headers,
        body: payloadBody,
      }).then((res) => parseJsonEnvelope<T>(res, "PUT request failed"));
    },
    patch: <T = unknown>(
      url: string,
      body?: unknown,
      init: RequestInit = {},
    ): Promise<T> => {
      const headers = new Headers(init.headers || {});
      let payloadBody = init.body;
      if (body !== undefined && payloadBody === undefined) {
        if (
          typeof body === "string" ||
          body instanceof FormData ||
          body instanceof URLSearchParams ||
          body instanceof Blob
        ) {
          payloadBody = body;
        } else {
          if (!headers.has("Content-Type")) {
            headers.set("Content-Type", "application/json");
          }
          payloadBody = JSON.stringify(body);
        }
      }
      return apiFetch(url, {
        ...init,
        method: "PATCH",
        headers,
        body: payloadBody,
      }).then((res) => parseJsonEnvelope<T>(res, "PATCH request failed"));
    },
    delete: <T = unknown>(url: string, init?: RequestInit): Promise<T> => {
      return apiFetch(url, { ...init, method: "DELETE" }).then((res) =>
        parseJsonEnvelope<T>(res, "DELETE request failed"),
      );
    },
  };
}

export type GossoClient<TProfile = UserProfile> = ReturnType<
  typeof createGossoClient<TProfile>
>;

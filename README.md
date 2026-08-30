# @gosso/client

Browser SDK for Gosso OAuth/OIDC single-page application clients.

`@gosso/client` provides the protocol and account self-service layer for ordinary Gosso clients:

- Authorization Code + PKCE redirects and callback handling
- HttpOnly Cookie Session, userinfo loading, logout, and automatic refresh
- origin-restricted authenticated `apiFetch` with CSRF handling and 401 retry
- username/password login, MFA verification, and passkey login
- profile, password, email, MFA, passkey, and session management APIs
- password reset request and completion APIs
- typed API errors for consistent consumer handling
- Step-up MFA for sensitive operations
- optional headless React provider, hooks, and callback component

The package intentionally does not ship styled React UI. Build app-specific pages with your own design system and use either the framework-neutral client or the optional headless React bindings underneath.

## Install

```bash
npm install @gosso/client
```

## Quick Start

```ts
import { createGossoClient } from "@gosso/client";

export const gossoClient = createGossoClient({
  issuer: window.location.origin,
  clientId: "blog-spa",
  redirectUri: `${window.location.origin}/callback`,
  scope: "openid profile email",
  postLoginDefaultPath: "/admin",
  loginPath: "/login",
  storagePrefix: "my-app",
  sessionProfileEndpoint: "/api/me/session",
  sessionRefreshEndpoint: "/api/auth/refresh",
  csrfCookieName: "blog_csrf_token",
});
```

Start an OIDC flow:

```ts
await gossoClient.redirectToAuthorize("/admin");
```

Handle the callback route:

```ts
const code = new URLSearchParams(location.search).get("code");
const state = new URLSearchParams(location.search).get("state");

if (!code || !state) throw new Error("Missing callback parameters");

const { redirectTo } = await gossoClient.handleRedirectCallback(code, state);
location.href = redirectTo;
```

Call protected APIs:

```ts
const response = await gossoClient.apiFetch("/api/posts", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ title: "Hello Gosso" }),
});
```

## Password, MFA, and Passkey Login

```ts
const result = await gossoClient.loginWithPassword(username, password);

if (result.requires_mfa) {
  await gossoClient.verifyMfa(String(result.mfa_token), code);
}
```

```ts
await gossoClient.loginWithPasskey();
```

Require fresh MFA before a sensitive operation (Gosso 1.3.0 or newer):

```ts
await gossoClient.stepUpMfa(code, "totp");
```

## React Bindings

React applications can import the optional bindings from the dedicated
subpath. React remains an optional peer dependency for non-React consumers.

```tsx
import {
  GossoProvider,
  useIsAuthenticated,
  useUserProfile,
} from "@gosso/client/react";
import { gossoClient } from "./auth";

function App() {
  return (
    <GossoProvider client={gossoClient} initializeSession fallback={null}>
      <AccountSummary />
    </GossoProvider>
  );
}

function AccountSummary() {
  const authenticated = useIsAuthenticated();
  const profile = useUserProfile();
  return authenticated ? <span>{profile?.name}</span> : null;
}
```

Use `AuthCallback` for the OAuth callback route, and `useMfa`, `usePasskeys`,
`useSessions`, and `useProfileManager` for SDK-owned account state and actions.
Enabling `initializeSession` makes guards wait while the provider restores an
existing HttpOnly Cookie Session in tabs that do not yet have a cached profile.

Callback error renderers can localize by stable error code without matching the
default English message:

```tsx
<AuthCallback
  onSuccess={(path) => navigate(path)}
  renderError={(message, detail) => (
    <p>
      {detail?.code === "CALLBACK_PARAMS_MISSING"
        ? "Invalid callback"
        : message}
    </p>
  )}
/>
```

## Account Settings

```ts
await gossoClient.updateProfile("New Display Name");
await gossoClient.changePassword(currentPassword, newPassword);
await gossoClient.requestEmailChange(newEmail, password);
await gossoClient.confirmEmailChange(newEmail, code);

const mfaStatus = await gossoClient.getMfaStatus();
const passkeys = await gossoClient.listPasskeys();
const sessions = await gossoClient.listSessions();

await gossoClient.requestPasswordReset(email);
await gossoClient.resetPassword(resetToken, newPassword);
```

## Configuration

```ts
interface GossoClientConfig {
  issuer: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  postLoginDefaultPath: string;
  loginPath: string;
  storagePrefix: string;
  sessionMode?: "token" | "cookie";
  allowedApiOrigins?: readonly string[];
  sessionProfileEndpoint?: string;
  sessionRefreshEndpoint?: string;
  csrfCookieName?: string;
  fetchImpl?: typeof fetch;
  onAuthRequired?: () => void;
  onSessionChanged?: (snapshot: SessionSnapshot) => void;
}
```

Cookie Session is the default when `sessionMode` is omitted. Use a unique
`storagePrefix` for each SPA on the same origin to isolate transient PKCE,
profile, and refresh-coordination state.

`apiFetch` accepts the page origin and issuer origin by default. Add only exact,
trusted HTTPS origins to `allowedApiOrigins`; credentials are rejected before a
request is sent to any other origin.

In BFF mode, `sessionProfileEndpoint` and `sessionRefreshEndpoint` must both be exact same-origin application endpoints. The SDK never sends a browser request to the issuer's token, userinfo, refresh, or revoke endpoints. `csrfCookieName` belongs to the application API only.

Gosso's default lifetimes are independent: Access Token 15 minutes, Refresh Token 168 hours, Session 24 hours, and CSRF Cookie 4 hours (capped at 24 hours). A missing CSRF Cookie does not invalidate the Refresh Token: the SDK first performs a safe session GET to recover Gosso's CSRF Cookie, then refreshes and retries the original application request once.

## Security Notes

- Use Authorization Code + PKCE for browser clients.
- Serve production clients over HTTPS.
- Keep the Gosso issuer and app behind a same-origin gateway when possible.
- Cookie Session is the secure default; access and refresh tokens remain in server-set `__Host-*` HttpOnly cookies and are never written by the SDK to Web Storage or JavaScript cookies.
- Explicit `sessionMode: "token"` is a legacy, tab-local mode. Tokens stay in memory, disappear on reload, and are sent only to configured origins.
- Cookie Session refresh is single-flight within a page and coordinated across tabs with the Web Locks API. Only a non-sensitive refresh generation marker is stored in `localStorage`.
- OAuth state and PKCE verifier generation requires Web Crypto and fails closed when a cryptographically secure random source is unavailable.
- Login and logout return locations must be application-local paths. See [MIGRATING.md](./MIGRATING.md) before upgrading from 0.3 or earlier.

## License

MIT

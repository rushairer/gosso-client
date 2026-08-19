# @gosso/client

Browser SDK for Gosso OAuth/OIDC single-page application clients.

`@gosso/client` provides the protocol and account self-service layer for ordinary Gosso clients:

- Authorization Code + PKCE redirects and callback handling
- token storage, userinfo loading, logout, and automatic refresh
- authenticated `apiFetch` with bearer headers and 401 retry
- username/password login, MFA verification, and passkey login
- profile, password, email, MFA, passkey, and session management APIs
- password reset request and completion APIs
- typed API errors for consistent consumer handling

The package intentionally does not ship React UI. Build app-specific pages with your own design system and call the SDK methods underneath.

## Install

```bash
npm install @gosso/client
```

## Quick Start

```ts
import { createGossoClient } from '@gosso/client';

export const gossoClient = createGossoClient({
  issuer: window.location.origin,
  clientId: 'blog-spa',
  redirectUri: `${window.location.origin}/callback`,
  scope: 'openid profile email',
  postLoginDefaultPath: '/admin',
  loginPath: '/login',
  storagePrefix: 'my-app',
  sessionMode: 'cookie',
  sessionProfileEndpoint: '/api/me/session',
  csrfCookieName: 'blog_csrf_token',
});
```

Start an OIDC flow:

```ts
await gossoClient.redirectToAuthorize('/admin');
```

Handle the callback route:

```ts
const code = new URLSearchParams(location.search).get('code');
const state = new URLSearchParams(location.search).get('state');

if (!code || !state) throw new Error('Missing callback parameters');

const { redirectTo } = await gossoClient.handleRedirectCallback(code, state);
location.href = redirectTo;
```

Call protected APIs:

```ts
const response = await gossoClient.apiFetch('/api/posts', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ title: 'Hello Gosso' }),
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

## Account Settings

```ts
await gossoClient.updateProfile('New Display Name');
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
  sessionMode?: 'token' | 'cookie';
  sessionProfileEndpoint?: string;
  csrfCookieName?: string;
  fetchImpl?: typeof fetch;
  onAuthRequired?: () => void;
  onSessionChanged?: (snapshot: SessionSnapshot) => void;
}
```

Use a unique `storagePrefix` for each SPA on the same origin to avoid token collisions.

In Cookie Session mode, `csrfCookieName` belongs to the application API only. Gosso identity requests always use `__Host-csrf_token` on HTTPS, or `csrf_token` only for an HTTP development issuer. Cookie lookup is exact and never depends on `document.cookie` order.

Gosso's default lifetimes are independent: Access Token 15 minutes, Refresh Token 168 hours, Session 24 hours, and CSRF Cookie 4 hours (capped at 24 hours). A missing CSRF Cookie does not invalidate the Refresh Token: the SDK first performs a safe session GET to recover Gosso's CSRF Cookie, then refreshes and retries the original application request once.

## Security Notes

- Use Authorization Code + PKCE for browser clients.
- Serve production clients over HTTPS.
- Keep the Gosso issuer and app behind a same-origin gateway when possible.
- Prefer `sessionMode: "cookie"`; access and refresh tokens then remain in `__Host-*` HttpOnly cookies and are never written to Web Storage.
- Cookie Session refresh is single-flight within a page and coordinated across tabs with the Web Locks API. Only a non-sensitive refresh generation marker is stored in `localStorage`.
- OAuth state and PKCE verifier generation requires Web Crypto and fails closed when a cryptographically secure random source is unavailable.

## License

MIT

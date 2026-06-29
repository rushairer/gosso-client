# @gosso/client

Browser SDK for Gosso OAuth/OIDC single-page application clients.

`@gosso/client` provides the protocol and account self-service layer for ordinary Gosso clients:

- Authorization Code + PKCE redirects and callback handling
- token storage, userinfo loading, logout, and automatic refresh
- authenticated `apiFetch` with bearer headers and 401 retry
- username/password login, MFA verification, and passkey login
- profile, password, email, MFA, passkey, and session management APIs

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
  fetchImpl?: typeof fetch;
  onAuthRequired?: () => void;
  onSessionChanged?: (snapshot: SessionSnapshot) => void;
}
```

Use a unique `storagePrefix` for each SPA on the same origin to avoid token collisions.

## Security Notes

- Use Authorization Code + PKCE for browser clients.
- Serve production clients over HTTPS.
- Keep the Gosso issuer and app behind a same-origin gateway when possible.
- Tokens are stored in browser `localStorage` and mirrored to an `access_token` cookie for same-origin Gosso redirects. Treat XSS prevention as part of your security boundary.

## License

MIT

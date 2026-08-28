# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic Versioning.

## [Unreleased]

## [0.6.0] - 2026-08-28

### Added
- Add `<RequireAuth />` and `<RequireAdmin />` route/component guards along with `useRequireAuth()` hook in `@gosso/client/react`.
- Add typed HTTP client helpers (`client.get()`, `client.post()`, `client.put()`, `client.patch()`, `client.delete()`, `client.requestJson()`) to `createGossoClient`.
- Support custom profile properties on `UserProfile`.

## [0.5.1] - 2026-08-28

### Fixed
- Cache the `getSnapshot()` object reference in `GossoClient` to ensure referential stability for React `useSyncExternalStore` (`useSession`), preventing infinite render loops and error boundary crashes.

## [0.5.0] - 2026-08-28

### Added
- Add `stepUpMfa()` for obtaining freshly authenticated claims before sensitive operations, including Cookie Session-safe responses that keep access tokens out of JavaScript.
- Add optional headless React bindings under `@gosso/client/react`, including `GossoProvider`, session and authorization hooks, account-management hooks, and an `AuthCallback` component.

### Changed
- Make the React peer dependency optional so non-React consumers continue to install only the framework-neutral SDK.

## [0.4.0] - 2026-08-24

### Changed
- Promote `0.4.0-rc.2` to `latest` without runtime code changes after Blog and Admin integration verification.

## [0.4.0-rc.2] - 2026-08-24

### Fixed
- Correct the release workflow's tag-to-package version validation before its first npm publish attempt.

## [0.4.0-rc.1] - 2026-08-24

### Added
- Add typed `ApiError` responses with HTTP status and stable error codes.
- Add SDK-owned password reset request and completion methods.
- Add exact `allowedApiOrigins` enforcement for authenticated requests.
- Add a 0.4 migration guide and package provenance release workflow.

### Changed
- Normalize Gouno, OAuth, empty, and invalid JSON API responses through the shared envelope parser.
- Make HttpOnly Cookie Session the default when `sessionMode` is omitted.
- Return a discriminated Cookie or legacy-token result from OAuth callbacks.
- Keep explicit legacy token sessions in memory only; page reload requires reauthentication.

### Security
- Fail closed when Web Crypto is unavailable instead of generating OAuth state and PKCE verifier values with `Math.random`.
- Stop writing access and refresh tokens to Web Storage or JavaScript cookies.
- Reject credentialed requests to untrusted origins and reject external or protocol-relative login/logout return paths.

## [0.3.0] - 2026-08-15
### Added
- Add `subscribe(listener)` to `GossoClient` so every SPA can observe the
  cookie-session snapshot without maintaining a duplicate authentication store.
- Add `refreshIdentityRequests` for the GOSSO Admin SPA, whose protected API
  requests are served by the same origin as the identity provider.

## [0.2.1] - 2026-08-14
### Fixed
- Select application and Gosso CSRF cookies by exact request target instead of cookie order.
- Recover an expired Gosso CSRF cookie before Cookie Session refresh, retry application requests once, and restart PKCE without redirect loops when refresh fails.
- Coordinate Cookie Session refresh within a page and across tabs using single-flight and Web Locks.
- Clear client state after logout only when Gosso confirms server-side session revocation.

## [0.2.0] - 2026-08-12
### Added
- Add opt-in `sessionMode: "cookie"` for HttpOnly Cookie-backed SPA sessions. It keeps access and refresh tokens out of JavaScript-accessible storage while preserving PKCE, MFA, passkeys and account-management APIs.
- Add `sessionProfileEndpoint` for same-origin applications to obtain minimal UI authorization claims without decoding a bearer token.

## [0.1.0] - 2026-06-29
### Added
- Initial `@gosso/client` browser SDK for Gosso ordinary SPA clients.
- Add PKCE redirects, callback handling, token refresh, authenticated `apiFetch`, password login, MFA verification, passkey login and registration, profile management, email changes, MFA settings, passkey management, and session management.

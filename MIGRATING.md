# Migrating to 0.5

Version 0.5 adds optional headless React bindings and Step-up MFA. Existing
framework-neutral imports from `@gosso/client` remain compatible.

React applications can wrap their component tree with `GossoProvider` and
replace duplicate subscription, session, profile, MFA, passkey, and session-list
state with hooks imported from `@gosso/client/react`. Callback routes can use
the SDK-owned `AuthCallback` component instead of parsing authorization query
parameters themselves.

`stepUpMfa(code, type)` requires Gosso 1.3.0 or newer. In Cookie Session mode,
the refreshed access token remains in an HttpOnly cookie and is not returned to
application JavaScript.

# Migrating to 0.4

Version 0.4 makes HttpOnly Cookie Session the default. Omit `sessionMode`, or
set it to `cookie`. Gosso must be reachable over HTTPS and configured with an
exact credentialed CORS origin when it is not same-origin.

Cookie callbacks return `{ sessionMode: 'cookie', redirectTo }`; tokens are set
only by Gosso with `Set-Cookie` and are not available to JavaScript. Replace
code that reads `tokenSet`, Web Storage, or an access-token cookie with
`getSnapshot()`, `subscribe()`, and `apiFetch()`.

`sessionMode: 'token'` remains an explicit legacy option. Its tokens live only
in memory and disappear on reload. `apiFetch` sends credentials only to the
page origin, issuer origin, or an exact origin listed in `allowedApiOrigins`.
All login and logout return values must be application-local paths.

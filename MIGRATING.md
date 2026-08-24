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

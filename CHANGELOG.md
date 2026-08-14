# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic Versioning.

## [Unreleased]

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

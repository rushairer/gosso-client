# GOSSO Client SDK - AI Agent Architectural Guidelines

This document defines the **immutable design principles, protocol rules, and release constraints** for `@gosso/client`.

---

## 1. Design & Protocol Principles

1. **Protocol Compliance**:
   - Implements standards-compliant OAuth 2.0 and OpenID Connect client utilities.
   - Built-in PKCE code verifier and code challenge (S256) generators.
   - RFC 8707 Resource Indicators and RFC 9207 Issuer Identification support.
   - OpenID Connect RP-Initiated Logout URL builder with `post_logout_redirect_uri` and `state`.
2. **Framework Agnostic & TypeScript First**:
   - Zero unnecessary runtime dependencies.
   - Strict TypeScript definitions with full typing for OIDC configurations and token responses.

---

## 2. Release & Versioning Guidelines

- **Semantic Versioning**:
  - Pre-1.0 development iterates on `0.x.y`.
  - Non-breaking additions: bump PATCH or MINOR.
  - Breaking API changes: bump MINOR (pre-1.0) or MAJOR (post-1.0).
- **Publish Pipeline**:
  - Always update `package.json` version, `CHANGELOG.md`, and tag the release accordingly.
  - Downstream projects (`gosso-admin`, `gouno-blog`) depend on published npm packages.

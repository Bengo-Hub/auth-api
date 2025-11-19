# Changelog

All notable changes to the Auth Service will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **API Key Management:** Added endpoints for generating, listing, and validating API keys
  - `POST /api/v1/admin/api-keys` - Generate new API key for a service
  - `GET /api/v1/admin/api-keys` - List all API keys (filtered by service)
  - `GET /api/v1/admin/api-keys/validate` - Validate API key (internal use)
- **Swagger UI Bearer Prefix:** Swagger UI now automatically adds "Bearer " prefix when users paste JWT tokens

### Changed
- Standardized Swagger documentation path to `/v1/docs` (previously `/api/v1/docs`)
- Updated OpenAPI specification servers to use HTTPS URLs for local development
- Swagger UI handler now uses protocol-aware URL detection for HTTPS compatibility
- Swagger UI now displays standard header with Explore button and URL input field
- Added `deepLinking`, `filter`, and `persistAuthorization` options to Swagger UI configuration

## [0.3.0] - 2025-11-14
### Added
- Sprint 2 token service delivering RSA-signed JWT access tokens, opaque refresh tokens with rotation, and `/api/v1/auth/refresh` + `/api/v1/auth/me` endpoints.
- Chi-based auth middleware wiring bearer validation on protected routes.
- Session persistence (Ent `sessions` schema) with client metadata, rotation logic, and audit coverage.

### Changed
- Registration/login handlers now emit token pairs together with user/tenant payloads.

## [0.4.0] - 2025-11-14
### Added
- Sprint 3 Google OAuth integration with signed state tokens, configurable provider metadata, and allowed-domain enforcement.
- Ent `user_identities` schema plus persistence for access/refresh tokens, verified email flag, and profile metadata.
- `/api/v1/auth/oauth/google/start` + `/callback` endpoints with handler/service wiring, plus OAuth helper utilities.

### Changed
- Auth service now auto-links/creates users from provider profiles, ensures tenant membership, and updates README/config docs for social login setup.

## [0.5.0] - 2025-11-14
### Added
- Sprint 4 OIDC core: Authorization Code + PKCE, discovery document, JWKS, `userinfo`, `/authorize` and `/token` endpoints.
- Ent schemas for `authorization_codes` and `consent_sessions` (future extensibility) with PKCE support and code consumption.

### Changed
- Router exposes OIDC endpoints; token service adds KID and JWKS exposure; README updated with OIDC surface.

## [0.6.0] - 2025-11-14
### Added
- Sprint 5 logout + revocations: session status revocation and Redis-backed JWT JTI revocation with middleware checks.
- Sprint 6 MFA (TOTP + backup codes) with endpoints to enroll/confirm/generate/regenerate.
- Sprint 7 admin APIs for tenants and OAuth clients.
- Sprint 8 entitlements and usage: new schemas, admin endpoints for entitlement upsert and usage increments.
- Sprint 10 hardening: Redis rate limiting on sensitive routes, `/metrics` Prometheus endpoint, and key rotation admin endpoint.

## [0.2.0] - 2025-11-14
### Added
- Sprint 1 local auth flows: registration, login, password reset request/confirmation, audit logging, login attempt tracking.
- Argon2id password hashing helper with configurable policy enforcement.
- REST handlers plus request/response envelopes and validation for `/api/v1/auth/*`.

### Changed
- Tenant memberships enforced during login/password reset to prevent cross-tenant leakage.

## [0.1.0] - 2025-11-14
### Added
- Sprint 0 foundations: service bootstrap (`cmd/server` + `internal/app`), typed config loader, zap logging, Chi router with health endpoint.
- Postgres/Redis clients, Ent schema for core identity + audit tables, and automated migrations.
- Token service scaffolding with RSA key loading utilities.


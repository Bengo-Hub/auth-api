# Changelog

All notable changes to the Auth Service will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Sprint 12 – App entity & GitHub-style S2S tokens**: New `App` Ent schema with `bng_app_*` prefixed tokens; full CRUD at `/api/v1/admin/apps` (create, list, get, update, rotate, revoke, delete); `ValidateAPIKey` detects `bng_app_*` prefix and routes to the apps table; seed creates a default "Codevertex Platform Services" platform app
- **`POST /api/v1/auth/me/change-password`**: Authenticated password change endpoint — verifies current password via Argon2id, hashes and stores new password, records audit entry; distinct from the unauthenticated `POST /api/v1/auth/password-reset/confirm` email-token flow
- **Sprint 11 – JWT Claims Enrichment**: Subscription data (`sub_plan`, `sub_status`, `sub_features`, `sub_limits`, `sub_expires`) embedded in JWT access tokens at login/refresh via subscription-service client; cached 5 min in Redis; graceful fallback on subscription-service unavailability
- **Session management endpoints**: `GET /api/v1/auth/sessions`, `POST /api/v1/auth/sessions/revoke`, `POST /api/v1/auth/sessions/revoke-all`
- **User preferences PATCH**: `PATCH /api/v1/auth/me` now accepts `preferences` object (`language`, `timezone`, `country`, `email_alerts`, `push_notifications`) stored in user metadata
- **Outlet context claims**: `outlet_id`, `outlet_code`, `outlet_use_case`, `is_hq_user` added to JWT claims post-outlet-selection
- **Tenant member management**: `GET/POST /api/v1/admin/tenants/{id}/members`, `PATCH/DELETE /api/v1/admin/tenants/{id}/members/{userId}`
- **API Key management (Sprint 12)**: `POST/GET /api/v1/admin/api-keys`, `DELETE /api/v1/admin/api-keys/{id}`, `GET /api/v1/admin/api-keys/validate` — `bng_*` prefixed developer keys with SHA-256 storage, prefix display only
- **Integration config CRUD endpoints** for secure storage of OAuth2 and third-party secrets
- **AES-256-GCM encryption utilities** for integration configuration data
- **Redis session resolver**: `bb_session` cookies now store session UUID (not full JWT) to stay within browser 4KB cookie limit; resolved via Redis on each request
- **Dynamic subscription API key**: Key resolved from `integration_configs` DB (5 min cache) so platform admins can rotate it via auth-ui without restarting pods

### Changed
- Standardized Swagger documentation path to `/v1/docs` (previously `/api/v1/docs`)
- Updated OpenAPI specification servers to use HTTPS URLs for local development
- Swagger UI handler now uses protocol-aware URL detection for HTTPS compatibility
- Swagger UI now displays standard header with Explore button and URL input field
- Added `deepLinking`, `filter`, and `persistAuthorization` options to Swagger UI configuration
- Rewrote `docs/developer-api.md` with clean, comprehensive endpoint reference covering all current flows

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


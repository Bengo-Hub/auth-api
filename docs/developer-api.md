# Auth Service – Developer API Guide

This document explains how to integrate with the BengoBox Auth Service for SSO, OAuth2/OIDC, session management, and admin operations.

## Base URL

Default local: `http://localhost:4101` (configurable via `AUTH_HTTP_PORT`).

## Authentication Flows

### 1) Local Email/Password

- Register: `POST /api/v1/auth/register`
- Login: `POST /api/v1/auth/login`
- Refresh: `POST /api/v1/auth/refresh`
- Me: `GET /api/v1/auth/me` (requires `Authorization: Bearer <access_token>`)
- Logout: `POST /api/v1/auth/logout` (invalidates JTI and marks session revoked)

Tokens:
- Access token: JWT (RS256, has `kid`, `sub`, `sid`, `scope`, `email`)
- Refresh token: Opaque string; rotated by default

### 2) OIDC – Authorization Code + PKCE

Discovery:
- `GET /api/v1/.well-known/openid-configuration`
- `GET /api/v1/.well-known/jwks.json`

Endpoints:
- `GET /api/v1/authorize` (requires app session, attaches PKCE `code_challenge`)
- `POST /api/v1/token` (exchanges code for `access_token` and `id_token`)
- `GET /api/v1/userinfo` (returns standard OIDC claims for current user)

Claims highlights:
- `sub` (UUID), `email`, `email_verified`, `tenant_id` (if present), `sid`

### 3) Social OAuth (Google, GitHub, Microsoft)

- Google: `POST /api/v1/auth/oauth/google/start` → `GET /api/v1/auth/oauth/google/callback`
- GitHub: `POST /api/v1/auth/oauth/github/start` → `GET /api/v1/auth/oauth/github/callback`
- Microsoft: `POST /api/v1/auth/oauth/microsoft/start` → `GET /api/v1/auth/oauth/microsoft/callback`

When enabled, the service links/creates users by provider subject and email, assigns tenant membership, and issues a first‑party token pair.

## MFA – TOTP

- Start TOTP: `POST /api/v1/auth/mfa/totp/start` → returns `secret` and provisioning URL
- Confirm: `POST /api/v1/auth/mfa/totp/confirm` `{ "code": "123456" }`
- Regenerate backup codes: `POST /api/v1/auth/mfa/backup-codes/regenerate`
- Consume backup code: `POST /api/v1/auth/mfa/backup-codes/consume` `{ "code": "..." }`

## Admin APIs

Require admin scopes (`admin` or `auth.admin`):

- Tenants: `GET/POST /api/v1/admin/tenants`
- Clients: `GET/POST /api/v1/admin/clients`
- Entitlements: `GET/POST /api/v1/admin/entitlements`
- Usage increment: `POST /api/v1/admin/usage/increment`
- Rotate signing keys: `POST /api/v1/admin/keys/rotate`

## Rate Limiting & Metrics

- Redis-backed fixed window on login/refresh (configurable in code).
- Prometheus metrics: `GET /metrics`.

## Error Contract

Errors use JSON envelope:
```json
{ "error": "message", "code": "identifier", "details": { } }
```

## Security Notes

- JWTs are RS256-signed; verify via JWKS and `kid`.
- Keep refresh tokens secret; they are rotated by default.
- Use HTTPS in production everywhere; rotate keys regularly (`/keys/rotate`).

## Example – Authorization Code + PKCE

1) Generate verifier/challenge using S256
2) Call `/authorize?client_id=...&redirect_uri=...&response_type=code&scope=openid%20email&code_challenge=...&code_challenge_method=S256&state=...&nonce=...`
3) On redirect, exchange code at `/token` with `code_verifier`
4) Use `access_token` for API calls; parse `id_token` for identity claims.

## Example – Service-to-Service (Client Credentials)

Planned in roadmap; use `oauth_clients` as service accounts and distribute credentials via secrets manager. For now, prefer short-lived JWTs issued from the admin console.*** End Patch  }}}  assistant to=functions.apply_patchentañassistant to=functions.apply_patchasumikerror(Exception('Invalid arguments for apply_patch tool. Expecting a string with the patch content.')) ***!


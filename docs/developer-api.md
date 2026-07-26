# Auth Service – Developer API Guide

This document explains how to integrate with the Codevertex Auth Service for SSO, OAuth2/OIDC, session management, and admin operations.

## Base URL

Production: `https://sso.codevertexafrica.com`
Local: `http://localhost:4101` (configurable via `AUTH_HTTP_PORT`)

## Authentication Flows

### 1) Local Email/Password

- Register: `POST /api/v1/auth/register`
- Login: `POST /api/v1/auth/login`
- Refresh: `POST /api/v1/auth/refresh`
- Me: `GET /api/v1/auth/me` (requires `Authorization: Bearer <access_token>`)
- Logout: `POST /api/v1/auth/logout` (invalidates JTI and marks session revoked)

Tokens:
- Access token: JWT (RS256, has `kid`, `sub`, `sid`, `scope`, `email`, subscription claims)
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
- `sub_plan`, `sub_status`, `sub_features`, `sub_limits`, `sub_expires` (subscription enrichment)
- `outlet_id`, `outlet_code`, `outlet_use_case`, `is_hq_user` (outlet context, post-selection)

### 3) Social OAuth (Google, GitHub, Microsoft)

- Google: `POST /api/v1/auth/oauth/google/start` → `GET /api/v1/auth/oauth/google/callback`
- GitHub: `POST /api/v1/auth/oauth/github/start` → `GET /api/v1/auth/oauth/github/callback`
- Microsoft: `POST /api/v1/auth/oauth/microsoft/start` → `GET /api/v1/auth/oauth/microsoft/callback`

When enabled, the service links/creates users by provider subject and email, assigns tenant membership, and issues a first-party token pair.

## MFA – TOTP

- Start TOTP: `POST /api/v1/auth/mfa/totp/start` → returns `secret` and provisioning URL
- Confirm: `POST /api/v1/auth/mfa/totp/confirm` `{ "code": "123456" }`
- Regenerate backup codes: `POST /api/v1/auth/mfa/backup-codes/regenerate`
- Consume backup code: `POST /api/v1/auth/mfa/backup-codes/consume` `{ "code": "..." }`

## User Profile & Preferences

Update own name, avatar URL, and notification preferences (authenticated):

```
PATCH /api/v1/auth/me
Authorization: Bearer <access_token>
{
  "name": "John Doe",
  "profile_picture_url": "https://cdn.example.com/avatar.jpg",
  "preferences": {
    "language": "English (US)",
    "timezone": "Africa/Nairobi",
    "country": "Kenya",
    "email_alerts": true,
    "push_notifications": false
  }
}
```

## Authenticated Password Change

For logged-in users who know their current password (no reset token needed):

```
POST /api/v1/auth/me/change-password
Authorization: Bearer <access_token>
{ "current_password": "OldPass!", "new_password": "NewStr0ng!" }
```

Returns `{"status":"password_changed"}` on success. Use `POST /api/v1/auth/password-reset/request` + `POST /api/v1/auth/password-reset/confirm` for the forgotten-password email flow.

## Session Management

```
GET  /api/v1/auth/sessions               # List current user's sessions
POST /api/v1/auth/sessions/revoke        # Revoke a session: { "session_id": "..." }
POST /api/v1/auth/sessions/revoke-all    # Revoke all except current
```

## Admin APIs

Require `Authorization: Bearer <platform_admin_jwt>`:

- Tenants: `GET/POST /api/v1/admin/tenants`
- Tenant members: `GET/POST /api/v1/admin/tenants/{id}/members`
- OAuth Clients: `GET/POST /api/v1/admin/clients`
- Users: `GET /api/v1/admin/users`, `PATCH /api/v1/admin/users/{id}`, `POST /api/v1/admin/users/{id}/suspend|deactivate|activate`
- Entitlements: `GET/POST /api/v1/admin/entitlements`
- Usage increment: `POST /api/v1/admin/usage/increment`
- Rotate signing keys: `POST /api/v1/admin/keys/rotate`

## App Management (S2S Tokens)

Platform admins manage GitHub-style `bng_app_*` tokens for service-to-service authentication:

```
POST   /api/v1/admin/apps              # Create app, returns one-time bng_app_* token
GET    /api/v1/admin/apps              # List apps (token never shown again)
GET    /api/v1/admin/apps/{id}         # Get app metadata
PUT    /api/v1/admin/apps/{id}         # Update name/description/scopes
DELETE /api/v1/admin/apps/{id}         # Delete app
POST   /api/v1/admin/apps/{id}/rotate  # Rotate token (returns new one-time token)
POST   /api/v1/admin/apps/{id}/revoke  # Revoke without delete
GET    /api/v1/admin/api-keys/validate # Validate bng_app_* or bng_* tokens (public, no auth)
```

Services pass the app token as `X-API-Key: bng_app_<token>` on inter-service requests.

## API Key Management (Tenant/Developer Keys)

```
POST   /api/v1/admin/api-keys          # Create API key
GET    /api/v1/admin/api-keys          # List API keys
DELETE /api/v1/admin/api-keys/{id}     # Revoke API key
GET    /api/v1/admin/api-keys/validate # Validate key (also handles bng_app_* prefix)
```

## Integrations

```
POST /api/v1/admin/integrations        # Create integration config (encrypted)
GET  /api/v1/admin/integrations        # List integrations
GET  /api/v1/admin/integrations/{id}   # Get integration
PUT  /api/v1/admin/integrations/{id}/status  # Enable/disable integration
DELETE /api/v1/admin/integrations/{id} # Delete integration
GET  /api/v1/auth/integrations/active  # Public: list enabled integrations for login UI
```

## Rate Limiting & Metrics

- Redis-backed fixed window on login/refresh (configurable in code).
- Prometheus metrics: `GET /metrics`.

## Error Contract

```json
{ "error": "message", "code": "identifier", "details": {} }
```

## Security Notes

- JWTs are RS256-signed; verify via JWKS and `kid`.
- Keep refresh tokens secret; they are rotated by default.
- Use HTTPS in production everywhere; rotate keys regularly (`/keys/rotate`).
- App tokens (`bng_app_*`) shown exactly once at creation and rotation — store them immediately.

## Example – Authorization Code + PKCE

1) Generate verifier/challenge using S256
2) Call `/authorize?client_id=...&redirect_uri=...&response_type=code&scope=openid%20email&code_challenge=...&code_challenge_method=S256&state=...&nonce=...`
3) On redirect, exchange code at `/token` with `code_verifier`
4) Use `access_token` for API calls; parse `id_token` for identity claims.

## Example – Service-to-Service (App Token)

```bash
# Validate an app token (used by downstream services)
curl https://sso.codevertexafrica.com/api/v1/admin/api-keys/validate \
  -H "X-API-Key: bng_app_<token>"
# Response: { "client_id": "app_abc123", "scopes": ["s2s:*"], "roles": ["superuser","service"] }
```

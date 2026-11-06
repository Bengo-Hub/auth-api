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

- Start TOTP: `POST /api/v1/auth/mfa/totp/start` returns `secret` and the provisioning URL. When an
  authenticator is already enabled, send `{ "current_code": "123456" }` from it: without it the answer
  is 409 `authenticator_exists`, with a wrong one 401 `invalid_totp`. An enrolment-only session can
  never replace an enabled authenticator (always 409).
- Confirm: `POST /api/v1/auth/mfa/totp/confirm` `{ "code": "123456" }`. On success the account's
  other enrolment-only sessions are revoked.
- Regenerate backup codes: `POST /api/v1/auth/mfa/backup-codes/regenerate`. An enrolment-only
  session gets the first set only: when unused codes exist it answers 409 `backup_codes_exist`.
- Consume backup code: `POST /api/v1/auth/mfa/backup-codes/consume` `{ "code": "..." }`
- Wrong authenticator codes on `POST /auth/login` are counted per account: after 5 in 10 minutes the
  answer is 429 `too_many_attempts` until the window passes (Redis; without it the per-address
  limiter remains).
- Lost authenticator: a platform owner calls `POST /api/v1/admin/users/{user_id}/mfa-reset` after
  confirming who is asking outside the system. It removes the authenticator and backup codes and
  revokes every session, is audited as `auth.mfa.reset`, and answers
  `{id, had_authenticator, sessions_revoked}`. A covered account then enrols again at its next sign-in.

## Sign-in methods (`amr`) and the MFA policy

### The `amr` claim

Every access token carries `amr`, the list of methods the session was signed in with (values
from RFC 8176, plus `totp` and `mfa`):

| Value  | Meaning |
|--------|---------|
| `pwd`  | Email and password |
| `otp`  | A one-time code sent to a phone or an email address |
| `fed`  | A social provider (Google, GitHub, Microsoft) |
| `hwk`  | A passkey |
| `pin`  | A service PIN (reserved: PIN sign-in happens in the services that own it, not here) |
| `totp` | An authenticator app code |
| `mfa`  | A second factor was verified on this sign-in |

Examples: `["pwd"]`, `["pwd","totp","mfa"]`, `["fed","totp","mfa"]`, `["otp","totp","mfa"]`,
`["hwk","totp","mfa"]`. The list is stored on the session: `POST /api/v1/auth/refresh`, the OIDC
code exchange (`POST /api/v1/token`, which copies it from the single sign-on session through the
authorization code) and outlet selection repeat it and never add a factor. The ID token carries
the same `amr`. A session signed in before this claim existed has no `amr`.

A resource server that needs a second factor checks that `amr` contains `mfa`. A token without
`amr` is treated as not having it.

### Enrolment-only tokens

When the MFA policy covers a member who has no authenticator app yet, sign-in succeeds with an
enrolment-only session instead of a normal one:

- the token has `mfa_enrollment_required: true`, an `amr` without `mfa`, and `aud` is only
  `mfa-enrollment` (a service validating `aud` refuses it outright);
- it has no `roles`, `permissions`, `user_services`, `outlet_ids`, subscription claims or
  `is_platform_owner`;
- the sign-in response (`/auth/login`, `/auth/phone/otp/verify`, `/auth/webauthn/authenticate/finish`)
  and `GET /auth/me` carry `mfa_enrollment_required: true` and empty `roles` and `permissions`;
- auth-api accepts it only on `GET /auth/me`, `POST /auth/mfa/totp/start`,
  `POST /auth/mfa/totp/confirm`, `POST /auth/mfa/backup-codes/regenerate` and `POST /auth/logout`.
  Any other route answers 403 `mfa_enrollment_required`, and `GET /authorize` treats the caller as
  signed out.

After setting up the authenticator the person signs out and signs in again, now with the code,
and gets a normal token with `mfa` in `amr`. Refreshing an enrolment-only session keeps it
enrolment-only.

### Who is covered

The policy is `{"required_roles": [...], "all_accounts": bool}`. A member is covered when any of
their memberships is covered by that tenant's effective policy (one of `required_roles` held there,
or `all_accounts` on), when the policy of the tenant they sign in to has `all_accounts` on, or when a
platform admin turned on enforcement for their account
(`POST /api/v1/admin/users/{id}/mfa-enforcement`; this applies in every tenant). Every membership
counts, not only the tenant named at sign-in, so naming a tenant with a weaker policy never lowers
what an account must prove: a platform owner may sign in to any tenant, and a passkey sign-in names
any tenant. The effective policy is the tenant's own (`mfa_policy` in its metadata) when it has one,
otherwise the platform default (`mfa_policy_default` in the platform tenant's metadata, cached for
30 seconds per pod). With neither, nothing is required. The Hadia tenant seed sets
`required_roles` to `hadia_admin`, `hadia_finance` and `hadia_support`. Shared demo logins are never
covered, because authenticator setup is refused for them: the demo tenant is recognised by its
`is_demo` column and slug only (tenant metadata `is_demo` is platform-only and exempts nothing), and a
demo account by profile `is_demo`, which registration strips and only a platform admin sets.

Every sign-in path applies it:

| Path | Covered, authenticator set up | Covered, no authenticator |
|------|-------------------------------|---------------------------|
| Password (`/auth/login`) | `mfa_required`, then resubmit with `totp_code` | Enrolment-only session |
| Phone code (`/auth/phone/otp/verify`) | 403 `mfa_required` with `mfa_challenge` | Enrolment-only session |
| Social provider callback | Redirect to `/auth/mfa?challenge=...` | Enrolment-only session |
| Passkey (`/auth/webauthn/authenticate/finish`) | `{"mfa_required":true,"mfa_challenge":...}` | Enrolment-only session |
| OIDC (`/authorize`, `/token`) | Session without `mfa`: sent back to sign-in (`reason=mfa_required`); `prompt=none` gets `interaction_required`; the code exchange answers `invalid_grant` | Sent back to sign-in; the code exchange issues an enrolment-only token |
| Refresh | Session without `mfa`: 401 `mfa_required` (sign in again) | Session becomes enrolment-only |
| Outlet selection (`/auth/select-outlet`) | Session without `mfa`: 401 | 401 |

Outlet selection mints only for a live session (active, not expired, the same user), so a token
from a logged-out or revoked session cannot renew itself. On a refresh a lookup error answers 5xx
(retry) instead of `mfa_required`, so a brief database error signs nobody out; the sign-in paths
keep failing closed.

The challenge is finished with `POST /api/v1/auth/oauth/mfa/verify {challenge, totp_code}`.
Lookup errors fail closed: the code is asked for and a full session is never issued on an error.
An account with an authenticator is still asked for its code on password, phone and social
sign-in even when no policy covers it, as before.

### Editing the policy (platform owners only)

Only a platform owner's session may read or change a policy; a tenant's own admin and
admin-scoped service tokens get 403. Every change is written to the audit log as
`auth.mfa_policy.updated`. The generic tenant update (`PUT /admin/tenants/{id}`) never writes
these keys, a tenant admin cannot set `is_platform_owner`, `billing_mode` or `is_demo` through it,
and its answer to a tenant admin leaves the policy out. It also refuses with 409 `tenant_changed`
when the row changed since it was read, and the policy routes re-apply their change to the newer
row, so neither save can silently revert the other.

```
GET   /api/v1/admin/mfa-policy                       # platform default
PATCH /api/v1/admin/mfa-policy                       { "required_roles": ["..."], "all_accounts": false }
GET   /api/v1/admin/tenants/{tenant_id}/mfa-policy   # the tenant's policy, or inherited
PATCH /api/v1/admin/tenants/{tenant_id}/mfa-policy   { "required_roles": ["hadia_admin"], "all_accounts": false }
PATCH /api/v1/admin/tenants/{tenant_id}/mfa-policy   { "inherit": true }   # follow the platform default again
```

Each answers `{policy, inherited, effective, available_roles}`: the stored policy, whether the
tenant follows the platform default, the policy sign-ins follow, and the role codes to pick from
(the role catalogue, roles the tenant's members hold, and any already in the policy). A role code
is 1 to 64 letters, digits or `_ . : -`, at most 100 per policy. A new policy applies at the next
sign-in or refresh.

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

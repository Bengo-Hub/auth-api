# OAuth Provider Setup Guide

This guide covers registering OAuth applications with Google, Microsoft, and GitHub, and wiring them into the Codevertex auth-service.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Canonical Callback URLs](#canonical-callback-urls)
3. [Authorized JavaScript Origins](#authorized-javascript-origins)
4. [Google OAuth Setup](#google-oauth-setup)
5. [Microsoft OAuth Setup](#microsoft-oauth-setup)
6. [GitHub OAuth Setup](#github-oauth-setup)
7. [Storing Credentials in auth-api](#storing-credentials-in-auth-api)
8. [End-to-end OAuth Flow](#end-to-end-oauth-flow)
9. [Multi-tenancy & Tenant Resolution](#multi-tenancy--tenant-resolution)
10. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

There are **two distinct callback layers** in the Codevertex OAuth flow — do not confuse them:

| Layer | Who calls it | Purpose |
| --- | --- | --- |
| **Provider → auth-api callback** | Google / Microsoft / GitHub | Delivers the authorization code to auth-api. **This is the URL you register in each provider's console.** |
| **auth-api → frontend callback** | auth-api | After auth-api finishes the token exchange + JIT provisioning, it redirects back to the frontend (`/auth/callback` on the client UI). Registered in auth-api's `OAuthClient` table, not in the provider console. |

**TL;DR:** The URL you paste into the Google/Microsoft/GitHub "Authorized redirect URI" field is always the **auth-api** URL, never the frontend URL.

---

## Canonical Callback URLs

Register **exactly these** URLs (plus the local-dev variant) in each provider's console.

### Production

| Provider | Authorized redirect URI |
| --- | --- |
| Google | `https://sso.codevertexitsolutions.com/api/v1/auth/oauth/google/callback` |
| Microsoft | `https://sso.codevertexitsolutions.com/api/v1/auth/oauth/microsoft/callback` |
| GitHub | `https://sso.codevertexitsolutions.com/api/v1/auth/oauth/github/callback` |

### Local Development

| Provider | Authorized redirect URI |
| --- | --- |
| Google | `http://localhost:8080/api/v1/auth/oauth/google/callback` |
| Microsoft | `http://localhost:8080/api/v1/auth/oauth/microsoft/callback` |
| GitHub | `http://localhost:8080/api/v1/auth/oauth/github/callback` |

> Port `8080` is the default auth-api port. Adjust if you run auth-api on a different port.

### Build pattern

The URL is assembled as:

```
{AUTH_API_BASE_URL}/api/v1/auth/oauth/{provider}/callback
```

The `AUTH_API_BASE_URL` value is taken from `cfg.Token.Issuer` and injected into `IntegrationConfig.encrypted_credentials` at seed time. See [cmd/seed/main.go](../cmd/seed/main.go) `seedIntegrations()` for the reference implementation.

---

## Authorized JavaScript Origins

Google (and optionally Microsoft) also require JavaScript origins. These are the **frontend hosts** that initiate the OAuth flow from the browser — not the auth-api.

### Production

- `https://accounts.codevertexitsolutions.com` — auth-ui (platform admin / tenant-less login page)
- `https://sso.codevertexitsolutions.com` — auth-api itself (for any redirects rendered in-browser)
- Any tenant-facing UI that initiates OAuth directly (e.g. `https://ordersapp.codevertexitsolutions.com`) if you call `/oauth/google/start` from that origin

### Local Development

- `http://localhost:3000` (auth-ui / tenant UIs)
- `http://localhost:8080` (auth-api)

---

## Google OAuth Setup

1. Open the [Google Cloud Console → APIs & Services → Credentials](https://console.cloud.google.com/apis/credentials).
2. Click **Create Credentials → OAuth client ID**.
3. **Application type**: Web application.
4. **Authorized JavaScript origins** (see list above):
   - `https://accounts.codevertexitsolutions.com`
   - `https://sso.codevertexitsolutions.com`
   - `http://localhost:3000` (dev)
5. **Authorized redirect URIs**:
   - `https://sso.codevertexitsolutions.com/api/v1/auth/oauth/google/callback`
   - `http://localhost:8080/api/v1/auth/oauth/google/callback` (dev)
6. Click **Create**. Copy the **Client ID** and **Client Secret**.
7. Ensure the OAuth consent screen has these scopes enabled:
   - `openid`
   - `email`
   - `profile`
8. Publish the consent screen (or add test users during development).

> **Common error**: "Invalid Redirect: URI must not be empty" — the redirect URI field was left blank. Paste the `.../api/v1/auth/oauth/google/callback` URL above.

---

## Microsoft OAuth Setup

1. Open the [Azure Portal → App registrations](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade).
2. Click **New registration**.
3. **Name**: e.g. `Codevertex SSO`.
4. **Supported account types**:
   - *Accounts in any organizational directory and personal Microsoft accounts* (multi-tenant + personal) — maps to `tenant_id="common"` in auth-api.
   - Or restrict to a specific org if you want SSO locked to one Azure AD tenant.
5. **Redirect URI**:
   - Platform: **Web**
   - URL: `https://sso.codevertexitsolutions.com/api/v1/auth/oauth/microsoft/callback`
   - Add a second Web redirect for dev: `http://localhost:8080/api/v1/auth/oauth/microsoft/callback`
6. Click **Register**. Copy the **Application (client) ID**.
7. Go to **Certificates & secrets → New client secret**. Copy the **Value** (not the Secret ID) — this is the `client_secret`.
8. Go to **API permissions → Add permission → Microsoft Graph → Delegated**:
   - `openid`
   - `email`
   - `profile`
   - `User.Read`
9. Click **Grant admin consent** if you restricted to a single tenant.

> `tenant_id` in auth-api stores the Microsoft directory GUID (or `common` for multi-tenant). Put it in `IntegrationConfig.encrypted_credentials.tenant_id`.

---

## GitHub OAuth Setup

1. Open [GitHub → Settings → Developer settings → OAuth Apps](https://github.com/settings/developers).
2. Click **New OAuth App**.
3. **Application name**: e.g. `Codevertex SSO`.
4. **Homepage URL**: `https://codevertexitsolutions.com`.
5. **Authorization callback URL**: `https://sso.codevertexitsolutions.com/api/v1/auth/oauth/github/callback`.
6. Click **Register application**. Copy the **Client ID**.
7. Click **Generate a new client secret**. Copy the **Client Secret** (shown once).
8. For local dev, register a second OAuth App with callback `http://localhost:8080/api/v1/auth/oauth/github/callback`. GitHub does not support multiple callbacks on a single OAuth App.

> GitHub does not have a "JavaScript origins" field — authorization is done entirely server-side via the callback URL.

---

## Storing Credentials in auth-api

Once you have the three `(client_id, client_secret)` pairs, there are two ways to load them.

### Option A — Seed via environment variables (recommended for first deploy)

Set these before running `cmd/seed`:

```bash
export GOOGLE_CLIENT_ID="..."
export GOOGLE_CLIENT_SECRET="..."

export MICROSOFT_CLIENT_ID="..."
export MICROSOFT_CLIENT_SECRET="..."
export MICROSOFT_TENANT_ID="common"   # or a specific Azure AD tenant GUID

export GITHUB_CLIENT_ID="..."         # or GIT_APP_ID
export GITHUB_CLIENT_SECRET="..."     # or GIT_APP_SECRET

go run ./cmd/seed
```

The seeder ([cmd/seed/main.go `seedIntegrations()`](../cmd/seed/main.go)) upserts one `IntegrationConfig` row per provider at platform scope (`tenant_id=NULL`), with `encrypted_credentials` populated as:

```json
{
  "client_id": "...",
  "client_secret": "...",
  "redirect_url": "https://sso.codevertexitsolutions.com/api/v1/auth/oauth/google/callback",
  "tenant_id": "common"   // microsoft only
}
```

The `redirect_url` is computed from `cfg.Token.Issuer`. The blob is encrypted at rest with AES-256-GCM using `AUTH_SECURITY_INTEGRATION_ENCRYPTION_KEY`.

### Option B — Configure via auth-ui admin

After deploying auth-api with dummy placeholder seeds, any platform admin can open [https://accounts.codevertexitsolutions.com/dashboard/integrations](https://accounts.codevertexitsolutions.com/dashboard/integrations), select the provider, and paste in the real client_id/client_secret/redirect_url. The UI calls `POST /api/v1/admin/integrations` which updates the same `IntegrationConfig` row.

---

## End-to-end OAuth Flow

```text
┌────────────┐    1. click "Sign in with Google"    ┌───────────────┐
│  auth-ui   │─────────────────────────────────────▶│   auth-api    │
│ (browser)  │       POST /oauth/google/start       │               │
│            │                                      │   (builds     │
│            │◀─────────────────────────────────────│    state JWT) │
│            │    2. { authorization_url, state }   └───────────────┘
│            │
│            │    3. redirect to Google
│            │─────────────────────────────────────▶┌───────────────┐
│            │                                      │   Google      │
│            │◀─────────────────────────────────────│               │
│            │    4. redirect with ?code&state      └───────────────┘
│            │
│            │    5. GET /oauth/google/callback?code=&state=
│            │─────────────────────────────────────▶┌───────────────┐
│            │                                      │   auth-api    │
│            │                                      │   a. verify   │
│            │                                      │      state    │
│            │                                      │   b. exchange │
│            │                                      │      code→tok │
│            │                                      │   c. fetch    │
│            │                                      │      profile  │
│            │                                      │   d. JIT user │
│            │                                      │   e. issue    │
│            │                                      │      JWT      │
│            │◀─────────────────────────────────────│               │
│            │    6. 302 to {redirect_uri}?code=    └───────────────┘
└────────────┘
```

Handler locations:

- `POST /api/v1/auth/oauth/{provider}/start` → [internal/httpapi/handlers/auth_handler.go:378](../internal/httpapi/handlers/auth_handler.go) (Google), `:426` (GitHub), `:468` (Microsoft)
- `GET /api/v1/auth/oauth/{provider}/callback` → [internal/httpapi/handlers/auth_handler.go:402](../internal/httpapi/handlers/auth_handler.go) (Google), `:447` (GitHub), `:489` (Microsoft)
- State JWT: [internal/oauth/state/state.go](../internal/oauth/state/state.go), signed HS256 with `AUTH_SECURITY_OAUTH_STATE_SECRET`, 10-minute TTL, carries `{tenant_slug, client_id, redirect_uri, nonce}`.
- JIT user creation: `resolveUserFromGoogleProfile`, `resolveUserFromGitHubProfile`, `resolveUserFromMicrosoftProfile` in [internal/httpapi/service.go](../internal/httpapi/service.go).

---

## Scope: platform-only

**OAuth provider credentials (`google`, `microsoft`, `github`) are stored at
platform scope only — `tenant_id` is always `NULL`.** Every tenant in the
Codevertex ecosystem authenticates through the same OAuth app; per-tenant
isolation is provided by the signed OAuth state JWT (`tenant_slug` claim), not
by separate credentials per tenant.

Enforcement is server-side in `admin_handler.go` via the
`platformOnlyIntegrations` map — any create request for `google`, `microsoft`,
or `github` silently drops the `tenant_id` field. The
`GET /api/v1/auth/integrations/active?category=oauth` endpoint ignores the
`tenant_slug` query param for the same reason.

If you need a per-tenant identity provider override in the future (e.g. a
dedicated Azure AD app for a large customer), that is a separate feature and
should use a distinct table / code path — do not repurpose `integration_configs`
to store per-tenant OAuth secrets.

## Multi-tenancy & Tenant Resolution

OAuth flows are tenant-aware end-to-end:

1. The frontend passes `tenant_slug` when calling `POST /oauth/{provider}/start`.
2. auth-api encodes `tenant_slug` inside the signed state JWT.
3. On callback, auth-api decodes the state, resolves the tenant by slug, and ensures the user has a `TenantMembership` for that tenant (JIT if missing).
4. The issued JWT's `tenant_id` + `tenant_slug` claims match the tenant the user signed into.

If no `tenant_slug` is supplied (e.g. login via `accounts.codevertexitsolutions.com`), the user lands on the platform-level admin tenant.

### Where to set tenant_slug from the UI

In auth-ui, the `OAuthButton` component reads the active tenant from the subdomain/path of the current request and includes it in the `POST /oauth/{provider}/start` body. See [auth-ui/src/app/login/page.tsx](../../auth-ui/src/app/login/page.tsx).

---

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Google: *"redirect_uri_mismatch"* | URL in console differs from what auth-api sends | Compare exact string — trailing slash, http vs https, port, path — against the canonical list above. |
| Google: *"Invalid Redirect: URI must not be empty"* at console creation | Redirect URI field left blank | Paste `https://sso.codevertexitsolutions.com/api/v1/auth/oauth/google/callback`. |
| Microsoft: *"AADSTS50011: reply URL doesn't match"* | Same as Google redirect_uri_mismatch | Check Azure App registration → Authentication → Redirect URIs. |
| GitHub: callback URL mismatch | GitHub only allows one callback per app | Register separate prod + dev OAuth Apps. |
| State JWT expired | User took >10 min between start and callback | User retries from scratch; adjust TTL via `AUTH_SECURITY_OAUTH_STATE_TTL` if needed. |
| `integration config not found` on callback | `IntegrationConfig` row missing or `is_active=false` | Run seeder with the env vars set, or enable the provider in auth-ui admin. |
| User signs in but lands on wrong tenant | `tenant_slug` not propagated to `/oauth/start` | Check that the frontend reads the active tenant from subdomain/path and sends it in the start request. |

---

## Related Documents

- [integrations.md](./integrations.md) — Full integration patterns across all Codevertex services
- [architecture.md](./architecture.md) — auth-service architecture, JIT provisioning, tenant sync
- [PRODUCTION-SETUP.md](./PRODUCTION-SETUP.md) — Production deployment checklist

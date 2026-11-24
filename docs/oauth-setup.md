# OAuth Provider Setup Guide

This guide covers registering OAuth applications with Google, Microsoft, GitHub and TikTok, and wiring them into the Codevertex auth-service.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Canonical Callback URLs](#canonical-callback-urls)
3. [Authorized JavaScript Origins](#authorized-javascript-origins)
4. [Google OAuth Setup](#google-oauth-setup)
5. [Microsoft OAuth Setup](#microsoft-oauth-setup)
6. [GitHub OAuth Setup](#github-oauth-setup)
7. [TikTok Login Kit Setup](#tiktok-login-kit-setup)
8. [Storing Credentials in auth-api](#storing-credentials-in-auth-api)
9. [End-to-end OAuth Flow](#end-to-end-oauth-flow)
10. [Multi-tenancy & Tenant Resolution](#multi-tenancy--tenant-resolution)
11. [Troubleshooting](#troubleshooting)

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
| Google | `https://sso.codevertexafrica.com/api/v1/auth/oauth/google/callback` |
| Microsoft | `https://sso.codevertexafrica.com/api/v1/auth/oauth/microsoft/callback` |
| GitHub | `https://sso.codevertexafrica.com/api/v1/auth/oauth/github/callback` |
| TikTok | `https://sso.codevertexafrica.com/api/v1/auth/oauth/tiktok/callback` |

### Local Development

| Provider | Authorized redirect URI |
| --- | --- |
| Google | `http://localhost:8080/api/v1/auth/oauth/google/callback` |
| Microsoft | `http://localhost:8080/api/v1/auth/oauth/microsoft/callback` |
| GitHub | `http://localhost:8080/api/v1/auth/oauth/github/callback` |

TikTok accepts only HTTPS redirect URIs, so local TikTok sign-in needs an HTTPS tunnel registered as a second Web redirect URI.

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

- `https://accounts.codevertexafrica.com` — auth-ui (platform admin / tenant-less login page)
- `https://sso.codevertexafrica.com` — auth-api itself (for any redirects rendered in-browser)
- Any tenant-facing UI that initiates OAuth directly (e.g. `https://ordering.codevertexafrica.com`) if you call `/oauth/google/start` from that origin

### Local Development

- `http://localhost:3000` (auth-ui / tenant UIs)
- `http://localhost:8080` (auth-api)

---

## Google OAuth Setup

1. Open the [Google Cloud Console → APIs & Services → Credentials](https://console.cloud.google.com/apis/credentials).
2. Click **Create Credentials → OAuth client ID**.
3. **Application type**: Web application.
4. **Authorized JavaScript origins** (see list above):
   - `https://accounts.codevertexafrica.com`
   - `https://sso.codevertexafrica.com`
   - `http://localhost:3000` (dev)
5. **Authorized redirect URIs**:
   - `https://sso.codevertexafrica.com/api/v1/auth/oauth/google/callback`
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
   - URL: `https://sso.codevertexafrica.com/api/v1/auth/oauth/microsoft/callback`
   - Add a second Web redirect for dev: `http://localhost:8080/api/v1/auth/oauth/microsoft/callback`
6. Click **Register**. Copy the **Application (client) ID**.
7. Go to **Certificates & secrets → New client secret**. Copy the **Value** (not the Secret ID) — this is the `client_secret`.
8. Go to **API permissions → Add permission → Microsoft Graph → Delegated**:
   - `openid`
   - `email`
   - `profile`
   - `User.Read`
9. Click **Grant admin consent** if you restricted to a single tenant.
10. Go to **Token configuration → Add optional claim → ID** and add `xms_edov` (and `email`). Entra sets `xms_edov` only when the email's domain owner has verified it. Without this claim auth-api never matches an existing account by a Microsoft email (see [Account matching and linking](#account-matching-and-linking)).

> `tenant_id` in auth-api stores the Microsoft directory GUID (or `common` for multi-tenant). Put it in `IntegrationConfig.encrypted_credentials.tenant_id`.

---

## GitHub OAuth Setup

1. Open [GitHub → Settings → Developer settings → OAuth Apps](https://github.com/settings/developers).
2. Click **New OAuth App**.
3. **Application name**: e.g. `Codevertex SSO`.
4. **Homepage URL**: `https://codevertexafrica.com`.
5. **Authorization callback URL**: `https://sso.codevertexafrica.com/api/v1/auth/oauth/github/callback`.
6. Click **Register application**. Copy the **Client ID**.
7. Click **Generate a new client secret**. Copy the **Client Secret** (shown once).
8. For local dev, register a second OAuth App with callback `http://localhost:8080/api/v1/auth/oauth/github/callback`. GitHub does not support multiple callbacks on a single OAuth App.

> GitHub does not have a "JavaScript origins" field — authorization is done entirely server-side via the callback URL.

---

## TikTok Login Kit Setup

The TikTok app is "Markeflow by Codevertex" in [TikTok for Developers](https://developers.tiktok.com/apps), with the Login Kit product added.

1. Under **Login Kit**, set the **Web** redirect URI to `https://sso.codevertexafrica.com/api/v1/auth/oauth/tiktok/callback`.
2. Make sure the app has the `user.info.basic` scope. Sign-in asks for nothing else.
3. Copy the **Client key** and **Client secret** from the app's **Credentials** section.
4. Open [Identity Providers](https://accounts.codevertexafrica.com/dashboard/developer/integrations) in auth-ui, fill in the TikTok card (Client Key, Client Secret, Redirect URI) and enable it. The button appears on the login and sign-up pages once the provider is active.

How TikTok differs from the other providers:

- The app id is sent as `client_key`, not `client_id`, on both the authorize URL (`https://www.tiktok.com/v2/auth/authorize/`) and the token call (`POST https://open.tiktokapis.com/v2/oauth/token/`, form encoded). The stored credentials use the key `client_key` for the same reason.
- Web apps do not use PKCE. TikTok requires `code_verifier` only for mobile and desktop apps.
- The profile comes from `GET https://open.tiktokapis.com/v2/user/info/?fields=open_id,union_id,avatar_url,display_name` and has no email address.
- The person is identified by `open_id` (TikTok scopes it to this app). The identity row is `provider=tiktok`, `provider_subject=<open_id>`, and its profile keeps `union_id`, the display name and the avatar.

Accounts without an email:

- A TikTok account already linked to a Codevertex account signs in to that account.
- A TikTok account seen for the first time gets a new account with a placeholder address `tiktok-<hash>@placeholder.local`, the same approach as phone-only accounts. The verify-email dialog then asks the person for a real address and replaces the placeholder once it is proven.
- The usual social sign-up rules decide whether the new account may join the tenant (`ensureMembership`): a customer-facing app gives its self-signup role, the platform tenant lets a new person register as a member, and any other organisation needs an existing membership. A refused sign-up leaves no account behind.
- Because there is no email to match on, an existing Codevertex account is never found by TikTok sign-in alone. To use TikTok with an existing account, sign in with that account and link TikTok under Account settings, Sign-in methods. After that, "Login with TikTok" lands in that account.
- Access and refresh tokens are not stored, as with the other providers. The 2FA rule is the same: an account with an authenticator app finishes on `/auth/mfa`.

---

## Account matching and linking

Every provider runs through one resolver (`resolveSocialUser` in [internal/services/auth/social_identity.go](../internal/services/auth/social_identity.go)). Each provider adapter ([internal/services/auth/social_oauth.go](../internal/services/auth/social_oauth.go)) only reports the subject, the email and whether the provider vouches for that email.

| Provider | Email trusted when |
|----------|--------------------|
| Google | `email_verified` is true |
| GitHub | the address is the primary verified one from `GET /user/emails` (always fetched). The public profile email is never trusted. |
| Microsoft | the ID token carries `xms_edov=true` with an `email` claim. Graph `mail` and `userPrincipalName` are never trusted: any Entra tenant admin can set them to any address. |
| TikTok | never (TikTok shares no email) |

The resolver, in order:

1. The provider identity (`provider`, `provider_subject`) is already linked: sign in to that account, whatever its email.
2. A trusted email matches an existing account: link the identity to it and mark the email verified.
3. An untrusted email matches an existing account: refuse with "an account with this email already exists: sign in with your email, then link this provider in Account settings". It never links and never creates a second account.
4. Otherwise create an account. With a trusted email it uses that address (verified); without one it gets a placeholder `<provider>-<hash>@placeholder.local` and the verify-email dialog asks for a real address.

The membership policy (`ensureMembership`) is unchanged. A new account it refuses is deleted again, for every provider, so a refused sign-up leaves nothing behind. An existing account it refuses keeps the identity it just linked, and with no organisation named it signs in to the person's own tenant as before. The email domain allow-list applies to the account's email or a trusted provider email, never to an untrusted one.

Linking a provider to an existing account (Account settings, Sign-in methods in auth-ui):

- `GET /api/v1/auth/me/identities` lists the linked providers and whether the account has a password.
- `POST /api/v1/auth/me/identities/{provider}/link` (signed in) returns the provider's authorization URL. The state carries `flow=link` and the person's id. The public start endpoints refuse `flow=link`.
- The callback reads the browser's own session (`bb_session`, through `TryAuth`) and links only when it is the same person named in the state. A provider account already linked to someone else is refused. The browser returns to `/dashboard/profile?tab=security` with `linked=<provider>` or `link_error=<message>`; no new session is made.
- `DELETE /api/v1/auth/me/identities/{id}` unlinks, unless it is the last way to sign in (no password and no other linked provider).
- The shared demo account cannot link or unlink. Link, unlink and refused links are written to the audit log (`auth.identity.linked`, `auth.identity.unlinked`, `auth.identity.link_refused`).

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
  "redirect_url": "https://sso.codevertexafrica.com/api/v1/auth/oauth/google/callback",
  "tenant_id": "common"   // microsoft only
}
```

The `redirect_url` is computed from `cfg.Token.Issuer`. The blob is encrypted at rest with AES-256-GCM using `AUTH_SECURITY_INTEGRATION_ENCRYPTION_KEY`.

The seeder does not create a TikTok row. TikTok is configured only through auth-ui (Option B), and its blob holds `client_key`, `client_secret` and `redirect_url`.

### Option B — Configure via auth-ui admin

After deploying auth-api with dummy placeholder seeds, any platform admin can open [https://accounts.codevertexafrica.com/dashboard/developer/integrations](https://accounts.codevertexafrica.com/dashboard/developer/integrations), select the provider, and paste in the real client_id/client_secret/redirect_url. The UI calls `POST /api/v1/admin/integrations` which updates the same `IntegrationConfig` row.

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

- `POST /api/v1/auth/oauth/{provider}/start` → `GoogleOAuthStart`, `GitHubOAuthStart`, `MicrosoftOAuthStart`, `TikTokOAuthStart` in [internal/httpapi/handlers/auth_handler.go](../internal/httpapi/handlers/auth_handler.go)
- `GET /api/v1/auth/oauth/{provider}/callback` → the provider's callback handler, all through `handleOAuthCallback`
- Linking endpoints: [internal/httpapi/handlers/auth_handler_identities.go](../internal/httpapi/handlers/auth_handler_identities.go)
- Shared start, callback and link flow, plus the provider adapters: [internal/services/auth/social_oauth.go](../internal/services/auth/social_oauth.go). Account resolver and identity rows: [internal/services/auth/social_identity.go](../internal/services/auth/social_identity.go). TikTok provider client: [internal/providers/tiktok/provider.go](../internal/providers/tiktok/provider.go).
- State JWT: [internal/oauth/state/state.go](../internal/oauth/state/state.go), signed HS256 with `AUTH_SECURITY_OAUTH_STATE_SECRET`, 10-minute TTL, carries `{tenant_slug, client_id, redirect_uri, nonce, flow}` and, for the link flow, the person's `user_id`.

---

## Scope: platform-only

**OAuth provider credentials (`google`, `microsoft`, `github`, `tiktok`) are stored at
platform scope only — `tenant_id` is always `NULL`.** Every tenant in the
Codevertex ecosystem authenticates through the same OAuth app; per-tenant
isolation is provided by the signed OAuth state JWT (`tenant_slug` claim), not
by separate credentials per tenant.

Enforcement is server-side in `admin_handler.go` via the
`platformOnlyIntegrations` map — any create request for `google`, `microsoft`,
`github` or `tiktok` silently drops the `tenant_id` field. The
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

If no `tenant_slug` is supplied (e.g. login via `accounts.codevertexafrica.com`), the user lands on the platform-level admin tenant.

### Where to set tenant_slug from the UI

In auth-ui, the `OAuthButton` component reads the active tenant from the subdomain/path of the current request and includes it in the `POST /oauth/{provider}/start` body. See [auth-ui/src/app/login/page.tsx](../../auth-ui/src/app/login/page.tsx).

---

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Google: *"redirect_uri_mismatch"* | URL in console differs from what auth-api sends | Compare exact string — trailing slash, http vs https, port, path — against the canonical list above. |
| Google: *"Invalid Redirect: URI must not be empty"* at console creation | Redirect URI field left blank | Paste `https://sso.codevertexafrica.com/api/v1/auth/oauth/google/callback`. |
| Microsoft: *"AADSTS50011: reply URL doesn't match"* | Same as Google redirect_uri_mismatch | Check Azure App registration → Authentication → Redirect URIs. |
| GitHub: callback URL mismatch | GitHub only allows one callback per app | Register separate prod + dev OAuth Apps. |
| TikTok: *"Redirect_uri is not matched with the uri when requesting code."* | The Redirect URI saved in auth-ui differs from the Login Kit Web redirect URI | Make both exactly `https://sso.codevertexafrica.com/api/v1/auth/oauth/tiktok/callback`. |
| TikTok: *"client_key"* error on the authorize page | Client Key missing or pasted with spaces, or the app is not yet approved for Login Kit | Re-save the key in auth-ui and check the app status in TikTok for Developers. |
| State JWT expired | User took >10 min between start and callback | User retries from scratch; adjust TTL via `AUTH_SECURITY_OAUTH_STATE_TTL` if needed. |
| `integration config not found` on callback | `IntegrationConfig` row missing or `is_active=false` | Run seeder with the env vars set, or enable the provider in auth-ui admin. |
| User signs in but lands on wrong tenant | `tenant_slug` not propagated to `/oauth/start` | Check that the frontend reads the active tenant from subdomain/path and sends it in the start request. |

---

## Related Documents

- [integrations.md](./integrations.md) — Full integration patterns across all Codevertex services
- [architecture.md](./architecture.md) — auth-service architecture, JIT provisioning, tenant sync
- [PRODUCTION-SETUP.md](./PRODUCTION-SETUP.md) — Production deployment checklist

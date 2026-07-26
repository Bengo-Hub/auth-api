# auth-api -- API Consumer Guide

**Last Updated**: March 6, 2026

This document defines the API patterns that frontend consumers (auth-ui, ordering-frontend, POS, other Codevertex services) must follow when integrating with `sso.codevertexafrica.com`.

---

## Base URL

| Environment | URL |
|-------------|-----|
| Local | `http://localhost:4101/api/v1` |
| Production | `https://sso.codevertexafrica.com/api/v1` |

---

## Authentication Flows

### 1. Email/Password Login

```
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "secure_password"
}
```

**Success Response** (200):
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "opaque-refresh-token",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "id": "user-uuid",
    "email": "user@example.com",
    "tenant_id": "tenant-uuid",
    "roles": ["admin"]
  }
}
```

**MFA Required** (200, partial):
```json
{
  "mfa_required": true,
  "mfa_token": "temporary-mfa-token",
  "mfa_methods": ["totp"]
}
```

When `mfa_required` is true, the frontend must prompt for a TOTP code and call:

```
POST /api/v1/auth/mfa/totp/confirm
{
  "mfa_token": "temporary-mfa-token",
  "code": "123456"
}
```

### 2. Registration

```
POST /api/v1/auth/register
{
  "email": "new@example.com",
  "password": "secure_password",
  "first_name": "Jane",
  "last_name": "Doe"
}
```

### 3. Token Refresh

```
POST /api/v1/auth/refresh
{
  "refresh_token": "opaque-refresh-token"
}
```

Refresh tokens are rotated on each use. The old refresh token is invalidated immediately.

### 4. Logout

```
POST /api/v1/auth/logout
Authorization: Bearer <access_token>
```

Invalidates the session, revokes the refresh token, and clears the `bb_session` cookie.

### 5. Current User

```
GET /api/v1/auth/me
Authorization: Bearer <access_token>
```

Returns the authenticated user's profile, tenant, and permissions.

---

## OIDC / SSO Integration

Services that redirect users to auth-ui for login use the standard OIDC Authorization Code + PKCE flow.

### Discovery

```
GET /api/v1/.well-known/openid-configuration
GET /api/v1/.well-known/jwks.json
```

### Authorization

```
GET /api/v1/authorize?
  client_id=ordering-app&
  redirect_uri=https://ordering.codevertexafrica.com/callback&
  response_type=code&
  scope=openid email profile&
  code_challenge=<S256 challenge>&
  code_challenge_method=S256&
  state=<csrf-state>&
  nonce=<nonce>
```

### Token Exchange

```
POST /api/v1/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=<authorization-code>&
redirect_uri=<original-redirect>&
client_id=<client-id>&
code_verifier=<pkce-verifier>
```

### UserInfo

```
GET /api/v1/userinfo
Authorization: Bearer <access_token>
```

Returns standard OIDC claims: `sub`, `email`, `email_verified`, `tenant_id`, `sid`.

---

## JWT Token Structure

All access tokens are RS256-signed JWTs. Verify via the JWKS endpoint using the `kid` header.

**Claims**:

| Claim | Type | Description |
|-------|------|-------------|
| `sub` | UUID | User ID |
| `email` | string | User email |
| `tenant_id` | UUID | Tenant ID |
| `tenant_slug` | string | Tenant slug (e.g., `urban-loft`) |
| `roles` | string[] | Global roles (e.g., `admin`, `super_admin`) |
| `scopes` | string[] | Granted OAuth scopes |
| `sid` | UUID | Session ID |
| `iss` | string | Issuer URL |
| `aud` | string | Audience (e.g., `urn:bengobox:services`) |
| `exp` | int | Expiry timestamp |
| `iat` | int | Issued-at timestamp |
| `kid` | string | Key ID for JWKS lookup |

---

## Admin APIs

All admin endpoints require a JWT with `admin` or `super_admin` role.

### Tenant Management

```
GET    /api/v1/admin/tenants         -- List all tenants
POST   /api/v1/admin/tenants         -- Create tenant
GET    /api/v1/admin/tenants/{id}    -- Get tenant details
```

### User Management (Tenant-Scoped)

```
GET    /api/v1/tenants/{tenant_id}/users    -- List tenant users
POST   /api/v1/tenants/{tenant_id}/users    -- Invite user to tenant
```

### OAuth Client Management

```
GET    /api/v1/admin/clients         -- List OAuth clients
POST   /api/v1/admin/clients         -- Register new OAuth client
```

### API Key Management

```
POST   /api/v1/admin/api-keys              -- Create API key
GET    /api/v1/admin/api-keys              -- List API keys for tenant
DELETE /api/v1/admin/api-keys/{id}         -- Revoke API key
GET    /api/v1/admin/api-keys/validate     -- Validate API key (X-API-Key header)
```

### Key Rotation

```
POST   /api/v1/admin/keys/rotate    -- Rotate JWKS signing keys
```

---

## Platform Admin APIs

Platform admin endpoints are gated by `super_admin` role (platform admin at `admin@codevertexafrica.com`).

**Payment gateway configuration** is owned by **treasury-api**; auth-api does not expose gateway CRUD. Use treasury-api for gateway list/create/update. Auth-ui redirects platform admins to treasury-ui (Codevertex Books).

### Role & Permission Management

```
GET    /api/v1/platform/roles        -- List all platform roles
POST   /api/v1/platform/roles        -- Create role
```

---

## API Key Validation (Service-to-Service)

Other Codevertex services validate API keys by calling:

```
GET /api/v1/admin/api-keys/validate
X-API-Key: bng_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

**Response** (200):
```json
{
  "client_id": "api-key-uuid",
  "tenant_id": "tenant-uuid",
  "scopes": ["read:orders", "write:inventory"],
  "service": "ordering-service"
}
```

Use `shared-auth-client` middleware for automatic JWT + API key validation:

```go
import authclient "github.com/Bengo-Hub/shared-auth-client"

validator := authclient.NewValidator(authclient.DefaultConfig(
    "https://sso.codevertexafrica.com/api/v1/.well-known/jwks.json",
    "https://sso.codevertexafrica.com",
))
apiKeyValidator := authclient.NewAPIKeyValidator(
    os.Getenv("AUTH_SERVICE_URL"), nil,
)
router.Use(authclient.NewAuthMiddlewareWithAPIKey(validator, apiKeyValidator).RequireAuth)
```

---

## Error Contract

All errors follow a consistent JSON envelope:

```json
{
  "error": "Human-readable message",
  "code": "machine_identifier",
  "details": {}
}
```

| HTTP Status | Meaning |
|-------------|---------|
| 400 | Validation error (check `details` for field-level errors) |
| 401 | Missing/invalid/expired token |
| 403 | Authenticated but insufficient permissions |
| 404 | Resource not found |
| 409 | Conflict (e.g., duplicate email) |
| 429 | Rate limited |
| 500 | Internal server error |

---

## Frontend Integration Patterns

### Token Storage

- **Access token**: Store in memory (Zustand store or React context). Never in localStorage.
- **Refresh token**: Handled via `bb_session` httpOnly cookie or returned in response body.
- **Session cookie**: `bb_session` is httpOnly, Secure, SameSite=Strict.

### Token Refresh Interceptor

When a request returns 401, the frontend must:

1. Call `/api/v1/auth/refresh` with the stored refresh token
2. Retry the original request with the new access token
3. If refresh fails, redirect to login

Implement as an Axios response interceptor with request queueing to avoid thundering herd on concurrent 401s.

### Role-Based UI Gating

After login, fetch permissions via `GET /api/v1/auth/me` or `GET /api/v1/users/me/permissions`. Gate UI sections based on roles:

| Role | Access |
|------|--------|
| `super_admin` | Platform admin section (roles, all tenants); gateways → treasury-api/ui |
| `admin` | Tenant admin section (users, settings, API keys) |
| `user` | Standard user features (profile, security) |

---

## Rate Limiting

- Login/refresh endpoints: Redis-backed fixed window (configurable)
- Admin endpoints: Standard rate limiting
- Prometheus metrics available at `/metrics` for monitoring

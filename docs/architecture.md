# auth-api -- Architecture

**Service**: auth-api (Go)
**Deployed**: authapi.codevertexitsolutions.com
**Port**: 4101
**Source of truth for**: tenants, outlets (all downstream services mirror via JIT sync + NATS events)

---

## Stack

| Layer | Technology |
|-------|-----------|
| Language | Go 1.22+ |
| HTTP | Chi router, shared-auth-client middleware |
| ORM | Ent (auto-generated, `internal/ent`) |
| Database | PostgreSQL 16 |
| Cache | Redis 7 (rate limit, revocation, integration credentials; GET `/api/v1/auth/me` cached by user ID, TTL = token expiry) |
| Events | NATS JetStream (stream: `auth`, subjects: `auth.*`); env: `EVENTS_NATS_URL` or `AUTH_EVENTS_NATS_URL` |
| Observability | Zap logger, Prometheus `/metrics` |
| Auth | Self-issued JWT (RS256, JWKS endpoint) |
| Migrations | Ent auto-migrate (transitioning to Atlas versioned migrations) |
| Shared libs | shared-auth-client, shared-events |

### Atlas migration transition

Auth-api currently uses Ent's `client.Schema.Create()` for auto-migration. All future schema changes must use Atlas:

1. Scaffold Ent schemas in `internal/ent/schema/`
2. Generate Atlas migrations: `atlas migrate diff --env ent`
3. Store in `migrations/` (versioned, sequential)
4. Apply via CI: `atlas migrate apply --url $DATABASE_URL`
5. No `client.Schema.Create()` in production paths

---

## Directory layout

```
auth-api/
  cmd/api/main.go              -- entry point, signal handling
  config/example.env           -- environment template
  internal/
    app/app.go                 -- bootstrap, DI, server wiring
    config/config.go           -- envconfig (AUTH_ prefix)
    database/postgres.go       -- database connection, Ent client init
    httpapi/
      handlers/
        admin_handler.go       -- tenant, client, entitlement, key rotation admin APIs
        oidc_handler.go        -- OIDC/OAuth2 endpoints (authorize, token, userinfo, jwks)
    services/
      auth/service.go          -- login, signup, refresh, logout, MFA, password reset
      oidc/service.go          -- OIDC provider logic, code exchange, consent
    ent/                       -- Ent-generated ORM (schema, client, predicates)
      schema/                  -- Ent schema definitions (users, tenants, sessions, etc.)
  docs/
    erd.md                     -- entity relationship overview
    integrations.md            -- cross-service integration guide
    developer-api.md           -- API consumer reference
    PRODUCTION-SETUP.md        -- production deployment guide
    local-testing.md           -- local dev instructions
    https-setup.md             -- TLS/certificate setup
```

---

## Core Responsibilities

### OAuth2/OIDC Provider

Auth-api is the **central identity provider** for all BengoBox services. It implements:

- **Authorization Code + PKCE** flow for web/SPA clients
- **Client Credentials** grant for service-to-service auth (roadmap)
- **Device Authorization** grant for kiosk/TV devices
- **JWKS endpoint** (`/.well-known/jwks.json`) for offline token validation
- **OpenID Connect Discovery** (`/.well-known/openid-configuration`)
- **UserInfo endpoint** for standard OIDC claims

### Tenant Management

- CRUD for tenants (organisations subscribed to BengoBox)
- Tenant slug as canonical identifier across all microservices
- Tenant domains and cookie configuration for SSO
- Tenant policies (password, session, MFA enforcement)
- Feature entitlements synced from treasury-api

### Outlet Management (source of truth)

Auth-api owns the canonical outlet/branch registry. All downstream services mirror outlet data — they never manage outlets independently.

- CRUD for outlets (`GET/POST/PUT /api/v1/tenants/{slug}/outlets`)
- Outlet fields: `id` (deterministic UUID), `code`, `name`, `use_case`, `is_hq`, `status`, `address`, `pin_login_message`
- Deterministic outlet UUID formula (shared across ALL services):
  ```go
  uuid.NewSHA1(uuid.NameSpaceURL, []byte(fmt.Sprintf("bengobox:cafe:outlet:%s:%s", tenantSlug, outletSlug)))
  ```
- On SSO login: if tenant has multiple outlets, the token response includes `requiresOutletSelection: true` + outlet list; client calls `POST /api/v1/auth/select-outlet` to exchange for a final JWT with outlet claims
- JWT outlet claims (`shared-auth-client v0.6.0`): `outlet_id`, `outlet_code`, `outlet_use_case`, `is_hq_user`

### User & Role Management

- User registration, login, password reset
- MFA (TOTP with backup codes)
- Social login (Google, GitHub, Microsoft)
- User-tenant memberships with global roles
- Permission-based RBAC enforcement

### API Key Management

- Create/list/revoke API keys per tenant
- SHA-256 hashed storage (plain key shown only on creation)
- Scope-based access control
- Validation endpoint for service-to-service auth

### Session & Token Management

- JWT access tokens (RS256, 15-min TTL)
- Opaque refresh tokens (rotated on use)
- Session tracking with device/IP binding
- Token revocation and introspection
- Key rotation with JWKS history

---

## Multi-Tenancy Model

- Every entity carries `tenant_id` for organisational isolation
- Tenant slug appears in URLs for downstream services (not in auth-api URLs directly)
- JWT claims include `tenant_id`, `tenant_slug`, `roles`, `scopes`
- Downstream services extract tenant context from JWT -- they never duplicate user/tenant tables

### Downstream tenant + outlet sync (JIT)

All Go backends (ordering-backend, notifications-api, subscriptions-api, treasury-api, pos-api, inventory-api, logistics-api) use a **uniform JIT (just-in-time) sync** workflow:

1. **Auth-api** is the source of truth for tenants AND outlets. Endpoints: `GET /api/v1/tenants/by-slug/{slug}` and `GET /api/v1/tenants/{slug}/outlets` (both public, no auth required).
2. When the **authorize** URL includes `?tenant=urban-loft` (or another slug), auth-api stores it in the authorization code metadata. On **token exchange**, the issued tokens carry `tenant_id`, `tenant_slug`, `outlet_id`, `outlet_code`, `outlet_use_case`, and `is_hq_user`.
3. If a tenant has multiple outlets, the token response includes `requiresOutletSelection: true`. The client navigates to `/{orgSlug}/auth/select-outlet`, calls `POST /api/v1/auth/select-outlet` with `ssoExchangeToken + outletId`, and receives a final JWT with outlet claims embedded.
4. Each downstream service's **tenant syncer** GETs the tenant from auth-api and upserts it locally. On first login per outlet, the service also syncs the outlet row via the outlets endpoint.
5. Outlet UUIDs are **deterministic** across all services — computed from the same formula. Services never generate their own outlet IDs.
6. **codevertex** is the platform owner tenant (elevated access). **codevertex-demo** is the cross-platform demo tenant with 6 outlets covering every use case. No separate sync job is required; sync on first request per tenant/outlet is sufficient.

---

## Event Publishing

Auth-api publishes domain events to NATS JetStream:

| Subject | Trigger | Consumers |
|---------|---------|-----------|
| `auth.tenant.created` | New tenant registered | All downstream services |
| `auth.tenant.updated` | Tenant metadata changed | All downstream services |
| `auth.tenant.synced` | Periodic/manual sync | All downstream services |
| `auth.user.created` | New user registered | All downstream services |
| `auth.user.updated` | User profile changed | All downstream services |
| `auth.role.assigned` | Role assigned to user | All downstream services |
| `auth.outlet.created` | New outlet created | pos-api, ordering-backend, inventory-api |
| `auth.outlet.updated` | Outlet name/use_case/status changed | pos-api, ordering-backend, inventory-api |
| `auth.outlet.archived` | Outlet deactivated | pos-api, ordering-backend, inventory-api |

Events use the outbox pattern: written to `outbox_events` table in the same transaction as the domain change, then published by a background worker.

---

## Seed Data

| Entity | Value | Notes |
|--------|-------|-------|
| Platform admin | `admin@codevertexitsolutions.com` | `superuser` role on all tenants |
| Platform tenant | `codevertex` | `is_platform_owner = true` |
| Real client | `urban-loft` (Urban Loft Cafe) | Hospitality only — hotel, bar, grill, cafe |
| Urban Loft admin | `admin@theurbanloftcafe.com` | `admin` role on `urban-loft` |
| Urban Loft outlet | BUSIA / hospitality / is_hq=true | Single outlet |
| **Demo tenant** | `codevertex-demo` | Cross-platform demo — all 6 use-cases |
| Demo admin | `admin@demo.codevertexitsolutions.com` | `admin` role on `codevertex-demo` |
| Demo outlets | HOSP/hospitality, RETAIL/retail, QSR/quick_service, PHARMA/pharmacy, SVC/services, LOGIS/logistics | One outlet per use case |
| Demo staff | `manager/cashier/waiter/kitchen/bar/receptionist @demo.codevertexitsolutions.com` | POS PIN staff for demo |
| OAuth clients | `pos-ui`, `inventory-ui`, `ordering-ui`, `auth-ui`, etc. | Pre-registered for SSO |

---

## Deployment

- Docker container deployed via ArgoCD to Kubernetes
- Helm values: `devops-k8s/values/auth-api-values.yaml`
- Environment variables from K8s secrets
- PostgreSQL (managed), Redis (managed), NATS JetStream (cluster)
- Horizontal scaling via HPA
- Health checks: `/healthz` (liveness), `/readyz` (readiness)
- Prometheus metrics: `/metrics`

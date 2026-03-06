# Sprint MVP Launch (March 17, 2026)

**Progress (March 2026)**: **Default tenants (seed):** Codevertex (platform owner, codevertexitsolutions.com), Masterspace Solutions (mss, masterspace.co.ke), Urban Loft Cafe (urban-loft, theurbanloftcafe.com), KURA (kura, kura.go.ke), UltiChange (ultichange, ultichange.org). Tenant metadata includes `base_domain`. OAuth client rider-app redirect URIs include riderapp.codevertexitsolutions.com. Verified in code: CP-1 seed has urban-loft tenant, platform admin (env), tenant admin (admin@theurbanloftcafe.com), demo users, OAuth clients (notifications-ui, ordering-ui, rider-app, cafe-website), scopes openid/profile/email/offline_access. Busia outlet and scopes pos.read/orders.manage not in seed. CP-2: JWKS and OIDC discovery implemented. CP-3: Outbox + NATS publisher. CP-4: API key validate implemented. **Tenant/brand**: GET /api/v1/tenants/by-slug/{slug} is public (no auth), returns PublicTenantResponse (id, name, slug, status, metadata) for frontend tenant discovery and branding; auth-ui, pos-ui, subscriptions-ui consume it. **RBAC**: Permission and RolePermission Ent schemas added; seed creates permissions for resources (orders, menu, users, tenants, riders, inventory, settings, gateways) with actions add, read, read_own, change, change_own, delete, manage, manage_own; role-permission mapping seeded for superuser, admin, staff, member, rider. GET /api/v1/auth/me now returns `roles` and `permissions`; frontends use this for nav, route protection, and 404/unauthorized (see docs/integrations.md). Redis cache for permission lookups is recommended (not yet implemented).

**Duration**: March 6 -- March 17, 2026 (10 working days)
**Status**: In Progress
**Goal**: Ensure auth-api is production-ready as the central identity provider for the BengoBox MVP launch, supporting the `urban-loft` tenant with Busia as the only active outlet.

---

## Hard Deadline Constraints

- **March 17**: All BengoBox services go live; auth-api must be stable at `authapi.codevertexitsolutions.com`
- **Tenant**: `urban-loft` only (The Urban Loft Cafe)
- **Outlet**: Busia only
- **Users**: Platform admin (`admin@codevertexitsolutions.com`), tenant admin (`admin@theurbanloftcafe.com`), demo/test users
- **Downstream dependents**: Every BengoBox service depends on auth-api for JWT validation and tenant context

---

## Critical Path Tasks

### CP-1: Seed Data Verification

**Priority**: P0 -- blocks all downstream services
**Owner**: Backend

- [x] Verify `urban-loft` tenant exists with correct UUID, slug, name, status
- [x] Verify platform admin (`admin@codevertexitsolutions.com`) has `super_admin` role
- [x] Verify tenant admin (`admin@theurbanloftcafe.com`) has `admin` role on `urban-loft`
- [ ] Verify Busia outlet is seeded and linked to `urban-loft` tenant
- [x] Verify demo users exist for cross-service integration testing
- [x] Verify default OAuth clients are registered (auth-ui, ordering-app, pos-app, etc.)
- [ ] Verify system scopes are seeded (`profile`, `email`, `offline_access`, `pos.read`, `orders.manage`)
- [ ] Remove or deactivate any stale test data

### CP-2: E2E Auth Flow Verification

**Priority**: P0
**Owner**: Backend + Frontend

The full happy path must work for every downstream consumer:

1. **Login**: User logs in at `auth.codevertexitsolutions.com/login`
2. **Token issuance**: JWT access token + refresh token returned
3. **OIDC redirect**: Authorization code flow with PKCE works for SSO from ordering-app, POS, etc.
4. **Token validation**: Downstream services validate JWTs via JWKS endpoint
5. **Token refresh**: Refresh token rotation works correctly
6. **Logout**: Session invalidation clears all tokens

Specific tasks:

- [ ] Test login flow end-to-end with `admin@theurbanloftcafe.com`
- [ ] Test OIDC authorization code + PKCE flow from ordering-frontend
- [x] Verify JWKS endpoint (`/.well-known/jwks.json`) returns valid keys
- [x] Verify OpenID Discovery (`/.well-known/openid-configuration`) is correct
- [ ] Test token refresh and rotation
- [ ] Test logout and session revocation
- [ ] Verify `bb_session` cookie is set correctly (httpOnly, Secure, SameSite)

### CP-3: NATS Event Publishing

**Priority**: P0 -- downstream services depend on auth events for tenant/user sync
**Owner**: Backend

- [x] Verify outbox publisher is running and draining events
- [x] Test: create tenant -> `auth.tenant.created` event published to NATS
- [x] Test: create user -> `auth.user.created` event published
- [x] Test: assign role -> `auth.role.assigned` event published
- [ ] Verify downstream services (ordering, POS, notifications) receive and process events
- [ ] Monitor outbox table for stuck events

### CP-4: API Key Validation

**Priority**: P0 -- service-to-service auth depends on this
**Owner**: Backend

- [x] Verify `GET /api/v1/admin/api-keys/validate` works with valid API key
- [ ] Verify shared-auth-client middleware correctly handles both JWT and API key auth
- [ ] Generate production API keys for each downstream service that needs S2S auth
- [ ] Test: invalid/expired API key returns 401
- [ ] Test: API key with restricted scopes enforces scope limitations

---

## High Priority Tasks

### HP-1: Atlas Migration Transition

**Priority**: P1 -- technical debt, blocks future schema changes
**Owner**: Backend

- [ ] Install Atlas CLI in dev environment and CI pipeline
- [ ] Generate initial Atlas migration from current Ent schema (`atlas migrate diff`)
- [ ] Create `atlas.hcl` config pointing to production DB
- [ ] Test migration apply on staging DB
- [ ] Update Dockerfile to run Atlas migrations on startup instead of Ent auto-migrate
- [ ] Document rollback procedure
- [ ] **Decision**: Run Atlas in CI only or also on app boot? (Recommend CI-only for production)

### HP-2: Platform Admin vs Tenant Admin Separation

**Priority**: P1
**Owner**: Backend + Frontend

- [ ] Verify `super_admin` role gates platform-level endpoints (gateways, all-tenant views, role management)
- [ ] Verify `admin` role gates tenant-level endpoints only (own tenant users, settings, API keys)
- [ ] Test: tenant admin cannot access platform admin endpoints (expect 403)
- [ ] Test: platform admin can access both platform and tenant endpoints
- [ ] Verify auth-ui correctly hides/shows platform admin section based on role

### HP-3: CORS & Security Headers

**Priority**: P1
**Owner**: Backend

- [ ] Verify CORS allows all production BengoBox frontend origins:
  - `https://auth.codevertexitsolutions.com`
  - `https://ordersapp.codevertexitsolutions.com`
  - `https://pos.codevertexitsolutions.com`
  - `https://notifications.codevertexitsolutions.com`
  - `https://theurbanloftcafe.com`
- [ ] Verify preflight (OPTIONS) requests work correctly
- [ ] Verify security headers: `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`
- [ ] Verify rate limiting is active on login/refresh endpoints

### HP-4: Social Login Verification

**Priority**: P1 -- best effort for launch
**Owner**: Backend

- [ ] Verify Google OAuth callback works in production
- [ ] Verify GitHub OAuth callback works in production
- [ ] Verify Microsoft OAuth callback works in production
- [ ] Ensure social login creates/links user correctly and issues first-party tokens

---

## Medium Priority Tasks

### MP-1: Multi-Tenant Isolation Verification

**Priority**: P2

- [ ] Verify tenant isolation: user in tenant A cannot access tenant B's data
- [ ] Verify JWT `tenant_id` claim is enforced on all tenant-scoped endpoints
- [ ] Test with a second test tenant to confirm isolation (don't expose in production)
- [x] Verify `GET /api/v1/tenants/by-slug/{slug}` returns correct tenant (public endpoint; returns id, name, slug, status, metadata)

### MP-2: MFA Verification

**Priority**: P2

- [ ] Test TOTP setup flow (generate secret, display QR, verify code)
- [ ] Test login with MFA enabled
- [ ] Test backup code consumption
- [ ] Verify MFA enforcement per tenant policy

### MP-3: Monitoring & Observability

**Priority**: P2

- [ ] Verify Prometheus metrics endpoint (`/metrics`) exposes auth success/failure rates, token validation latency
- [ ] Create basic Grafana dashboard: login rate, token refresh rate, error rate
- [ ] Set up critical alerts: high 401 rate, JWKS endpoint failures, DB connection exhaustion

---

## Out of Scope (Post-MVP)

- SAML support (enterprise SSO)
- Passwordless authentication (magic links)
- WebAuthn/FIDO2
- Advanced audit log UI
- User activity timeline
- Compliance reporting (SOC2, GDPR)
- Client Credentials grant (service accounts)
- Apple Sign In

---

## Deployment Checklist

### Pre-Launch (March 14-16)

- [ ] Run full seed on production DB (tenant, outlet, users, OAuth clients, scopes, permissions, role_permission)
- [ ] Verify all environment variables set in K8s secrets (DB, Redis, NATS, JWKS keys)
- [ ] Verify NATS JetStream streams and consumers created for `auth.*` subjects
- [ ] Verify Redis connectivity for rate limiting and session cache
- [ ] Run `atlas migrate apply` on production DB (if Atlas transition complete)
- [ ] Smoke test all critical endpoints on staging
- [ ] Verify TLS certificate for `authapi.codevertexitsolutions.com`
- [ ] Verify JWKS keys are rotated and current

### Launch Day (March 17)

- [ ] Deploy final image via ArgoCD
- [ ] Verify `/healthz` returns 200
- [ ] Test login flow with tenant admin account
- [ ] Test OIDC flow from ordering-frontend
- [ ] Verify JWKS endpoint accessible from all downstream services
- [ ] Monitor error rate for first 2 hours

### Post-Launch (March 18-21)

- [ ] Monitor login success/failure rates
- [ ] Review error logs for unexpected 5xx
- [ ] Check outbox table is draining (no stuck events)
- [ ] Verify all downstream services can validate tokens
- [ ] Triage any blocking bugs as hotfixes

---

## Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| JWKS endpoint down | All services reject tokens | Redis JWKS cache with TTL; multiple replicas |
| DB migration breaks schema | App crash on boot | Atlas versioned migrations with rollback; test on staging first |
| NATS unavailable | Auth events lost, downstream out of sync | Outbox pattern persists events in DB; publisher retries on reconnect |
| Refresh token leak | Account takeover | Token rotation; session binding; device fingerprinting |
| Rate limiter Redis down | Brute-force vulnerability | Fallback to in-memory rate limiting; alert on Redis failure |

---

## Success Criteria

- [ ] All downstream BengoBox services can authenticate users via OIDC/JWT
- [ ] Platform admin can manage tenants, roles, gateways at `auth.codevertexitsolutions.com`
- [ ] Tenant admin can manage users, API keys for `urban-loft`
- [ ] Auth events (`auth.tenant.created`, `auth.user.created`, `auth.role.assigned`) flow to NATS
- [ ] Zero cross-tenant data leaks
- [ ] p95 login latency < 500ms
- [ ] p95 token validation latency < 50ms
- [ ] Error rate < 1% for auth endpoints

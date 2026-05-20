## Auth Service Delivery Plan

### Vision & Mandate
- Deliver a unified authentication, authorization, and identity orchestration platform for the entire BengoBox ecosystem (ordering-backend, POS, inventory, logistics, treasury, notifications, ERP, partner APIs) with a canonical `tenant_slug` propagated to all services.
- Provide standards-compliant OAuth2/OpenID Connect capabilities to power Single Sign-On (SSO) across web, mobile, kiosk, and service-to-service flows.
- Establish a secure foundation for multi-tenant, multi-brand operations with fine-grained policy enforcement, while delegating application-specific RBAC to downstream services.
- Ensure extensibility for future identity protocols (SAML, SCIM, FIDO2) and marketplace integrations.
- **Entity Ownership**: This service owns all identity and access management entities: users, tenants, outlets, sessions, OAuth clients, MFA settings, and global tenant roles. All other services reference these entities via `user_id`, `tenant_id`, `tenant_slug`, and `outlet_id` but never duplicate user or tenant data.
- Act as the canonical source for tenant/outlet discovery: when a user authenticates, this service emits webhooks to downstream services (ordering-backend, logistics, inventory, POS, treasury, notifications) so they can sync tenant/outlet metadata before handling domain-specific data.

### Scope & Responsibilities
1. **SSO & OAuth2/OIDC Provider**
   - Authorization Code + PKCE, Device Code, Client Credentials, Refresh Token flows.
   - JWT/opaque token issuance (access, ID, refresh) with asymmetric signing (JWKS) and token introspection.
   - Discovery endpoints (`/.well-known/openid-configuration`, `/.well-known/jwks.json`).
2. **Identity & Account Management**
   - Local accounts (email/password with Argon2id via shared library), passwordless login (magic links), invite/onboarding flows.
   - Social login (Google, Microsoft, Apple, GitHub, configurable providers), account linking/unlinking.
   - Multi-tenant support: organisations, roles, groups, tenant membership claims.
3. **Security Hardening**
   - MFA/2FA (TOTP, OTP via notifications service, WebAuthn roadmap), backup codes, risk-based prompts.
   - Session management, device tracking, adaptive authentication (IP/risk scoring), anomaly detection.
   - Token revocation, logout propagation (front-channel/back-channel), short-lived tokens with auto-rotation.
4. **Client & Scope Management**
   - Self-service and admin APIs/UI for registering OAuth clients, defining redirect URIs, allowed scopes, consent policies.
   - Service accounts (machine-to-machine) with secret rotation and policy enforcement.
5. **Audit, Compliance & Operations**
   - Immutable audit log (logins, failures, MFA, admin actions), export for compliance.
   - Key management (KMS integration), automated rotation, health monitoring, metrics.
   - Regulatory compliance (GDPR, Kenyan DPA, SOC2-friendly logging), incident response hooks.
6. **Subscription & Feature Gating**
   - Integration with treasury for tenant entitlements (premium auth features, MFA enforcement).
   - Usage metering (active users, auth transactions), overage events.
7. **Extensibility**
   - Plugin architecture for downstream services to publish custom claims (POS roles, inventory tenant IDs).
   - Federation roadmap (SAML, SCIM provisioning, enterprise IdP integration).

### Technical Foundations
- **Language & Runtime:** Go 1.22+, clean architecture, gofmt/golangci-lint.
- **Frameworks:** chi router, `golang.org/x/oauth2`, `github.com/golang-jwt/jwt/v5`, `github.com/coreos/go-oidc`.
- **Data:** PostgreSQL (users, sessions, clients, audit), Redis (session cache, rate limits, revocation lists).
- **ORM & Migrations:** Ent with schema-as-code migrations.
- **Security:** HTTPS everywhere, TLS termination, mTLS for internal service calls, secure cookies.
- **Observability:** zap logging, OpenTelemetry, Prometheus metrics, audit log streaming to SIEM.
- **Deployment:** Docker/Helm, ArgoCD pipelines, blue/green or canary deployments.
- **Testing:** Go test + table-driven, Testcontainers (Postgres/Redis), OIDC conformance tests, penetration testing.

### Data Model Highlights
- `users`, `user_identities` (external providers), `user_profiles`, `user_devices`.
- `tenants`, `tenant_memberships`, `tenant_roles`, `role_bindings`.
- `oauth_clients`, `oauth_client_scopes`, `oauth_grants`, `oauth_consent_sessions`.
- `sessions`, `refresh_tokens`, `token_revocations`, `login_attempts`.
- `audit_logs`, `security_events`, `mfa_secrets`, `backup_codes`.
- `feature_entitlements`, `usage_metrics`.

### Architecture Overview
- **Identity Gateway:** handles auth flows, consent screens, MFA prompts, device management.
- **Token Service:** issues/validates tokens, manages signing keys, introspection.
- **Session & Device Service:** tracks sessions, rotates refresh tokens, enforces device policies.
- **Client Registry:** admin APIs/UI for client onboarding, scope approval, secrets.
- **Integration Layer:** connectors to notifications (OTP, alerts), treasury (billing), inventory/POS/logistics (user provisioning), analytics.
- **Policy Engine (future):** attribute-based access rules, risk scoring, adaptive MFA.

### API Surfaces
- Public endpoints: `/authorize`, `/token`, `/userinfo`, `/introspect`, `/revoke`, `/logout`, `/device`, `/.well-known/*`.
- Admin APIs: `/admin/tenants`, `/admin/users`, `/admin/clients`, `/admin/audit`.
- Webhooks/events: `auth.user.created`, `auth.user.locked`, `auth.tenant.invite.accepted`, `auth.usage.threshold_exceeded`.
- Tenant discovery webhooks: `auth.tenant.synced`, `auth.outlet.synced` ensure all services hydrate tenant/outlet context without polling.
- SDKs: Go/TypeScript clients auto-generated from OpenAPI.

### Integration Principles
- **Downstream Services** authenticate requests by validating JWT (local JWKS cache) or introspection for opaque tokens.
- **Claims Strategy:** include tenant ID(s), global groups, service-specific scopes; services still own fine-grained RBAC.
- **Consent & Scopes:** support explicit consent for third-party or external partner integrations.
- **Notifications Integration:** OTP, login alerts, suspicious activity via notifications service.
- **Treasury Integration:** billing for premium auth features, license checks, usage ingestion (MAU, auth calls).
- **POS/Inventory/Logistics:** support non-interactive service accounts, SSO for internal staff dashboards, kiosk device registration.

### Cross-Cutting Concerns
- Multi-region resilience, active-passive or active-active (key replication).
- Rate limiting, bot protection, brute-force detection.
- Threat modelling (phishing, token theft, SSRF) and remediation playbooks.
- Disaster recovery (backup/restore of keys, user DB, audit logs).
- Localization/internationalization for login UI, policy, and notifications.

### Roadmap (Indicative Sprints)
- [x] **Sprint 0 – Foundations:** Server bootstrap (`cmd/server`), structured config loader, zap logging, Redis/Postgres clients, health endpoint, Ent schema (users, tenants, memberships, OAuth clients, audit, sessions, reset tokens, login attempts).
- [x] **Sprint 1 – Local Auth Basics:** Argon2id hashing, registration/login flows with tenant membership enforcement, password reset issuance & confirmation, audit logging, login attempt tracking, validation + error handling.
- [x] **Sprint 2 – Token Service:** RSA-backed JWT minting/verification, refresh token rotation with session persistence, `/auth/refresh` + `/auth/me` endpoints, auth middleware, session telemetry updates.
- [x] **Sprint 3 – External Providers:** Google, GitHub, Microsoft OAuth login/linking, user identity store, signed OAuth state helper, provider configuration & domain gating, `/auth/oauth/{provider}/*` endpoints that mint first-party tokens. (Apple planned separately)
- [x] **Sprint 4 – OIDC Compliance:** Authorization Code + PKCE, discovery docs, JWKS, userinfo, consent flows.
- [x] **Sprint 5 – Sessions & Logout:** multi-device session management, revocation, global logout propagation, security events.
- [x] **Sprint 6 – MFA & Risk Controls:** TOTP, backup codes, policies, integration with notifications for SMS/email OTP.
- [x] **Sprint 7 – Tenant & Client Admin:** tenant management APIs, client registry UI, scope management, service accounts.
- [x] **Sprint 8 – Subscription & Usage:** entitlement checks (treasury), usage metering, plan gating, billing events.
- [ ] **Sprint 9 – Integrations:** SDKs, service integration guides, migration of existing services, SSO across BengoBox apps.
- [x] **Sprint 10 – Hardening & Launch:** key rotation workflows, rate limiting, analytics, monitoring dashboards, chaos testing, production rollout.
- [x] **Sprint 11 – JWT Claims Enrichment:** Embed subscription data in JWT at login time (see below). ✅ COMPLETE — subscription client wired in `mintTokensForUser`; claims embedded at login/refresh; 5 min Redis cache; graceful fallback.
- [x] **Sprint 12 – API Key Management:** Full API key lifecycle for service-to-service authentication. ✅ COMPLETE — `api_keys` schema, `bng_*` token generation, validate/create/list/revoke endpoints; `App` entity with `bng_app_*` GitHub-style S2S tokens; prefix routing in `ValidateAPIKey`.

### Backlog & Future Enhancements
- FIDO2/WebAuthn, push-based MFA.
- SCIM provisioning for tenant admins (create users, sync groups).
- Enterprise federation (SAML 2.0, Azure AD B2B).
- Behavioral analytics, UEBA (User and Entity Behavior Analytics).
- Privacy features (account anonymisation, GDPR data export portals).

### Password Hashing - Shared Library Adoption ✓ COMPLETE

**Status:** December 2025 - Implemented

The auth-service has been updated to use the centralized shared password hasher library (`github.com/Bengo-Hub/shared-password-hasher@v0.1.0`) instead of maintaining its own custom Argon2id implementation.

**Implementation Details:**
- **File:** `internal/password/argon2.go` - now wraps shared library
- **Dependency:** Added to `go.mod`: `github.com/Bengo-Hub/shared-password-hasher v0.1.0`
- **Parameters:** Uses shared library defaults (m=65536, t=3, p=2, keylen=32)
- **Compatibility:** 100% backwards compatible with existing password hashes
- **Migration Path:** Existing config parameters (Argon2Time, Argon2Memory, etc.) are retained but ignored

**Benefits:**
1. **Single Source of Truth:** Password hashing logic centralized in shared library
2. **Consistency:** Auth-service, TruLoad backend, and all Go services use identical algorithm
3. **Reduced Code:** Eliminated 100+ lines of custom hashing logic
4. **Maintainability:** Future parameter updates only need to happen in shared library
5. **Cross-Service Compatibility:** All services can verify hashes from any other service

**For Other Services:**
- **Go Services (ordering, subscription, projects, notifications, pos, iot):** Already delegate to auth-service, no direct hashing needed
- **ISPBilling (Python):** Uses bcrypt - migration planned (see recommendations below)
- **pharmacymis (Python/Django):** Uses Django PBKDF2 - migration planned (see recommendations below)
- **TruLoad Backend (.NET):** Has compatible Argon2id implementation (.NET-specific, cannot import Go library)

**Future Considerations:**
- If shared library parameters need to change, update `github.com/Bengo-Hub/shared-password-hasher` and all services will automatically adopt
- Config parameters in auth-service (Argon2Time, Argon2Memory) remain for backwards compatibility but are superseded by shared library

---

### Sprint 11 – JWT Claims Enrichment ✅ COMPLETE

**Objective:** Embed subscription data in JWT tokens at login time to enable zero-latency feature gating in downstream services.

**Background:**
Currently, services must make per-request calls to subscription-service to check feature entitlements. This adds latency (50-100ms) and creates coupling. By enriching JWT claims at token issuance, services can perform feature checks locally.

**Tasks:**
- [x] Add subscription-service client to auth-service
- [x] Fetch tenant subscription data during login/refresh
- [x] Extend JWT claims with subscription fields:
  ```go
  SubscriptionPlan     string         `json:"sub_plan"`
  SubscriptionFeatures []string       `json:"sub_features"`
  SubscriptionLimits   map[string]int `json:"sub_limits"`
  SubscriptionStatus   string         `json:"sub_status"`
  SubscriptionExpires  *time.Time     `json:"sub_expires"`
  ```
- [x] Handle subscription-service unavailability gracefully (cache, defaults)
- [ ] Subscribe to `subscription.entitlements_changed` event → invalidate affected sessions (future)
- [x] Update shared-auth-client to parse new claims (✅ Done in v0.2.0)
- [ ] Add tests for enriched token generation (future)

**Integration:**
- auth-service calls `GET /api/v1/tenants/{tenant_id}/subscription` on subscription-service
- Response cached in Redis (5 min TTL) to reduce load
- On subscription change event, auth-service invalidates session cache

**Dependencies:**
- subscription-service `/api/v1/tenants/{tenant_id}/subscription` endpoint

---

### Sprint 12 – API Key Management ✅ COMPLETE

**Objective:** Provide full API key lifecycle for service-to-service authentication and external integrations.

**Tasks:**
- [x] Create `api_keys` Ent schema (prefix, hash, scopes, roles, status, expiry, last_used_at)
- [x] Create API key generation endpoint: `POST /api/v1/admin/api-keys`
- [x] Create API key validation endpoint: `GET /api/v1/admin/api-keys/validate` (also detects `bng_app_*` → apps table)
- [x] Add API key revocation: `DELETE /api/v1/admin/api-keys/{id}`
- [x] Create `App` Ent schema with `bng_app_*` GitHub-style S2S tokens
- [x] App CRUD: `POST/GET/PUT/DELETE /api/v1/admin/apps`, `POST /api/v1/admin/apps/{id}/rotate`, `POST /api/v1/admin/apps/{id}/revoke`
- [x] Seed default platform app ("Codevertex Platform Services") in `cmd/seed/main.go`
- [ ] Add usage tracking update on validation (last_used_at, last_used_ip) — future
- [ ] Implement per-key rate limiting — future
- [ ] Add rotation endpoint for `api_keys` (not apps): `POST /api/v1/admin/api-keys/{id}/rotate` — future

**Response Format (validation endpoint):**
```json
{
  "client_id": "uuid",
  "tenant_id": "uuid",
  "scopes": ["orders.read", "inventory.write"],
  "roles": ["service_account"],
  "service": "ordering-service",
  "subscription_plan": "PROFESSIONAL",
  "subscription_features": ["group_ordering", "route_optimization"],
  "subscription_limits": {"monthly_orders": 10000},
  "subscription_status": "ACTIVE"
}
```

**Security:**
- Keys generated with crypto/rand (32 bytes, base64 encoded)
- Only key_prefix stored in plaintext for identification
- Full key shown only once at creation
- Rate limiting: 100 validations/minute per key

---

### Immediate Actions
- Align with treasury on entitlement payloads and billing events.
- Define service integration playbook (redirect URIs, claims mapping) for all BengoBox teams.
- Finalize threat model, choose crypto/key management strategy (KMS/HSM).
- Kick off Sprint 0 after sign-off and environment provisioning.

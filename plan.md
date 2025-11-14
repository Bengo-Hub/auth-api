## Auth Service Delivery Plan

### Vision & Mandate
- Deliver a unified authentication, authorization, and identity orchestration platform for the entire BengoBox ecosystem (food delivery backend, POS, inventory, logistics, treasury, notifications, ERP, partner APIs) with a canonical `tenant_slug` propagated to all services.
- Provide standards-compliant OAuth2/OpenID Connect capabilities to power Single Sign-On (SSO) across web, mobile, kiosk, and service-to-service flows.
- Establish a secure foundation for multi-tenant, multi-brand operations with fine-grained policy enforcement, while delegating application-specific RBAC to downstream services.
- Ensure extensibility for future identity protocols (SAML, SCIM, FIDO2) and marketplace integrations.
- Act as the canonical source for tenant/outlet discovery: when a user authenticates, this service emits webhooks to downstream services (food-delivery, logistics, inventory, POS, treasury, notifications) so they can sync tenant/outlet metadata before handling domain-specific data.

### Scope & Responsibilities
1. **SSO & OAuth2/OIDC Provider**
   - Authorization Code + PKCE, Device Code, Client Credentials, Refresh Token flows.
   - JWT/opaque token issuance (access, ID, refresh) with asymmetric signing (JWKS) and token introspection.
   - Discovery endpoints (`/.well-known/openid-configuration`, `/.well-known/jwks.json`).
2. **Identity & Account Management**
   - Local accounts (email/password with bcrypt/argon2), passwordless login (magic links), invite/onboarding flows.
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

### Backlog & Future Enhancements
- FIDO2/WebAuthn, push-based MFA.
- SCIM provisioning for tenant admins (create users, sync groups).
- Enterprise federation (SAML 2.0, Azure AD B2B).
- Behavioral analytics, UEBA (User and Entity Behavior Analytics).
- Privacy features (account anonymisation, GDPR data export portals).

### Immediate Actions
- Align with treasury on entitlement payloads and billing events.
- Define service integration playbook (redirect URIs, claims mapping) for all BengoBox teams.
- Finalize threat model, choose crypto/key management strategy (KMS/HSM).
- Kick off Sprint 0 after sign-off and environment provisioning.

# Auth Service – Entity Relationship Overview

The auth service acts as the central identity provider (OIDC/OAuth2) for all BengoBox properties.  
Schema definitions are managed with Ent, and all tables are multi-tenant and auditable.

> **Conventions**
> - UUID primary keys unless noted.
> - `tenant_id` ensures organisational isolation (single-tenant clients still populate this).
> - Timestamps use `TIMESTAMPTZ`.
> - Secrets are stored hashed or encrypted (never in plaintext).

---

## Core Identity

| Table | Key Columns | Purpose / Notes |
|-------|-------------|-----------------|
| `tenants` | `id`, `slug`, `name`, `status`, `created_at`, `updated_at` | Organisations subscribed to BengoBox services. `slug` is the canonical identifier shared across all Go microservices. |
| `tenant_domains` | `id`, `tenant_id`, `domain`, `cookie_mode`, `is_primary`, `created_at`, `updated_at` | Allowed login domains / cookie scopes for SSO. |
| `users` | `id`, `tenant_id`, `email`, `phone`, `password_hash`, `status`, `metadata`, `last_login_at`, `created_at`, `updated_at` | Canonical user record. `email` unique per tenant. |
| `user_profiles` | `user_id (PK)`, `display_name`, `avatar_url`, `locale`, `timezone`, `attributes_json`, `updated_at` | Lightweight profile extensions exposed via `/userinfo`. |
| `user_devices` | `id`, `user_id`, `tenant_id`, `device_fingerprint`, `user_agent`, `ip_address`, `first_seen_at`, `last_seen_at`, `platform`, `status` | Device trust state; used for session policing and MFA prompts. |
| `user_external_identities` | `id`, `user_id`, `provider`, `provider_subject`, `provider_email`, `access_token_hash`, `refresh_token_hash`, `scope`, `linked_at`, `metadata` | Social/enterprise identity link table. |
| `user_tenants` | `(user_id, tenant_id) PK`, `role`, `status`, `invited_by`, `invited_at`, `accepted_at` | Tenant membership with default global role (service-specific RBAC is owned downstream). |

## Session & Token Management

| Table | Key Columns | Purpose / Notes |
|-------|-------------|-----------------|
| `session_tokens` | `id`, `tenant_id`, `user_id`, `session_type`, `status`, `refresh_token_hash`, `client_id`, `issued_at`, `expires_at`, `revoked_at`, `revocation_reason`, `ip_address`, `user_agent`, `device_id` | Long-lived refresh sessions and device bindings. |
| `access_tokens` | `id`, `session_id`, `jti`, `client_id`, `scope`, `audience`, `issued_at`, `expires_at`, `revoked_at` | Optional reference storage for opaque or JWT-hash tracking (enables introspection & revocation). |
| `token_revocations` | `id`, `token_type`, `jti`, `session_id`, `reason`, `recorded_at` | Revocation list used for short-lived token invalidation. |
| `authorization_codes` | `id`, `client_id`, `tenant_id`, `user_id`, `redirect_uri`, `code_challenge`, `expires_at`, `consumed_at`, `scope` | PKCE authorisation codes for OIDC flows. |
| `device_codes` | `id`, `client_id`, `user_code`, `device_code_hash`, `verification_uri`, `expires_at`, `status`, `interval_seconds`, `tenant_id` | Device authorization grant flow (kiosk/TV). |
| `consent_sessions` | `id`, `tenant_id`, `user_id`, `client_id`, `granted_scopes`, `granted_claims`, `expires_at`, `last_used_at`, `metadata` | Records user consent decisions for third-party clients. |

## OAuth2 / OIDC Client Registry

| Table | Key Columns | Purpose / Notes |
|-------|-------------|-----------------|
| `oauth_clients` | `id`, `tenant_id`, `client_id`, `client_secret_hash`, `name`, `application_type`, `token_endpoint_auth_method`, `default_scopes`, `logo_url`, `is_active`, `created_at`, `updated_at` | Registered applications (web, SPA, native, service). |
| `oauth_client_redirect_uris` | `id`, `client_id`, `redirect_uri`, `description`, `is_primary` | Approved redirect URIs. |
| `oauth_client_post_logout_redirect_uris` | `id`, `client_id`, `post_logout_redirect_uri`, `description` | Logout callback endpoints. |
| `oauth_client_grants` | `id`, `client_id`, `grant_type`, `is_enabled`, `created_at` | Allowed grant types per client. |
| `oauth_client_scopes` | `id`, `client_id`, `scope`, `description`, `is_default` | Fine-grained scope catalogue for each client. |

## Multi-Factor Authentication

| Table | Key Columns | Purpose / Notes |
|-------|-------------|-----------------|
| `mfa_settings` | `user_id (PK)`, `tenant_id`, `primary_method`, `enforced_at`, `enforced_by`, `recovery_channel`, `created_at`, `updated_at` | MFA policy at the user level. |
| `mfa_totp_secrets` | `user_id (PK)`, `secret`, `algorithm`, `digits`, `period`, `enabled_at`, `last_used_at` | TOTP configuration (secret stored encrypted). |
| `mfa_backup_codes` | `id`, `user_id`, `code_hash`, `used_at`, `created_at` | Single-use recovery codes. |
| `mfa_webauthn_credentials` | `id`, `user_id`, `credential_id`, `public_key`, `sign_count`, `nick_name`, `registered_at`, `last_used_at`, `is_active` | WebAuthn (U2F/FIDO2) credentials roadmap. |

## Policy & Governance

| Table | Key Columns | Purpose / Notes |
|-------|-------------|-----------------|
| `tenant_policies` | `tenant_id (PK)`, `password_policy_json`, `session_policy_json`, `mfa_policy_json`, `allowed_providers`, `created_at`, `updated_at` | Configurable security policies enforced during auth flows. |
| `feature_entitlements` | `id`, `tenant_id`, `feature_code`, `limit_json`, `plan_source`, `synced_at` | Entitlement snapshot received from `treasury-app`. |
| `usage_metrics` | `id`, `tenant_id`, `metric_date`, `active_users`, `auth_transactions`, `mfa_prompts`, `machine_tokens`, `created_at` | Aggregated usage for billing and capacity planning. |

## Audit & Security Events

| Table | Key Columns | Purpose / Notes |
|-------|-------------|-----------------|
| `audit_logs` | `id`, `tenant_id`, `user_id`, `action`, `resource_type`, `resource_id`, `ip_address`, `user_agent`, `context_json`, `occurred_at` | Immutable audit trail (login success/failure, admin actions). |
| `security_events` | `id`, `tenant_id`, `user_id`, `event_type`, `risk_score`, `detected_at`, `resolved_at`, `metadata` | Suspicious activity, anomaly detection, account lockouts. |
| `admin_activity` | `id`, `admin_user_id`, `tenant_id`, `action`, `target_type`, `target_id`, `payload`, `created_at` | Admin console activity log with auditing requirements. |
| `key_rotation_events` | `id`, `key_id`, `previous_kid`, `rotation_type`, `rotated_at`, `rotated_by`, `notes` | JWKS/private-key lifecycle history (backed by HSM/KMS). |

## Webhooks & Integrations

| Table | Key Columns | Purpose / Notes |
|-------|-------------|-----------------|
| `integration_webhooks` | `id`, `tenant_id`, `event_key`, `target_url`, `secret`, `status`, `last_invoked_at`, `retry_count`, `metadata` | Outbound webhooks for downstream services (account created, tenant/outlet synced, password reset). |
| `integration_subscriptions` | `id`, `tenant_id`, `service_code`, `config_json`, `created_at`, `updated_at` | Configuration for consuming events from other services (e.g., user provisioning from ERP). |

## Relationships & Notes

- `users` have many `session_tokens`, `user_devices`, and `user_external_identities`.
- `session_tokens` link to `access_tokens` and `token_revocations` for revocation workflows.
- Clients (`oauth_clients`) own redirect URIs, grant permissions, scopes, and can request consent from users.
- Tenant policies and entitlements originate from `treasury-app`; changes trigger webhook notifications to dependent services.
- **Entity Ownership**: This service owns all identity entities (users, tenants, outlets, sessions, OAuth clients, MFA). Downstream services (cafe-backend, POS, inventory, logistics, treasury, notifications) validate JWTs via JWKS and map `tenant_id`, `tenant_slug`, `user_id`, and global `roles` claims onto their local RBAC models. **Services never duplicate user or tenant tables**—they only store `user_id` and `tenant_id` references. Service-specific RBAC (POS cashier, logistics dispatcher) is owned by each service but references `user_id` from auth-service.
- Tenant/outlet discovery webhooks (`auth.tenant.synced`, `auth.outlet.synced`) ensure downstream services hydrate metadata before persisting domain data.
- MFA challenges use notifications service for SMS/email delivery; push or app-based challenges integrate later.
- See `docs/cross-service-entity-ownership.md` for complete entity ownership matrix.

## Seed Data & Defaults

- System scopes: `profile`, `email`, `offline_access`, `pos.read`, `orders.manage`, etc.
- Default admin client registered for internal dashboards with confidential grant.
- Example tenants seeded for Urban Café to enable cross-service integration testing.

---

This ERD should be kept in sync with Ent schema changes. Run `go generate ./internal/ent` after each schema update and regenerate this document when new entities or relationships are introduced.


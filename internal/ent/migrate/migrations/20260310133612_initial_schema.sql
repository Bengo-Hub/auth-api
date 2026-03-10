-- Create "oauth_clients" table
CREATE TABLE "oauth_clients" ("id" uuid NOT NULL, "client_id" character varying NOT NULL, "client_secret" character varying NULL, "name" character varying NOT NULL, "redirect_uris" jsonb NULL, "allowed_scopes" jsonb NULL, "public" boolean NOT NULL DEFAULT false, "tenant_id" character varying NULL, "created_by" uuid NULL, "metadata" jsonb NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create index "oauth_clients_client_id_key" to table: "oauth_clients"
CREATE UNIQUE INDEX "oauth_clients_client_id_key" ON "oauth_clients" ("client_id");
-- Create "outbox_events" table
CREATE TABLE "outbox_events" ("id" uuid NOT NULL, "tenant_id" uuid NOT NULL, "aggregate_type" character varying NOT NULL, "aggregate_id" uuid NOT NULL, "event_type" character varying NOT NULL, "payload" jsonb NOT NULL, "status" character varying NOT NULL DEFAULT 'PENDING', "attempts" bigint NOT NULL DEFAULT 0, "last_attempt_at" timestamptz NULL, "published_at" timestamptz NULL, "error_message" character varying NULL, "created_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create index "outboxevent_aggregate_type_aggregate_id" to table: "outbox_events"
CREATE INDEX "outboxevent_aggregate_type_aggregate_id" ON "outbox_events" ("aggregate_type", "aggregate_id");
-- Create index "outboxevent_created_at" to table: "outbox_events"
CREATE INDEX "outboxevent_created_at" ON "outbox_events" ("created_at");
-- Create index "outboxevent_event_type" to table: "outbox_events"
CREATE INDEX "outboxevent_event_type" ON "outbox_events" ("event_type");
-- Create index "outboxevent_status" to table: "outbox_events"
CREATE INDEX "outboxevent_status" ON "outbox_events" ("status");
-- Create index "outboxevent_tenant_id" to table: "outbox_events"
CREATE INDEX "outboxevent_tenant_id" ON "outbox_events" ("tenant_id");
-- Create "users" table
CREATE TABLE "users" ("id" uuid NOT NULL, "email" character varying NOT NULL, "password_hash" character varying NULL, "status" character varying NOT NULL DEFAULT 'active', "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "primary_tenant_id" character varying NULL, "profile" jsonb NULL, "last_login_at" timestamptz NULL, PRIMARY KEY ("id"));
-- Create index "users_email_key" to table: "users"
CREATE UNIQUE INDEX "users_email_key" ON "users" ("email");
-- Create "consent_sessions" table
CREATE TABLE "consent_sessions" ("id" uuid NOT NULL, "user_id" uuid NOT NULL, "client_id" character varying NOT NULL, "granted_scopes" character varying NOT NULL DEFAULT '', "granted_claims" jsonb NULL, "expires_at" timestamptz NULL, "last_used_at" timestamptz NULL, "metadata" jsonb NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create "feature_entitlements" table
CREATE TABLE "feature_entitlements" ("id" uuid NOT NULL, "tenant_id" uuid NOT NULL, "feature_code" character varying NOT NULL, "limit_json" jsonb NULL, "plan_source" character varying NOT NULL DEFAULT '', "synced_at" timestamptz NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create "integration_configs" table
CREATE TABLE "integration_configs" ("id" uuid NOT NULL, "tenant_id" uuid NULL, "name" character varying NOT NULL, "display_name" character varying NOT NULL, "description" character varying NULL, "base_url" character varying NULL, "encrypted_credentials" text NOT NULL, "endpoints_json" jsonb NULL, "is_active" boolean NOT NULL DEFAULT true, "status" character varying NOT NULL DEFAULT 'active', "environment" character varying NOT NULL DEFAULT 'production', "key_id" character varying NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create index "integrationconfig_is_active" to table: "integration_configs"
CREATE INDEX "integrationconfig_is_active" ON "integration_configs" ("is_active");
-- Create index "integrationconfig_name" to table: "integration_configs"
CREATE INDEX "integrationconfig_name" ON "integration_configs" ("name");
-- Create index "integrationconfig_tenant_id_name" to table: "integration_configs"
CREATE UNIQUE INDEX "integrationconfig_tenant_id_name" ON "integration_configs" ("tenant_id", "name");
-- Create "login_attempts" table
CREATE TABLE "login_attempts" ("id" uuid NOT NULL, "tenant_id" uuid NULL, "user_id" uuid NULL, "email" character varying NOT NULL DEFAULT '', "ip_address" character varying NULL, "user_agent" character varying NULL, "success" boolean NOT NULL DEFAULT false, "failure_reason" character varying NULL, "occurred_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create "usage_metrics" table
CREATE TABLE "usage_metrics" ("id" uuid NOT NULL, "tenant_id" uuid NOT NULL, "metric_date" timestamptz NOT NULL, "active_users" bigint NOT NULL DEFAULT 0, "auth_transactions" bigint NOT NULL DEFAULT 0, "mfa_prompts" bigint NOT NULL DEFAULT 0, "machine_tokens" bigint NOT NULL DEFAULT 0, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create "mfa_settings" table
CREATE TABLE "mfa_settings" ("id" bigint NOT NULL GENERATED BY DEFAULT AS IDENTITY, "user_id" uuid NOT NULL, "primary_method" character varying NOT NULL DEFAULT '', "enforced_at" timestamptz NULL, "recovery_channel" character varying NOT NULL DEFAULT '', "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create index "mfa_settings_user_id_key" to table: "mfa_settings"
CREATE UNIQUE INDEX "mfa_settings_user_id_key" ON "mfa_settings" ("user_id");
-- Create "api_keys" table
CREATE TABLE "api_keys" ("id" uuid NOT NULL, "name" character varying NOT NULL, "key_hash" character varying NOT NULL, "key_prefix" character varying NOT NULL, "tenant_id" uuid NOT NULL, "service" character varying NULL, "created_by" uuid NULL, "scopes" jsonb NULL, "allowed_ips" jsonb NULL, "status" character varying NOT NULL DEFAULT 'active', "expires_at" timestamptz NULL, "last_used_at" timestamptz NULL, "last_used_ip" character varying NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "revoked_at" timestamptz NULL, "revoked_reason" character varying NULL, PRIMARY KEY ("id"));
-- Create index "apikey_key_hash" to table: "api_keys"
CREATE UNIQUE INDEX "apikey_key_hash" ON "api_keys" ("key_hash");
-- Create index "apikey_service_status" to table: "api_keys"
CREATE INDEX "apikey_service_status" ON "api_keys" ("service", "status");
-- Create index "apikey_status_expires_at" to table: "api_keys"
CREATE INDEX "apikey_status_expires_at" ON "api_keys" ("status", "expires_at");
-- Create index "apikey_tenant_id_status" to table: "api_keys"
CREATE INDEX "apikey_tenant_id_status" ON "api_keys" ("tenant_id", "status");
-- Create "audit_logs" table
CREATE TABLE "audit_logs" ("id" uuid NOT NULL, "tenant_id" uuid NULL, "user_id" uuid NULL, "action" character varying NOT NULL, "resource_type" character varying NULL, "resource_id" character varying NULL, "ip_address" character varying NULL, "user_agent" character varying NULL, "context" jsonb NULL, "occurred_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create "authorization_codes" table
CREATE TABLE "authorization_codes" ("id" uuid NOT NULL, "client_id" character varying NOT NULL, "redirect_uri" character varying NOT NULL, "scope" character varying NOT NULL DEFAULT '', "code_hash" character varying NOT NULL, "code_challenge" character varying NOT NULL DEFAULT '', "code_challenge_method" character varying NOT NULL DEFAULT '', "nonce" character varying NOT NULL DEFAULT '', "expires_at" timestamptz NOT NULL, "consumed_at" timestamptz NULL, "metadata" jsonb NULL, "created_at" timestamptz NOT NULL, "user_id" uuid NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "authorization_codes_users_authorization_codes" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create "mfa_backup_codes" table
CREATE TABLE "mfa_backup_codes" ("id" uuid NOT NULL, "code_hash" character varying NOT NULL, "used_at" timestamptz NULL, "created_at" timestamptz NOT NULL, "user_id" uuid NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "mfa_backup_codes_users_mfa_backup_codes" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create "mfatotp_secrets" table
CREATE TABLE "mfatotp_secrets" ("id" uuid NOT NULL, "secret" character varying NOT NULL, "digits" bigint NOT NULL DEFAULT 6, "period" bigint NOT NULL DEFAULT 30, "enabled_at" timestamptz NULL, "last_used_at" timestamptz NULL, "created_at" timestamptz NOT NULL, "user_id" uuid NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "mfatotp_secrets_users_mfa_totp" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create "password_reset_tokens" table
CREATE TABLE "password_reset_tokens" ("id" uuid NOT NULL, "token_hash" character varying NOT NULL, "expires_at" timestamptz NOT NULL, "used_at" timestamptz NULL, "created_at" timestamptz NOT NULL, "user_id" uuid NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "password_reset_tokens_users_password_reset_tokens" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create "permissions" table
CREATE TABLE "permissions" ("id" bigint NOT NULL GENERATED BY DEFAULT AS IDENTITY, "code" character varying NOT NULL, "resource" character varying NOT NULL, "action" character varying NOT NULL, PRIMARY KEY ("id"));
-- Create index "permission_resource_action" to table: "permissions"
CREATE UNIQUE INDEX "permission_resource_action" ON "permissions" ("resource", "action");
-- Create index "permissions_code_key" to table: "permissions"
CREATE UNIQUE INDEX "permissions_code_key" ON "permissions" ("code");
-- Create "role_permissions" table
CREATE TABLE "role_permissions" ("id" bigint NOT NULL GENERATED BY DEFAULT AS IDENTITY, "role_name" character varying NOT NULL, "permission_id" bigint NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "role_permissions_permissions_permission" FOREIGN KEY ("permission_id") REFERENCES "permissions" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "rolepermission_role_name" to table: "role_permissions"
CREATE INDEX "rolepermission_role_name" ON "role_permissions" ("role_name");
-- Create index "rolepermission_role_name_permission_id" to table: "role_permissions"
CREATE UNIQUE INDEX "rolepermission_role_name_permission_id" ON "role_permissions" ("role_name", "permission_id");
-- Create "sessions" table
CREATE TABLE "sessions" ("id" uuid NOT NULL, "tenant_id" uuid NULL, "client_id" character varying NULL, "session_type" character varying NOT NULL DEFAULT 'user', "status" character varying NOT NULL DEFAULT 'active', "refresh_token_hash" character varying NOT NULL, "issued_at" timestamptz NOT NULL, "expires_at" timestamptz NOT NULL, "revoked_at" timestamptz NULL, "revocation_reason" character varying NULL, "ip_address" character varying NULL, "user_agent" character varying NULL, "metadata" jsonb NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "user_id" uuid NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "sessions_users_sessions" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create "tenants" table
CREATE TABLE "tenants" ("id" uuid NOT NULL, "name" character varying NOT NULL, "slug" character varying NOT NULL, "status" character varying NOT NULL DEFAULT 'active', "contact_email" character varying NULL, "contact_phone" character varying NULL, "logo_url" character varying NULL, "website" character varying NULL, "country" character varying NULL DEFAULT 'KE', "timezone" character varying NULL DEFAULT 'Africa/Nairobi', "brand_colors" jsonb NULL, "org_size" character varying NULL, "use_case" character varying NULL, "subscription_plan" character varying NULL, "subscription_status" character varying NULL, "subscription_expires_at" timestamptz NULL, "subscription_id" character varying NULL, "tier_limits" jsonb NULL, "metadata" jsonb NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create index "tenant_slug" to table: "tenants"
CREATE UNIQUE INDEX "tenant_slug" ON "tenants" ("slug");
-- Create index "tenant_status" to table: "tenants"
CREATE INDEX "tenant_status" ON "tenants" ("status");
-- Create index "tenant_subscription_plan" to table: "tenants"
CREATE INDEX "tenant_subscription_plan" ON "tenants" ("subscription_plan");
-- Create index "tenants_slug_key" to table: "tenants"
CREATE UNIQUE INDEX "tenants_slug_key" ON "tenants" ("slug");
-- Create "tenant_memberships" table
CREATE TABLE "tenant_memberships" ("id" uuid NOT NULL, "roles" jsonb NULL, "status" character varying NOT NULL DEFAULT 'active', "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "tenant_id" uuid NOT NULL, "user_id" uuid NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "tenant_memberships_tenants_memberships" FOREIGN KEY ("tenant_id") REFERENCES "tenants" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION, CONSTRAINT "tenant_memberships_users_memberships" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "tenantmembership_user_id_tenant_id" to table: "tenant_memberships"
CREATE UNIQUE INDEX "tenantmembership_user_id_tenant_id" ON "tenant_memberships" ("user_id", "tenant_id");
-- Create "user_identities" table
CREATE TABLE "user_identities" ("id" uuid NOT NULL, "provider" character varying NOT NULL, "provider_subject" character varying NOT NULL, "provider_email" character varying NOT NULL, "email_verified" boolean NOT NULL DEFAULT false, "access_token" character varying NULL, "refresh_token" character varying NULL, "token_expiry" timestamptz NULL, "scope" character varying NULL, "profile" jsonb NULL, "linked_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "user_id" uuid NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "user_identities_users_identities" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "useridentity_provider_provider_email" to table: "user_identities"
CREATE INDEX "useridentity_provider_provider_email" ON "user_identities" ("provider", "provider_email");
-- Create index "useridentity_provider_provider_subject" to table: "user_identities"
CREATE UNIQUE INDEX "useridentity_provider_provider_subject" ON "user_identities" ("provider", "provider_subject");

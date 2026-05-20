-- Create "apps" table
CREATE TABLE "apps" ("id" uuid NOT NULL, "name" character varying NOT NULL, "description" character varying NULL, "app_type" character varying NOT NULL DEFAULT 'tenant', "tenant_id" uuid NULL, "created_by" uuid NULL, "client_id" character varying NOT NULL, "key_hash" character varying NOT NULL, "key_prefix" character varying NOT NULL, "scopes" jsonb NULL, "allowed_ips" jsonb NULL, "status" character varying NOT NULL DEFAULT 'active', "expires_at" timestamptz NULL, "last_used_at" timestamptz NULL, "last_used_ip" character varying NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "revoked_at" timestamptz NULL, "revoked_reason" character varying NULL, PRIMARY KEY ("id"));
-- Create index "app_app_type_status" to table: "apps"
CREATE INDEX "app_app_type_status" ON "apps" ("app_type", "status");
-- Create index "app_client_id" to table: "apps"
CREATE UNIQUE INDEX "app_client_id" ON "apps" ("client_id");
-- Create index "app_key_hash" to table: "apps"
CREATE UNIQUE INDEX "app_key_hash" ON "apps" ("key_hash");
-- Create index "app_status_expires_at" to table: "apps"
CREATE INDEX "app_status_expires_at" ON "apps" ("status", "expires_at");
-- Create index "app_tenant_id_status" to table: "apps"
CREATE INDEX "app_tenant_id_status" ON "apps" ("tenant_id", "status");
-- Create index "apps_client_id_key" to table: "apps"
CREATE UNIQUE INDEX "apps_client_id_key" ON "apps" ("client_id");

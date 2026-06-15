-- Create "roles" table
CREATE TABLE "roles" ("id" uuid NOT NULL, "role_code" character varying NOT NULL, "name" character varying NOT NULL, "description" character varying NULL, "is_system" boolean NOT NULL DEFAULT false, "scope" character varying NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create index "role_is_system" to table: "roles"
CREATE INDEX "role_is_system" ON "roles" ("is_system");
-- Create index "roles_role_code_key" to table: "roles"
CREATE UNIQUE INDEX "roles_role_code_key" ON "roles" ("role_code");
-- Create "password_policies" table
CREATE TABLE "password_policies" ("id" uuid NOT NULL, "tenant_id" uuid NULL, "min_length" bigint NOT NULL DEFAULT 8, "require_upper" boolean NOT NULL DEFAULT true, "require_lower" boolean NOT NULL DEFAULT true, "require_digit" boolean NOT NULL DEFAULT true, "require_symbol" boolean NOT NULL DEFAULT false, "expiry_days" bigint NOT NULL DEFAULT 0, "reuse_block_count" bigint NOT NULL DEFAULT 0, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create index "passwordpolicy_tenant_id" to table: "password_policies"
CREATE UNIQUE INDEX "passwordpolicy_tenant_id" ON "password_policies" ("tenant_id");

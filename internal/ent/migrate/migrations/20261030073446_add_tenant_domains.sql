-- Create "tenant_domains" table
CREATE TABLE "tenant_domains" ("id" uuid NOT NULL, "tenant_id" uuid NOT NULL, "service" character varying NOT NULL, "hostname" character varying NOT NULL, "status" character varying NOT NULL DEFAULT 'pending_dns', "dns_mode" character varying NOT NULL DEFAULT 'external', "cf_zone_id" character varying NULL, "cf_record_id" character varying NULL, "last_error" character varying NULL, "last_checked_at" timestamptz NULL, "activated_at" timestamptz NULL, "created_by" character varying NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create index "tenant_domains_hostname_key" to table: "tenant_domains"
CREATE UNIQUE INDEX "tenant_domains_hostname_key" ON "tenant_domains" ("hostname");
-- Create index "tenantdomain_status" to table: "tenant_domains"
CREATE INDEX "tenantdomain_status" ON "tenant_domains" ("status");
-- Create index "tenantdomain_tenant_id" to table: "tenant_domains"
CREATE INDEX "tenantdomain_tenant_id" ON "tenant_domains" ("tenant_id");

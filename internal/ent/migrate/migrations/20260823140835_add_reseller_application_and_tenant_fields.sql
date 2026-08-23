-- Modify "tenants" table
ALTER TABLE "tenants" ADD COLUMN "is_reseller" boolean NOT NULL DEFAULT false, ADD COLUMN "managed_by_reseller_tenant_id" uuid NULL;
-- Create index "tenant_managed_by_reseller_tenant_id" to table: "tenants"
CREATE INDEX "tenant_managed_by_reseller_tenant_id" ON "tenants" ("managed_by_reseller_tenant_id");
-- Create "reseller_applications" table
CREATE TABLE "reseller_applications" ("id" uuid NOT NULL, "tenant_id" uuid NULL, "business_name" character varying NOT NULL, "business_registration_no" character varying NULL, "tax_pin" character varying NULL, "contact_email" character varying NOT NULL, "contact_phone" character varying NULL, "country" character varying NULL DEFAULT 'KE', "requested_tier" character varying NOT NULL DEFAULT 'registered', "status" character varying NOT NULL DEFAULT 'pending', "kyb_reference" character varying NULL, "kyb_result" text NULL, "agreement_acceptance_id" uuid NULL, "notes" text NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create index "resellerapplication_status" to table: "reseller_applications"
CREATE INDEX "resellerapplication_status" ON "reseller_applications" ("status");
-- Create index "resellerapplication_tenant_id" to table: "reseller_applications"
CREATE INDEX "resellerapplication_tenant_id" ON "reseller_applications" ("tenant_id");
-- Create index "resellerapplication_tenant_id_status" to table: "reseller_applications"
CREATE INDEX "resellerapplication_tenant_id_status" ON "reseller_applications" ("tenant_id", "status");

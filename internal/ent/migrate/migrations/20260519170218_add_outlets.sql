-- Create "outlets" table
CREATE TABLE "outlets" ("id" uuid NOT NULL, "code" character varying NOT NULL, "name" character varying NOT NULL, "use_case" character varying NOT NULL DEFAULT 'hospitality', "address" character varying NULL, "timezone" character varying NULL DEFAULT 'Africa/Nairobi', "is_hq" boolean NOT NULL DEFAULT false, "status" character varying NOT NULL DEFAULT 'active', "pin_login_message" character varying NULL, "metadata" jsonb NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, "tenant_id" uuid NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "outlets_tenants_outlets" FOREIGN KEY ("tenant_id") REFERENCES "tenants" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "outlet_tenant_id_code" to table: "outlets"
CREATE UNIQUE INDEX "outlet_tenant_id_code" ON "outlets" ("tenant_id", "code");
-- Create index "outlet_tenant_id_is_hq" to table: "outlets"
CREATE INDEX "outlet_tenant_id_is_hq" ON "outlets" ("tenant_id", "is_hq");
-- Create index "outlet_tenant_id_status" to table: "outlets"
CREATE INDEX "outlet_tenant_id_status" ON "outlets" ("tenant_id", "status");

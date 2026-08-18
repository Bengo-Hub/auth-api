-- Create "integration_requests" table
CREATE TABLE "integration_requests" ("id" uuid NOT NULL, "request_type" character varying NOT NULL DEFAULT 'etims_integration', "tenant_id" uuid NULL, "requester_name" character varying NOT NULL, "requester_email" character varying NOT NULL, "requester_phone" character varying NULL, "company_name" character varying NULL, "kra_pin" character varying NULL, "integration_mode" character varying NOT NULL DEFAULT 'self_serve', "notes" text NULL, "source" character varying NOT NULL DEFAULT 'tenant_portal', "status" character varying NOT NULL DEFAULT 'pending', "admin_notes" text NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create index "integrationrequest_request_type" to table: "integration_requests"
CREATE INDEX "integrationrequest_request_type" ON "integration_requests" ("request_type");
-- Create index "integrationrequest_status" to table: "integration_requests"
CREATE INDEX "integrationrequest_status" ON "integration_requests" ("status");
-- Create index "integrationrequest_tenant_id" to table: "integration_requests"
CREATE INDEX "integrationrequest_tenant_id" ON "integration_requests" ("tenant_id");

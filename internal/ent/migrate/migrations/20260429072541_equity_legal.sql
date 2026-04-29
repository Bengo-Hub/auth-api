-- Create "equity_holder_applications" table
CREATE TABLE "equity_holder_applications" ("id" uuid NOT NULL, "tenant_id" uuid NOT NULL, "status" character varying NOT NULL DEFAULT 'pending', "kyc_reference" character varying NULL, "kyc_result" text NULL, "epa_acceptance_id" uuid NULL, "treasury_holder_id" uuid NULL, "notes" text NULL, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create index "equityholderapplication_status" to table: "equity_holder_applications"
CREATE INDEX "equityholderapplication_status" ON "equity_holder_applications" ("status");
-- Create index "equityholderapplication_tenant_id" to table: "equity_holder_applications"
CREATE INDEX "equityholderapplication_tenant_id" ON "equity_holder_applications" ("tenant_id");
-- Create index "equityholderapplication_tenant_id_status" to table: "equity_holder_applications"
CREATE INDEX "equityholderapplication_tenant_id_status" ON "equity_holder_applications" ("tenant_id", "status");
-- Create "legal_acceptances" table
CREATE TABLE "legal_acceptances" ("id" uuid NOT NULL, "entity_id" uuid NOT NULL, "entity_type" character varying NOT NULL, "doc_type" character varying NOT NULL, "doc_version" character varying NOT NULL, "accepted_at" timestamptz NOT NULL, "ip_address" character varying NULL, "user_agent" character varying NULL, "signature_image_url" character varying NULL, "created_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create index "legalacceptance_entity_id" to table: "legal_acceptances"
CREATE INDEX "legalacceptance_entity_id" ON "legal_acceptances" ("entity_id");
-- Create index "legalacceptance_entity_id_doc_type" to table: "legal_acceptances"
CREATE INDEX "legalacceptance_entity_id_doc_type" ON "legal_acceptances" ("entity_id", "doc_type");
-- Create "legal_documents" table
CREATE TABLE "legal_documents" ("id" uuid NOT NULL, "doc_type" character varying NOT NULL, "version" character varying NOT NULL, "html_content" text NOT NULL, "effective_date" timestamptz NOT NULL, "is_current" boolean NOT NULL DEFAULT false, "created_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create index "legaldocument_doc_type_is_current" to table: "legal_documents"
CREATE INDEX "legaldocument_doc_type_is_current" ON "legal_documents" ("doc_type", "is_current");
-- Create index "legaldocument_doc_type_version" to table: "legal_documents"
CREATE UNIQUE INDEX "legaldocument_doc_type_version" ON "legal_documents" ("doc_type", "version");
-- Create "referral_links" table
CREATE TABLE "referral_links" ("id" uuid NOT NULL, "referrer_tenant_id" uuid NOT NULL, "referral_code" character varying NOT NULL, "program_id" character varying NULL, "clicks" bigint NOT NULL DEFAULT 0, "expires_at" timestamptz NULL, "is_active" boolean NOT NULL DEFAULT true, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create index "referral_links_referral_code_key" to table: "referral_links"
CREATE UNIQUE INDEX "referral_links_referral_code_key" ON "referral_links" ("referral_code");
-- Create index "referrallink_is_active" to table: "referral_links"
CREATE INDEX "referrallink_is_active" ON "referral_links" ("is_active");
-- Create index "referrallink_referral_code" to table: "referral_links"
CREATE UNIQUE INDEX "referrallink_referral_code" ON "referral_links" ("referral_code");
-- Create index "referrallink_referrer_tenant_id" to table: "referral_links"
CREATE INDEX "referrallink_referrer_tenant_id" ON "referral_links" ("referrer_tenant_id");

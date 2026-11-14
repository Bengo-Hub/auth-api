-- Modify "legal_documents" table: editorial details of a version (title, change summary, material
-- flag, who edited and published it) for dashboard-managed legal documents (owner 2026-11-15).
-- The new doc_type values (TERMS_OF_SERVICE, PRIVACY_POLICY, COOKIE_POLICY, REFUND_POLICY,
-- DATA_REQUESTS) need no change here: doc_type is a character varying column.
ALTER TABLE "legal_documents" ADD COLUMN "metadata" jsonb NULL;

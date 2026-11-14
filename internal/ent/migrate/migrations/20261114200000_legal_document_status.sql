-- Modify "legal_documents" table: draft state for effective-dated legal documents (owner 2026-11-14).
-- Every existing row is a published version, so the default fills them in.
ALTER TABLE "legal_documents" ADD COLUMN "status" character varying NOT NULL DEFAULT 'published';
-- Create index "legaldocument_doc_type_status" to table: "legal_documents"
CREATE INDEX "legaldocument_doc_type_status" ON "legal_documents" ("doc_type", "status");

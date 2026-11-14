-- Modify "legal_acceptances" table: who accepted on the tenant's behalf (MarketFlow auto-publish terms, 2026-11-14).
-- doc_type is a varchar column, so the new MARKETFLOW_AUTOPUBLISH_TERMS enum value needs no DDL.
ALTER TABLE "legal_acceptances" ADD COLUMN "accepted_by_user_id" uuid NULL;

-- Modify "tenant_domains" table
ALTER TABLE "tenant_domains" ADD COLUMN "grace_until" timestamptz NULL;

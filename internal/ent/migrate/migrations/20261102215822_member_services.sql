-- Modify "tenant_memberships" table
ALTER TABLE "tenant_memberships" ADD COLUMN "services" jsonb NULL;

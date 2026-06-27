-- Modify "tenants" table
ALTER TABLE "tenants" ADD COLUMN "is_demo" boolean NOT NULL DEFAULT false;

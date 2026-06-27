-- Modify "tenants" table — backfill KRA/tax onboarding columns whose versioned
-- migration was previously missing from history (columns already live in prod).
-- Idempotent so replay over an environment that already has them is a no-op.
ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "tax_pin" character varying NULL;
ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "vat_registered" boolean NOT NULL DEFAULT false;
ALTER TABLE "tenants" ADD COLUMN IF NOT EXISTS "vat_registered_on" timestamptz NULL;

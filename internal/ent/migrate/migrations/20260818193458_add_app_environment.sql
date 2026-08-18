-- Modify "apps" table
ALTER TABLE "apps" ADD COLUMN "environment" character varying NOT NULL DEFAULT 'sandbox';

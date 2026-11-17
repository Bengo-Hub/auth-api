-- Modify "apps" table
ALTER TABLE "apps" ADD COLUMN "client_secret_hash" character varying NULL, ADD COLUMN "client_secret_rotated_at" timestamptz NULL;

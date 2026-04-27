-- Modify "users" table
ALTER TABLE "users" ADD COLUMN "terms_accepted" boolean NOT NULL DEFAULT false, ADD COLUMN "terms_accepted_at" timestamptz NULL;

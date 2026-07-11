-- Modify "users" table
ALTER TABLE "users" ADD COLUMN "email_verification_required_at" timestamptz NULL;

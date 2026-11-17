-- Modify "apps" table: general per-app metadata. It holds the rotation grace entries
-- (previous_client_secret, previous_key) so a rotated credential keeps working until its grace
-- period ends (Stripe-style rotation).
ALTER TABLE "apps" ADD COLUMN "metadata" jsonb NULL;
-- Create index "app_metadata" to table: "apps"; serves the metadata @> '{"previous_key":{"hash":...}}'
-- fallback lookup of an API key replaced by a rotation.
CREATE INDEX "app_metadata" ON "apps" USING GIN ("metadata" jsonb_path_ops);

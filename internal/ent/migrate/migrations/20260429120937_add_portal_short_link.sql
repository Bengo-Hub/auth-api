-- Create "portal_short_links" table
CREATE TABLE "portal_short_links" ("id" uuid NOT NULL, "code" character varying NOT NULL, "holder_id" uuid NOT NULL, "jwt_token" text NOT NULL, "expires_at" timestamptz NOT NULL, "clicks" bigint NOT NULL DEFAULT 0, "created_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create index "portal_short_links_code_key" to table: "portal_short_links"
CREATE UNIQUE INDEX "portal_short_links_code_key" ON "portal_short_links" ("code");
-- Create index "portalshortlink_code" to table: "portal_short_links"
CREATE UNIQUE INDEX "portalshortlink_code" ON "portal_short_links" ("code");
-- Create index "portalshortlink_expires_at" to table: "portal_short_links"
CREATE INDEX "portalshortlink_expires_at" ON "portal_short_links" ("expires_at");
-- Create index "portalshortlink_holder_id" to table: "portal_short_links"
CREATE INDEX "portalshortlink_holder_id" ON "portal_short_links" ("holder_id");

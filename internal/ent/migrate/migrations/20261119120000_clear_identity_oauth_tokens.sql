-- Clear the provider access and refresh tokens that social sign-in kept on "user_identities"
-- (2026-11-19). Nothing reads them, sign-in no longer writes them, and the privacy policy says
-- they are not stored. auth-api migrates with Schema.Create, which does not run this file, so
-- database.ClearIdentityOAuthTokens runs the same change after every migrate. Idempotent.
UPDATE "user_identities" SET "access_token" = NULL, "refresh_token" = NULL WHERE "access_token" IS NOT NULL OR "refresh_token" IS NOT NULL;

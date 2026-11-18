-- Create index "mfatotpsecret_user_id" to table: "mfatotp_secrets"
CREATE UNIQUE INDEX "mfatotpsecret_user_id" ON "mfatotp_secrets" ("user_id");

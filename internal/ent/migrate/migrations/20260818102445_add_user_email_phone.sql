-- Create "user_emails" table
CREATE TABLE "user_emails" ("id" uuid NOT NULL, "email" character varying NOT NULL, "is_verified" boolean NOT NULL DEFAULT false, "verified_at" timestamptz NULL, "is_primary" boolean NOT NULL DEFAULT false, "created_at" timestamptz NOT NULL, "user_id" uuid NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "user_emails_users_emails" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "useremail_email" to table: "user_emails"
CREATE UNIQUE INDEX "useremail_email" ON "user_emails" ("email");
-- Create index "useremail_user_id" to table: "user_emails"
CREATE INDEX "useremail_user_id" ON "user_emails" ("user_id");
-- Create "user_phones" table
CREATE TABLE "user_phones" ("id" uuid NOT NULL, "phone" character varying NOT NULL, "is_verified" boolean NOT NULL DEFAULT false, "verified_at" timestamptz NULL, "is_primary" boolean NOT NULL DEFAULT false, "created_at" timestamptz NOT NULL, "user_id" uuid NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "user_phones_users_phones" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION);
-- Create index "userphone_phone" to table: "user_phones"
CREATE UNIQUE INDEX "userphone_phone" ON "user_phones" ("phone");
-- Create index "userphone_user_id" to table: "user_phones"
CREATE INDEX "userphone_user_id" ON "user_phones" ("user_id");

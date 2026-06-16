-- Create "platform_backup_settings" table
CREATE TABLE "platform_backup_settings" ("id" uuid NOT NULL, "singleton" character varying NOT NULL, "auto_enabled" boolean NOT NULL DEFAULT false, "schedule_hour" bigint NOT NULL DEFAULT 2, "retention_days" bigint NOT NULL DEFAULT 4, "created_at" timestamptz NOT NULL, "updated_at" timestamptz NOT NULL, PRIMARY KEY ("id"));
-- Create index "platform_backup_settings_singleton_key" to table: "platform_backup_settings"
CREATE UNIQUE INDEX "platform_backup_settings_singleton_key" ON "platform_backup_settings" ("singleton");

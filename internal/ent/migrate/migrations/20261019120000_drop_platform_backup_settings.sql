-- The in-process platform backup was removed (its pg_dumpall scheduler never ran); the
-- infra/postgresql-backup CronJob is the platform's disaster-recovery backup.
DROP TABLE IF EXISTS "platform_backup_settings";

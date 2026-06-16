-- Companion to subscriptions-api/scripts/rename_complete_to_powersuite.sql.
--
-- Run against the AUTH-service database.
--
-- The auth `tenants` table denormalizes the tenant's plan code in
-- subscription_plan (written by auth-api Register() / subscription sync). After
-- the subscription-service rename of the "Complete" bundle to "PowerSuite", flip
-- any tenant still pointing at a COMPLETE_* code. Idempotent; safe to re-run.

BEGIN;

UPDATE tenants
SET subscription_plan = replace(subscription_plan, 'COMPLETE_', 'POWERSUITE_'),
    updated_at = now()
WHERE subscription_plan LIKE 'COMPLETE\_%';

COMMIT;

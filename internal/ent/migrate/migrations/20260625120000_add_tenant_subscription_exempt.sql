-- Add platform-granted subscription exemption flag to tenants (source of truth; stamped into JWT as sub_exempt)
ALTER TABLE "tenants" ADD COLUMN "subscription_exempt" boolean NOT NULL DEFAULT false;

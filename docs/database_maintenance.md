# Database maintenance

The production database runbook for this service (reset, ownership fixes, connection checks) names
cluster namespaces, the database admin role and pod names, so it lives in the private operations
docs: `codevertex-private-docs`
`shared-docs-internal/operations/service-runbooks/auth-api-database-maintenance.md`, next to the
platform-wide `shared-docs-internal/operations/database-maintenance.md`.

For local development, run PostgreSQL yourself and point `POSTGRES_URL` at it; migrations run on
startup.

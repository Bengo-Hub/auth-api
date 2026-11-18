# Auth Service: production setup and troubleshooting

The production runbook (cluster namespaces, database inspection commands, seeding and the admin
account) is kept in the private operations docs, `codevertex-private-docs`
`shared-docs-internal/operations/service-runbooks/auth-api-production-setup.md`. This page keeps
only what is safe in a public repository.

## Service

- URL: https://sso.codevertexafrica.com
- Health: `GET /healthz` returns `{"status":"ok","time":"..."}`
- Swagger UI: `/v1/docs/`
- OpenAPI spec: `/api/v1/openapi.json`
- TLS: Let's Encrypt certificate, HTTPS enforced at the ingress

## API endpoints

### Health and monitoring

| Method | Path | Description |
|--------|------|-------------|
| GET | `/healthz` | Health check |
| GET | `/metrics` | Prometheus metrics |
| GET | `/v1/docs/` | Swagger UI |
| GET | `/api/v1/openapi.json` | OpenAPI spec |

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/auth/register` | User registration |
| POST | `/api/v1/auth/login` | Email and password login |
| POST | `/api/v1/auth/refresh` | Refresh token |
| POST | `/api/v1/auth/password-reset/request` | Request a password reset |
| GET | `/api/v1/auth/me` | Authenticated user |
| POST | `/api/v1/auth/logout` | Logout |

## Login request shape

```bash
curl -X POST "https://sso.codevertexafrica.com/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email": "<email>", "password": "<password>", "tenant_slug": "<tenant-slug>"}'
```

A 401 with "tenant not found" usually means a wrong `tenant_slug`.

## Migrations and seeding

- Migrations run on startup (`Database.RunMigrations`, on by default) with Ent schema migrations.
- `cmd/seed` creates the default tenant and admin user; it reads the admin password from
  `SEED_ADMIN_PASSWORD` and never has a default in production.

## Health checks in Kubernetes

Readiness, liveness and startup probes all call `/healthz` on the `http` port (see the chart values
in devops-k8s `apps/auth-api/values.yaml`).

## Security notes

1. JWT signing keys are RSA keys mounted from a SealedSecret, never from this repo.
2. HTTPS is enforced through the ingress SSL redirect.
3. Login and token endpoints are rate limited.

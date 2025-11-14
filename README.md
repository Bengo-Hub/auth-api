# Auth Service (SSO Platform)

The Auth Service provides centralised authentication, authorisation, and session management for the BengoBox ecosystem.  
It exposes standards-compliant OAuth2/OpenID Connect flows to web, mobile, POS, logistics, inventory, treasury, and other platform services.

## Key Features

- Multi-tenant identity store with organisation-aware policies.
- OAuth2/OIDC provider (Authorization Code + PKCE, Device Code, Client Credentials, Refresh Token).
- Social sign-in (Google, Microsoft, Apple, GitHub) with account linking.
- MFA (TOTP, WebAuthn roadmap), adaptive risk-based challenges, device trust.
- Session management, logout propagation, token revocation, JWKS discovery.
- Client registry APIs and admin console for scopes, secrets, and tenant security policies.
- Usage metering and entitlement checks integrated with the treasury service.

## Tech Stack

- Go 1.22+, Ent ORM, PostgreSQL, Redis.
- HTTP transport via `chi`, OAuth/OIDC libraries (`go-oidc`, `golang.org/x/oauth2`).
- OpenAPI/Swagger docs, ConnectRPC (optional) for internal services.
- Observability: zap logging, Prometheus metrics, OpenTelemetry traces.

## Local Development

```shell
# install dependencies & generate Ent code
go generate ./internal/ent

# (optional) spin up infra
docker compose up -d postgres redis

# run the API
AUTH_ENV=development AUTH_DB_URL=postgres://postgres:postgres@localhost:5432/auth%20service?sslmode=disable \
AUTH_TOKEN_PRIVATE_KEY_PATH=./config/keys/dev_jwt_private.pem \
AUTH_TOKEN_PUBLIC_KEY_PATH=./config/keys/dev_jwt_public.pem \
go run ./cmd/server
```

Endpoints default to `http://localhost:4101`. Adjust via `AUTH_HTTP_PORT`. In production, the canonical issuer and domain are:

- Issuer: `https://auth.codevertexitsolutions.com`
- OIDC discovery: `https://auth.codevertexitsolutions.com/api/v1/.well-known/openid-configuration`
- Authorization: `https://auth.codevertexitsolutions.com/api/v1/authorize`
- Token: `https://auth.codevertexitsolutions.com/api/v1/token`
- JWKS: `https://auth.codevertexitsolutions.com/api/v1/.well-known/jwks.json`
- UserInfo: `https://auth.codevertexitsolutions.com/api/v1/userinfo`

### Configuration & Secrets

- Copy `config/example.env` and adjust values or export them with your preferred secret manager.
- Generate RSA keys for JWT signing (4096-bit recommended):
  ```shell
  openssl genrsa -out config/keys/dev_jwt_private.pem 4096
  openssl rsa -in config/keys/dev_jwt_private.pem -pubout -out config/keys/dev_jwt_public.pem
  ```
- Provide Postgres + Redis connection strings via `AUTH_DB_URL` and `AUTH_REDIS_ADDR`. Redis powers rate-limits/blacklists (future sprint) but is already initialised for health checks.
- To enable Google OAuth, set `AUTH_PROVIDERS_GOOGLE_ENABLED=true` together with `CLIENT_ID`, `CLIENT_SECRET`, and `REDIRECT_URL` (normally `https://auth.bengobox.com/api/v1/auth/oauth/google/callback`).  
  Use `AUTH_SECURITY_OAUTH_STATE_SECRET` (32+ random bytes) to sign OAuth state tokens and optionally restrict tenants by domain via `AUTH_PROVIDERS_GOOGLE_ALLOWED_DOMAINS=example.com,contoso.com`.

### Documentation

- Developer API guide: [docs/developer-api.md](docs/developer-api.md)
- Local testing with Docker (Redis): [docs/local-testing.md](docs/local-testing.md)
- Interactive Swagger UI: `GET /api/v1/docs` (loads `openapi.json`)
  - Default admin for quick testing:
    - Email: `admin@codevertexitsolutions.com`
    - Password: `ChangeMe123!`
    - Tenant: `bengobox`

### HTTP Surface (Sprint 4)

| Method | Path                              | Description                     |
|--------|-----------------------------------|---------------------------------|
| POST   | `/api/v1/auth/register`           | Create user + tenant membership |
| POST   | `/api/v1/auth/login`              | Email/password login            |
| POST   | `/api/v1/auth/refresh`            | Rotate refresh token + JWT      |
| POST   | `/api/v1/auth/password-reset/*`   | Request/confirm reset tokens    |
| POST   | `/api/v1/auth/oauth/google/start` | Generate Google OAuth URL       |
| GET    | `/api/v1/auth/oauth/google/callback` | Finish Google OAuth login    |
| GET    | `/api/v1/.well-known/openid-configuration` | OIDC discovery           |
| GET    | `/api/v1/.well-known/jwks.json`  | JWKS public keys                |
| GET    | `/api/v1/authorize`               | OIDC authorize (requires auth)  |
| POST   | `/api/v1/token`                    | OIDC token exchange             |
| GET    | `/api/v1/userinfo`                 | OIDC userinfo (requires auth)   |
| GET    | `/api/v1/auth/me`                 | Returns authenticated profile   |
| GET    | `/healthz`                        | Liveness probe                  |
| GET    | `/metrics`                        | Prometheus metrics              |

### Admin APIs (secured by admin scopes)

| Method | Path                              | Description                     |
|--------|-----------------------------------|---------------------------------|
| GET    | `/api/v1/admin/tenants`          | List tenants                    |
| POST   | `/api/v1/admin/tenants`          | Create tenant                   |
| GET    | `/api/v1/admin/clients`          | List OAuth clients              |
| POST   | `/api/v1/admin/clients`          | Create OAuth client             |
| GET    | `/api/v1/admin/entitlements`     | List tenant entitlements        |
| POST   | `/api/v1/admin/entitlements`     | Upsert tenant entitlement       |
| POST   | `/api/v1/admin/usage/increment`  | Increment usage counter         |
| POST   | `/api/v1/admin/keys/rotate`      | Reload signing keys             |

### MFA
- TOTP enrollment/confirmation and backup codes under `/api/v1/auth/mfa/*` (requires auth).

## Project Structure

- `cmd/` – binaries (`server`, `migrate`, `seed`).
- `internal/app` – service bootstrap, configuration, DI.
- `internal/ent` – Ent schema definitions and generated client.
- `internal/http` – handlers and middleware.
- `internal/oauth` – grant flows, token service.
- `internal/services` – domain logic (sessions, MFA, clients).
- `docs/` – architecture notes, ERD, integration playbooks.

## Integrations

- **Food Delivery / POS / Logistics / Inventory:** validate JWTs, consume `userinfo`, introspect tokens when required. Tenant/outlet discovery webhooks emitted here ensure each service hydrates metadata on login (polling not required).
- **Treasury:** receives metering events and returns feature entitlements for subscription plans.
- **Notifications:** delivers OTP and security alerts.

Refer to [docs/erd.md](docs/erd.md) and [plan.md](plan.md)` for module-level design.

## Status

- Planning phase – schema and integration design underway.
- See `CHANGELOG.md` for milestone history.


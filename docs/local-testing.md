# Local Testing (with Docker for Redis)

This guide shows how to run the Auth Service locally for development. It assumes:
- PostgreSQL is installed locally and reachable (per project preference).
- Redis runs in Docker.

## 1) Prepare Environment

Generate RSA keys:

```bash
openssl genrsa -out config/keys/dev_jwt_private.pem 4096
openssl rsa -in config/keys/dev_jwt_private.pem -pubout -out config/keys/dev_jwt_public.pem
```

On Windows PowerShell:

```powershell
New-Item -ItemType Directory -Force -Path .\config\keys | Out-Null
openssl genrsa -out .\config\keys\dev_jwt_private.pem 4096
openssl rsa -in .\config\keys\dev_jwt_private.pem -pubout -out .\config\keys\dev_jwt_public.pem
```

Copy and edit env:

```bash
cp config/example.env .env
```

Set:
- `AUTH_DB_URL=postgres://postgres:postgres@localhost:5432/auth_service?sslmode=disable`
- `AUTH_TOKEN_PRIVATE_KEY_PATH=./config/keys/dev_jwt_private.pem`
- `AUTH_TOKEN_PUBLIC_KEY_PATH=./config/keys/dev_jwt_public.pem`

## 2) Run Redis in Docker

```bash
docker run -d --name redis -p 6379:6379 redis:7
```

## 3) Migrate and Seed

```bash
go run ./cmd/migrate
SEED_ADMIN_PASSWORD=ChangeMe123! go run ./cmd/seed
```

The seed creates user `admin@codevertexitsolutions.com` with role `superuser` in tenant `codevertex`.

## 4) Run the API

```bash
go run ./cmd/server
```

You should see it listening on `http://localhost:4101`.

## 5) Quick Test

- Health: `curl http://localhost:4101/healthz`
- JWKS: `curl http://localhost:4101/api/v1/.well-known/jwks.json`
- Login: `POST /api/v1/auth/login` with `{ "email":"admin@codevertexitsolutions.com","password":"ChangeMe123!","tenant_slug":"codevertex" }`

Note on Redis: If you see a warning like “maint_notifications disabled due to handshake error,” it’s a harmless client fallback and safe to ignore locally. Upgrading Redis to 7.2+ removes it.

## 6) (Optional) Dockerizing the Service

Although local-first is preferred, the repo also includes a Dockerfile for CI. To build locally:

```bash
docker build -t auth-service:local .
docker run --rm -p 4101:4101 --env-file .env -v $PWD/config/keys:/app/config/keys auth-service:local
```


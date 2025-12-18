#!/bin/bash
cd "d:\Projects\BengoBox\auth-service\auth-api"
export AUTH_ENV=development
export AUTH_SERVICE_NAME=auth-api
export AUTH_HTTP_HOST=0.0.0.0
export AUTH_HTTP_PORT=4101
export AUTH_DB_URL="postgres://postgres:postgres@localhost:5432/auth_service?sslmode=disable"
export AUTH_TOKEN_PRIVATE_KEY_PATH="./config/keys/dev_jwt_private.pem"
export AUTH_TOKEN_PUBLIC_KEY_PATH="./config/keys/dev_jwt_public.pem"
export AUTH_TOKEN_ISSUER="https://auth.codevertex.local"
export AUTH_TOKEN_AUDIENCE="codevertex"
export AUTH_REDIS_ADDR="127.0.0.1:6379"
export AUTH_SECURITY_PASSWORD_MIN_LENGTH=12
export AUTH_SECURITY_OAUTH_STATE_SECRET="replace-me"
go run ./cmd/server/main.go

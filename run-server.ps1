$ErrorActionPreference = "Stop"
Push-Location "d:\Projects\BengoBox\auth-service\auth-api"
try {
    $env:AUTH_ENV = "development"
    $env:AUTH_SERVICE_NAME = "auth-api"
    $env:AUTH_HTTP_HOST = "0.0.0.0"
    $env:AUTH_HTTP_PORT = "4101"
    $env:AUTH_DB_URL = "postgres://postgres:postgres@localhost:5432/auth_service?sslmode=disable"
    $env:AUTH_TOKEN_PRIVATE_KEY_PATH = "./config/keys/dev_jwt_private.pem"
    $env:AUTH_TOKEN_PUBLIC_KEY_PATH = "./config/keys/dev_jwt_public.pem"
    $env:AUTH_TOKEN_ISSUER = "https://auth.codevertex.local"
    $env:AUTH_TOKEN_AUDIENCE = "codevertex"
    $env:AUTH_REDIS_ADDR = "127.0.0.1:6379"
    $env:AUTH_SECURITY_PASSWORD_MIN_LENGTH = "12"
    $env:AUTH_SECURITY_OAUTH_STATE_SECRET = "replace-me"
    
    Write-Host "Starting auth-api server on port 4101..." -ForegroundColor Green
    & go run ./cmd/server/main.go
} finally {
    Pop-Location
}

#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

APP_PORT=4101
REDIS_CONTAINER_NAME="redis"
SERVICE_IMAGE="auth-api:local"
SERVICE_CONTAINER_NAME="auth-api-local"
ENV_FILE="$ROOT_DIR/.env"
EXAMPLE_ENV="$ROOT_DIR/config/example.env"
KEYS_DIR="$ROOT_DIR/config/keys"
PRIV_KEY="$KEYS_DIR/dev_jwt_private.pem"
PUB_KEY="$KEYS_DIR/dev_jwt_public.pem"
CERTS_DIR="$ROOT_DIR/config/certs"

log() {
  echo "[local-deploy] $*"
}

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1"
    exit 1
  fi
}

ensure_env() {
  if [[ ! -f "$ENV_FILE" ]]; then
    log "Creating .env from config/example.env"
    cp "$EXAMPLE_ENV" "$ENV_FILE"

    # Normalize DB name and key paths
    if grep -q '^AUTH_DB_URL=' "$ENV_FILE"; then
      sed -i.bak 's|^AUTH_DB_URL=.*|AUTH_DB_URL=postgres://postgres:postgres@localhost:5432/auth_service?sslmode=disable|' "$ENV_FILE" || true
    else
      printf "AUTH_DB_URL=postgres://postgres:postgres@localhost:5432/auth_service?sslmode=disable\n" >> "$ENV_FILE"
    fi
    if grep -q '^AUTH_TOKEN_PRIVATE_KEY_PATH=' "$ENV_FILE"; then
      sed -i.bak 's|^AUTH_TOKEN_PRIVATE_KEY_PATH=.*|AUTH_TOKEN_PRIVATE_KEY_PATH=./config/keys/dev_jwt_private.pem|' "$ENV_FILE" || true
    else
      printf "AUTH_TOKEN_PRIVATE_KEY_PATH=./config/keys/dev_jwt_private.pem\n" >> "$ENV_FILE"
    fi
    if grep -q '^AUTH_TOKEN_PUBLIC_KEY_PATH=' "$ENV_FILE"; then
      sed -i.bak 's|^AUTH_TOKEN_PUBLIC_KEY_PATH=.*|AUTH_TOKEN_PUBLIC_KEY_PATH=./config/keys/dev_jwt_public.pem|' "$ENV_FILE" || true
    else
      printf "AUTH_TOKEN_PUBLIC_KEY_PATH=./config/keys/dev_jwt_public.pem\n" >> "$ENV_FILE"
    fi
    rm -f "$ENV_FILE.bak"
  fi
}

ensure_keys() {
  mkdir -p "$KEYS_DIR"
  if [[ ! -f "$PRIV_KEY" || ! -f "$PUB_KEY" ]]; then
    require openssl
  fi
  if [[ ! -f "$PRIV_KEY" ]]; then
    log "Generating JWT private key"
    openssl genrsa -out "$PRIV_KEY" 4096
  fi
  if [[ ! -f "$PUB_KEY" ]]; then
    log "Deriving JWT public key"
    openssl rsa -in "$PRIV_KEY" -pubout -out "$PUB_KEY"
  fi
}

ensure_redis() {
  if ! command -v docker >/dev/null 2>&1; then
    log "Docker not found; skipping Redis container. Ensure Redis is reachable at 127.0.0.1:6379."
    return 0
  fi
  if ! docker ps -a --format '{{.Names}}' | grep -wq "$REDIS_CONTAINER_NAME"; then
    log "Starting Redis container"
    docker run -d --name "$REDIS_CONTAINER_NAME" -p 6379:6379 redis:7 >/dev/null
  elif ! docker ps --format '{{.Names}}' | grep -wq "$REDIS_CONTAINER_NAME"; then
    log "Starting existing Redis container"
    docker start "$REDIS_CONTAINER_NAME" >/dev/null
  else
    log "Redis container already running"
  fi
}

migrate() {
  if ! command -v go >/dev/null 2>&1; then
    log "Go not installed; skipping migrations."
    return 0
  fi
  log "Running database migrations"
  set -a; source "$ENV_FILE"; set +a
  go run ./cmd/migrate || { log "Migrations failed"; exit 1; }
}

seed() {
  if ! command -v go >/dev/null 2>&1; then
    log "Go not installed; skipping seed."
    return 0
  fi
  local password="${SEED_ADMIN_PASSWORD:-}"
  if [[ -z "$password" ]]; then
    log "Skipping seed (set SEED_ADMIN_PASSWORD to seed admin user)."
    return 0
  fi
  log "Seeding data"
  set -a; source "$ENV_FILE"; set +a
  SEED_ADMIN_PASSWORD="$password" go run ./cmd/seed
}

run_local() {
  require go
  log "Starting auth service locally on :$APP_PORT"
  set -a; source "$ENV_FILE"; set +a
  go run ./cmd/server
}

run_docker() {
  require docker
  log "Building image $SERVICE_IMAGE"
  docker build -t "$SERVICE_IMAGE" .

  # Prepare host overrides for DB and Redis if needed
  local override_env=()
  if grep -q '^AUTH_DB_URL=' "$ENV_FILE"; then
    local db_url
    db_url="$(grep '^AUTH_DB_URL=' "$ENV_FILE" | sed 's/^AUTH_DB_URL=//')"
    if [[ "$db_url" == *"localhost"* || "$db_url" == *"127.0.0.1"* ]]; then
      db_url="${db_url//localhost/host.docker.internal}"
      db_url="${db_url//127.0.0.1/host.docker.internal}"
      override_env+=("-e" "AUTH_DB_URL=$db_url")
    fi
  fi
  override_env+=("-e" "AUTH_REDIS_ADDR=host.docker.internal:6379")

  # Stop existing container if running
  if docker ps -a --format '{{.Names}}' | grep -wq "$SERVICE_CONTAINER_NAME"; then
    docker rm -f "$SERVICE_CONTAINER_NAME" >/dev/null 2>&1 || true
  fi

  # Mount TLS certificates if directory exists and contains cert files
  local cert_volumes=()
  if [[ -d "$CERTS_DIR" ]] && [[ -n "$(find "$CERTS_DIR" -name "*.pem" 2>/dev/null)" ]]; then
    cert_volumes=("-v" "$CERTS_DIR:/app/config/certs")
    log "Mounting TLS certificates from $CERTS_DIR"
  fi
  
  log "Running container $SERVICE_CONTAINER_NAME on :$APP_PORT"
  docker run --name "$SERVICE_CONTAINER_NAME" --rm \
    -p "$APP_PORT:$APP_PORT" \
    --env-file "$ENV_FILE" \
    "${override_env[@]}" \
    -v "$KEYS_DIR:/app/config/keys" \
    "${cert_volumes[@]}" \
    "$SERVICE_IMAGE"
}

usage() {
  cat <<USAGE
Usage: $(basename "$0") [command]

Commands:
  init         Generate keys and ensure .env exists
  redis        Ensure Redis (Docker) is running
  migrate      Run database migrations
  seed         Seed data (requires SEED_ADMIN_PASSWORD env var)
  up           Init, Redis, migrate, then run locally
  up-docker    Init, Redis, then run in Docker
  run          Run locally (go run ./cmd/server)
  run-docker   Run in Docker (build+run)
  help         Show this help

Examples:
  SEED_ADMIN_PASSWORD='ChangeMe123!' ./local-deploy.sh seed
  ./local-deploy.sh up
  ./local-deploy.sh up-docker
USAGE
}

case "${1:-up}" in
  init)
    ensure_env
    ensure_keys
    ;;
  redis)
    ensure_redis
    ;;
  migrate)
    ensure_env
    migrate
    ;;
  seed)
    ensure_env
    seed
    ;;
  run)
    ensure_env
    ensure_keys
    run_local
    ;;
  run-docker)
    ensure_env
    ensure_keys
    run_docker
    ;;
  up)
    ensure_env
    ensure_keys
    ensure_redis
    migrate
    run_local
    ;;
  up-docker)
    ensure_env
    ensure_keys
    ensure_redis
    run_docker
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    usage
    exit 1
    ;;
esac



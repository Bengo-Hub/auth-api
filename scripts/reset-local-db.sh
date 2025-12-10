#!/usr/bin/env bash
# Reset local auth database for testing
set -euo pipefail

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if PostgreSQL is running in Kubernetes cluster
if command -v kubectl &> /dev/null && kubectl get namespace auth &> /dev/null; then
    info "Found Kubernetes auth namespace - resetting cluster database"
    
    # Get PostgreSQL credentials
    if ! kubectl get secret -n infra postgresql &> /dev/null; then
        error "PostgreSQL secret not found in infra namespace"
        exit 1
    fi
    
    info "Dropping and recreating auth database..."
    kubectl exec -n infra postgresql-0 -c postgresql -- psql -U admin_user -d postgres <<EOF
DROP DATABASE IF EXISTS auth;
CREATE DATABASE auth OWNER auth_user;
\c auth
GRANT ALL PRIVILEGES ON DATABASE auth TO auth_user;
GRANT ALL PRIVILEGES ON SCHEMA public TO auth_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO auth_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO auth_user;
EOF
    
    success "Database reset complete"
    info "Next steps:"
    echo "  1. Delete auth pods to trigger restart: kubectl delete pod -n auth -l app=auth-api"
    echo "  2. Pods will automatically run migrations and seeding"
    echo "  3. Check logs: kubectl logs -n auth -l app=auth-api -f"
    
elif docker ps &> /dev/null; then
    info "Using Docker for local PostgreSQL"
    
    # Check if postgres container is running
    if ! docker ps | grep -q postgres; then
        error "No PostgreSQL container running"
        error "Start PostgreSQL: docker run -d --name postgres -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:16"
        exit 1
    fi
    
    CONTAINER_NAME=$(docker ps --filter "ancestor=postgres" --format "{{.Names}}" | head -1)
    info "Found PostgreSQL container: $CONTAINER_NAME"
    
    info "Dropping and recreating auth database..."
    docker exec -i "$CONTAINER_NAME" psql -U postgres <<EOF
DROP DATABASE IF EXISTS auth;
CREATE DATABASE auth;
\c auth
CREATE USER IF NOT EXISTS auth_user WITH PASSWORD 'postgres';
GRANT ALL PRIVILEGES ON DATABASE auth TO auth_user;
GRANT ALL PRIVILEGES ON SCHEMA public TO auth_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO auth_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO auth_user;
EOF
    
    success "Database reset complete"
    info "Next steps:"
    echo "  1. Run migrations: go run ./cmd/migrate"
    echo "  2. Run seed: go run ./cmd/seed"
    echo "  3. Start server: go run ./cmd/server"
    
else
    info "Using local PostgreSQL installation"
    
    # Try to connect to local PostgreSQL
    if ! command -v psql &> /dev/null; then
        error "psql not found - install PostgreSQL client"
        exit 1
    fi
    
    DB_URL=${AUTH_DB_URL:-postgresql://postgres:postgres@localhost:5432/postgres}
    
    info "Dropping and recreating auth database..."
    psql "$DB_URL" <<EOF
DROP DATABASE IF EXISTS auth;
CREATE DATABASE auth;
\c auth
GRANT ALL PRIVILEGES ON DATABASE auth TO postgres;
GRANT ALL PRIVILEGES ON SCHEMA public TO postgres;
EOF
    
    success "Database reset complete"
    info "Next steps:"
    echo "  1. Update AUTH_DB_URL in .env"
    echo "  2. Run migrations: go run ./cmd/migrate"
    echo "  3. Run seed: go run ./cmd/seed"
    echo "  4. Start server: go run ./cmd/server"
fi

info "Database is now clean and ready for migrations"


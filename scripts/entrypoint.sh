#!/bin/sh
# Entrypoint script for Auth-API service
# Waits for database to be ready before starting the server

set -e

echo "=========================================="
echo "🚀 Auth-API Service Startup"
echo "=========================================="

# Wait for database to be ready (with timeout)
echo "🔌 Waiting for database connection..."
# 60 retries * 5s = 5 minutes
MAX_RETRIES=60
RETRY_COUNT=0

# Use the auth-migrate binary to check connection if possible, 
# or just use a simple nc check if available, or try to run the server with a short timeout.
# Since we have auth-migrate, we can try to run it with a flag if it supports it, 
# but usually Go apps just fail if DB is down.

# We'll use a simple loop to check if the DB port is reachable if nc is available,
# but since we are in alpine, we might have nc.
# Alternatively, we can try to run auth-migrate which should fail if DB is down.

until /usr/local/bin/auth-migrate > /dev/null 2>&1 || [ $RETRY_COUNT -eq $MAX_RETRIES ]; do
  RETRY_COUNT=$((RETRY_COUNT+1))
  echo "⏳ Database not ready yet or migrations failing... (attempt $RETRY_COUNT/$MAX_RETRIES)"
  sleep 5
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
  echo "❌ Database connection timeout after $MAX_RETRIES attempts"
  echo "⚠️ Proceeding to start server anyway (will fail if DB is critical)"
else
  echo "✅ Database connected and migrations completed (attempt $RETRY_COUNT)"
fi

echo ""
echo "=========================================="
echo "✅ Starting Auth-API server"
echo "=========================================="
echo ""

exec /usr/local/bin/auth

# Auth Service - Production Setup & Troubleshooting

## 🚀 Production Deployment Status

### Service Status
- **URL**: https://sso.codevertexitsolutions.com
- **Health Endpoint**: `/healthz` ✅
- **Swagger UI**: `/v1/docs/` ✅
- **Certificate**: Valid (Let's Encrypt)
- **Pods**: 2/2 Running
- **Database**: Connected (auth database in infra namespace)

---

## 🔐 Default Credentials (Seeded Automatically)

### Admin User
- **Email**: `admin@codevertexitsolutions.com`
- **Password**: `ChangeMe123!`
- **Tenant Slug**: `codevertex` ⚠️ **IMPORTANT: Use `codevertex` NOT `bengobox`**
- **Status**: Active

### Tenant
- **Name**: CodeVertex
- **Slug**: `codevertex`
- **Status**: Active
- **ID**: `493fb7fa-8470-4e02-a663-442529970839` (example)

---

## 📝 API Endpoints

### Health & Monitoring
| Method | Path | Description |
|--------|------|-------------|
| GET | `/healthz` | Health check endpoint |
| GET | `/metrics` | Prometheus metrics |
| GET | `/v1/docs/` | Swagger UI documentation |
| GET | `/api/v1/openapi.json` | OpenAPI spec |

### Authentication
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/auth/register` | User registration |
| POST | `/api/v1/auth/login` | Email/password login |
| POST | `/api/v1/auth/refresh` | Refresh token |
| POST | `/api/v1/auth/password-reset/request` | Request password reset |
| GET | `/api/v1/auth/me` | Get authenticated user |
| POST | `/api/v1/auth/logout` | Logout |

---

## 🧪 Testing the Service

### 1. Health Check
```bash
# Internal (from cluster)
kubectl exec -n auth <pod-name> -- wget -qO- http://localhost:4101/healthz

# External (HTTPS)
curl https://sso.codevertexitsolutions.com/healthz
# Expected: {"status":"ok","time":"..."}
```

### 2. Login Test
```bash
curl -X POST "https://sso.codevertexitsolutions.com/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@codevertexitsolutions.com",
    "password": "ChangeMe123!",
    "tenant_slug": "codevertex"
  }'
```

**Expected Response** (200 OK):
```json
{
  "user": {
    "id": "...",
    "email": "admin@codevertexitsolutions.com",
    "status": "active"
  },
  "access_token": "eyJ...",
  "refresh_token": "...",
  "tenant": {
    "id": "...",
    "name": "CodeVertex",
    "slug": "codevertex"
  }
}
```

---

## 🐛 Common Issues & Solutions

### Issue 1: "Failed to fetch" / CORS Error
**Symptoms**: 
- Browser shows "Failed to fetch" 
- "URL scheme must be http or https for CORS request"

**Cause**: Usually a certificate issue or incorrect URL

**Solution**:
1. Verify certificate is valid:
   ```bash
   kubectl get certificate -n auth sso-codevertexitsolutions-tls
   # Should show "Ready: True"
   ```

2. Check DNS resolution:
   ```bash
   nslookup sso.codevertexitsolutions.com
   ```

3. Test from Swagger UI instead: https://sso.codevertexitsolutions.com/v1/docs/

### Issue 2: "tenant not found" / Authentication Failed
**Symptoms**:
- 401 Unauthorized
- "tenant not found" error

**Cause**: Using wrong tenant slug

**Solution**:
- ✅ Use: `"tenant_slug": "codevertex"`
- ❌ Not: `"tenant_slug": codevertex`

### Issue 3: No Data in Database
**Symptoms**:
- Empty users/tenants tables
- "user not found" errors

**Solution**:
Run manual seeding:
```bash
# Connect to a pod
kubectl exec -n auth <pod-name> -it -- sh

# Set admin password
export SEED_ADMIN_PASSWORD="ChangeMe123!"

# Run seed (if available)
# Note: Current Dockerfile doesn't include seed binary
# Seeding happens via init container or manually
```

---

## 📊 Database Inspection

### Check Data
```bash
# List tenants
kubectl exec -n infra postgresql-0 -c postgresql -- \
  psql -U admin_user -d auth -c "SELECT id, name, slug, status FROM tenants;"

# List users
kubectl exec -n infra postgresql-0 -c postgresql -- \
  psql -U admin_user -d auth -c "SELECT id, email, status FROM users;"

# Count records
kubectl exec -n infra postgresql-0 -c postgresql -- \
  psql -U admin_user -d auth -c "SELECT 
    (SELECT COUNT(*) FROM tenants) as tenants,
    (SELECT COUNT(*) FROM users) as users,
    (SELECT COUNT(*) FROM sessions) as sessions;"
```

### Check Tables
```bash
kubectl exec -n infra postgresql-0 -c postgresql -- \
  psql -U admin_user -d auth -c "\dt"
```

---

## 🔄 Migrations & Seeding

### How It Works

1. **Migrations**: Run automatically on startup
   - Controlled by config: `Database.RunMigrations` (enabled by default)
   - Uses Ent schema migrations
   - Tables created on first run

2. **Seeding**: Manual or via init container
   - Default admin user: `admin@codevertexitsolutions.com`
   - Default tenant: `codevertex`
   - Password: Set via `SEED_ADMIN_PASSWORD` env var

### Manual Seeding (if needed)
The service handles its own seeding via:
- `cmd/seed/main.go` - Standalone seed command
- Requires: `SEED_ADMIN_PASSWORD` environment variable
- Creates: Default tenant (`codevertex`) and admin user

**Note**: Currently, the Dockerfile only includes the `cmd/server` binary, not `cmd/seed`.

---

## 🏥 Health Check Details

### Endpoint: `/healthz`
Returns:
```json
{
  "status": "ok",
  "time": "2025-12-03T06:37:28.729280605Z"
}
```

### Integration with Kubernetes
```yaml
# Configured in values.yaml
healthCheck:
  enabled: true
  readiness:
    httpGet:
      path: /healthz
      port: http
    initialDelaySeconds: 10
    periodSeconds: 10
  liveness:
    httpGet:
      path: /healthz
      port: http
    initialDelaySeconds: 30
    periodSeconds: 20
  startup:
    httpGet:
      path: /healthz
      port: http
    initialDelaySeconds: 5
    periodSeconds: 10
    failureThreshold: 15
```

---

## 📚 API Documentation

### Swagger UI
- **URL**: https://sso.codevertexitsolutions.com/v1/docs/
- **Features**:
  - Interactive API testing
  - Request/response examples
  - Schema definitions
  - Authentication testing (click "Authorize" button)

### OpenAPI Spec
- **URL**: https://sso.codevertexitsolutions.com/api/v1/openapi.json
- **Format**: OpenAPI 3.0

---

## 🔐 Security Notes

1. **Default Password**: Change `ChangeMe123!` immediately in production
2. **JWT Keys**: RSA keys mounted from `auth-token-keys` secret
3. **HTTPS**: Enforced via Ingress SSL redirect
4. **CORS**: Configured to allow all origins (`*`) - restrict in production
5. **Rate Limiting**: Applied to login and token endpoints

---

## 📞 Support

For issues or questions:
1. Check this guide first
2. Review logs: `kubectl logs -n auth -l app=auth-service`
3. Check pod status: `kubectl get pods -n auth`
4. Verify database connectivity: `kubectl exec -n auth <pod> -- wget -qO- http://localhost:4101/healthz`


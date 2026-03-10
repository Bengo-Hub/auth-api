# Database Maintenance Procedures

This document records operational procedures for maintaining the Auth Service database within the Kubernetes cluster.

## Database Reset Procedures

These commands can be used to reset the `auth` database when needed.

### 1. Identify Resources
- **PostgreSQL Pod:** `postgresql-0` (Namespace: `infra`)
- **Auth API Deployment:** `auth-api` (Namespace: `auth`)

### 2. Preparation: Scale Down Auth API
To ensure no active connections to the database:
```powershell
kubectl scale deployment auth-api -n auth --replicas=0
```

### 3. Terminate Active Sessions
If the database is still being accessed, terminate sessions from the `postgres` or `admin_user` context:
```powershell
kubectl exec postgresql-0 -n infra -- env PGPASSWORD=Vertex2020! psql -h 127.0.0.1 -U admin_user -d postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='auth' AND pid<>pg_backend_pid();"
```

### 4. Drop and Recreate Database
```powershell
kubectl exec postgresql-0 -n infra -- /bin/bash -c "export PGPASSWORD='Vertex2020!'; dropdb -h 127.0.0.1 -U admin_user auth --if-exists; createdb -h 127.0.0.1 -U admin_user auth"
```

### 5. Fix Database Ownership
When creating a database with a superuser, you must transfer ownership to the application user:
```powershell
kubectl exec postgresql-0 -n infra -- /bin/bash -c "export PGPASSWORD='Vertex2020!'; psql -h 127.0.0.1 -U admin_user -d postgres -c 'ALTER DATABASE auth OWNER TO auth_user;'"
```

### 6. Restore Auth API Deployment
```powershell
kubectl rollout restart deployment auth-api -n auth
```

### 7. Verification
Check if the pods are running and healthy:
```powershell
kubectl get pods -n auth
```

### 8. Database Verification
Verify the database contains the required tables:
```powershell
kubectl exec postgresql-0 -n infra -- psql -h 127.0.0.1 -U auth_user -d auth -c "\dt"
```

## Database Connection Check

To verify database connectivity from the auth-api pod:
```powershell
kubectl exec auth-api-85769676fb-clpn6 -n auth -- psql -h postgresql.infra.svc.cluster.local -U auth_user -d auth -c "SELECT COUNT(*) FROM users;"
```

## Current Database Status

As of the last maintenance check:
- Database: `auth` (owned by `auth_user`)
- Tables: 21 tables present
- Users: 6 user records in the users table
- Status: Healthy and operational

## Common Issues

### Pod Restart Loop
If auth-api pods are in restart loop due to database connection issues:
1. Check database connectivity: `kubectl exec postgresql-0 -n infra -- psql -h 127.0.0.1 -U auth_user -d auth -c "\l"`
2. Verify user permissions: `kubectl exec postgresql-0 -n infra -- psql -h 127.0.0.1 -U auth_user -d auth -c "\du"`
3. Check auth-api logs: `kubectl logs auth-api-85769676fb-clpn6 -n auth --tail=50`

### Database Ownership Issues
If auth-api cannot access the database due to ownership:
```powershell
kubectl exec postgresql-0 -n infra -- /bin/bash -c "export PGPASSWORD='Vertex2020!'; psql -h 127.0.0.1 -U admin_user -d postgres -c 'ALTER DATABASE auth OWNER TO auth_user;'"
```

## Security Notes

- The database password is stored in the `auth-service-secrets` secret in the `auth` namespace
- Only the `auth_user` should have access to the `auth` database
- Regular backups should be scheduled for the auth database
- All database operations should be logged in the audit_logs table

# HTTPS Setup with mkcert for Local Development

This guide explains how to enable HTTPS for the auth service using mkcert certificates in your local Docker environment.

## Prerequisites

1. Install [mkcert](https://github.com/FiloSottile/mkcert) and set up the local CA:
   ```powershell
   # Windows PowerShell
   choco install mkcert
   mkcert -install
   ```

2. Generate certificates for your local domain:
   ```powershell
   # Navigate to auth-service directory
   cd auth-service
   
   # Create certs directory
   mkdir -p config\certs
   
   # Generate certificate for auth.codevertex.local
   mkcert -key-file config\certs\auth.codevertex.local-key.pem -cert-file config\certs\auth.codevertex.local.pem auth.codevertex.local
   ```

## Configuration

1. **Update your `.env` file** (or create it from `config/example.env`):
   ```env
   AUTH_HTTP_TLS_CERT_FILE=./config/certs/auth.codevertex.local.pem
   AUTH_HTTP_TLS_KEY_FILE=./config/certs/auth.codevertex.local-key.pem
   ```

2. **Rebuild and restart the Docker container**:
   ```powershell
   .\local-deploy.ps1 run-docker
   ```

   Or if the container is already running:
   ```powershell
   docker stop auth-service-local
   docker rm auth-service-local
   .\local-deploy.ps1 run-docker
   ```

## Verification

Once the service is running with TLS enabled, you should be able to access:
- ✅ `https://auth.codevertex.local:4101/api/v1/docs`
- ✅ `https://auth.codevertex.local:4101/api/v1/.well-known/jwks.json`

The service will automatically use HTTPS when both `AUTH_HTTP_TLS_CERT_FILE` and `AUTH_HTTP_TLS_KEY_FILE` are set. If these are not set, it will fall back to HTTP.

## Troubleshooting

### Certificates not found
- Ensure the `config/certs` directory exists and contains your `.pem` files
- Check that the paths in `.env` are correct (relative to the container's working directory `/app`)
- Verify the certificates are mounted: `docker exec auth-service-local ls -la /app/config/certs`

### Port already in use
- Make sure no other service is using port 4101
- Check: `netstat -ano | findstr :4101` (Windows) or `lsof -i :4101` (Linux/Mac)

### Browser certificate warnings
- Ensure mkcert CA is installed: `mkcert -install`
- Clear browser cache and restart browser
- Verify the certificate is valid: `openssl x509 -in config/certs/auth.codevertex.local.pem -text -noout`

## Notes

- The certificates directory (`config/certs`) is automatically mounted into the Docker container when it contains `.pem` files
- Certificates are not included in the Docker image - they're mounted as volumes for security
- The service logs will indicate whether it's running in HTTP or HTTPS mode


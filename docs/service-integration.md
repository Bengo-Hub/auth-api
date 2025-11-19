# Service Integration Guide

This guide explains how to integrate other services with the auth-service for centralized authentication and user management.

## Overview

The auth-service handles all authentication logic for all services within the BengoBox ecosystem. Services should:

1. **Redirect users to auth-service** for registration and login
2. **Receive redirects back** after successful authentication with tokens
3. **Use JWT tokens** for API authentication via the shared auth-client

## Authentication Flows

### 1. Registration Flow

When a user wants to create an account from your service:

```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "secure-password-123",
  "tenant_slug": "your-tenant-slug",
  "profile": {
    "first_name": "John",
    "last_name": "Doe"
  },
  "client_id": "your-client-id",
  "redirect_uri": "https://your-service.com/auth/callback"
}
```

**Response (with redirect_uri):**
- HTTP 302 Redirect to `redirect_uri` with tokens in URL fragment or query params:
  - `access_token`: JWT access token
  - `refresh_token`: Opaque refresh token
  - `expires_in`: Token expiration in seconds
  - `user_id`: User UUID
  - `tenant_id`: Tenant UUID

**Response (without redirect_uri):**
- HTTP 201 Created with JSON body containing tokens

### 2. Login Flow

When a user wants to log in from your service:

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "secure-password-123",
  "tenant_slug": "your-tenant-slug",
  "client_id": "your-client-id",
  "redirect_uri": "https://your-service.com/auth/callback"
}
```

**Response (with redirect_uri):**
- HTTP 302 Redirect to `redirect_uri` with tokens (same format as registration)

**Response (without redirect_uri):**
- HTTP 200 OK with JSON body containing tokens

### 3. OAuth Flow (Google, GitHub, Microsoft)

For social authentication:

**Step 1: Initiate OAuth**
```http
POST /api/v1/auth/oauth/google/start
Content-Type: application/json

{
  "tenant_slug": "your-tenant-slug",
  "client_id": "your-client-id",
  "flow": "login",
  "redirect_uri": "https://your-service.com/auth/callback"
}
```

**Response:**
```json
{
  "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?..."
}
```

**Step 2: Redirect user to `authorization_url`**

**Step 3: User completes OAuth on provider**

**Step 4: Provider redirects to auth-service callback**

**Step 5: Auth-service redirects to your `redirect_uri` with tokens**

## Frontend Integration

### Web Application (SPA)

For Single Page Applications, use URL fragments to receive tokens:

```javascript
// After redirect from auth-service
const hashParams = new URLSearchParams(window.location.hash.substring(1));
const accessToken = hashParams.get('access_token');
const refreshToken = hashParams.get('refresh_token');

// Store tokens securely
localStorage.setItem('access_token', accessToken);
localStorage.setItem('refresh_token', refreshToken);

// Redirect to dashboard
window.location.href = '/dashboard';
```

### Traditional Web Application

For server-rendered applications, use query parameters:

```javascript
// After redirect from auth-service
const urlParams = new URLSearchParams(window.location.search);
const accessToken = urlParams.get('access_token');
const refreshToken = urlParams.get('refresh_token');

// Send tokens to your backend to establish session
fetch('/api/auth/session', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ access_token: accessToken, refresh_token: refreshToken })
});
```

## Backend Integration

### Using Shared Auth Client

All services should use the `shared/auth-client` package for JWT validation:

```go
import authclient "github.com/Bengo-Hub/shared-auth-client"

// Initialize validator
config := authclient.DefaultConfig(
    "https://auth.codevertex.local:4101/api/v1/.well-known/jwks.json",
    "https://auth.codevertex.local:4101",
    "bengobox",
)
validator, _ := authclient.NewValidator(config)
authMiddleware := authclient.NewAuthMiddleware(validator)

// Apply middleware
router.Use(authclient.ChiMiddleware(authMiddleware))
```

### Proxying Registration/Login Requests

If your service needs to handle registration/login requests directly (e.g., for form submissions), proxy them to auth-service:

```go
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
    // Forward request to auth-service
    reqBody, _ := io.ReadAll(r.Body)
    
    resp, err := http.Post(
        "https://auth.codevertex.local:4101/api/v1/auth/register",
        "application/json",
        bytes.NewReader(reqBody),
    )
    if err != nil {
        http.Error(w, "Registration failed", http.StatusInternalServerError)
        return
    }
    
    // If redirect_uri was provided, auth-service will redirect
    // Otherwise, forward JSON response
    if resp.StatusCode == http.StatusFound {
        redirectURL := resp.Header.Get("Location")
        http.Redirect(w, r, redirectURL, http.StatusFound)
        return
    }
    
    // Forward JSON response
    body, _ := io.ReadAll(resp.Body)
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(resp.StatusCode)
    w.Write(body)
}
```

## Redirect URI Format

The `redirect_uri` parameter determines where users are sent after authentication:

- **SPA (Single Page Application)**: Use URL fragments
  - Example: `https://your-app.com/auth/callback#access_token=...`
  - Tokens are in the URL fragment (not sent to server)

- **Traditional Web App**: Use query parameters
  - Example: `https://your-app.com/auth/callback?access_token=...`
  - Tokens are in query params (sent to server)

The auth-service automatically detects the format based on the redirect URI:
- URLs ending with `/`, `/dashboard`, `/home`, or containing `#` → Fragment format
- Other URLs → Query parameter format

## Security Considerations

1. **Validate Redirect URIs**: In production, validate `redirect_uri` against your OAuth client's allowed redirect URIs
2. **HTTPS Only**: Always use HTTPS for redirect URIs in production
3. **Token Storage**: Store tokens securely (httpOnly cookies for web apps, secure storage for mobile)
4. **Token Refresh**: Implement token refresh logic using the `refresh_token`
5. **CORS**: Configure CORS on auth-service to allow requests from your service domains

## Example: Complete Integration

### Frontend (React)

```jsx
// Login component
const handleLogin = async (email, password) => {
  const response = await fetch('https://auth.codevertex.local:4101/api/v1/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email,
      password,
      tenant_slug: 'my-tenant',
      client_id: 'my-client-id',
      redirect_uri: `${window.location.origin}/auth/callback`
    }),
    redirect: 'follow' // Follow redirects
  });
  
  // If redirect happened, browser will navigate automatically
  // Otherwise, handle JSON response
  if (response.ok) {
    const data = await response.json();
    localStorage.setItem('access_token', data.access_token);
    window.location.href = '/dashboard';
  }
};

// Callback component
const AuthCallback = () => {
  useEffect(() => {
    const hashParams = new URLSearchParams(window.location.hash.substring(1));
    const accessToken = hashParams.get('access_token');
    
    if (accessToken) {
      localStorage.setItem('access_token', accessToken);
      window.location.href = '/dashboard';
    }
  }, []);
  
  return <div>Authenticating...</div>;
};
```

### Backend (Go)

```go
// Handler that proxies to auth-service
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Email       string `json:"email"`
        Password    string `json:"password"`
        TenantSlug  string `json:"tenant_slug"`
        ClientID    string `json:"client_id"`
        RedirectURI string `json:"redirect_uri"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    
    // Add your service's redirect URI
    req.RedirectURI = "https://your-service.com/auth/callback"
    
    // Forward to auth-service
    body, _ := json.Marshal(req)
    resp, err := http.Post(
        "https://auth.codevertex.local:4101/api/v1/auth/login",
        "application/json",
        bytes.NewReader(body),
    )
    if err != nil {
        http.Error(w, "Login failed", http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()
    
    // Forward response (redirect or JSON)
    for k, v := range resp.Header {
        w.Header()[k] = v
    }
    w.WriteHeader(resp.StatusCode)
    io.Copy(w, resp.Body)
}
```

## Migration Guide

If your service currently has its own user registration/login:

1. **Remove local user creation**: All user accounts are created in auth-service
2. **Update registration endpoint**: Proxy to auth-service or redirect to auth-service UI
3. **Update login endpoint**: Proxy to auth-service or redirect to auth-service UI
4. **Update OAuth flows**: Use auth-service OAuth endpoints instead of direct provider integration
5. **Sync user data**: Query auth-service `/api/v1/auth/me` endpoint to get user profile
6. **Update JWT validation**: Use shared auth-client for all protected routes

## Support

For questions or issues, refer to:
- Auth-service Swagger docs: `https://auth.codevertex.local:4101/v1/docs`
- Shared auth-client README: `shared/auth-client/README.md`


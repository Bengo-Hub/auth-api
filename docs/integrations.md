# Auth Service - Integration Guide

## Overview

The Auth Service is the central identity provider for all BengoBox services. This document details all integration points, protocols, data flows, and implementation guidelines for services integrating with auth-service.

---

## Table of Contents

1. [Integration Patterns](#integration-patterns)
2. [Internal BengoBox Service Integrations](#internal-bengobox-service-integrations)
3. [External Third-Party Integrations](#external-third-party-integrations)
4. [User & Tenant Synchronization](#user--tenant-synchronization)
5. [Event-Driven Architecture](#event-driven-architecture)
6. [Integration Security](#integration-security)
7. [Error Handling & Resilience](#error-handling--resilience)

---

## Integration Patterns

### 1. OAuth2/OIDC Provider Pattern

**Use Case**: Services requiring SSO authentication and authorization

**Flow**:
1. User initiates login from service frontend
2. Frontend redirects to auth-service `/authorize` endpoint
3. Auth-service handles authentication (local, social, MFA)
4. Auth-service redirects back with authorization code
5. Frontend exchanges code for tokens via `/token` endpoint
6. Service validates tokens using JWKS or introspection

**Endpoints**:
- `GET /authorize` - Authorization endpoint
- `POST /token` - Token exchange endpoint
- `GET /.well-known/openid-configuration` - Discovery document
- `GET /.well-known/jwks.json` - Public keys for JWT validation

### 2. JWT Validation Pattern

**Use Case**: Services validating tokens on each request

**Implementation**:
- Services cache JWKS from `/.well-known/jwks.json`
- Validate JWT signature using cached public keys
- Extract claims (user_id, tenant_id, scopes, roles)
- Use claims for authorization decisions

### 3. Webhook Pattern

**Use Case**: Synchronizing user/tenant data changes

**Events Published**:
- `auth.user.created` - New user created
- `auth.user.updated` - User profile updated
- `auth.user.deactivated` - User deactivated
- `auth.user.locked` - User account locked
- `auth.tenant.created` - New tenant created
- `auth.tenant.updated` - Tenant updated
- `auth.tenant.synced` - Tenant metadata synced
- `auth.outlet.created` - New outlet created
- `auth.outlet.updated` - Outlet updated
- `auth.outlet.synced` - Outlet metadata synced

### 4. REST API Pattern

**Use Case**: Direct user/tenant lookup, admin operations

**Endpoints**:
- `GET /api/v1/users/{id}` - Get user details
- `GET /api/v1/tenants/{id}` - Get tenant details
- `GET /api/v1/tenants/by-slug/{slug}` - Get tenant by slug (public, for tenant auto-discovery)
- `POST /api/v1/tenants` - Create tenant (public, for tenant auto-discovery, accepts `id` field for matching UUIDs across services)
- `POST /api/v1/introspect` - Token introspection
- `POST /api/v1/revoke` - Token revocation

---

## Internal BengoBox Service Integrations

### Cafe Backend

**Integration Type**: OAuth2/OIDC + Events + REST

**Use Cases**:
- User authentication for cafe orders
- Tenant/outlet context for multi-tenant operations
- User profile sync for customer accounts

**Events Consumed**:
- `auth.user.created` - Create customer account
- `auth.user.updated` - Update customer profile
- `auth.tenant.synced` - Sync tenant metadata

**Events Published**: None (auth-service is publisher)

**REST API Usage**:
- JWT validation on protected routes
- User lookup for order attribution
- Tenant lookup for outlet routing

### Logistics Service

**Integration Type**: OAuth2/OIDC + Events + REST

**Use Cases**:
- Rider/driver authentication
- Fleet member identity verification
- Tenant context for dispatch operations

**Events Consumed**:
- `auth.user.created` - Create rider profile reference
- `auth.user.updated` - Update rider identity
- `auth.tenant.synced` - Sync tenant/outlet metadata

**REST API Usage**:
- JWT validation for API requests
- User lookup for fleet member verification

### Treasury App

**Integration Type**: OAuth2/OIDC + Events + REST

**Use Cases**:
- User authentication for financial operations
- Tenant context for multi-tenant accounting
- Subscription billing integration

**Events Consumed**:
- `auth.user.created` - Create financial user profile
- `auth.tenant.created` - Initialize tenant billing
- `auth.tenant.updated` - Update subscription context

**Events Published**: None (auth-service is publisher)

**REST API Usage**:
- JWT validation for payment operations
- Tenant lookup for invoice generation
- Usage metering for premium auth features

### Projects Service

**Integration Type**: OAuth2/OIDC + Events + REST

**Use Cases**:
- User authentication for project management
- Team member identity verification
- Tenant context for project isolation

**Events Consumed**:
- `auth.user.created` - Create project team member
- `auth.user.updated` - Update team member profile
- `auth.tenant.synced` - Sync tenant metadata

**REST API Usage**:
- JWT validation for API requests
- User lookup for team assignments

### Notifications Service

**Integration Type**: Events + REST

**Use Cases**:
- User lookup for notification delivery
- Tenant context for notification routing
- OTP delivery for MFA

**Events Consumed**: None (auth-service publishes events)

**Events Published**: None (auth-service is publisher)

**REST API Usage**:
- User lookup for email/phone delivery
- Tenant lookup for notification preferences

### POS Service

**Integration Type**: OAuth2/OIDC + Events + REST

**Use Cases**:
- Cashier authentication
- Device registration
- Tenant/outlet context

**Events Consumed**:
- `auth.user.created` - Create POS user role
- `auth.outlet.synced` - Sync outlet metadata

**REST API Usage**:
- JWT validation for POS operations
- Device registration with user context

### Inventory Service

**Integration Type**: OAuth2/OIDC + Events + REST

**Use Cases**:
- Warehouse manager authentication
- Tenant context for inventory isolation

**Events Consumed**:
- `auth.user.created` - Create inventory user
- `auth.tenant.synced` - Sync tenant metadata

**REST API Usage**:
- JWT validation for inventory operations

### ERP Service

**Integration Type**: OAuth2/OIDC + Events + REST

**Use Cases**:
- Employee authentication
- Organizational structure sync
- Tenant context

**Events Consumed**:
- `auth.user.created` - Create ERP employee
- `auth.user.updated` - Update employee identity
- `auth.tenant.synced` - Sync tenant metadata

**REST API Usage**:
- JWT validation for ERP operations
- User lookup for employee records

### IoT Service

**Integration Type**: OAuth2/OIDC + Events + REST

**Use Cases**:
- Device administrator authentication
- Tenant context for device isolation

**Events Consumed**:
- `auth.user.created` - Create IoT admin user
- `auth.tenant.synced` - Sync tenant metadata

**REST API Usage**:
- JWT validation for device management

### TruLoad Backend

**Integration Type**: OAuth2/OIDC + Events + REST

**Use Cases**:
- Officer authentication
- Station context
- User identity sync

**Events Consumed**:
- `auth.user.created` - Create officer profile
- `auth.user.updated` - Update officer identity

**REST API Usage**:
- JWT validation for weighing operations
- User lookup for officer attribution

**Note**: TruLoad integrates only with auth-service and notifications-service. No treasury integration.

---

## External Third-Party Integrations

### Google OAuth

**Purpose**: Social login via Google accounts

**Configuration**:
- Client ID: Stored in encrypted configuration (Tier 1 - Developer only)
- Client Secret: Stored encrypted at rest in database
- Redirect URI: `https://auth.codevertexitsolutions.co.ke/auth/oauth/google/callback`

**Flow**:
1. User clicks "Sign in with Google"
2. Redirect to Google OAuth consent screen
3. User authorizes
4. Google redirects with authorization code
5. Exchange code for access token
6. Fetch user profile from Google
7. Create/link user identity
8. Issue first-party JWT tokens

### Microsoft OAuth

**Purpose**: Social login via Microsoft 365 accounts

**Configuration**:
- Client ID: Stored in encrypted configuration (Tier 1)
- Client Secret: Stored encrypted at rest
- Redirect URI: `https://auth.codevertexitsolutions.co.ke/auth/oauth/microsoft/callback`

**Flow**: Similar to Google OAuth

### GitHub OAuth

**Purpose**: Developer login via GitHub accounts

**Configuration**:
- Client ID: Stored in encrypted configuration (Tier 1)
- Client Secret: Stored encrypted at rest
- Redirect URI: `https://auth.codevertexitsolutions.co.ke/auth/oauth/github/callback`

**Flow**: Similar to Google OAuth

### Apple Sign In

**Purpose**: Social login via Apple ID

**Status**: Planned for future implementation

**Configuration**:
- Service ID: Stored in encrypted configuration (Tier 1)
- Private Key: Stored encrypted at rest
- Team ID: Stored in configuration

---

## User & Tenant Synchronization

### Synchronization Architecture

**Principle**: Auth-service is the source of truth for user identity and authentication. Services maintain local user tables for app-specific data (roles, permissions, preferences) but sync identity data from auth-service.

**Identity Data (Synced from Auth-Service)**:
- Email
- Phone
- Password hash (managed by auth-service)
- Account status (active, locked, deactivated)
- MFA settings
- Session data

**App-Specific Data (Managed Locally)**:
- Service-specific roles
- Service-specific permissions
- App preferences
- Work assignments (shifts, stations, projects)
- Service-specific metadata

### Synchronization Methods

#### 1. Event-Driven Sync (Preferred)

**Webhook Events**:
- `auth.user.created` - Trigger local user creation
- `auth.user.updated` - Update local user identity fields
- `auth.user.deactivated` - Deactivate local user
- `auth.user.locked` - Lock local user access

**Implementation**:
```go
// Webhook handler in downstream service
func (h *WebhookHandler) HandleAuthUserCreated(ctx context.Context, event AuthUserCreatedEvent) {
    // Create local user with app-specific defaults
    user := &User{
        AuthServiceUserID: event.UserID,
        Email: event.Email,
        Phone: event.Phone,
        Status: "active",
        AppSpecificRole: "default_role",
    }
    h.db.CreateUser(ctx, user)
}
```

#### 2. Periodic Sync (Fallback)

**Schedule**: Every 15 minutes

**Process**:
1. Query auth-service for users updated since last sync
2. Update local user records
3. Mark sync status and timestamp

**Use Case**: Recovery from missed events, initial sync

#### 3. On-Demand Sync

**Trigger**: User lookup with stale data

**Process**:
1. Check local user sync status
2. If stale (>1 hour), fetch from auth-service
3. Update local record
4. Return to caller

### Tenant Synchronization

**Events**:
- `auth.tenant.created` - New tenant created
- `auth.tenant.updated` - Tenant updated
- `auth.tenant.synced` - Tenant metadata synced

**Data Synced**:
- Tenant ID
- Tenant slug (canonical identifier)
- Tenant name
- Tenant status
- Tenant metadata

**Outlet Synchronization**:
- `auth.outlet.created` - New outlet created
- `auth.outlet.updated` - Outlet updated
- `auth.outlet.synced` - Outlet metadata synced

---

## Event-Driven Architecture

### Event Catalog

#### User Events

**auth.user.created**
```json
{
  "event_id": "uuid",
  "event_type": "auth.user.created",
  "tenant_id": "tenant-uuid",
  "timestamp": "2024-12-05T10:30:00Z",
  "data": {
    "user_id": "user-uuid",
    "email": "user@example.com",
    "phone": "+254712345678",
    "status": "active"
  }
}
```

**auth.user.updated**
```json
{
  "event_id": "uuid",
  "event_type": "auth.user.updated",
  "tenant_id": "tenant-uuid",
  "timestamp": "2024-12-05T10:30:00Z",
  "data": {
    "user_id": "user-uuid",
    "email": "newemail@example.com",
    "phone": "+254712345679",
    "status": "active"
  }
}
```

**auth.user.deactivated**
```json
{
  "event_id": "uuid",
  "event_type": "auth.user.deactivated",
  "tenant_id": "tenant-uuid",
  "timestamp": "2024-12-05T10:30:00Z",
  "data": {
    "user_id": "user-uuid",
    "reason": "account_closed"
  }
}
```

**auth.user.locked**
```json
{
  "event_id": "uuid",
  "event_type": "auth.user.locked",
  "tenant_id": "tenant-uuid",
  "timestamp": "2024-12-05T10:30:00Z",
  "data": {
    "user_id": "user-uuid",
    "reason": "too_many_failed_attempts",
    "locked_until": "2024-12-05T11:30:00Z"
  }
}
```

#### Tenant Events

**auth.tenant.created**
```json
{
  "event_id": "uuid",
  "event_type": "auth.tenant.created",
  "timestamp": "2024-12-05T10:30:00Z",
  "data": {
    "tenant_id": "tenant-uuid",
    "tenant_slug": "tenant-slug",
    "name": "Tenant Name",
    "status": "active"
  }
}
```

**auth.tenant.synced**
```json
{
  "event_id": "uuid",
  "event_type": "auth.tenant.synced",
  "timestamp": "2024-12-05T10:30:00Z",
  "data": {
    "tenant_id": "tenant-uuid",
    "tenant_slug": "tenant-slug",
    "name": "Updated Tenant Name",
    "metadata": {
      "plan": "professional",
      "features": ["mfa", "sso"]
    }
  }
}
```

#### Outlet Events

**auth.outlet.created**
```json
{
  "event_id": "uuid",
  "event_type": "auth.outlet.created",
  "tenant_id": "tenant-uuid",
  "timestamp": "2024-12-05T10:30:00Z",
  "data": {
    "outlet_id": "outlet-uuid",
    "tenant_id": "tenant-uuid",
    "code": "OUTLET-001",
    "name": "Main Outlet",
    "address": {...}
  }
}
```

### Event Publishing

**Transport**: NATS JetStream

**Subject Pattern**: `auth.{entity}.{action}`

**Reliability**:
- At-least-once delivery
- Event deduplication via event_id
- Retry on failure
- Dead letter queue for failed events

---

## Integration Security

### Authentication

**JWT Tokens**:
- Signed with RSA-256
- Short-lived access tokens (15 minutes)
- Long-lived refresh tokens (7 days)
- Token rotation on refresh

**API Keys**:
- Service-to-service communication
- Stored in K8s secrets
- Rotated quarterly

### Authorization

**Scopes**:
- `openid` - Basic OpenID Connect
- `profile` - User profile access
- `email` - Email address access
- `offline_access` - Refresh token issuance
- Service-specific scopes (e.g., `cafe:orders`, `logistics:dispatch`)

**Claims**:
- `sub` - User ID
- `email` - User email
- `tenant_id` - Tenant ID
- `tenant_slug` - Tenant slug
- `roles` - Global roles
- `scopes` - Granted scopes

### Secrets Management

**Two-Tier Configuration**:

**Tier 1 (Developer/Superuser Only)**:
- OAuth client secrets
- API keys
- Encryption keys
- Database credentials

**Tier 2 (Business Users)**:
- Tenant branding
- Feature toggles
- Notification preferences

**Encryption**:
- Secrets encrypted at rest (AES-256-GCM)
- Decrypted only when used
- Key rotation every 90 days

### Webhook Security

**Signature Verification**:
- HMAC-SHA256 signatures
- Secret shared via K8s secret
- Timestamp validation (5-minute window)
- Nonce validation (prevent replay attacks)

---

## Error Handling & Resilience

### Retry Policies

**Exponential Backoff**:
- Initial delay: 1 second
- Max delay: 30 seconds
- Max retries: 3

**Circuit Breaker**:
- Opens after 5 consecutive failures
- Half-open after 60 seconds
- Closes on successful request

### Fallback Strategies

**Auth-Service Unavailable**:
- Return 503 Service Unavailable
- Log error for monitoring
- Alert operations team

**Token Validation Failure**:
- Return 401 Unauthorized
- Clear client-side tokens
- Redirect to login

**Event Delivery Failure**:
- Retry with exponential backoff
- Dead letter queue after max retries
- Manual reconciliation interface

### Monitoring

**Metrics**:
- Authentication success/failure rates
- Token validation latency
- Event publishing success rates
- Webhook delivery success rates

**Alerts**:
- High authentication failure rate
- Token validation errors
- Event delivery failures
- Service unavailability

---

## References

- [OAuth 2.0 Specification](https://oauth.net/2/)
- [OpenID Connect Specification](https://openid.net/connect/)
- [JWT Specification](https://jwt.io/)
- [NATS JetStream Documentation](https://docs.nats.io/nats-concepts/jetstream)



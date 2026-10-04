# 🛡️ Enterprise Multi-Tenant Authentication & API Gateway Service

[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20.x-green.svg)](https://nodejs.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](https://www.docker.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791.svg)](https://www.postgresql.org/)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D.svg)](https://redis.io/)
[![JWT RS256](https://img.shields.io/badge/JWT-RS256-orange.svg)](https://jwt.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A standalone, production-ready, cloud-native **Multi-Tenant Authentication and API Gateway Service** built with TypeScript, Node.js, PostgreSQL, and Redis. It provides cryptographic identity management, token rotation, distributed rate limiting, and dynamic reverse proxy routing to downstream microservices.

---

## 🏛️ System Architecture

```mermaid
graph TD
    Client[📱 Client / Frontend] -->|HTTPS Request| Gateway[🚪 API Gateway & Auth Service]
    
    subgraph Gateway Core
        RL[⏱️ Redis Sliding-Window Rate Limiter]
        Auth[🔐 RS256 JWT & RBAC Engine]
        Proxy[🔀 Dynamic Reverse Proxy Engine]
        Audit[📝 Audit Logger]
    end

    Gateway --> RL
    RL --> Auth
    Auth --> Proxy
    
    subgraph Infrastructure
        PG[(🐘 PostgreSQL Multi-Tenant DB)]
        RD[(⚡ Redis Token Blacklist & Rate Limit Store)]
    end

    Auth <--> PG
    Auth <--> RD
    Audit --> PG
    
    subgraph Downstream Microservices
        ServiceA[📦 Microservice A]
        ServiceB[💳 Microservice B]
        ServiceC[📊 Analytics Service]
    end

    Proxy -->|Enriched Headers: X-User-Id, X-Tenant-Id| ServiceA
    Proxy -->|Enriched Headers: X-User-Id, X-Tenant-Id| ServiceB
    Proxy -->|Enriched Headers: X-User-Id, X-Tenant-Id| ServiceC
```

---

## 🌟 Key Features

### 1. 🔐 Cryptographic Authentication & Security
- **RS256 Asymmetric Signing**: Access tokens are signed using a 2048-bit RSA private key and verifiable via public key or standard **JWKS** (`/api/v1/auth/jwks.json`).
- **Refresh Token Rotation & Family Reuse Detection**: Automatically tracks token lineage. If an invalidated refresh token is reused, all tokens in the family are instantly revoked.
- **Redis Token Blacklist**: Instant session termination and JTI-based token revocation with auto-expiring TTLs.
- **Tenant Isolation**: Non-SuperAdmin users are cryptographically constrained within their tenant boundaries.

### 2. 👥 Granular Multi-Tenant RBAC
Hierarchical roles and permissions matrix:
- **`SuperAdmin`**: Platform-wide cross-tenant control, tenant provisioning, route management.
- **`TenantAdmin`**: Organization administrator, user onboarding, role assignments.
- **`Member`**: Standard tenant collaborator.
- **`Viewer`**: Read-only tenant consumer.

### 3. ⏱️ Distributed Sliding-Window Rate Limiting
- Atomic sliding-window rate evaluation via **Redis Lua scripts** and sorted sets.
- Configurable per IP, per User, per Tenant, and per Route.
- RFC-compliant rate limit response headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, `Retry-After`.

### 4. 🔀 Dynamic Reverse Proxy Gateway
- Dynamic route registration stored in PostgreSQL with runtime live caching.
- Path-based routing with prefix stripping, timeout safeguards, and downstream circuit breaking.
- Contextual header injection: `X-User-Id`, `X-Tenant-Id`, `X-User-Roles`, `X-Correlation-ID`.

---

## 📊 Database Entity-Relationship (ER) Diagram

```mermaid
erDiagram
    TENANTS ||--o{ USERS : owns
    TENANTS ||--o{ REFRESH_TOKENS : scopes
    TENANTS ||--o{ USER_ROLES : partitions
    TENANTS ||--o{ AUDIT_LOGS : records
    USERS ||--o{ REFRESH_TOKENS : creates
    USERS ||--o{ USER_ROLES : assigned
    USERS ||--o{ AUDIT_LOGS : generates
    ROLES ||--o{ USER_ROLES : has
    ROLES ||--o{ ROLE_PERMISSIONS : includes
    PERMISSIONS ||--o{ ROLE_PERMISSIONS : defines

    TENANTS {
        uuid id PK
        string name
        string slug UK
        string plan
        boolean is_active
        jsonb metadata
        timestamp created_at
    }

    USERS {
        uuid id PK
        uuid tenant_id FK
        string email
        string password_hash
        string full_name
        boolean is_active
        timestamp created_at
    }

    ROLES {
        uuid id PK
        string name UK
        string description
        boolean is_system
    }

    PERMISSIONS {
        uuid id PK
        string name UK
        string resource
        string action
    }

    REFRESH_TOKENS {
        uuid id PK
        uuid user_id FK
        uuid tenant_id FK
        string token_hash UK
        uuid family_id
        boolean is_revoked
        timestamp expires_at
    }

    AUDIT_LOGS {
        uuid id PK
        uuid tenant_id FK
        uuid user_id FK
        string ip_address
        string action
        string resource
        int status_code
        jsonb details
        timestamp created_at
    }

    GATEWAY_ROUTES {
        uuid id PK
        string path_prefix UK
        string target_url
        boolean is_protected
        string[] required_roles
        string[] required_permissions
        int rate_limit_max
        int rate_limit_window_sec
        boolean strip_prefix
    }
```

---

## 🔄 Authentication & Refresh Token Rotation Flow

```mermaid
sequenceDiagram
    autonumber
    actor Client
    participant Gateway as API Gateway
    participant Redis as Redis Cache
    participant DB as PostgreSQL

    Client->>Gateway: POST /api/v1/auth/login {email, password}
    Gateway->>DB: Query User & Validate Password Hash
    Gateway->>DB: Insert Refresh Token (Family ID: F1)
    Gateway-->>Client: Return RS256 JWT Access Token + Refresh Token (R1)

    Note over Client, Gateway: Access Token expires after 15m...

    Client->>Gateway: POST /api/v1/auth/refresh {refreshToken: R1}
    Gateway->>DB: Lookup R1 & Check is_revoked status
    Gateway->>DB: Invalidate R1, Issue R2 in Family F1
    Gateway-->>Client: Return New Access Token + New Refresh Token (R2)

    Note over Client, Gateway: Stolen Token Reuse Attack Scenario:
    Client->>Gateway: Attacker sends old R1
    Gateway->>DB: Detect R1 is already revoked!
    Gateway->>DB: Revoke ENTIRE Family F1
    Gateway-->>Client: 401 Unauthorized (TOKEN_REUSE_DETECTED)
```

---

## 🚀 Quick Start (Docker Compose)

### 1. Clone & Start the Stack
```bash
# Start PostgreSQL, Redis, Auth Gateway, and Downstream Microservice
docker-compose up --build -d
```

### 2. Verify Services
- **API Gateway**: `http://localhost:4000`
- **Swagger / OpenAPI Documentation**: `http://localhost:4000/docs`
- **Health Probes**: `http://localhost:4000/health`
- **JWKS Endpoint**: `http://localhost:4000/api/v1/auth/jwks.json`

---

## 🛠️ Local Development Setup

```bash
# 1. Install dependencies
npm install

# 2. Generate 2048-bit RSA Private/Public Keypair
npm run generate-keys

# 3. Copy environment config
cp .env.example .env

# 4. Run database migrations and seed default data
npm run migrate
npm run seed

# 5. Start development server with live reload
npm run dev

# 6. Run automated test suite
npm test
```

---

## 📖 API Usage & Endpoint Examples

### 1. User Login
```bash
curl -X POST http://localhost:4000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "superadmin@acme.com",
    "password": "Password123!",
    "tenantSlug": "acme-corp"
  }'
```

### 2. Token Refresh with Rotation
```bash
curl -X POST http://localhost:4000/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "<YOUR_REFRESH_TOKEN>"
  }'
```

### 3. Logout & Revocation Blacklist
```bash
curl -X POST http://localhost:4000/api/v1/auth/logout \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "<YOUR_REFRESH_TOKEN>"
  }'
```

### 4. Create Organization / Tenant (SuperAdmin Only)
```bash
curl -X POST http://localhost:4000/api/v1/tenants \
  -H "Authorization: Bearer <SUPERADMIN_ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Stark Industries",
    "slug": "stark-industries",
    "plan": "enterprise"
  }'
```

### 5. Register Dynamic Gateway Upstream Route
```bash
curl -X POST http://localhost:4000/api/v1/gateway/routes \
  -H "Authorization: Bearer <SUPERADMIN_ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "pathPrefix": "/api/v1/payments",
    "targetUrl": "http://payment-service:8080",
    "isProtected": true,
    "requiredRoles": ["TenantAdmin", "Member"],
    "requiredPermissions": ["proxy:access"],
    "rateLimitWindowSec": 60,
    "rateLimitMax": 100,
    "stripPrefix": true,
    "customHeaders": {
      "X-Microservice-Version": "v2"
    }
  }'
```

### 6. Accessing Proxied Downstream Microservice
```bash
curl -X GET http://localhost:4000/gateway/api/v1/echo \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

---

## 🔒 Security Best Practices Implemented
1. **Asymmetric Cryptography**: RS256 with isolated private key on Gateway, while downstream services consume only public keys via JWKS.
2. **Defensive Rotation**: Refresh token reuse detection immediately invalidates token family compromise.
3. **Blacklisting with TTL**: Revoked access tokens are blacklisted in Redis with TTL matching remaining validity.
4. **Least Privilege RBAC**: Database-enforced role and permission mapping with tenant boundaries.
5. **DDoS & Brute Force Defense**: Distributed Redis sliding-window limiter on authentication endpoints.
6. **Immutable Audit Trails**: Every state change and auth lifecycle event logged to PostgreSQL.

---

## 📄 License
MIT License. Created by Cloud Solutions & Security Engineering Team.

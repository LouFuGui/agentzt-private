# Vault Integration Guide

> HashiCorp Vault integration for secure secrets management in agentzt gateway.

## Overview

This guide explains how to integrate HashiCorp Vault with agentzt to:

- **Securely store and manage** Model API keys, tool credentials, and gateway signing keys
- **Auto-rotate credentials** for database connections
- **Support HSM integration** (Enterprise tier) for hardware-bound keys
- **Audit all secret access** with Vault's comprehensive logging
- **Fail-safe design** with fallback to environment variables

## Architecture

```
agentzt-gateway (no secrets in code/env)
    ↓
Vault Client
    ├─ Authenticate (token, AppRole, K8s JWT)
    ├─ Read secrets (KV v2 backend)
    ├─ Manage leases (auto-renew, revoke)
    └─ Cache secrets (configurable TTL)
    ↓
Vault Server
    ├─ KV v2 (Anthropic key, tool creds, gateway key)
    ├─ Database (dynamic credentials)
    ├─ Transit (encryption as a service, optional)
    └─ Audit Log (tamper-evident access record)
```

## Quick Start (Local Development)

### 1. Start Vault in dev mode

```bash
# Docker (recommended)
docker run --rm -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID="myroot" \
  vault:latest server -dev

# Or with Homebrew
vault server -dev -dev-root-token-id="myroot"
```

### 2. Configure Vault secrets

```bash
export VAULT_ADDR='http://localhost:8200'
export VAULT_TOKEN='myroot'

# Enable KV v2 secrets engine
vault secrets enable -version=2 -path=secret kv

# Store Anthropic API key
vault kv put secret/agentzt/upstream-anthropic-key \
  key="sk-ant-..." \
  description="Anthropic Claude API key"

# Store tool credentials (example: email)
vault kv put secret/agentzt/tools/email \
  email_user="bot@company.com" \
  email_password="app-specific-password"

# Store gateway signing key (Ed25519 JWK format)
vault kv put secret/agentzt/gateway-signing-key \
  privateKeyJwk='{"kty":"OKP","crv":"Ed25519","d":"..."}'

# Verify secrets
vault kv list secret/agentzt
vault kv get secret/agentzt/upstream-anthropic-key
```

### 3. Update agentzt config

Edit `config/gateway.json`:

```json
{
  "port": 8700,
  "issuer": "agentzt-gateway",
  "upstream": {
    "mode": "passthrough",
    "anthropicBaseUrl": "https://api.anthropic.com"
  },
  "vault": {
    "enabled": true,
    "server": {
      "address": "http://localhost:8200"
    },
    "auth": {
      "method": "token",
      "token": "myroot"
    }
}
```

Or use environment variable:

```bash
export VAULT_ADDR='http://localhost:8200'
export VAULT_TOKEN='myroot'
npm run gateway
```

### 4. Run agentzt

```bash
npm run gateway

# Output:
# ✓ Vault secrets manager initialized
# ✓ Vault authenticated (address: http://localhost:8200)
# ✓ Auto-renewal started (interval: 3600000ms)
```

## Authentication Methods

### Token Auth (Development)

```json
{
  "vault": {
    "enabled": true,
    "server": {
      "address": "http://localhost:8200"
    },
    "auth": {
      "method": "token",
      "token": "s.xxxxxxxxxxxxxxxx"
    }
  }
}
```

**Env vars:** `VAULT_ADDR`, `VAULT_TOKEN`

### AppRole Auth (Production)

```json
{
  "vault": {
    "enabled": true,
    "server": {
      "address": "https://vault.company.com:8200",
      "tls": {
        "ca_cert": "/etc/vault/ca.crt"
      }
    },
    "auth": {
      "method": "approle",
      "roleId": "${VAULT_ROLE_ID}",
      "secretId": "${VAULT_SECRET_ID}",
      "mount": "approle"
    }
  }
}
```

**Setup:**

```bash
# Create AppRole
vault auth enable approle
vault write auth/approle/role/agentzt-gateway \
  token_num_uses=0 \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_num_uses=0 \
  policies="agentzt-policy"

# Get role ID
vault read auth/approle/role/agentzt-gateway/role-id

# Generate secret ID
vault write -f auth/approle/role/agentzt-gateway/secret-id

# Create policy
vault policy write agentzt-policy - <<EOF
path "secret/data/agentzt/*" {
  capabilities = ["read", "list"]
}
path "database/static-creds/postgres-readonly" {
  capabilities = ["read"]
}
path "sys/leases/renew" {
  capabilities = ["update"]
}
path "sys/leases/revoke" {
  capabilities = ["update"]
}
EOF
```

**Env vars:** `VAULT_ROLE_ID`, `VAULT_SECRET_ID`

### Kubernetes Auth (Cloud Native)

```json
{
  "vault": {
    "enabled": true,
    "server": {
      "address": "https://vault.vault.svc.cluster.local:8200",
      "namespace": "agentzt"
    },
    "auth": {
      "method": "kubernetes",
      "role": "agentzt-gateway",
      "jwt": "${KUBE_SA_JWT}"
    }
  }
}
```

**Setup:**

```bash
# Enable Kubernetes auth
vault auth enable kubernetes

# Configure
vault write auth/kubernetes/config \
  kubernetes_host="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT" \
  kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  token_reviewer_jwt=@/var/run/secrets/kubernetes.io/serviceaccount/token

# Create role
vault write auth/kubernetes/role/agentzt-gateway \
  bound_service_account_names=agentzt-gateway \
  bound_service_account_namespaces=default \
  policies=agentzt-policy \
  ttl=1h
```

## Secret Paths

All paths use **KV v2** backend unless otherwise noted.

| Purpose | Path | Notes |
|---------|------|-------|
| **Model API Key** | `secret/data/agentzt/upstream-anthropic-key` | Single `key` field |
| **Gateway Signing Key** | `secret/data/agentzt/gateway-signing-key` | Ed25519 JWK format |
| **Tool Credentials** | `secret/data/agentzt/tools/{toolName}` | Tool-specific fields |
| **Database (dynamic)** | `database/static-creds/{roleName}` | Auto-generated, auto-rotated |

### Example Secrets

**Anthropic API Key:**
```bash
vault kv put secret/agentzt/upstream-anthropic-key \
  key="sk-ant-v0-abc123..."
```

**Tool Credentials (Email):**
```bash
vault kv put secret/agentzt/tools/email \
  email_user="bot@company.com" \
  email_password="xyz789" \
  smtp_host="smtp.gmail.com" \
  smtp_port="587"
```

**Tool Credentials (Database):**
```bash
vault kv put secret/agentzt/tools/database \
  host="db.company.internal" \
  port="5432" \
  database="enterprise" \
  username="agent_readonly" \
  password="secure_password"
```

**Gateway Signing Key:**
```bash
# Generate Ed25519 key first (outside Vault)
openssl genpkey -algorithm ed25519 -out gateway.key
openssl pkey -in gateway.key -text

# Store JWK format
vault kv put secret/agentzt/gateway-signing-key \
  privateKeyJwk='{"kty":"OKP","crv":"Ed25519","d":"..."}'
```

## Dynamic Database Credentials

For auto-rotating database credentials:

### Setup (PostgreSQL example)

```bash
# Enable database secrets engine
vault secrets enable database

# Configure PostgreSQL connection
vault write database/config/postgresql \
  plugin_name=postgresql-database-plugin \
  allowed_roles="readonly,readwrite" \
  connection_url="postgresql://{{username}}:{{password}}@db.example.com:5432/postgres" \
  username="vault" \
  password="vault-password"

# Create readonly role (auto-generates credentials)
vault write database/roles/postgres-readonly \
  db_name=postgresql \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  default_ttl="1h" \
  max_ttl="24h"
```

### Usage in agentzt

```typescript
// Automatically gets fresh credentials every time
const creds = await getDatabaseCredentialsFromVault('postgres-readonly');
// { username: 'v-token-abc123', password: 'xyz789', leaseId: '...', leaseDuration: 3600 }

// Vault auto-rotates these after 1 hour (default_ttl)
// Or manually revoke:
await revokeLease(creds.leaseId);
```

## Configuration Reference

```typescript
interface VaultConfig {
  server: {
    enabled: boolean;
    address: string;           // e.g., 'http://localhost:8200'
    namespace?: string;        // Enterprise edition
    tls?: {
      skip_verify?: boolean;   // NOT for production
      ca_cert?: string;
      client_cert?: string;
      client_key?: string;
    };
  };
  
  auth: {
    method: 'token' | 'approle' | 'kubernetes';
    // ... method-specific fields
  };
  
  secrets?: {
    modelApiKey: string;
    gatewaySigningKey: string;
    toolsPrefix: string;
    databasePrefix: string;
  };
  
  autoRenew?: {
    enabled: boolean;
    intervalMs?: number;       // default: 3600000
  };
  
  cache?: {
    enabled: boolean;
    ttlMs?: number;           // default: 300000
  };
  
  failOpen?: boolean;          // default: false
  timeoutMs?: number;          // default: 5000
}
```

## Security Best Practices

### 1. Use AppRole in Production

❌ **Never** use token auth in production  
✅ **Always** use AppRole or Kubernetes auth

```bash
# Rotate secret IDs regularly
vault write -f auth/approle/role/agentzt-gateway/secret-id
```

### 2. TLS Certificate Verification

```json
{
  "vault": {
    "server": {
      "tls": {
        "ca_cert": "/etc/vault/ca.crt",
        "client_cert": "/etc/vault/client.crt",
        "client_key": "/etc/vault/client.key"
      }
    }
  }
}
```

### 3. HSM Integration (Enterprise)

Store the gateway signing key in an HSM:

```bash
# Configure Vault to use HSM for auto-unseal
vault write sys/config/seal-wrap \
  type="pkcs11" \
  lib="/usr/lib/softhsm/libsofthsm2.so" \
  slot="0" \
  pin="1234"
```

### 4. Audit Logging

Enable Vault audit logging:

```bash
# File audit backend
vault audit enable file file_path=/var/log/vault-audit.log

# Syslog
vault audit enable syslog tag="vault"

# Query audit logs
vault audit list
vault read sys/audit
```

### 5. Least Privilege Policies

```bash
# Create restrictive policy for agentzt-gateway
vault policy write agentzt-policy - <<EOF
# Read-only access to secrets
path "secret/data/agentzt/*" {
  capabilities = ["read", "list"]
}

# Database credentials (read-only)
path "database/static-creds/postgres-readonly" {
  capabilities = ["read"]
}

# Lease renewal only (no revoke)
path "sys/leases/renew" {
  capabilities = ["update"]
}

# Deny all other paths
path "*" {
  capabilities = ["deny"]
}
EOF
```

## Troubleshooting

### Issue: "Vault client not available"

**Cause:** Vault initialization failed or `failOpen=false`

**Fix:**
```bash
# Check Vault is running
curl http://localhost:8200/v1/sys/health

# Check auth credentials
export VAULT_ADDR='http://localhost:8200'
vault login -method=approle \
  role_id="..." \
  secret_id="..."

# Enable debug logging
AGENTZT_LOG_LEVEL=debug npm run gateway
```

### Issue: "Failed to renew lease"

**Cause:** Lease expired or revoked

**Fix:**
```bash
# Check lease status
vault lease lookup database/static-creds/postgres-readonly/abc123

# Increase TTL
vault write database/roles/postgres-readonly max_ttl="48h"
```

### Issue: "Vault error: 403 permission denied"

**Cause:** AppRole policy insufficient

**Fix:** Verify policy grants correct paths:
```bash
vault read auth/approle/role/agentzt-gateway
vault policy read agentzt-policy
```

## Migration from Env Vars

1. **Add Vault config** to `gateway.json`
2. **Keep env var** fallback temporarily
3. **Test with Vault** enabled
4. **Remove env vars** from CI/CD
5. **Update documentation**

```bash
# Before (env vars)
export AGENTZT_UPSTREAM_ANTHROPIC_KEY="sk-ant-..."

# After (Vault)
export VAULT_ADDR='http://localhost:8200'
export VAULT_TOKEN='s.xxx'
npm run gateway
```

## Advanced Topics

### Multi-cluster Deployment

Use Vault Enterprise namespaces for isolation:

```json
{
  "vault": {
    "server": {
      "address": "https://vault.company.com:8200",
      "namespace": "agentzt/prod/us-east-1"
    }
  }
}
```

### Secret Rotation Strategies

1. **Lease-based** (automatic): Database credentials, short TTL
2. **Static** (manual): API keys, long TTL, audit-triggered rotation
3. **Transit** (encryption): Encrypt agent requests before sending

### Observability

Monitor Vault access:

```bash
# Tail audit log
tail -f /var/log/vault-audit.log | jq

# Query specific agent access
vault audit list
```

## References

- [Vault Official Docs](https://www.vaultproject.io/docs)
- [AppRole Auth Method](https://www.vaultproject.io/docs/auth/approle)
- [Database Secrets Engine](https://www.vaultproject.io/docs/secrets/databases)
- [Kubernetes Auth Method](https://www.vaultproject.io/docs/auth/kubernetes)
- [Vault HSM Integration](https://www.vaultproject.io/docs/configuration/seal)

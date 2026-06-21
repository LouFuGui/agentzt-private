/**
 * Vault configuration and types for secrets management.
 * Supports multiple authentication methods and secret backends.
 */

export type VaultAuthMethod = 'token' | 'approle' | 'kubernetes';

export interface VaultAppRoleAuth {
  method: 'approle';
  roleId: string;           // from env var or config
  secretId: string;         // from env var or config
  mount?: string;           // default: 'approle'
}

export interface VaultTokenAuth {
  method: 'token';
  token: string;            // from VAULT_TOKEN env var
}

export interface VaultKubernetesAuth {
  method: 'kubernetes';
  role: string;
  jwt: string;              // service account JWT
  mount?: string;           // default: 'kubernetes'
}

export type VaultAuth = VaultTokenAuth | VaultAppRoleAuth | VaultKubernetesAuth;

/**
 * Vault secret paths and their purposes.
 * All paths use KV v2 backend (secret/data/...).
 */
export interface VaultSecretPaths {
  // Model API credentials
  modelApiKey: string;      // default: secret/data/agentzt/upstream-anthropic-key
  
  // Gateway signing key (HSM integration in Enterprise)
  gatewaySigningKey: string; // default: secret/data/agentzt/gateway-signing-key
  
  // Tool-specific credentials (tool name as suffix)
  toolsPrefix: string;      // default: secret/data/agentzt/tools
  
  // Database dynamic credentials
  databasePrefix: string;   // default: database/static-creds
}

/**
 * Vault server configuration.
 */
export interface VaultServerConfig {
  address: string;          // e.g., 'http://localhost:8200' or 'https://vault.company.com:8200'
  namespace?: string;       // Enterprise edition feature
  tls?: {
    skip_verify?: boolean;  // NOT recommended for production
    ca_cert?: string;       // path to CA cert file
    client_cert?: string;   // path to client cert file
    client_key?: string;    // path to client key file
  };
}

/**
 * Complete Vault integration configuration.
 */
export interface VaultConfig {
  enabled: boolean;
  server: VaultServerConfig;
  auth: VaultAuth;
  secrets?: VaultSecretPaths;
  
  // Auto-renewal settings
  autoRenew?: {
    enabled: boolean;
    intervalMs?: number;    // default: 3600000 (1 hour)
  };
  
  // Lease management
  leaseManagement?: {
    enabled: boolean;
    revokeOnShutdown?: boolean; // default: true
  };
  
  // Caching (advanced)
  cache?: {
    enabled: boolean;
    ttlMs?: number;         // default: 300000 (5 minutes)
  };
  
  // Error handling
  failOpen?: boolean;       // default: false (fail closed for security)
  timeoutMs?: number;       // default: 5000
}

/**
 * Default Vault secret paths.
 */
export const DEFAULT_VAULT_PATHS: VaultSecretPaths = {
  modelApiKey: 'secret/data/agentzt/upstream-anthropic-key',
  gatewaySigningKey: 'secret/data/agentzt/gateway-signing-key',
  toolsPrefix: 'secret/data/agentzt/tools',
  databasePrefix: 'database/static-creds',
};

/**
 * Default Vault configuration.
 */
export const DEFAULT_VAULT_CONFIG: Partial<VaultConfig> = {
  autoRenew: {
    enabled: true,
    intervalMs: 3600000, // 1 hour
  },
  leaseManagement: {
    enabled: true,
    revokeOnShutdown: true,
  },
  cache: {
    enabled: true,
    ttlMs: 300000, // 5 minutes
  },
  failOpen: false,
  timeoutMs: 5000,
};

export type VaultAuthMethod = 'token' | 'approle' | 'kubernetes';

export interface VaultAppRoleAuth {
  method: 'approle';
  roleId: string;
  secretId: string;
  mount?: string;
}

export interface VaultTokenAuth {
  method: 'token';
  token: string;
}

export interface VaultKubernetesAuth {
  method: 'kubernetes';
  role: string;
  jwt: string;
  mount?: string;
}

export type VaultAuth = VaultTokenAuth | VaultAppRoleAuth | VaultKubernetesAuth;

export interface VaultSecretPaths {
  modelApiKey: string;
  gatewaySigningKey: string;
  toolsPrefix: string;
  databasePrefix: string;
}

export interface VaultServerConfig {
  address: string;
  namespace?: string;
  tls?: {
    skip_verify?: false;
    ca_cert?: string;
    client_cert?: string;
    client_key?: string;
  };
}

export interface VaultConfig {
  enabled: boolean;
  server: VaultServerConfig;
  auth: VaultAuth;
  secrets?: VaultSecretPaths;
  autoRenew?: {
    enabled: boolean;
    intervalMs?: number;
  };
  leaseManagement?: {
    enabled: boolean;
    revokeOnShutdown?: boolean;
  };
  cache?: {
    enabled: boolean;
    ttlMs?: number;
  };
  failOpen?: boolean;
  timeoutMs?: number;
}

export const DEFAULT_VAULT_PATHS: VaultSecretPaths = {
  modelApiKey: 'secret/data/agentzt/upstream-anthropic-key',
  gatewaySigningKey: 'secret/data/agentzt/gateway-signing-key',
  toolsPrefix: 'secret/data/agentzt/tools',
  databasePrefix: 'database/static-creds',
};

export const DEFAULT_VAULT_CONFIG = {
  autoRenew: {
    enabled: true,
    intervalMs: 3600000,
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

export function resolveVaultConfig(input?: Partial<VaultConfig>): VaultConfig | null {
  const envEnabled = process.env.AGENTZT_VAULT === '1' ||
    (process.env.VAULT_ADDR !== undefined && process.env.VAULT_TOKEN !== undefined);
  if (!input?.enabled && !envEnabled) return null;

  const method = (process.env.VAULT_AUTH_METHOD ?? input?.auth?.method ?? 'token') as VaultAuthMethod;
  const address = process.env.VAULT_ADDR ?? input?.server?.address;
  if (!address) throw new Error('Vault address is required (vault.server.address or VAULT_ADDR)');

  const auth = resolveVaultAuth(method, input?.auth);
  return {
    enabled: true,
    server: {
      address,
      namespace: process.env.VAULT_NAMESPACE ?? input?.server?.namespace,
      tls: input?.server?.tls,
    },
    auth,
    secrets: { ...DEFAULT_VAULT_PATHS, ...input?.secrets },
    autoRenew: { ...DEFAULT_VAULT_CONFIG.autoRenew, ...input?.autoRenew },
    leaseManagement: { ...DEFAULT_VAULT_CONFIG.leaseManagement, ...input?.leaseManagement },
    cache: { ...DEFAULT_VAULT_CONFIG.cache, ...input?.cache },
    failOpen: input?.failOpen ?? DEFAULT_VAULT_CONFIG.failOpen,
    timeoutMs: input?.timeoutMs ?? DEFAULT_VAULT_CONFIG.timeoutMs,
  };
}

function resolveVaultAuth(method: VaultAuthMethod, input?: VaultAuth): VaultAuth {
  if (method === 'token') {
    const token = process.env.VAULT_TOKEN ?? (input?.method === 'token' ? input.token : '');
    if (!token) throw new Error('Vault token auth requires vault.auth.token or VAULT_TOKEN');
    return { method, token };
  }
  if (method === 'approle') {
    const roleId = process.env.VAULT_ROLE_ID ?? (input?.method === 'approle' ? input.roleId : '');
    const secretId = process.env.VAULT_SECRET_ID ?? (input?.method === 'approle' ? input.secretId : '');
    if (!roleId || !secretId) throw new Error('Vault AppRole auth requires roleId/secretId or VAULT_ROLE_ID/VAULT_SECRET_ID');
    return { method, roleId, secretId, mount: input?.method === 'approle' ? input.mount : undefined };
  }
  const role = process.env.VAULT_K8S_ROLE ?? (input?.method === 'kubernetes' ? input.role : '');
  const jwt = process.env.VAULT_JWT ?? (input?.method === 'kubernetes' ? input.jwt : '');
  if (!role || !jwt) throw new Error('Vault Kubernetes auth requires role/jwt or VAULT_K8S_ROLE/VAULT_JWT');
  return { method, role, jwt, mount: input?.method === 'kubernetes' ? input.mount : undefined };
}

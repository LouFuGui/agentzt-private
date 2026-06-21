import type {
  VaultConfig,
  VaultAuth,
  VaultSecretPaths,
  VaultTokenAuth,
  VaultAppRoleAuth,
  VaultKubernetesAuth,
} from './vault-config.ts';
import { DEFAULT_VAULT_PATHS, DEFAULT_VAULT_CONFIG } from './vault-config.ts';
import { makeLogger } from '../shared/log.ts';

const log = makeLogger('vault');

export interface SecretData {
  [key: string]: string | number | boolean;
}

export interface VaultSecret {
  leaseId: string;
  leaseDuration: number;
  renewable: boolean;
  data: SecretData;
}

export interface DatabaseCredentials {
  username: string;
  password: string;
  leaseId?: string;
  leaseDuration?: number;
}

/**
 * Vault client for retrieving and managing secrets.
 * Supports multiple auth methods, caching, and auto-renewal.
 */
export class VaultClient {
  private config: VaultConfig;
  private secretPaths: VaultSecretPaths;
  private token: string = '';
  private tokenExpiry: number = 0;
  private secretCache: Map<string, { data: SecretData; expiry: number }> = new Map();
  private leaseIds: Set<string> = new Set();
  private renewalIntervalId?: NodeJS.Timeout;

  constructor(config: VaultConfig) {
    this.config = { ...config };
    this.secretPaths = config.secrets ?? DEFAULT_VAULT_PATHS;
    
    // Validate configuration
    if (!this.config.server?.address) {
      throw new Error('Vault address is required');
    }
    if (!this.config.auth) {
      throw new Error('Vault auth method is required');
    }
  }

  /**
   * Initialize the Vault client: authenticate and setup auto-renewal.
   */
  async init(): Promise<void> {
    try {
      // Authenticate to Vault
      await this.authenticate();
      log.info(`✓ Vault authenticated (address: ${this.config.server.address})`);

      // Start auto-renewal if configured
      if (this.config.autoRenew?.enabled) {
        this.startAutoRenewal();
      }
    } catch (err) {
      const msg = `Failed to initialize Vault: ${(err as Error).message}`;
      log.error(msg);
      if (!this.config.failOpen) {
        throw new Error(msg);
      }
      log.warn('failOpen=true, continuing without Vault');
    }
  }

  /**
   * Authenticate to Vault using the configured auth method.
   */
  private async authenticate(): Promise<void> {
    const auth = this.config.auth;
    let token: string;

    if (auth.method === 'token') {
      const ta = auth as VaultTokenAuth;
      token = ta.token;
    } else if (auth.method === 'approle') {
      const aa = auth as VaultAppRoleAuth;
      const resp = await this.request('POST', `/v1/auth/${aa.mount ?? 'approle'}/login`, {
        role_id: aa.roleId,
        secret_id: aa.secretId,
      });
      token = resp.auth.client_token;
      this.tokenExpiry = Math.floor(Date.now() / 1000) + resp.auth.lease_duration;
    } else if (auth.method === 'kubernetes') {
      const ka = auth as VaultKubernetesAuth;
      const resp = await this.request('POST', `/v1/auth/${ka.mount ?? 'kubernetes'}/login`, {
        role: ka.role,
        jwt: ka.jwt,
      });
      token = resp.auth.client_token;
      this.tokenExpiry = Math.floor(Date.now() / 1000) + resp.auth.lease_duration;
    } else {
      throw new Error(`Unknown auth method: ${(auth as any).method}`);
    }

    this.token = token;
  }

  /**
   * Retrieve the Model API key from Vault.
   */
  async getModelApiKey(): Promise<string> {
    const secret = await this.readSecret(this.secretPaths.modelApiKey);
    const key = secret.data['key'] || secret.data['api_key'] || secret.data['anthropic_key'];
    if (!key) {
      throw new Error('Model API key not found in Vault secret');
    }
    return String(key);
  }

  /**
   * Retrieve tool credentials from Vault.
   * Path: secret/data/agentzt/tools/{toolName}
   */
  async getToolCredentials(toolName: string): Promise<SecretData> {
    const path = `${this.secretPaths.toolsPrefix}/${toolName}`;
    const secret = await this.readSecret(path);
    return secret.data;
  }

  /**
   * Retrieve the gateway signing key (JWK format).
   */
  async getGatewaySigningKey(): Promise<JsonWebKey> {
    const secret = await this.readSecret(this.secretPaths.gatewaySigningKey);
    const key = secret.data['privateKeyJwk'] || secret.data['key'];
    if (!key) {
      throw new Error('Gateway signing key not found in Vault secret');
    }
    if (typeof key === 'string') {
      try {
        return JSON.parse(key) as JsonWebKey;
      } catch {
        return key as JsonWebKey;
      }
    }
    return key as JsonWebKey;
  }

  /**
   * Retrieve dynamic database credentials.
   * Vault automatically generates and manages the lifecycle.
   */
  async getDatabaseCredentials(roleName: string): Promise<DatabaseCredentials> {
    const path = `${this.secretPaths.databasePrefix}/${roleName}`;
    const secret = await this.readSecret(path);
    
    if (secret.leaseId) {
      this.leaseIds.add(secret.leaseId);
    }

    return {
      username: String(secret.data['username']),
      password: String(secret.data['password']),
      leaseId: secret.leaseId,
      leaseDuration: secret.leaseDuration,
    };
  }

  /**
   * Read a secret from Vault (with caching support).
   */
  private async readSecret(path: string): Promise<VaultSecret> {
    // Check cache first
    if (this.config.cache?.enabled) {
      const cached = this.secretCache.get(path);
      if (cached && cached.expiry > Date.now()) {
        return { leaseId: '', leaseDuration: 0, renewable: false, data: cached.data };
      }
      this.secretCache.delete(path);
    }

    // Fetch from Vault
    const resp = await this.request('GET', `/v1/${path}`);
    const secret: VaultSecret = {
      leaseId: resp.lease_id || '',
      leaseDuration: resp.lease_duration || 3600,
      renewable: resp.renewable ?? false,
      data: resp.data?.data || resp.data,
    };

    // Cache the secret
    if (this.config.cache?.enabled) {
      const ttl = this.config.cache.ttlMs ?? 300000;
      this.secretCache.set(path, { data: secret.data, expiry: Date.now() + ttl });
    }

    return secret;
  }

  /**
   * Renew a lease (for long-lived credentials).
   */
  async renewLease(leaseId: string): Promise<void> {
    try {
      await this.request('PUT', `/v1/sys/leases/renew`, { lease_id: leaseId });
      log.debug(`✓ Renewed lease ${leaseId.slice(0, 20)}...`);
    } catch (err) {
      log.warn(`Failed to renew lease: ${(err as Error).message}`);
    }
  }

  /**
   * Revoke a lease (cleanup).
   */
  async revokeLease(leaseId: string): Promise<void> {
    try {
      await this.request('PUT', `/v1/sys/leases/revoke`, { lease_id: leaseId });
      this.leaseIds.delete(leaseId);
      log.debug(`✓ Revoked lease ${leaseId.slice(0, 20)}...`);
    } catch (err) {
      log.warn(`Failed to revoke lease: ${(err as Error).message}`);
    }
  }

  /**
   * Start automatic lease renewal.
   */
  private startAutoRenewal(): void {
    const interval = this.config.autoRenew?.intervalMs ?? 3600000;
    this.renewalIntervalId = setInterval(async () => {
      const leases = Array.from(this.leaseIds);
      for (const leaseId of leases) {
        await this.renewLease(leaseId);
      }
    }, interval);
    log.info(`✓ Auto-renewal started (interval: ${interval}ms)`);
  }

  /**
   * Cleanup: revoke all managed leases.
   */
  async shutdown(): Promise<void> {
    // Stop auto-renewal
    if (this.renewalIntervalId) {
      clearInterval(this.renewalIntervalId);
    }

    // Revoke all leases
    if (this.config.leaseManagement?.revokeOnShutdown) {
      const leases = Array.from(this.leaseIds);
      for (const leaseId of leases) {
        await this.revokeLease(leaseId);
      }
    }

    this.secretCache.clear();
    log.info('✓ Vault client shutdown');
  }

  /**
   * Make an HTTP request to Vault.
   */
  private async request(
    method: string,
    path: string,
    body?: Record<string, unknown>,
  ): Promise<any> {
    const url = new URL(path, this.config.server.address);
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
      'X-Vault-Token': this.token,
    };

    if (this.config.server.namespace) {
      headers['X-Vault-Namespace'] = this.config.server.namespace;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeoutMs ?? 5000);

    try {
      const resp = await fetch(url.toString(), {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      const data = await resp.json();

      if (!resp.ok) {
        throw new Error(`Vault error: ${resp.status} ${data.errors?.join(', ') || data.error || ''}`);
      }

      return data;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Health check: is Vault accessible?
   */
  async healthCheck(): Promise<boolean> {
    try {
      await this.request('GET', '/v1/sys/health');
      return true;
    } catch {
      return false;
    }
  }
}

/**
 * Create and initialize a Vault client from config.
 */
export async function createVaultClient(config: VaultConfig): Promise<VaultClient> {
  const client = new VaultClient(config);
  await client.init();
  return client;
}

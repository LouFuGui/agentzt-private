import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { readFileSync } from 'node:fs';
import type { RequestOptions } from 'node:https';
import type {
  VaultConfig,
  VaultSecretPaths,
  VaultTokenAuth,
  VaultAppRoleAuth,
  VaultKubernetesAuth,
} from './vault-config.ts';
import { DEFAULT_VAULT_PATHS } from './vault-config.ts';
import { makeLogger } from '../shared/log.ts';

const log = makeLogger('vault');

export type SecretData = Record<string, string | number | boolean | JsonWebKey>;

export type VaultSecret = {
  leaseId: string;
  leaseDuration: number;
  renewable: boolean;
  data: SecretData;
};

export type DatabaseCredentials = {
  username: string;
  password: string;
  leaseId?: string;
  leaseDuration?: number;
};

type VaultResponse = {
  auth?: {
    client_token?: string;
    lease_duration?: number;
    renewable?: boolean;
  };
  lease_id?: string;
  lease_duration?: number;
  renewable?: boolean;
  data?: Record<string, unknown>;
  errors?: string[];
  error?: string;
};

export class VaultClient {
  private config: VaultConfig;
  private secretPaths: VaultSecretPaths;
  private token = '';
  private tokenExpiry = 0;
  private secretCache = new Map<string, { secret: VaultSecret; expiry: number }>();
  private leaseIds = new Set<string>();
  private renewalIntervalId?: NodeJS.Timeout;

  constructor(config: VaultConfig) {
    this.config = { ...config };
    this.secretPaths = { ...DEFAULT_VAULT_PATHS, ...config.secrets };
    if (!this.config.server.address) throw new Error('Vault address is required');
  }

  async init(): Promise<void> {
    try {
      await this.authenticate();
      log.info(`Vault authenticated (address: ${this.config.server.address})`);
      if (this.config.autoRenew?.enabled) this.startAutoRenewal();
    } catch (err) {
      const msg = `Failed to initialize Vault: ${(err as Error).message}`;
      log.error(msg);
      if (!this.config.failOpen) throw new Error(msg);
      log.warn('failOpen=true, continuing without Vault');
    }
  }

  private async authenticate(): Promise<void> {
    const auth = this.config.auth;
    if (auth.method === 'token') {
      const token = (auth as VaultTokenAuth).token;
      if (!token) throw new Error('Vault token is empty');
      this.token = token;
      return;
    }

    if (auth.method === 'approle') {
      const appRole = auth as VaultAppRoleAuth;
      const resp = await this.request('POST', `/v1/auth/${appRole.mount ?? 'approle'}/login`, {
        role_id: appRole.roleId,
        secret_id: appRole.secretId,
      }, false);
      this.setTokenFromAuth(resp);
      return;
    }

    if (auth.method === 'kubernetes') {
      const kubernetes = auth as VaultKubernetesAuth;
      const resp = await this.request('POST', `/v1/auth/${kubernetes.mount ?? 'kubernetes'}/login`, {
        role: kubernetes.role,
        jwt: kubernetes.jwt,
      }, false);
      this.setTokenFromAuth(resp);
      return;
    }

    throw new Error(`Unknown Vault auth method: ${(auth as { method?: string }).method}`);
  }

  private setTokenFromAuth(resp: VaultResponse): void {
    const token = resp.auth?.client_token;
    if (!token) throw new Error('Vault login response did not include a client token');
    this.token = token;
    const ttl = resp.auth?.lease_duration ?? 0;
    if (ttl > 0) this.tokenExpiry = Math.floor(Date.now() / 1000) + ttl;
  }

  async getModelApiKey(): Promise<string> {
    const secret = await this.readSecret(this.secretPaths.modelApiKey);
    const key = secret.data['key'] ?? secret.data['api_key'] ?? secret.data['anthropic_key'];
    if (!key) throw new Error('Model API key not found in Vault secret');
    return String(key);
  }

  async getToolCredentials(toolName: string): Promise<SecretData> {
    const safeName = encodeURIComponent(toolName).replace(/%2F/gi, '/');
    const secret = await this.readSecret(`${this.secretPaths.toolsPrefix}/${safeName}`);
    return secret.data;
  }

  async getGatewaySigningKey(): Promise<JsonWebKey> {
    const secret = await this.readSecret(this.secretPaths.gatewaySigningKey);
    const key = secret.data['privateKeyJwk'] ?? secret.data['key'];
    if (!key) throw new Error('Gateway signing key not found in Vault secret');
    if (typeof key === 'string') {
      try {
        return JSON.parse(key) as JsonWebKey;
      } catch (err) {
        throw new Error(`Gateway signing key in Vault must be valid JWK JSON: ${(err as Error).message}`);
      }
    }
    if (typeof key === 'object') return key as JsonWebKey;
    throw new Error('Gateway signing key in Vault must be a JWK object or JSON string');
  }

  async getDatabaseCredentials(roleName: string): Promise<DatabaseCredentials> {
    const secret = await this.readSecret(`${this.secretPaths.databasePrefix}/${roleName}`);
    if (secret.leaseId) this.leaseIds.add(secret.leaseId);
    const username = secret.data['username'];
    const password = secret.data['password'];
    if (username == null || password == null) {
      throw new Error(`Database credentials not found in Vault secret for role "${roleName}"`);
    }
    return {
      username: String(username),
      password: String(password),
      leaseId: secret.leaseId || undefined,
      leaseDuration: secret.leaseDuration || undefined,
    };
  }

  private async readSecret(path: string): Promise<VaultSecret> {
    const cached = this.config.cache?.enabled ? this.secretCache.get(path) : undefined;
    if (cached && cached.expiry > Date.now()) return cached.secret;
    if (cached) this.secretCache.delete(path);

    const resp = await this.request('GET', `/v1/${path}`);
    const secret: VaultSecret = {
      leaseId: resp.lease_id ?? '',
      leaseDuration: resp.lease_duration ?? 0,
      renewable: resp.renewable ?? false,
      data: unwrapKvData(resp.data),
    };

    if (this.config.cache?.enabled) {
      const configuredTtl = this.config.cache.ttlMs ?? 300000;
      const leaseTtl = secret.leaseDuration > 0 ? Math.max(1000, Math.floor(secret.leaseDuration * 800)) : configuredTtl;
      this.secretCache.set(path, { secret, expiry: Date.now() + Math.min(configuredTtl, leaseTtl) });
    }
    return secret;
  }

  async renewLease(leaseId: string): Promise<void> {
    try {
      await this.request('PUT', '/v1/sys/leases/renew', { lease_id: leaseId });
      log.info(`Renewed Vault lease ${leaseId.slice(0, 20)}...`);
    } catch (err) {
      log.warn(`Failed to renew Vault lease: ${(err as Error).message}`);
    }
  }

  async revokeLease(leaseId: string): Promise<void> {
    try {
      await this.request('PUT', '/v1/sys/leases/revoke', { lease_id: leaseId });
      this.leaseIds.delete(leaseId);
      log.info(`Revoked Vault lease ${leaseId.slice(0, 20)}...`);
    } catch (err) {
      log.warn(`Failed to revoke Vault lease: ${(err as Error).message}`);
    }
  }

  private startAutoRenewal(): void {
    const interval = this.config.autoRenew?.intervalMs ?? 3600000;
    this.renewalIntervalId = setInterval(async () => {
      if (this.tokenExpiry > 0 && this.tokenExpiry - Math.floor(Date.now() / 1000) < interval / 1000) {
        await this.renewSelfToken();
      }
      for (const leaseId of Array.from(this.leaseIds)) await this.renewLease(leaseId);
    }, interval);
    this.renewalIntervalId.unref?.();
    log.info(`Vault auto-renewal started (interval: ${interval}ms)`);
  }

  private async renewSelfToken(): Promise<void> {
    try {
      const resp = await this.request('POST', '/v1/auth/token/renew-self');
      const ttl = resp.auth?.lease_duration ?? 0;
      if (ttl > 0) this.tokenExpiry = Math.floor(Date.now() / 1000) + ttl;
      log.info('Renewed Vault client token');
    } catch (err) {
      log.warn(`Failed to renew Vault client token: ${(err as Error).message}`);
    }
  }

  async shutdown(): Promise<void> {
    if (this.renewalIntervalId) clearInterval(this.renewalIntervalId);
    if (this.config.leaseManagement?.revokeOnShutdown) {
      for (const leaseId of Array.from(this.leaseIds)) await this.revokeLease(leaseId);
    }
    this.secretCache.clear();
    log.info('Vault client shutdown');
  }

  private async request(
    method: string,
    path: string,
    body?: Record<string, unknown>,
    includeToken = true,
  ): Promise<VaultResponse> {
    const url = new URL(path, this.config.server.address);
    const payload = body ? Buffer.from(JSON.stringify(body)) : undefined;
    const headers: Record<string, string | number> = { 'Content-Type': 'application/json' };
    if (includeToken && this.token) headers['X-Vault-Token'] = this.token;
    if (this.config.server.namespace) headers['X-Vault-Namespace'] = this.config.server.namespace;
    if (payload) headers['Content-Length'] = payload.length;

    const options: RequestOptions = {
      method,
      hostname: url.hostname,
      port: url.port,
      path: `${url.pathname}${url.search}`,
      headers,
      timeout: this.config.timeoutMs ?? 5000,
      ...tlsOptions(this.config),
    };

    const transport = url.protocol === 'https:' ? httpsRequest : httpRequest;
    return await new Promise<VaultResponse>((resolve, reject) => {
      const req = transport(options, (resp) => {
        const chunks: Buffer[] = [];
        resp.on('data', (chunk: Buffer) => chunks.push(chunk));
        resp.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          const data = text ? JSON.parse(text) as VaultResponse : {};
          if ((resp.statusCode ?? 500) < 200 || (resp.statusCode ?? 500) >= 300) {
            reject(new Error(`Vault error: ${resp.statusCode} ${data.errors?.join(', ') ?? data.error ?? ''}`.trim()));
            return;
          }
          resolve(data);
        });
      });
      req.on('timeout', () => req.destroy(new Error(`Vault request timed out after ${options.timeout}ms`)));
      req.on('error', reject);
      if (payload) req.write(payload);
      req.end();
    });
  }

  async healthCheck(): Promise<boolean> {
    try {
      await this.request('GET', '/v1/sys/health');
      return true;
    } catch {
      return false;
    }
  }
}

function unwrapKvData(data: Record<string, unknown> | undefined): SecretData {
  const raw = data?.['data'];
  const value = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : data;
  const out: SecretData = {};
  for (const [key, entry] of Object.entries(value ?? {})) {
    if (typeof entry === 'string' || typeof entry === 'number' || typeof entry === 'boolean') {
      out[key] = entry;
    } else if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
      out[key] = entry as JsonWebKey;
    }
  }
  return out;
}

function tlsOptions(config: VaultConfig): RequestOptions {
  const tls = config.server.tls;
  if (!tls) return {};
  return {
    rejectUnauthorized: tls.skip_verify ? false : undefined,
    ca: tls.ca_cert ? readFileSync(tls.ca_cert) : undefined,
    cert: tls.client_cert ? readFileSync(tls.client_cert) : undefined,
    key: tls.client_key ? readFileSync(tls.client_key) : undefined,
  };
}

export async function createVaultClient(config: VaultConfig): Promise<VaultClient> {
  const client = new VaultClient(config);
  await client.init();
  return client;
}

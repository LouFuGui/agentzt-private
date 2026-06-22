import type { VaultConfig } from './vault-config.ts';
import { VaultClient } from './vault-client.ts';
import { makeLogger } from '../shared/log.ts';

const log = makeLogger('vault-secrets');

let globalVaultClient: VaultClient | null = null;
let initPromise: Promise<VaultClient | null> | null = null;

export async function initializeVault(config: VaultConfig | null | undefined): Promise<VaultClient | null> {
  if (!config?.enabled) return null;
  if (globalVaultClient) return globalVaultClient;
  if (initPromise) return await initPromise;

  initPromise = (async () => {
    try {
      const client = new VaultClient(config);
      await client.init();
      globalVaultClient = client;
      log.info('Vault secrets manager initialized');
      return client;
    } catch (err) {
      initPromise = null;
      log.error(`Failed to initialize Vault: ${(err as Error).message}`);
      if (!config.failOpen) throw err;
      return null;
    }
  })();

  return await initPromise;
}

export function getVaultClient(): VaultClient | null {
  return globalVaultClient;
}

export async function getModelApiKeyFromVault(
  config: VaultConfig | null | undefined,
  fallbackEnvVar?: string,
): Promise<string | null> {
  const client = await initializeVault(config);
  if (client) {
    try {
      return await client.getModelApiKey();
    } catch (err) {
      log.error(`Failed to get model API key from Vault: ${(err as Error).message}`);
      if (!config?.failOpen) throw err;
    }
  }

  return fallbackEnvVar ? process.env[fallbackEnvVar] ?? null : null;
}

export async function getToolCredentialsFromVault(
  config: VaultConfig | null | undefined,
  toolName: string,
): Promise<Record<string, string>> {
  const client = await initializeVault(config);
  if (!client) return {};

  try {
    const creds = await client.getToolCredentials(toolName);
    const stringCreds: Record<string, string> = {};
    for (const [key, value] of Object.entries(creds)) {
      stringCreds[key] = typeof value === 'object' ? JSON.stringify(value) : String(value);
    }
    return stringCreds;
  } catch (err) {
    log.warn(`Failed to get credentials for tool ${toolName}: ${(err as Error).message}`);
    if (!config?.failOpen) throw err;
    return {};
  }
}

export async function getGatewaySigningKeyFromVault(
  config: VaultConfig | null | undefined,
): Promise<JsonWebKey | null> {
  const client = await initializeVault(config);
  if (!client) return null;

  try {
    return await client.getGatewaySigningKey();
  } catch (err) {
    log.error(`Failed to get gateway signing key from Vault: ${(err as Error).message}`);
    if (!config?.failOpen) throw err;
    return null;
  }
}

export async function getDatabaseCredentialsFromVault(
  config: VaultConfig | null | undefined,
  roleName: string,
) {
  const client = await initializeVault(config);
  if (!client) throw new Error('Vault client not available');
  return await client.getDatabaseCredentials(roleName);
}

export async function shutdownVault(): Promise<void> {
  if (globalVaultClient) {
    await globalVaultClient.shutdown();
    globalVaultClient = null;
  }
  initPromise = null;
}

export async function checkVaultHealth(): Promise<boolean> {
  if (!globalVaultClient) return false;
  return await globalVaultClient.healthCheck();
}

/**
 * Vault secrets manager that integrates with agentzt gateway.
 * Provides a unified interface for all secret retrieval needs.
 */

import type { VaultConfig } from './vault-config.ts';
import { VaultClient } from './vault-client.ts';
import { makeLogger } from '../shared/log.ts';

const log = makeLogger('vault-secrets');

/**
 * Global Vault client instance (singleton).
 */
let globalVaultClient: VaultClient | null = null;

/**
 * Initialize the global Vault client.
 */
export async function initializeVault(config: VaultConfig): Promise<void> {
  try {
    globalVaultClient = new VaultClient(config);
    await globalVaultClient.init();
    log.info('✓ Vault secrets manager initialized');
  } catch (err) {
    log.error(`Failed to initialize Vault: ${(err as Error).message}`);
    if (!config.failOpen) {
      throw err;
    }
  }
}

/**
 * Get the global Vault client instance.
 */
export function getVaultClient(): VaultClient | null {
  return globalVaultClient;
}

/**
 * Retrieve the Model API key from Vault.
 * Falls back to environment variable if Vault is not available.
 */
export async function getModelApiKeyFromVault(
  vaultEnabled: boolean,
  fallbackEnvVar?: string,
): Promise<string | null> {
  if (vaultEnabled && globalVaultClient) {
    try {
      return await globalVaultClient.getModelApiKey();
    } catch (err) {
      log.error(`Failed to get model API key from Vault: ${(err as Error).message}`);
      // Fall through to env var fallback
    }
  }

  // Fallback to environment variable
  if (fallbackEnvVar) {
    return process.env[fallbackEnvVar] || null;
  }

  return null;
}

/**
 * Retrieve tool credentials from Vault.
 * Falls back to empty object if Vault is not available.
 */
export async function getToolCredentialsFromVault(toolName: string): Promise<Record<string, string>> {
  if (!globalVaultClient) {
    log.debug(`Vault client not available, no credentials for tool: ${toolName}`);
    return {};
  }

  try {
    const creds = await globalVaultClient.getToolCredentials(toolName);
    // Convert all values to strings
    const stringCreds: Record<string, string> = {};
    for (const [key, value] of Object.entries(creds)) {
      stringCreds[key] = String(value);
    }
    return stringCreds;
  } catch (err) {
    log.warn(`Failed to get credentials for tool ${toolName}: ${(err as Error).message}`);
    return {};
  }
}

/**
 * Retrieve the gateway signing key from Vault.
 * Falls back to local file if Vault is not available.
 */
export async function getGatewaySigningKeyFromVault(
  vaultEnabled: boolean,
): Promise<JsonWebKey | null> {
  if (vaultEnabled && globalVaultClient) {
    try {
      return await globalVaultClient.getGatewaySigningKey();
    } catch (err) {
      log.error(`Failed to get gateway signing key from Vault: ${(err as Error).message}`);
      // Fall through to local file fallback
    }
  }

  return null;
}

/**
 * Retrieve database credentials from Vault.
 * Vault automatically rotates these credentials.
 */
export async function getDatabaseCredentialsFromVault(roleName: string) {
  if (!globalVaultClient) {
    throw new Error('Vault client not available');
  }

  return await globalVaultClient.getDatabaseCredentials(roleName);
}

/**
 * Shutdown the Vault client (cleanup).
 */
export async function shutdownVault(): Promise<void> {
  if (globalVaultClient) {
    await globalVaultClient.shutdown();
    globalVaultClient = null;
    log.info('✓ Vault client shutdown');
  }
}

/**
 * Health check: is Vault available?
 */
export async function checkVaultHealth(): Promise<boolean> {
  if (!globalVaultClient) {
    return false;
  }
  return await globalVaultClient.healthCheck();
}

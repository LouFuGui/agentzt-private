import { DatabaseSync } from 'node:sqlite';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { APPS_DB_FILE } from '../shared/paths.ts';
import { makeLogger } from '../shared/log.ts';
import type {
  App,
  AppConfig,
  AppQuota,
  UserTier,
  DEFAULT_QUOTA_BY_TIER,
} from '../shared/types.ts';
import { DEFAULT_APP_CONFIG } from '../shared/types.ts';

const log = makeLogger('app-store');

// ============================================================================
// API Key Generation
// ============================================================================

/**
 * Generate a secure random string of specified length
 */
function secureRandomString(length: number): string {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const bytes = randomBytes(length);
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars[bytes[i]! % chars.length];
  }
  return result;
}

/**
 * Generate API Key: sk-xxai-{32-char random}
 */
export function generateApiKey(): string {
  return `sk-xxai-${secureRandomString(32)}`;
}

/**
 * Generate Model API Key: sk-xxai-model-{32-char random}
 */
export function generateModelApiKey(): string {
  return `sk-xxai-model-${secureRandomString(32)}`;
}

/**
 * Generate App ID: app-{random-id}
 */
export function generateAppId(): string {
  return `app-${secureRandomString(16)}`;
}

// ============================================================================
// Default Quota Factory
// ============================================================================

export function getDefaultQuota(tier: UserTier): AppQuota {
  const limits: Record<UserTier, { checksLimit: number; tokensLimit: number }> = {
    personal: { checksLimit: 1000, tokensLimit: 100000 },
    business: { checksLimit: 10000, tokensLimit: 1000000 },
    enterprise: { checksLimit: 100000, tokensLimit: 10000000 },
  };
  return {
    ...limits[tier],
    checksUsed: 0,
    tokensUsed: 0,
  };
}

// ============================================================================
// SQLite App Store
// ============================================================================

/**
 * AppStore: SQLite-based application storage with CRUD operations
 * Provides complete isolation for each application's configuration
 */
export class AppStore {
  private db: DatabaseSync;

  constructor(dbPath: string = APPS_DB_FILE) {
    // Ensure the directory exists
    const dir = dirname(dbPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    this.db = new DatabaseSync(dbPath);
    appStoreInstance = this;
    this.initTables();
    log.info(`AppStore initialized at ${dbPath}`);
  }

  private initTables(): void {
    // Apps table - stores basic app info
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS apps (
        app_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        api_key TEXT NOT NULL UNIQUE,
        model_api_key TEXT NOT NULL UNIQUE,
        owner_id TEXT NOT NULL,
        created_at TEXT NOT NULL
      )
    `);

    // App configurations table - stores JSON config
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS app_configs (
        app_id TEXT PRIMARY KEY,
        config_json TEXT NOT NULL,
        FOREIGN KEY (app_id) REFERENCES apps(app_id) ON DELETE CASCADE
      )
    `);

    // App quotas table - stores quota info
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS app_quotas (
        app_id TEXT PRIMARY KEY,
        checks_limit INTEGER NOT NULL,
        checks_used INTEGER NOT NULL DEFAULT 0,
        tokens_limit INTEGER NOT NULL,
        tokens_used INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY (app_id) REFERENCES apps(app_id) ON DELETE CASCADE
      )
    `);

    // Create indexes for faster lookups
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_apps_api_key ON apps(api_key)`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_apps_model_api_key ON apps(model_api_key)`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_apps_owner_id ON apps(owner_id)`);
  }

  // ============================================================================
  // CRUD Operations
  // ============================================================================

  /**
   * Create a new application with default configuration
   */
  createApp(
    name: string,
    ownerId: string,
    tier: UserTier = 'personal',
  ): App {
    const appId = generateAppId();
    const apiKey = generateApiKey();
    const modelApiKey = generateModelApiKey();
    const createdAt = new Date().toISOString();
    const config = { ...DEFAULT_APP_CONFIG };
    const quota = getDefaultQuota(tier);

    // Insert app
    const insertApp = this.db.prepare(`
      INSERT INTO apps (app_id, name, api_key, model_api_key, owner_id, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    insertApp.run(appId, name, apiKey, modelApiKey, ownerId, createdAt);

    // Insert config
    const insertConfig = this.db.prepare(`
      INSERT INTO app_configs (app_id, config_json)
      VALUES (?, ?)
    `);
    insertConfig.run(appId, JSON.stringify(config));

    // Insert quota
    const insertQuota = this.db.prepare(`
      INSERT INTO app_quotas (app_id, checks_limit, checks_used, tokens_limit, tokens_used)
      VALUES (?, ?, ?, ?, ?)
    `);
    insertQuota.run(appId, quota.checksLimit, quota.checksUsed, quota.tokensLimit, quota.tokensUsed);

    log.info(`Created app ${appId} for owner ${ownerId}`);

    return {
      appId,
      name,
      apiKey,
      modelApiKey,
      config,
      quota,
      createdAt,
      ownerId,
    };
  }

  /**
   * Get application by ID
   */
  getApp(appId: string): App | null {
    const row = this.db.prepare(`
      SELECT a.app_id, a.name, a.api_key, a.model_api_key, a.owner_id, a.created_at,
             c.config_json,
             q.checks_limit, q.checks_used, q.tokens_limit, q.tokens_used
      FROM apps a
      JOIN app_configs c ON a.app_id = c.app_id
      JOIN app_quotas q ON a.app_id = q.app_id
      WHERE a.app_id = ?
    `).get(appId) as {
      app_id: string;
      name: string;
      api_key: string;
      model_api_key: string;
      owner_id: string;
      created_at: string;
      config_json: string;
      checks_limit: number;
      checks_used: number;
      tokens_limit: number;
      tokens_used: number;
    } | undefined;

    if (!row) return null;

    return {
      appId: row.app_id,
      name: row.name,
      apiKey: row.api_key,
      modelApiKey: row.model_api_key,
      ownerId: row.owner_id,
      createdAt: row.created_at,
      config: JSON.parse(row.config_json) as AppConfig,
      quota: {
        checksLimit: row.checks_limit,
        checksUsed: row.checks_used,
        tokensLimit: row.tokens_limit,
        tokensUsed: row.tokens_used,
      },
    };
  }

  /**
   * Get application by API Key
   */
  getAppByApiKey(apiKey: string): App | null {
    const row = this.db.prepare(`
      SELECT a.app_id, a.name, a.api_key, a.model_api_key, a.owner_id, a.created_at,
             c.config_json,
             q.checks_limit, q.checks_used, q.tokens_limit, q.tokens_used
      FROM apps a
      JOIN app_configs c ON a.app_id = c.app_id
      JOIN app_quotas q ON a.app_id = q.app_id
      WHERE a.api_key = ?
    `).get(apiKey) as {
      app_id: string;
      name: string;
      api_key: string;
      model_api_key: string;
      owner_id: string;
      created_at: string;
      config_json: string;
      checks_limit: number;
      checks_used: number;
      tokens_limit: number;
      tokens_used: number;
    } | undefined;

    if (!row) return null;

    return {
      appId: row.app_id,
      name: row.name,
      apiKey: row.api_key,
      modelApiKey: row.model_api_key,
      ownerId: row.owner_id,
      createdAt: row.created_at,
      config: JSON.parse(row.config_json) as AppConfig,
      quota: {
        checksLimit: row.checks_limit,
        checksUsed: row.checks_used,
        tokensLimit: row.tokens_limit,
        tokensUsed: row.tokens_used,
      },
    };
  }

  /**
   * Get application by Model API Key
   */
  getAppByModelApiKey(modelApiKey: string): App | null {
    const row = this.db.prepare(`
      SELECT a.app_id, a.name, a.api_key, a.model_api_key, a.owner_id, a.created_at,
             c.config_json,
             q.checks_limit, q.checks_used, q.tokens_limit, q.tokens_used
      FROM apps a
      JOIN app_configs c ON a.app_id = c.app_id
      JOIN app_quotas q ON a.app_id = q.app_id
      WHERE a.model_api_key = ?
    `).get(modelApiKey) as {
      app_id: string;
      name: string;
      api_key: string;
      model_api_key: string;
      owner_id: string;
      created_at: string;
      config_json: string;
      checks_limit: number;
      checks_used: number;
      tokens_limit: number;
      tokens_used: number;
    } | undefined;

    if (!row) return null;

    return {
      appId: row.app_id,
      name: row.name,
      apiKey: row.api_key,
      modelApiKey: row.model_api_key,
      ownerId: row.owner_id,
      createdAt: row.created_at,
      config: JSON.parse(row.config_json) as AppConfig,
      quota: {
        checksLimit: row.checks_limit,
        checksUsed: row.checks_used,
        tokensLimit: row.tokens_limit,
        tokensUsed: row.tokens_used,
      },
    };
  }

  /**
   * List all applications for an owner
   */
  listAppsByOwner(ownerId: string): App[] {
    const rows = this.db.prepare(`
      SELECT a.app_id, a.name, a.api_key, a.model_api_key, a.owner_id, a.created_at,
             c.config_json,
             q.checks_limit, q.checks_used, q.tokens_limit, q.tokens_used
      FROM apps a
      JOIN app_configs c ON a.app_id = c.app_id
      JOIN app_quotas q ON a.app_id = q.app_id
      WHERE a.owner_id = ?
      ORDER BY a.created_at DESC
    `).all(ownerId) as Array<{
      app_id: string;
      name: string;
      api_key: string;
      model_api_key: string;
      owner_id: string;
      created_at: string;
      config_json: string;
      checks_limit: number;
      checks_used: number;
      tokens_limit: number;
      tokens_used: number;
    }>;

    return rows.map((row) => ({
      appId: row.app_id,
      name: row.name,
      apiKey: row.api_key,
      modelApiKey: row.model_api_key,
      ownerId: row.owner_id,
      createdAt: row.created_at,
      config: JSON.parse(row.config_json) as AppConfig,
      quota: {
        checksLimit: row.checks_limit,
        checksUsed: row.checks_used,
        tokensLimit: row.tokens_limit,
        tokensUsed: row.tokens_used,
      },
    }));
  }

  /**
   * List all applications
   */
  listAllApps(): App[] {
    const rows = this.db.prepare(`
      SELECT a.app_id, a.name, a.api_key, a.model_api_key, a.owner_id, a.created_at,
             c.config_json,
             q.checks_limit, q.checks_used, q.tokens_limit, q.tokens_used
      FROM apps a
      JOIN app_configs c ON a.app_id = c.app_id
      JOIN app_quotas q ON a.app_id = q.app_id
      ORDER BY a.created_at DESC
    `).all() as Array<{
      app_id: string;
      name: string;
      api_key: string;
      model_api_key: string;
      owner_id: string;
      created_at: string;
      config_json: string;
      checks_limit: number;
      checks_used: number;
      tokens_limit: number;
      tokens_used: number;
    }>;

    return rows.map((row) => ({
      appId: row.app_id,
      name: row.name,
      apiKey: row.api_key,
      modelApiKey: row.model_api_key,
      ownerId: row.owner_id,
      createdAt: row.created_at,
      config: JSON.parse(row.config_json) as AppConfig,
      quota: {
        checksLimit: row.checks_limit,
        checksUsed: row.checks_used,
        tokensLimit: row.tokens_limit,
        tokensUsed: row.tokens_used,
      },
    }));
  }

  /**
   * Update application name
   */
  updateAppName(appId: string, name: string): boolean {
    const result = this.db.prepare(`
      UPDATE apps SET name = ? WHERE app_id = ?
    `).run(name, appId);
    return result.changes > 0;
  }

  /**
   * Update application configuration
   */
  updateAppConfig(appId: string, config: Partial<AppConfig>): boolean {
    const app = this.getApp(appId);
    if (!app) return false;

    const newConfig = { ...app.config, ...config };
    const result = this.db.prepare(`
      UPDATE app_configs SET config_json = ? WHERE app_id = ?
    `).run(JSON.stringify(newConfig), appId);

    return result.changes > 0;
  }

  /**
   * Update application quota
   */
  updateAppQuota(appId: string, quota: Partial<AppQuota>): boolean {
    const app = this.getApp(appId);
    if (!app) return false;

    const newQuota = { ...app.quota, ...quota };
    const result = this.db.prepare(`
      UPDATE app_quotas 
      SET checks_limit = ?, checks_used = ?, tokens_limit = ?, tokens_used = ?
      WHERE app_id = ?
    `).run(
      newQuota.checksLimit,
      newQuota.checksUsed,
      newQuota.tokensLimit,
      newQuota.tokensUsed,
      appId,
    );

    return result.changes > 0;
  }

  /**
   * Increment quota usage
   */
  incrementQuotaUsage(appId: string, checksDelta: number = 0, tokensDelta: number = 0): boolean {
    const result = this.db.prepare(`
      UPDATE app_quotas 
      SET checks_used = checks_used + ?, tokens_used = tokens_used + ?
      WHERE app_id = ?
    `).run(checksDelta, tokensDelta, appId);

    return result.changes > 0;
  }

  /**
   * Regenerate API Key
   */
  regenerateApiKey(appId: string): { apiKey: string; modelApiKey: string } | null {
    const newApiKey = generateApiKey();
    const newModelApiKey = generateModelApiKey();

    const result = this.db.prepare(`
      UPDATE apps SET api_key = ?, model_api_key = ? WHERE app_id = ?
    `).run(newApiKey, newModelApiKey, appId);

    if (result.changes === 0) return null;

    log.info(`Regenerated API keys for app ${appId}`);
    return { apiKey: newApiKey, modelApiKey: newModelApiKey };
  }

  /**
   * Delete application
   */
  deleteApp(appId: string): boolean {
    // Due to CASCADE, deleting from apps will also delete from app_configs and app_quotas
    const result = this.db.prepare(`DELETE FROM apps WHERE app_id = ?`).run(appId);
    if (result.changes > 0) {
      log.info(`Deleted app ${appId}`);
    }
    return result.changes > 0;
  }

  /**
   * Check if API Key exists (for validation)
   */
  apiKeyExists(apiKey: string): boolean {
    const row = this.db.prepare(`SELECT 1 FROM apps WHERE api_key = ?`).get(apiKey);
    return !!row;
  }

  /**
   * Check if Model API Key exists (for validation)
   */
  modelApiKeyExists(modelApiKey: string): boolean {
    const row = this.db.prepare(`SELECT 1 FROM apps WHERE model_api_key = ?`).get(modelApiKey);
    return !!row;
  }

  /**
   * Close the database connection
   */
  close(): void {
    this.db.close();
    log.info('AppStore closed');
  }
}

// Singleton instance
let appStoreInstance: AppStore | null = null;

/**
 * Get the singleton AppStore instance
 */
export function getAppStore(): AppStore {
  if (!appStoreInstance) {
    appStoreInstance = new AppStore();
  }
  return appStoreInstance;
}

/**
 * Reset the singleton (for testing)
 */
export function resetAppStore(): void {
  if (appStoreInstance) {
    appStoreInstance.close();
    appStoreInstance = null;
  }
}
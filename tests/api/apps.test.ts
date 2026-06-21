/**
 * Application Management API Tests
 * Tests for creating, configuring, and managing applications and API keys
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { existsSync, unlinkSync } from 'node:fs';

// Import modules to test
import {
  handleCreateApp,
  handleListApps,
  handleGetApp,
  handleUpdateApp,
  handleDeleteApp,
  handleRegenerateKey,
  routeAppsApi,
  validateApiKeyAndGetApp,
  getAppFromHeader,
} from '../../src/api/apps.ts';
import {
  AppStore,
  getAppStore,
  resetAppStore,
  generateApiKey,
  generateModelApiKey,
  generateAppId,
  getDefaultQuota,
} from '../../src/api/app-store.ts';
import type { App, UserTier, AppQuota } from '../../src/shared/types.ts';

// Helper to create HTTP request
async function makeRequest(
  port: number,
  method: string,
  path: string,
  body?: unknown,
  headers?: Record<string, string>,
): Promise<{ status: number; body: unknown }> {
  const response = await fetch(`http://localhost:${port}${path}`, {
    method,
    headers: {
      'content-type': 'application/json',
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const responseBody = await response.json();
  return { status: response.status, body: responseBody };
}

describe('Application Management Tests', () => {
  describe('API Key Generation', () => {
    it('should generate valid API key format', () => {
      const apiKey = generateApiKey();
      
      expect(apiKey).toBeDefined();
      expect(apiKey).toMatch(/^sk-xxai-[a-zA-Z0-9]{32}$/);
      expect(apiKey.length).toBe(42); // sk-xxai- + 32 chars
    });

    it('should generate unique API keys', () => {
      const keys = new Set<string>();
      
      for (let i = 0; i < 100; i++) {
        keys.add(generateApiKey());
      }
      
      expect(keys.size).toBe(100);
    });

    it('should generate valid Model API key format', () => {
      const modelApiKey = generateModelApiKey();
      
      expect(modelApiKey).toBeDefined();
      expect(modelApiKey).toMatch(/^sk-xxai-model-[a-zA-Z0-9]{32}$/);
      expect(modelApiKey.length).toBe(48); // sk-xxai-model- + 32 chars
    });

    it('should generate unique Model API keys', () => {
      const keys = new Set<string>();
      
      for (let i = 0; i < 100; i++) {
        keys.add(generateModelApiKey());
      }
      
      expect(keys.size).toBe(100);
    });

    it('should generate valid App ID format', () => {
      const appId = generateAppId();
      
      expect(appId).toBeDefined();
      expect(appId).toMatch(/^app-[a-zA-Z0-9]{16}$/);
      expect(appId.length).toBe(20); // app- + 16 chars
    });

    it('should generate unique App IDs', () => {
      const ids = new Set<string>();
      
      for (let i = 0; i < 100; i++) {
        ids.add(generateAppId());
      }
      
      expect(ids.size).toBe(100);
    });
  });

  describe('Default Quota', () => {
    it('should return correct quota for personal tier', () => {
      const quota = getDefaultQuota('personal');
      
      expect(quota.checksLimit).toBe(1000);
      expect(quota.tokensLimit).toBe(100000);
      expect(quota.checksUsed).toBe(0);
      expect(quota.tokensUsed).toBe(0);
    });

    it('should return correct quota for business tier', () => {
      const quota = getDefaultQuota('business');
      
      expect(quota.checksLimit).toBe(10000);
      expect(quota.tokensLimit).toBe(1000000);
      expect(quota.checksUsed).toBe(0);
      expect(quota.tokensUsed).toBe(0);
    });

    it('should return correct quota for enterprise tier', () => {
      const quota = getDefaultQuota('enterprise');
      
      expect(quota.checksLimit).toBe(100000);
      expect(quota.tokensLimit).toBe(10000000);
      expect(quota.checksUsed).toBe(0);
      expect(quota.tokensUsed).toBe(0);
    });
  });

  describe('AppStore', () => {
    let appStore: AppStore;
    const testDbPath = './test-apps.db';

    beforeEach(() => {
      // Clean up test database
      if (existsSync(testDbPath)) {
        try {
          unlinkSync(testDbPath);
        } catch {
          // Ignore errors
        }
      }
      
      appStore = new AppStore(testDbPath);
    });

    afterEach(() => {
      appStore.close();
      
      // Clean up test database
      if (existsSync(testDbPath)) {
        try {
          unlinkSync(testDbPath);
        } catch {
          // Ignore errors
        }
      }
    });

    it('should create a new application', () => {
      const app = appStore.createApp('Test App', 'user_test', 'personal');
      
      expect(app).toBeDefined();
      expect(app.appId).toBeDefined();
      expect(app.name).toBe('Test App');
      expect(app.ownerId).toBe('user_test');
      expect(app.apiKey).toMatch(/^sk-xxai-/);
      expect(app.modelApiKey).toMatch(/^sk-xxai-model-/);
      expect(app.createdAt).toBeDefined();
      expect(app.config).toBeDefined();
      expect(app.quota).toBeDefined();
    });

    it('should create app with correct tier quota', () => {
      const tiers: UserTier[] = ['personal', 'business', 'enterprise'];
      
      for (const tier of tiers) {
        const app = appStore.createApp(`Test ${tier}`, 'user_test', tier);
        const expectedQuota = getDefaultQuota(tier);
        
        expect(app.quota.checksLimit).toBe(expectedQuota.checksLimit);
        expect(app.quota.tokensLimit).toBe(expectedQuota.tokensLimit);
      }
    });

    it('should get application by ID', () => {
      const created = appStore.createApp('Test App', 'user_test');
      const app = appStore.getApp(created.appId);
      
      expect(app).toBeDefined();
      expect(app?.appId).toBe(created.appId);
      expect(app?.name).toBe('Test App');
    });

    it('should return null for non-existent app ID', () => {
      const app = appStore.getApp('non-existent-id');
      expect(app).toBeNull();
    });

    it('should get application by API key', () => {
      const created = appStore.createApp('Test App', 'user_test');
      const app = appStore.getAppByApiKey(created.apiKey);
      
      expect(app).toBeDefined();
      expect(app?.appId).toBe(created.appId);
    });

    it('should return null for invalid API key', () => {
      const app = appStore.getAppByApiKey('invalid-key');
      expect(app).toBeNull();
    });

    it('should get application by Model API key', () => {
      const created = appStore.createApp('Test App', 'user_test');
      const app = appStore.getAppByModelApiKey(created.modelApiKey);
      
      expect(app).toBeDefined();
      expect(app?.appId).toBe(created.appId);
    });

    it('should list applications by owner', () => {
      appStore.createApp('App 1', 'user_1');
      appStore.createApp('App 2', 'user_1');
      appStore.createApp('App 3', 'user_2');
      
      const user1Apps = appStore.listAppsByOwner('user_1');
      const user2Apps = appStore.listAppsByOwner('user_2');
      
      expect(user1Apps.length).toBe(2);
      expect(user2Apps.length).toBe(1);
    });

    it('should list all applications', () => {
      appStore.createApp('App 1', 'user_1');
      appStore.createApp('App 2', 'user_2');
      appStore.createApp('App 3', 'user_3');
      
      const allApps = appStore.listAllApps();
      expect(allApps.length).toBe(3);
    });

    it('should update application name', () => {
      const created = appStore.createApp('Old Name', 'user_test');
      const updated = appStore.updateAppName(created.appId, 'New Name');
      
      expect(updated).toBe(true);
      
      const app = appStore.getApp(created.appId);
      expect(app?.name).toBe('New Name');
    });

    it('should update application configuration', () => {
      const created = appStore.createApp('Test App', 'user_test');
      
      const updated = appStore.updateAppConfig(created.appId, {
        sensitivity: {
          level: 'high',
          threshold: 0.4,
        },
      });
      
      expect(updated).toBe(true);
      
      const app = appStore.getApp(created.appId);
      expect(app?.config.sensitivity.level).toBe('high');
      expect(app?.config.sensitivity.threshold).toBe(0.4);
    });

    it('should update application quota', () => {
      const created = appStore.createApp('Test App', 'user_test');
      
      const updated = appStore.updateAppQuota(created.appId, {
        checksLimit: 5000,
        tokensLimit: 500000,
      });
      
      expect(updated).toBe(true);
      
      const app = appStore.getApp(created.appId);
      expect(app?.quota.checksLimit).toBe(5000);
      expect(app?.quota.tokensLimit).toBe(500000);
    });

    it('should increment quota usage', () => {
      const created = appStore.createApp('Test App', 'user_test');
      
      appStore.incrementQuotaUsage(created.appId, 10, 100);
      
      const app = appStore.getApp(created.appId);
      expect(app?.quota.checksUsed).toBe(10);
      expect(app?.quota.tokensUsed).toBe(100);
    });

    it('should regenerate API keys', () => {
      const created = appStore.createApp('Test App', 'user_test');
      const originalApiKey = created.apiKey;
      const originalModelKey = created.modelApiKey;
      
      const newKeys = appStore.regenerateApiKey(created.appId);
      
      expect(newKeys).toBeDefined();
      expect(newKeys?.apiKey).not.toBe(originalApiKey);
      expect(newKeys?.modelApiKey).not.toBe(originalModelKey);
      
      // Old keys should no longer work
      expect(appStore.getAppByApiKey(originalApiKey)).toBeNull();
      expect(appStore.getAppByModelApiKey(originalModelKey)).toBeNull();
      
      // New keys should work
      expect(appStore.getAppByApiKey(newKeys!.apiKey)).toBeDefined();
      expect(appStore.getAppByModelApiKey(newKeys!.modelApiKey)).toBeDefined();
    });

    it('should delete application', () => {
      const created = appStore.createApp('Test App', 'user_test');
      const deleted = appStore.deleteApp(created.appId);
      
      expect(deleted).toBe(true);
      expect(appStore.getApp(created.appId)).toBeNull();
    });

    it('should check API key existence', () => {
      const created = appStore.createApp('Test App', 'user_test');
      
      expect(appStore.apiKeyExists(created.apiKey)).toBe(true);
      expect(appStore.apiKeyExists('invalid-key')).toBe(false);
    });

    it('should check Model API key existence', () => {
      const created = appStore.createApp('Test App', 'user_test');
      
      expect(appStore.modelApiKeyExists(created.modelApiKey)).toBe(true);
      expect(appStore.modelApiKeyExists('invalid-key')).toBe(false);
    });
  });

  describe('Apps API Integration', () => {
    let server: ReturnType<typeof createServer>;
    let port: number;
    let appStore: AppStore;
    const testDbPath = './test-apps-api.db';

    beforeEach(() => {
      // Clean up test database
      if (existsSync(testDbPath)) {
        try {
          unlinkSync(testDbPath);
        } catch {
          // Ignore errors
        }
      }
      
      appStore = new AppStore(testDbPath);

      server = createServer(async (req, res) => {
        const handled = await routeAppsApi(req, res);
        if (!handled) {
          res.writeHead(404);
          res.end(JSON.stringify({ error: 'not found' }));
        }
      });

      return new Promise<void>((resolve) => {
        server.listen(0, () => {
          port = (server.address() as AddressInfo).port;
          resolve();
        });
      });
    });

    afterEach(() => {
      server.close();
      appStore.close();
      
      // Clean up test database
      if (existsSync(testDbPath)) {
        try {
          unlinkSync(testDbPath);
        } catch {
          // Ignore errors
        }
      }
    });

    it('should create application via API', async () => {
      const response = await makeRequest(port, 'POST', '/api/apps', {
        name: 'Test App',
        tier: 'business',
      }, {
        'x-user-id': 'user_test',
      });

      expect(response.status).toBe(201);
      expect(response.body.appId).toBeDefined();
      expect(response.body.name).toBe('Test App');
      expect(response.body.apiKey).toMatch(/^sk-xxai-/);
      expect(response.body.modelApiKey).toMatch(/^sk-xxai-model-/);
    });

    it('should reject creation without authentication', async () => {
      const response = await makeRequest(port, 'POST', '/api/apps', {
        name: 'Test App',
      });

      expect(response.status).toBe(401);
    });

    it('should reject creation with invalid name', async () => {
      const response = await makeRequest(port, 'POST', '/api/apps', {
        name: '',
      }, {
        'x-user-id': 'user_test',
      });

      expect(response.status).toBe(400);
    });

    it('should reject creation with invalid tier', async () => {
      const response = await makeRequest(port, 'POST', '/api/apps', {
        name: 'Test App',
        tier: 'invalid',
      }, {
        'x-user-id': 'user_test',
      });

      expect(response.status).toBe(400);
    });

    it('should list applications', async () => {
      // Create some apps
      await makeRequest(port, 'POST', '/api/apps', {
        name: 'App 1',
      }, {
        'x-user-id': 'user_test',
      });

      await makeRequest(port, 'POST', '/api/apps', {
        name: 'App 2',
      }, {
        'x-user-id': 'user_test',
      });

      const response = await makeRequest(port, 'GET', '/api/apps', undefined, {
        'x-user-id': 'user_test',
      });

      expect(response.status).toBe(200);
      expect(response.body.apps).toBeDefined();
      expect(response.body.total).toBe(2);
    });

    it('should get application details', async () => {
      // Create app
      const createResponse = await makeRequest(port, 'POST', '/api/apps', {
        name: 'Test App',
      }, {
        'x-user-id': 'user_test',
      });

      const appId = createResponse.body.appId;

      // Get app
      const response = await makeRequest(port, 'GET', `/api/apps/${appId}`, undefined, {
        'x-user-id': 'user_test',
      });

      expect(response.status).toBe(200);
      expect(response.body.appId).toBe(appId);
      expect(response.body.name).toBe('Test App');
    });

    it('should reject access to non-owned app', async () => {
      // Create app for user1
      const createResponse = await makeRequest(port, 'POST', '/api/apps', {
        name: 'Test App',
      }, {
        'x-user-id': 'user1',
      });

      const appId = createResponse.body.appId;

      // Try to access with user2
      const response = await makeRequest(port, 'GET', `/api/apps/${appId}`, undefined, {
        'x-user-id': 'user2',
      });

      expect(response.status).toBe(403);
    });

    it('should update application', async () => {
      // Create app
      const createResponse = await makeRequest(port, 'POST', '/api/apps', {
        name: 'Test App',
      }, {
        'x-user-id': 'user_test',
      });

      const appId = createResponse.body.appId;

      // Update app
      const response = await makeRequest(port, 'PUT', `/api/apps/${appId}`, {
        name: 'Updated App',
      }, {
        'x-user-id': 'user_test',
      });

      expect(response.status).toBe(200);
      expect(response.body.name).toBe('Updated App');
    });

    it('should delete application', async () => {
      // Create app
      const createResponse = await makeRequest(port, 'POST', '/api/apps', {
        name: 'Test App',
      }, {
        'x-user-id': 'user_test',
      });

      const appId = createResponse.body.appId;

      // Delete app
      const response = await makeRequest(port, 'DELETE', `/api/apps/${appId}`, undefined, {
        'x-user-id': 'user_test',
      });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);

      // Verify deleted
      const getResponse = await makeRequest(port, 'GET', `/api/apps/${appId}`, undefined, {
        'x-user-id': 'user_test',
      });

      expect(getResponse.status).toBe(404);
    });

    it('should regenerate API keys', async () => {
      // Create app
      const createResponse = await makeRequest(port, 'POST', '/api/apps', {
        name: 'Test App',
      }, {
        'x-user-id': 'user_test',
      });

      const appId = createResponse.body.appId;
      const originalApiKey = createResponse.body.apiKey;

      // Regenerate keys
      const response = await makeRequest(port, 'POST', `/api/apps/${appId}/regenerate-key`, undefined, {
        'x-user-id': 'user_test',
      });

      expect(response.status).toBe(200);
      expect(response.body.apiKey).toBeDefined();
      expect(response.body.apiKey).not.toBe(originalApiKey);
    });
  });

  describe('API Key Validation', () => {
    let appStore: AppStore;
    const testDbPath = './test-validation.db';

    beforeEach(() => {
      if (existsSync(testDbPath)) {
        try {
          unlinkSync(testDbPath);
        } catch {
          // Ignore
        }
      }
      
      appStore = new AppStore(testDbPath);
    });

    afterEach(() => {
      appStore.close();
      
      if (existsSync(testDbPath)) {
        try {
          unlinkSync(testDbPath);
        } catch {
          // Ignore
        }
      }
    });

    it('should validate API key and get app', () => {
      const app = appStore.createApp('Test App', 'user_test');
      const validated = validateApiKeyAndGetApp(app.apiKey);
      
      expect(validated).toBeDefined();
      expect(validated?.appId).toBe(app.appId);
    });

    it('should validate Model API key and get app', () => {
      const app = appStore.createApp('Test App', 'user_test');
      const validated = validateApiKeyAndGetApp(app.modelApiKey);
      
      expect(validated).toBeDefined();
      expect(validated?.appId).toBe(app.appId);
    });

    it('should return null for invalid API key', () => {
      const validated = validateApiKeyAndGetApp('invalid-key');
      expect(validated).toBeNull();
    });
  });
});
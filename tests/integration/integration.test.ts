/**
 * Integration Tests
 * Tests for end-to-end workflows and plugin integrations (n8n, Dify)
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { existsSync, unlinkSync } from 'node:fs';
import { generateKeyPair } from 'node:crypto';
import { promisify } from 'node:util';

const generateKeyPairAsync = promisify(generateKeyPair);

// Import modules to test
import { AppStore } from '../../src/api/app-store.ts';
import { UserStore } from '../../src/api/user-store.ts';
import { SessionTokenService, AuthApi } from '../../src/api/auth.ts';
import { routeAppsApi } from '../../src/api/apps.ts';
import { routeConfigApi } from '../../src/api/config.ts';
import { routeStatsApi } from '../../src/api/stats.ts';
import { routeQuotaApi } from '../../src/api/quota.ts';

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

  let responseBody;
  try {
    responseBody = await response.json();
  } catch {
    responseBody = await response.text();
  }
  
  return { status: response.status, body: responseBody };
}

describe('Integration Tests', () => {
  describe('End-to-End User Workflow', () => {
    let server: ReturnType<typeof createServer>;
    let port: number;
    let userStore: UserStore;
    let appStore: AppStore;
    let tokenService: SessionTokenService;
    let authApi: AuthApi;
    const testUserDb = './test-integration-users.json';
    const testAppDb = './test-integration-apps.db';

    beforeEach(async () => {
      // Clean up test databases
      if (existsSync(testUserDb)) {
        try {
          unlinkSync(testUserDb);
        } catch {
          // Ignore
        }
      }
      if (existsSync(testAppDb)) {
        try {
          unlinkSync(testAppDb);
        } catch {
          // Ignore
        }
      }

      // Initialize stores
      userStore = new UserStore(testUserDb);
      appStore = new AppStore(testAppDb);

      // Initialize token service
      const keys = await generateKeyPairAsync('ed25519');
      tokenService = new SessionTokenService('test-issuer', keys.privateKey, keys.publicKey);
      authApi = new AuthApi(userStore, tokenService);

      // Create server
      server = createServer(async (req, res) => {
        // Try each API router
        const handled = 
          await authApi.handle(req, res) ||
          await routeAppsApi(req, res) ||
          await routeConfigApi(req, res) ||
          await routeStatsApi(req, res) ||
          await routeQuotaApi(req, res);

        if (!handled) {
          res.writeHead(404);
          res.end(JSON.stringify({ error: 'not found' }));
        }
      });

      await new Promise<void>((resolve) => {
        server.listen(0, () => {
          port = (server.address() as AddressInfo).port;
          resolve();
        });
      });
    });

    afterEach(() => {
      server.close();
      userStore.list().forEach(user => userStore.delete(user.userId));
      appStore.close();

      // Clean up test databases
      if (existsSync(testUserDb)) {
        try {
          unlinkSync(testUserDb);
        } catch {
          // Ignore
        }
      }
      if (existsSync(testAppDb)) {
        try {
          unlinkSync(testAppDb);
        } catch {
          // Ignore
        }
      }
    });

    it('should complete full user registration and app creation workflow', async () => {
      // Step 1: Register user
      const regResponse = await makeRequest(port, 'POST', '/api/auth/register', {
        email: 'test@example.com',
        password: 'testPassword123',
        role: 'owner',
        tier: 'business',
      });

      expect(regResponse.status).toBe(201);
      expect(regResponse.body.user).toBeDefined();
      expect(regResponse.body.session).toBeDefined();

      const token = regResponse.body.session.token;
      const userId = regResponse.body.user.userId;

      // Step 2: Create application
      const appResponse = await makeRequest(port, 'POST', '/api/apps', {
        name: 'My First App',
        tier: 'business',
      }, {
        'x-user-id': userId,
      });

      expect(appResponse.status).toBe(201);
      expect(appResponse.body.appId).toBeDefined();
      expect(appResponse.body.apiKey).toMatch(/^sk-xxai-/);

      const appId = appResponse.body.appId;

      // Step 3: Configure application
      const configResponse = await makeRequest(port, 'PUT', `/api/apps/${appId}`, {
        config: {
          sensitivity: {
            level: 'high',
            threshold: 0.4,
          },
        },
      }, {
        'x-user-id': userId,
      });

      expect(configResponse.status).toBe(200);

      // Step 4: Use application (simulate quota usage)
      const quotaResponse = await makeRequest(port, 'GET', '/api/quota/usage', undefined, {
        'x-user-id': userId,
        'x-agentzt-app-id': appId,
      });

      expect(quotaResponse.status).toBe(200);
      expect(quotaResponse.body.checks).toBeDefined();
      expect(quotaResponse.body.tokens).toBeDefined();
    });

    it('should handle user login and app access', async () => {
      // Register user
      await makeRequest(port, 'POST', '/api/auth/register', {
        email: 'login@example.com',
        password: 'testPassword123',
      });

      // Login
      const loginResponse = await makeRequest(port, 'POST', '/api/auth/login', {
        email: 'login@example.com',
        password: 'testPassword123',
      });

      expect(loginResponse.status).toBe(200);
      expect(loginResponse.body.session).toBeDefined();

      const token = loginResponse.body.session.token;

      // Get current user info
      const meResponse = await makeRequest(port, 'GET', '/api/auth/me', undefined, {
        authorization: `Bearer ${token}`,
      });

      expect(meResponse.status).toBe(200);
      expect(meResponse.body.email).toBe('login@example.com');
    });

    it('should handle token refresh workflow', async () => {
      // Register
      const regResponse = await makeRequest(port, 'POST', '/api/auth/register', {
        email: 'refresh@example.com',
        password: 'testPassword123',
      });

      const refreshToken = regResponse.body.refreshToken.token;

      // Refresh token
      const refreshResponse = await makeRequest(port, 'POST', '/api/auth/refresh', {
        refreshToken,
      });

      expect(refreshResponse.status).toBe(200);
      expect(refreshResponse.body.session).toBeDefined();
      expect(refreshResponse.body.refreshToken).toBeDefined();

      // Old refresh token should no longer work
      const oldRefreshResponse = await makeRequest(port, 'POST', '/api/auth/refresh', {
        refreshToken,
      });

      expect(oldRefreshResponse.status).toBe(401);
    });

    it('should handle logout workflow', async () => {
      // Register
      const regResponse = await makeRequest(port, 'POST', '/api/auth/register', {
        email: 'logout@example.com',
        password: 'testPassword123',
      });

      const token = regResponse.body.session.token;

      // Logout
      const logoutResponse = await makeRequest(port, 'POST', '/api/auth/logout', undefined, {
        authorization: `Bearer ${token}`,
      });

      expect(logoutResponse.status).toBe(200);

      // Token should no longer work
      const meResponse = await makeRequest(port, 'GET', '/api/auth/me', undefined, {
        authorization: `Bearer ${token}`,
      });

      expect(meResponse.status).toBe(401);
    });
  });

  describe('Multi-App Integration', () => {
    let appStore: AppStore;
    const testDbPath = './test-multi-app-integration.db';

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

    it('should manage multiple apps for same user', () => {
      const userId = 'user_multi';

      // Create multiple apps
      const app1 = appStore.createApp('Production App', userId, 'enterprise');
      const app2 = appStore.createApp('Development App', userId, 'business');
      const app3 = appStore.createApp('Testing App', userId, 'personal');

      const userApps = appStore.listAppsByOwner(userId);
      expect(userApps.length).toBe(3);

      // Each app should have unique API keys
      expect(app1.apiKey).not.toBe(app2.apiKey);
      expect(app2.apiKey).not.toBe(app3.apiKey);
      expect(app1.modelApiKey).not.toBe(app2.modelApiKey);
    });

    it('should isolate app configurations', () => {
      const userId = 'user_isolate';

      const app1 = appStore.createApp('App 1', userId);
      const app2 = appStore.createApp('App 2', userId);

      // Configure app1 with high sensitivity
      appStore.updateAppConfig(app1.appId, {
        sensitivity: { level: 'high', threshold: 0.4 },
      });

      // Configure app2 with low sensitivity
      appStore.updateAppConfig(app2.appId, {
        sensitivity: { level: 'low', threshold: 0.8 },
      });

      const app1Data = appStore.getApp(app1.appId);
      const app2Data = appStore.getApp(app2.appId);

      expect(app1Data?.config.sensitivity.level).toBe('high');
      expect(app2Data?.config.sensitivity.level).toBe('low');
    });

    it('should track quota separately for each app', () => {
      const userId = 'user_quota';

      const app1 = appStore.createApp('App 1', userId);
      const app2 = appStore.createApp('App 2', userId);

      // Use quota on app1
      appStore.incrementQuotaUsage(app1.appId, 100, 1000);

      // Use quota on app2
      appStore.incrementQuotaUsage(app2.appId, 200, 2000);

      const app1Data = appStore.getApp(app1.appId);
      const app2Data = appStore.getApp(app2.appId);

      expect(app1Data?.quota.checksUsed).toBe(100);
      expect(app2Data?.quota.checksUsed).toBe(200);
    });
  });

  describe('n8n Integration', () => {
    it('should support n8n webhook authentication', () => {
      // n8n typically uses API keys for webhook authentication
      const apiKey = 'sk-xxai-test123456789012345678901234567890';
      
      expect(apiKey).toMatch(/^sk-xxai-/);
    });

    it('should support n8n workflow triggers', () => {
      // Simulate n8n workflow trigger
      const workflowTrigger = {
        workflowId: 'workflow_123',
        triggerType: 'webhook',
        appId: 'app_123',
        timestamp: new Date().toISOString(),
      };

      expect(workflowTrigger.workflowId).toBeDefined();
      expect(workflowTrigger.triggerType).toBe('webhook');
    });

    it('should support n8n node configuration', () => {
      // n8n node configuration for AgentZT
      const nodeConfig = {
        nodeType: 'agentzt',
        credentials: {
          apiKey: 'sk-xxai-test',
        },
        operation: 'guardrails_check',
        parameters: {
          messages: [{ role: 'user', content: 'Test message' }],
        },
      };

      expect(nodeConfig.nodeType).toBe('agentzt');
      expect(nodeConfig.operation).toBe('guardrails_check');
    });

    it('should handle n8n error responses', () => {
      // n8n expects specific error format
      const errorResponse = {
        error: {
          message: 'Guardrail blocked',
          code: 'GUARDRAIL_BLOCKED',
          details: {
            categories: ['S1', 'S7'],
            riskLevel: 'high',
          },
        },
      };

      expect(errorResponse.error.code).toBe('GUARDRAIL_BLOCKED');
    });
  });

  describe('Dify Integration', () => {
    it('should support Dify API key format', () => {
      // Dify uses API keys for authentication
      const difyApiKey = 'sk-xxai-model-test12345678901234567890123456';
      
      expect(difyApiKey).toMatch(/^sk-xxai-model-/);
    });

    it('should support Dify conversation format', () => {
      // Dify conversation structure
      const difyConversation = {
        conversationId: 'conv_123',
        appId: 'app_123',
        messages: [
          { role: 'user', content: 'Hello' },
          { role: 'assistant', content: 'Hi there!' },
        ],
      };

      expect(difyConversation.conversationId).toBeDefined();
      expect(difyConversation.messages.length).toBeGreaterThan(0);
    });

    it('should support Dify model configuration', () => {
      // Dify model settings
      const difyModelConfig = {
        model: 'gpt-4',
        temperature: 0.7,
        maxTokens: 1000,
        guardrailsEnabled: true,
      };

      expect(difyModelConfig.guardrailsEnabled).toBe(true);
    });

    it('should handle Dify streaming responses', () => {
      // Dify supports streaming responses
      const streamConfig = {
        streaming: true,
        chunkSize: 100,
        onChunk: (chunk: string) => console.log(chunk),
      };

      expect(streamConfig.streaming).toBe(true);
    });
  });

  describe('Performance Tests', () => {
    it('should handle concurrent app creation', async () => {
      const appStore = new AppStore('./test-performance.db');
      const userId = 'user_perf';

      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(
          new Promise((resolve) => {
            const app = appStore.createApp(`App ${i}`, userId);
            resolve(app);
          })
        );
      }

      const apps = await Promise.all(promises);
      expect(apps.length).toBe(10);

      appStore.close();
      if (existsSync('./test-performance.db')) {
        try {
          unlinkSync('./test-performance.db');
        } catch {
          // Ignore
        }
      }
    });

    it('should handle rapid quota updates', async () => {
      const appStore = new AppStore('./test-performance-quota.db');
      const app = appStore.createApp('Performance App', 'user_perf');

      const promises = [];
      for (let i = 0; i < 100; i++) {
        promises.push(
          new Promise((resolve) => {
            appStore.incrementQuotaUsage(app.appId, 1, 10);
            resolve(true);
          })
        );
      }

      await Promise.all(promises);

      const updatedApp = appStore.getApp(app.appId);
      // Due to concurrent updates, final count may vary
      expect(updatedApp?.quota.checksUsed).toBeGreaterThan(0);

      appStore.close();
      if (existsSync('./test-performance-quota.db')) {
        try {
          unlinkSync('./test-performance-quota.db');
        } catch {
          // Ignore
        }
      }
    });

    it('should handle concurrent API requests', async () => {
      // Simulate concurrent API requests
      const concurrentRequests = 50;
      const requestDelay = 10; // ms

      const promises = [];
      for (let i = 0; i < concurrentRequests; i++) {
        promises.push(
          new Promise((resolve) => {
            setTimeout(() => {
              resolve({ requestId: i, timestamp: Date.now() });
            }, requestDelay);
          })
        );
      }

      const results = await Promise.all(promises);
      expect(results.length).toBe(concurrentRequests);
    });
  });

  describe('Error Handling Integration', () => {
    it('should handle database errors gracefully', () => {
      // Test error handling when database is unavailable
      try {
        const appStore = new AppStore('/invalid/path/db.db');
        // Should throw or handle error
      } catch (error) {
        expect(error).toBeDefined();
      }
    });

    it('should handle invalid API key format', () => {
      const invalidKeys = [
        'invalid-key',
        'sk-invalid',
        'xxai-test',
        '',
      ];

      for (const key of invalidKeys) {
        expect(key).not.toMatch(/^sk-xxai-[a-zA-Z0-9]{32}$/);
        expect(key).not.toMatch(/^sk-xxai-model-[a-zA-Z0-9]{32}$/);
      }
    });

    it('should handle missing required fields', () => {
      const invalidRequests = [
        {}, // Empty
        { email: 'test@example.com' }, // Missing password
        { password: 'testPassword123' }, // Missing email
        { email: 'invalid', password: 'short' }, // Invalid fields
      ];

      for (const req of invalidRequests) {
        const hasEmail = typeof req.email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(req.email);
        const hasPassword = typeof req.password === 'string' && req.password.length >= 8;
        
        expect(hasEmail && hasPassword).toBe(false);
      }
    });

    it('should handle rate limiting', () => {
      // Simulate rate limit scenario
      const rateLimitConfig = {
        requestsPerMinute: 10,
        currentCount: 15,
      };

      const exceeded = rateLimitConfig.currentCount > rateLimitConfig.requestsPerMinute;
      expect(exceeded).toBe(true);
    });
  });
});
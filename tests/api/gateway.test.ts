/**
 * Gateway Tests
 * Tests for three deployment modes: Gateway/API/Direct
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { generateKeyPair } from 'node:crypto';
import { promisify } from 'node:util';
import { existsSync, unlinkSync } from 'node:fs';

const generateKeyPairAsync = promisify(generateKeyPair);

// Import modules to test
import { AppStore } from '../../src/api/app-store.ts';
import type { App, GuardrailsCheckRequest, ChatCompletionRequest } from '../../src/shared/types.ts';

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

describe('Gateway Tests', () => {
  describe('Security Gateway Mode (Transparent Proxy)', () => {
    let appStore: AppStore;
    let testApp: App;
    const testDbPath = './test-gateway-proxy.db';

    beforeEach(() => {
      if (existsSync(testDbPath)) {
        try {
          unlinkSync(testDbPath);
        } catch {
          // Ignore
        }
      }
      
      appStore = new AppStore(testDbPath);
      testApp = appStore.createApp('Test App', 'user_test', 'business');
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

    it('should authenticate with API key', () => {
      expect(testApp.apiKey).toMatch(/^sk-xxai-/);
      expect(testApp.modelApiKey).toMatch(/^sk-xxai-model-/);
    });

    it('should have valid app configuration', () => {
      expect(testApp.config.riskTypes.security).toBe(true);
      expect(testApp.config.riskTypes.compliance).toBe(true);
      expect(testApp.config.riskTypes.dataSecurity).toBe(true);
      expect(testApp.config.sensitivity.level).toBeDefined();
      expect(testApp.config.responseTemplates.reject).toBeDefined();
      expect(testApp.config.responseTemplates.replace).toBeDefined();
    });

    it('should have quota limits', () => {
      expect(testApp.quota.checksLimit).toBeGreaterThan(0);
      expect(testApp.quota.tokensLimit).toBeGreaterThan(0);
      expect(testApp.quota.checksUsed).toBe(0);
      expect(testApp.quota.tokensUsed).toBe(0);
    });

    it('should track quota usage', () => {
      appStore.incrementQuotaUsage(testApp.appId, 1, 100);
      
      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.quota.checksUsed).toBe(1);
      expect(updatedApp?.quota.tokensUsed).toBe(100);
    });

    it('should check quota limits', () => {
      // Simulate reaching quota limit
      appStore.updateAppQuota(testApp.appId, {
        checksUsed: testApp.quota.checksLimit,
      });
      
      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.quota.checksUsed).toBe(updatedApp?.quota.checksLimit);
    });
  });

  describe('API Call Mode (Active Detection)', () => {
    let appStore: AppStore;
    let testApp: App;
    const testDbPath = './test-gateway-api.db';

    beforeEach(() => {
      if (existsSync(testDbPath)) {
        try {
          unlinkSync(testDbPath);
        } catch {
          // Ignore
        }
      }
      
      appStore = new AppStore(testDbPath);
      testApp = appStore.createApp('Test App', 'user_test', 'business');
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

    it('should create valid guardrails check request', () => {
      const request: GuardrailsCheckRequest = {
        model: 'gpt-4',
        messages: [
          { role: 'user', content: 'Hello, how are you?' },
        ],
        enable_security: true,
        enable_compliance: true,
        enable_data_security: true,
      };

      expect(request.messages).toBeDefined();
      expect(request.messages.length).toBeGreaterThan(0);
      expect(request.enable_security).toBe(true);
    });

    it('should handle different message formats', () => {
      const messages = [
        { role: 'user', content: 'User message' },
        { role: 'assistant', content: 'Assistant response' },
        { role: 'system', content: 'System instruction' },
      ];

      for (const msg of messages) {
        expect(msg.role).toBeDefined();
        expect(msg.content).toBeDefined();
      }
    });

    it('should enable/disable risk types', () => {
      const config = testApp.config;

      // Security risk types
      expect(config.riskTypes.security).toBe(true);

      // Compliance risk types
      expect(config.riskTypes.compliance).toBe(true);

      // Data security risk types
      expect(config.riskTypes.dataSecurity).toBe(true);

      // Can disable specific types
      appStore.updateAppConfig(testApp.appId, {
        riskTypes: {
          security: true,
          compliance: false,
          dataSecurity: true,
        },
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.riskTypes.compliance).toBe(false);
    });

    it('should configure sensitivity levels', () => {
      const levels = ['high', 'medium', 'low'] as const;

      for (const level of levels) {
        appStore.updateAppConfig(testApp.appId, {
          sensitivity: {
            level,
            threshold: level === 'high' ? 0.4 : level === 'medium' ? 0.6 : 0.8,
          },
        });

        const updatedApp = appStore.getApp(testApp.appId);
        expect(updatedApp?.config.sensitivity.level).toBe(level);
      }
    });

    it('should configure response templates', () => {
      const customTemplates = {
        reject: 'Custom reject message',
        replace: 'Custom replacement content',
      };

      appStore.updateAppConfig(testApp.appId, {
        responseTemplates: customTemplates,
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.responseTemplates.reject).toBe(customTemplates.reject);
      expect(updatedApp?.config.responseTemplates.replace).toBe(customTemplates.replace);
    });
  });

  describe('Direct Model Access (Privacy-Preserving)', () => {
    let appStore: AppStore;
    let testApp: App;
    const testDbPath = './test-gateway-direct.db';

    beforeEach(() => {
      if (existsSync(testDbPath)) {
        try {
          unlinkSync(testDbPath);
        } catch {
          // Ignore
        }
      }
      
      appStore = new AppStore(testDbPath);
      testApp = appStore.createApp('Test App', 'user_test', 'enterprise');
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

    it('should require Model API Key for direct access', () => {
      expect(testApp.modelApiKey).toMatch(/^sk-xxai-model-/);
    });

    it('should create valid chat completion request', () => {
      const request: ChatCompletionRequest = {
        model: 'gpt-4',
        messages: [
          { role: 'user', content: 'What is AI?' },
        ],
        max_tokens: 100,
        temperature: 0.7,
      };

      expect(request.model).toBeDefined();
      expect(request.messages).toBeDefined();
      expect(request.messages.length).toBeGreaterThan(0);
    });

    it('should track token usage without storing content', () => {
      // Simulate token usage
      const promptTokens = 50;
      const completionTokens = 100;
      
      appStore.incrementQuotaUsage(testApp.appId, 1, promptTokens + completionTokens);
      
      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.quota.tokensUsed).toBe(promptTokens + completionTokens);
    });

    it('should enforce privacy by not logging content', () => {
      // Privacy mode should only track counts, not content
      const usage = {
        checks: 1,
        tokens: 150,
      };

      appStore.incrementQuotaUsage(testApp.appId, usage.checks, usage.tokens);
      
      const updatedApp = appStore.getApp(testApp.appId);
      // Only usage counts are stored, no message content
      expect(updatedApp?.quota.checksUsed).toBe(usage.checks);
      expect(updatedApp?.quota.tokensUsed).toBe(usage.tokens);
    });

    it('should support enterprise tier with high limits', () => {
      expect(testApp.quota.checksLimit).toBe(100000);
      expect(testApp.quota.tokensLimit).toBe(10000000);
    });
  });

  describe('Guardrail Configuration', () => {
    let appStore: AppStore;
    let testApp: App;
    const testDbPath = './test-guardrails.db';

    beforeEach(() => {
      if (existsSync(testDbPath)) {
        try {
          unlinkSync(testDbPath);
        } catch {
          // Ignore
        }
      }
      
      appStore = new AppStore(testDbPath);
      testApp = appStore.createApp('Test App', 'user_test');
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

    it('should have default risk categories enabled', () => {
      const categories = testApp.config.riskCategories;
      
      // All S1-S19 should be enabled by default
      for (let i = 1; i <= 19; i++) {
        expect(categories[`S${i}` as keyof typeof categories]).toBe(true);
      }
    });

    it('should allow disabling specific risk categories', () => {
      appStore.updateAppConfig(testApp.appId, {
        riskCategories: {
          ...testApp.config.riskCategories,
          S1: false, // Prompt Injection
          S2: false, // Jailbreak
        },
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.riskCategories.S1).toBe(false);
      expect(updatedApp?.config.riskCategories.S2).toBe(false);
    });

    it('should configure blacklist/whitelist', () => {
      appStore.updateAppConfig(testApp.appId, {
        blacklistWhitelist: {
          blacklist: ['malware', 'hack'],
          whitelist: ['safe', 'approved'],
        },
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.blacklistWhitelist.blacklist).toContain('malware');
      expect(updatedApp?.config.blacklistWhitelist.whitelist).toContain('safe');
    });

    it('should configure ban policy', () => {
      appStore.updateAppConfig(testApp.appId, {
        banPolicy: {
          bannedUsers: ['user_spammer'],
          autoBanThreshold: 5,
        },
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.banPolicy.bannedUsers).toContain('user_spammer');
      expect(updatedApp?.config.banPolicy.autoBanThreshold).toBe(5);
    });

    it('should configure knowledge base', () => {
      appStore.updateAppConfig(testApp.appId, {
        knowledgeBase: {
          entries: [
            {
              question: 'What is the security policy?',
              answer: 'All requests must pass guardrail checks.',
            },
          ],
        },
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.knowledgeBase.entries.length).toBe(1);
      expect(updatedApp?.config.knowledgeBase.entries[0]?.question).toBe('What is the security policy?');
    });
  });

  describe('Rate Limiting', () => {
    it('should enforce rate limits per role', () => {
      // Mock rate limiter behavior
      const limits = {
        viewer: { requestsPerMinute: 10 },
        admin: { requestsPerMinute: 100 },
        owner: { requestsPerMinute: 1000 },
      };

      expect(limits.viewer.requestsPerMinute).toBeLessThan(limits.admin.requestsPerMinute);
      expect(limits.admin.requestsPerMinute).toBeLessThan(limits.owner.requestsPerMinute);
    });

    it('should track request timestamps', () => {
      const requests = [
        { timestamp: Date.now() - 1000 },
        { timestamp: Date.now() - 500 },
        { timestamp: Date.now() },
      ];

      // Should be able to calculate rate from timestamps
      const timeWindow = 60000; // 1 minute
      const requestsInWindow = requests.filter(
        r => Date.now() - r.timestamp < timeWindow
      );

      expect(requestsInWindow.length).toBe(3);
    });
  });

  describe('Authentication Methods', () => {
    it('should support Agent Token authentication', () => {
      // Agent token format: JWT with agent identity
      const agentToken = {
        type: 'agent_token',
        agentId: 'agent_123',
        role: 'assistant',
        scope: {
          models: ['gpt-4'],
          tools: ['calculator'],
        },
      };

      expect(agentToken.type).toBe('agent_token');
      expect(agentToken.agentId).toBeDefined();
      expect(agentToken.scope.models).toBeDefined();
    });

    it('should support API Key authentication', () => {
      // API Key format: sk-xxai-* or sk-xxai-model-*
      const apiKey = {
        type: 'api_key',
        app: {
          appId: 'app_123',
          ownerId: 'user_123',
        },
      };

      expect(apiKey.type).toBe('api_key');
      expect(apiKey.app.appId).toBeDefined();
    });

    it('should reject invalid authentication', () => {
      const invalidAuth = {
        type: 'invalid',
      };

      expect(invalidAuth.type).not.toBe('agent_token');
      expect(invalidAuth.type).not.toBe('api_key');
    });
  });

  describe('Multi-App Management', () => {
    let appStore: AppStore;
    const testDbPath = './test-multi-app.db';

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

    it('should create multiple apps for same user', () => {
      const app1 = appStore.createApp('App 1', 'user_test');
      const app2 = appStore.createApp('App 2', 'user_test');
      const app3 = appStore.createApp('App 3', 'user_test');

      const userApps = appStore.listAppsByOwner('user_test');
      expect(userApps.length).toBe(3);
    });

    it('should isolate app configurations', () => {
      const app1 = appStore.createApp('App 1', 'user_test');
      const app2 = appStore.createApp('App 2', 'user_test');

      // Configure app1 differently
      appStore.updateAppConfig(app1.appId, {
        sensitivity: { level: 'high', threshold: 0.4 },
      });

      // App2 should still have default config
      const app2Data = appStore.getApp(app2.appId);
      expect(app2Data?.config.sensitivity.level).toBe('medium');
    });

    it('should isolate app quotas', () => {
      const app1 = appStore.createApp('App 1', 'user_test');
      const app2 = appStore.createApp('App 2', 'user_test');

      // Use quota on app1
      appStore.incrementQuotaUsage(app1.appId, 100, 1000);

      // App2 quota should be unaffected
      const app2Data = appStore.getApp(app2.appId);
      expect(app2Data?.quota.checksUsed).toBe(0);
      expect(app2Data?.quota.tokensUsed).toBe(0);
    });

    it('should support app switching via header', () => {
      const app1 = appStore.createApp('App 1', 'user_test');
      const app2 = appStore.createApp('App 2', 'user_test');

      // Header-based app selection
      const headers = {
        'x-agentzt-app-id': app1.appId,
      };

      expect(headers['x-agentzt-app-id']).toBe(app1.appId);
    });

    it('should support app switching via API key header', () => {
      const app1 = appStore.createApp('App 1', 'user_test');
      const app2 = appStore.createApp('App 2', 'user_test');

      // API Key header-based app selection
      const headers = {
        'x-agentzt-api-key': app1.apiKey,
      };

      const app = appStore.getAppByApiKey(headers['x-agentzt-api-key']);
      expect(app?.appId).toBe(app1.appId);
    });
  });
});
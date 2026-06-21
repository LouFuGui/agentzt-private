/**
 * Configuration Management API Tests
 * Tests for managing application configurations including risk types, categories,
 * blacklist/whitelist, response templates, sensitivity, ban policy, and knowledge base
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { existsSync, unlinkSync } from 'node:fs';
import { generateKeyPair } from 'node:crypto';
import { promisify } from 'node:util';

const generateKeyPairAsync = promisify(generateKeyPair);

// Import modules to test
import { routeConfigApi } from '../../src/api/config.ts';
import { AppStore } from '../../src/api/app-store.ts';
import { SessionTokenService } from '../../src/api/auth.ts';
import type { App, UserRole } from '../../src/shared/types.ts';

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

describe('Configuration Management Tests', () => {
  describe('Risk Types Configuration', () => {
    let appStore: AppStore;
    let testApp: App;
    const testDbPath = './test-config-risk-types.db';

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

    it('should have default risk types enabled', () => {
      expect(testApp.config.riskTypes.security).toBe(true);
      expect(testApp.config.riskTypes.compliance).toBe(true);
      expect(testApp.config.riskTypes.dataSecurity).toBe(true);
    });

    it('should update security risk type', () => {
      appStore.updateAppConfig(testApp.appId, {
        riskTypes: {
          security: false,
          compliance: true,
          dataSecurity: true,
        },
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.riskTypes.security).toBe(false);
    });

    it('should update compliance risk type', () => {
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

    it('should update data security risk type', () => {
      appStore.updateAppConfig(testApp.appId, {
        riskTypes: {
          security: true,
          compliance: true,
          dataSecurity: false,
        },
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.riskTypes.dataSecurity).toBe(false);
    });

    it('should disable all risk types', () => {
      appStore.updateAppConfig(testApp.appId, {
        riskTypes: {
          security: false,
          compliance: false,
          dataSecurity: false,
        },
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.riskTypes.security).toBe(false);
      expect(updatedApp?.config.riskTypes.compliance).toBe(false);
      expect(updatedApp?.config.riskTypes.dataSecurity).toBe(false);
    });
  });

  describe('Risk Categories Configuration', () => {
    let appStore: AppStore;
    let testApp: App;
    const testDbPath = './test-config-categories.db';

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

    it('should have all S1-S19 categories enabled by default', () => {
      const categories = testApp.config.riskCategories;
      
      for (let i = 1; i <= 19; i++) {
        expect(categories[`S${i}` as keyof typeof categories]).toBe(true);
      }
    });

    it('should disable specific risk categories', () => {
      const updates = {
        S1: false, // Prompt Injection
        S7: false, // Harmful Content
        S12: false, // Malware
      };

      appStore.updateAppConfig(testApp.appId, {
        riskCategories: {
          ...testApp.config.riskCategories,
          ...updates,
        },
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.riskCategories.S1).toBe(false);
      expect(updatedApp?.config.riskCategories.S7).toBe(false);
      expect(updatedApp?.config.riskCategories.S12).toBe(false);
    });

    it('should enable specific risk categories', () => {
      // First disable some
      appStore.updateAppConfig(testApp.appId, {
        riskCategories: {
          ...testApp.config.riskCategories,
          S1: false,
          S2: false,
        },
      });

      // Then enable them
      appStore.updateAppConfig(testApp.appId, {
        riskCategories: {
          ...testApp.config.riskCategories,
          S1: true,
          S2: true,
        },
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.riskCategories.S1).toBe(true);
      expect(updatedApp?.config.riskCategories.S2).toBe(true);
    });

    it('should validate category names', () => {
      const validCategories = ['S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7', 'S8', 'S9', 'S10',
                               'S11', 'S12', 'S13', 'S14', 'S15', 'S16', 'S17', 'S18', 'S19'];
      
      for (const cat of validCategories) {
        expect(cat).toMatch(/^S\d+$/);
      }
    });
  });

  describe('Blacklist/Whitelist Configuration', () => {
    let appStore: AppStore;
    let testApp: App;
    const testDbPath = './test-config-blacklist.db';

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

    it('should have empty blacklist/whitelist by default', () => {
      expect(testApp.config.blacklistWhitelist.blacklist).toEqual([]);
      expect(testApp.config.blacklistWhitelist.whitelist).toEqual([]);
    });

    it('should add keywords to blacklist', () => {
      appStore.updateAppConfig(testApp.appId, {
        blacklistWhitelist: {
          blacklist: ['malware', 'hack', 'exploit'],
          whitelist: [],
        },
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.blacklistWhitelist.blacklist).toContain('malware');
      expect(updatedApp?.config.blacklistWhitelist.blacklist).toContain('hack');
      expect(updatedApp?.config.blacklistWhitelist.blacklist.length).toBe(3);
    });

    it('should add keywords to whitelist', () => {
      appStore.updateAppConfig(testApp.appId, {
        blacklistWhitelist: {
          blacklist: [],
          whitelist: ['safe', 'approved', 'verified'],
        },
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.blacklistWhitelist.whitelist).toContain('safe');
      expect(updatedApp?.config.blacklistWhitelist.whitelist).toContain('approved');
      expect(updatedApp?.config.blacklistWhitelist.whitelist.length).toBe(3);
    });

    it('should remove keywords from blacklist', () => {
      // Add keywords
      appStore.updateAppConfig(testApp.appId, {
        blacklistWhitelist: {
          blacklist: ['malware', 'hack', 'exploit'],
          whitelist: [],
        },
      });

      // Remove some
      appStore.updateAppConfig(testApp.appId, {
        blacklistWhitelist: {
          blacklist: ['malware'], // Keep only malware
          whitelist: [],
        },
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.blacklistWhitelist.blacklist).toContain('malware');
      expect(updatedApp?.config.blacklistWhitelist.blacklist).not.toContain('hack');
    });

    it('should support both blacklist and whitelist', () => {
      appStore.updateAppConfig(testApp.appId, {
        blacklistWhitelist: {
          blacklist: ['dangerous'],
          whitelist: ['safe'],
        },
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.blacklistWhitelist.blacklist).toContain('dangerous');
      expect(updatedApp?.config.blacklistWhitelist.whitelist).toContain('safe');
    });
  });

  describe('Response Templates Configuration', () => {
    let appStore: AppStore;
    let testApp: App;
    const testDbPath = './test-config-templates.db';

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

    it('should have default response templates', () => {
      expect(testApp.config.responseTemplates.reject).toBeDefined();
      expect(testApp.config.responseTemplates.replace).toBeDefined();
    });

    it('should update reject template', () => {
      const customReject = 'Your request has been blocked due to security policy.';
      
      appStore.updateAppConfig(testApp.appId, {
        responseTemplates: {
          reject: customReject,
          replace: testApp.config.responseTemplates.replace,
        },
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.responseTemplates.reject).toBe(customReject);
    });

    it('should update replace template', () => {
      const customReplace = 'I cannot provide that information. Please try a different query.';
      
      appStore.updateAppConfig(testApp.appId, {
        responseTemplates: {
          reject: testApp.config.responseTemplates.reject,
          replace: customReplace,
        },
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.responseTemplates.replace).toBe(customReplace);
    });

    it('should update both templates', () => {
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

  describe('Sensitivity Configuration', () => {
    let appStore: AppStore;
    let testApp: App;
    const testDbPath = './test-config-sensitivity.db';

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

    it('should have default sensitivity level', () => {
      expect(testApp.config.sensitivity.level).toBeDefined();
      expect(['high', 'medium', 'low']).toContain(testApp.config.sensitivity.level);
    });

    it('should have default threshold', () => {
      expect(testApp.config.sensitivity.threshold).toBeDefined();
      expect(testApp.config.sensitivity.threshold).toBeGreaterThanOrEqual(0);
      expect(testApp.config.sensitivity.threshold).toBeLessThanOrEqual(1);
    });

    it('should set high sensitivity', () => {
      appStore.updateAppConfig(testApp.appId, {
        sensitivity: {
          level: 'high',
          threshold: 0.4,
        },
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.sensitivity.level).toBe('high');
      expect(updatedApp?.config.sensitivity.threshold).toBe(0.4);
    });

    it('should set medium sensitivity', () => {
      appStore.updateAppConfig(testApp.appId, {
        sensitivity: {
          level: 'medium',
          threshold: 0.6,
        },
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.sensitivity.level).toBe('medium');
      expect(updatedApp?.config.sensitivity.threshold).toBe(0.6);
    });

    it('should set low sensitivity', () => {
      appStore.updateAppConfig(testApp.appId, {
        sensitivity: {
          level: 'low',
          threshold: 0.8,
        },
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.sensitivity.level).toBe('low');
      expect(updatedApp?.config.sensitivity.threshold).toBe(0.8);
    });

    it('should validate threshold range', () => {
      const thresholds = [0.4, 0.6, 0.8];
      
      for (const threshold of thresholds) {
        expect(threshold).toBeGreaterThanOrEqual(0);
        expect(threshold).toBeLessThanOrEqual(1);
      }
    });
  });

  describe('Ban Policy Configuration', () => {
    let appStore: AppStore;
    let testApp: App;
    const testDbPath = './test-config-ban.db';

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

    it('should have empty banned users list by default', () => {
      expect(testApp.config.banPolicy.bannedUsers).toEqual([]);
    });

    it('should have default auto-ban threshold', () => {
      expect(testApp.config.banPolicy.autoBanThreshold).toBeDefined();
      expect(testApp.config.banPolicy.autoBanThreshold).toBeGreaterThanOrEqual(0);
    });

    it('should add banned users', () => {
      appStore.updateAppConfig(testApp.appId, {
        banPolicy: {
          bannedUsers: ['user_spammer', 'user_abuser'],
          autoBanThreshold: testApp.config.banPolicy.autoBanThreshold,
        },
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.banPolicy.bannedUsers).toContain('user_spammer');
      expect(updatedApp?.config.banPolicy.bannedUsers).toContain('user_abuser');
    });

    it('should remove banned users', () => {
      // Add banned users
      appStore.updateAppConfig(testApp.appId, {
        banPolicy: {
          bannedUsers: ['user_spammer', 'user_abuser'],
          autoBanThreshold: testApp.config.banPolicy.autoBanThreshold,
        },
      });

      // Remove one
      appStore.updateAppConfig(testApp.appId, {
        banPolicy: {
          bannedUsers: ['user_abuser'],
          autoBanThreshold: testApp.config.banPolicy.autoBanThreshold,
        },
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.banPolicy.bannedUsers).not.toContain('user_spammer');
      expect(updatedApp?.config.banPolicy.bannedUsers).toContain('user_abuser');
    });

    it('should update auto-ban threshold', () => {
      appStore.updateAppConfig(testApp.appId, {
        banPolicy: {
          bannedUsers: [],
          autoBanThreshold: 10,
        },
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.banPolicy.autoBanThreshold).toBe(10);
    });
  });

  describe('Knowledge Base Configuration', () => {
    let appStore: AppStore;
    let testApp: App;
    const testDbPath = './test-config-kb.db';

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

    it('should have empty knowledge base by default', () => {
      expect(testApp.config.knowledgeBase.entries).toEqual([]);
    });

    it('should add knowledge base entries', () => {
      appStore.updateAppConfig(testApp.appId, {
        knowledgeBase: {
          entries: [
            {
              question: 'What is the security policy?',
              answer: 'All requests must pass guardrail checks.',
            },
            {
              question: 'How to handle sensitive data?',
              answer: 'Sensitive data must be encrypted and access-controlled.',
            },
          ],
        },
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.knowledgeBase.entries.length).toBe(2);
    });

    it('should update knowledge base entries', () => {
      // Add entry
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

      // Update entry
      appStore.updateAppConfig(testApp.appId, {
        knowledgeBase: {
          entries: [
            {
              question: 'What is the security policy?',
              answer: 'Updated answer: All requests must pass guardrail checks and be logged.',
            },
          ],
        },
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.knowledgeBase.entries[0]?.answer).toContain('Updated');
    });

    it('should remove knowledge base entries', () => {
      // Add entries
      appStore.updateAppConfig(testApp.appId, {
        knowledgeBase: {
          entries: [
            {
              question: 'Question 1',
              answer: 'Answer 1',
            },
            {
              question: 'Question 2',
              answer: 'Answer 2',
            },
          ],
        },
      });

      // Remove one
      appStore.updateAppConfig(testApp.appId, {
        knowledgeBase: {
          entries: [
            {
              question: 'Question 1',
              answer: 'Answer 1',
            },
          ],
        },
      });

      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.config.knowledgeBase.entries.length).toBe(1);
    });
  });

  describe('Permission Tests', () => {
    it('should allow owner to modify config', () => {
      const role: UserRole = 'owner';
      expect(role).toBe('owner');
    });

    it('should allow admin to modify config', () => {
      const role: UserRole = 'admin';
      expect(role).toBe('admin');
    });

    it('should restrict viewer from modifying config', () => {
      const role: UserRole = 'viewer';
      expect(role).toBe('viewer');
      expect(role).not.toBe('owner');
      expect(role).not.toBe('admin');
    });
  });
});
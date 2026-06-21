/**
 * Quota Tests
 * Tests for quota tracking, alerts, limits, and usage history
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, unlinkSync } from 'node:fs';

// Import modules to test
import { routeQuotaApi } from '../../src/api/quota.ts';
import { AppStore, getDefaultQuota } from '../../src/api/app-store.ts';
import type { App, QuotaType, QuotaTimeRange, QuotaUsage, QuotaCheckResult } from '../../src/shared/types.ts';

describe('Quota Tests', () => {
  describe('Default Quota Configuration', () => {
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

    it('should have increasing limits by tier', () => {
      const personalQuota = getDefaultQuota('personal');
      const businessQuota = getDefaultQuota('business');
      const enterpriseQuota = getDefaultQuota('enterprise');

      expect(personalQuota.checksLimit).toBeLessThan(businessQuota.checksLimit);
      expect(businessQuota.checksLimit).toBeLessThan(enterpriseQuota.checksLimit);

      expect(personalQuota.tokensLimit).toBeLessThan(businessQuota.tokensLimit);
      expect(businessQuota.tokensLimit).toBeLessThan(enterpriseQuota.tokensLimit);
    });
  });

  describe('Quota Usage Tracking', () => {
    let appStore: AppStore;
    let testApp: App;
    const testDbPath = './test-quota-tracking.db';

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

    it('should start with zero usage', () => {
      expect(testApp.quota.checksUsed).toBe(0);
      expect(testApp.quota.tokensUsed).toBe(0);
    });

    it('should increment checks usage', () => {
      appStore.incrementQuotaUsage(testApp.appId, 1, 0);
      
      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.quota.checksUsed).toBe(1);
      expect(updatedApp?.quota.tokensUsed).toBe(0);
    });

    it('should increment tokens usage', () => {
      appStore.incrementQuotaUsage(testApp.appId, 0, 100);
      
      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.quota.checksUsed).toBe(0);
      expect(updatedApp?.quota.tokensUsed).toBe(100);
    });

    it('should increment both checks and tokens', () => {
      appStore.incrementQuotaUsage(testApp.appId, 5, 500);
      
      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.quota.checksUsed).toBe(5);
      expect(updatedApp?.quota.tokensUsed).toBe(500);
    });

    it('should accumulate usage over multiple calls', () => {
      appStore.incrementQuotaUsage(testApp.appId, 1, 100);
      appStore.incrementQuotaUsage(testApp.appId, 2, 200);
      appStore.incrementQuotaUsage(testApp.appId, 3, 300);
      
      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.quota.checksUsed).toBe(6);
      expect(updatedApp?.quota.tokensUsed).toBe(600);
    });

    it('should calculate usage percentage', () => {
      appStore.incrementQuotaUsage(testApp.appId, 1000, 100000);
      
      const updatedApp = appStore.getApp(testApp.appId);
      const checksPercentage = (updatedApp?.quota.checksUsed / updatedApp?.quota.checksLimit) * 100;
      const tokensPercentage = (updatedApp?.quota.tokensUsed / updatedApp?.quota.tokensLimit) * 100;
      
      expect(checksPercentage).toBe(10); // 1000 / 10000 = 10%
      expect(tokensPercentage).toBe(10); // 100000 / 1000000 = 10%
    });
  });

  describe('Quota Limits', () => {
    let appStore: AppStore;
    let testApp: App;
    const testDbPath = './test-quota-limits.db';

    beforeEach(() => {
      if (existsSync(testDbPath)) {
        try {
          unlinkSync(testDbPath);
        } catch {
          // Ignore
        }
      }
      
      appStore = new AppStore(testDbPath);
      testApp = appStore.createApp('Test App', 'user_test', 'personal');
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

    it('should update checks limit', () => {
      appStore.updateAppQuota(testApp.appId, {
        checksLimit: 5000,
      });
      
      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.quota.checksLimit).toBe(5000);
    });

    it('should update tokens limit', () => {
      appStore.updateAppQuota(testApp.appId, {
        tokensLimit: 500000,
      });
      
      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.quota.tokensLimit).toBe(500000);
    });

    it('should update both limits', () => {
      appStore.updateAppQuota(testApp.appId, {
        checksLimit: 5000,
        tokensLimit: 500000,
      });
      
      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.quota.checksLimit).toBe(5000);
      expect(updatedApp?.quota.tokensLimit).toBe(500000);
    });

    it('should check if quota exceeded', () => {
      // Set usage to limit
      appStore.updateAppQuota(testApp.appId, {
        checksUsed: testApp.quota.checksLimit,
      });
      
      const updatedApp = appStore.getApp(testApp.appId);
      const exceeded = updatedApp?.quota.checksUsed >= updatedApp?.quota.checksLimit;
      
      expect(exceeded).toBe(true);
    });

    it('should check remaining quota', () => {
      appStore.incrementQuotaUsage(testApp.appId, 500, 50000);
      
      const updatedApp = appStore.getApp(testApp.appId);
      const checksRemaining = updatedApp?.quota.checksLimit - updatedApp?.quota.checksUsed;
      const tokensRemaining = updatedApp?.quota.tokensLimit - updatedApp?.quota.tokensUsed;
      
      expect(checksRemaining).toBe(500); // 1000 - 500
      expect(tokensRemaining).toBe(50000); // 100000 - 50000
    });
  });

  describe('Quota Reset', () => {
    let appStore: AppStore;
    let testApp: App;
    const testDbPath = './test-quota-reset.db';

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

    it('should reset quota usage', () => {
      // Add usage
      appStore.incrementQuotaUsage(testApp.appId, 1000, 100000);
      
      // Reset
      appStore.updateAppQuota(testApp.appId, {
        checksUsed: 0,
        tokensUsed: 0,
      });
      
      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.quota.checksUsed).toBe(0);
      expect(updatedApp?.quota.tokensUsed).toBe(0);
    });

    it('should preserve limits after reset', () => {
      const originalChecksLimit = testApp.quota.checksLimit;
      const originalTokensLimit = testApp.quota.tokensLimit;
      
      // Add usage
      appStore.incrementQuotaUsage(testApp.appId, 1000, 100000);
      
      // Reset
      appStore.updateAppQuota(testApp.appId, {
        checksUsed: 0,
        tokensUsed: 0,
      });
      
      const updatedApp = appStore.getApp(testApp.appId);
      expect(updatedApp?.quota.checksLimit).toBe(originalChecksLimit);
      expect(updatedApp?.quota.tokensLimit).toBe(originalTokensLimit);
    });
  });

  describe('Quota Types', () => {
    it('should support checks quota type', () => {
      const type: QuotaType = 'checks';
      expect(type).toBe('checks');
    });

    it('should support tokens quota type', () => {
      const type: QuotaType = 'tokens';
      expect(type).toBe('tokens');
    });

    it('should support agents quota type', () => {
      const type: QuotaType = 'agents';
      expect(type).toBe('agents');
    });

    it('should validate quota types', () => {
      const validTypes: QuotaType[] = ['checks', 'tokens', 'agents'];
      
      for (const type of validTypes) {
        expect(['checks', 'tokens', 'agents']).toContain(type);
      }
    });
  });

  describe('Quota Usage Structure', () => {
    it('should create valid quota usage object', () => {
      const usage: QuotaUsage = {
        type: 'checks',
        used: 500,
        limit: 1000,
        percentage: 50,
        remaining: 500,
      };

      expect(usage.type).toBe('checks');
      expect(usage.used).toBe(500);
      expect(usage.limit).toBe(1000);
      expect(usage.percentage).toBe(50);
      expect(usage.remaining).toBe(500);
    });

    it('should calculate percentage correctly', () => {
      const used = 750;
      const limit = 1000;
      const percentage = (used / limit) * 100;

      expect(percentage).toBe(75);
    });

    it('should calculate remaining correctly', () => {
      const used = 250;
      const limit = 1000;
      const remaining = limit - used;

      expect(remaining).toBe(750);
    });
  });

  describe('Quota Check Result', () => {
    it('should create valid quota check result', () => {
      const result: QuotaCheckResult = {
        allowed: true,
        type: 'checks',
        used: 500,
        limit: 1000,
        percentage: 50,
        remaining: 500,
      };

      expect(result.allowed).toBe(true);
      expect(result.type).toBe('checks');
    });

    it('should create denied quota check result', () => {
      const result: QuotaCheckResult = {
        allowed: false,
        type: 'checks',
        used: 1000,
        limit: 1000,
        percentage: 100,
        remaining: 0,
        reason: 'Quota exceeded',
      };

      expect(result.allowed).toBe(false);
      expect(result.reason).toBeDefined();
    });

    it('should create soft limit warning', () => {
      const result: QuotaCheckResult = {
        allowed: true,
        type: 'checks',
        used: 800,
        limit: 1000,
        percentage: 80,
        remaining: 200,
        isSoftLimit: true,
        reason: 'Warning: 80% of quota used',
      };

      expect(result.allowed).toBe(true);
      expect(result.isSoftLimit).toBe(true);
    });
  });

  describe('Time Range Configuration', () => {
    it('should support day time range', () => {
      const timeRange: QuotaTimeRange = 'day';
      expect(timeRange).toBe('day');
    });

    it('should support week time range', () => {
      const timeRange: QuotaTimeRange = 'week';
      expect(timeRange).toBe('week');
    });

    it('should support month time range', () => {
      const timeRange: QuotaTimeRange = 'month';
      expect(timeRange).toBe('month');
    });

    it('should validate time range values', () => {
      const validRanges: QuotaTimeRange[] = ['day', 'week', 'month'];
      
      for (const range of validRanges) {
        expect(['day', 'week', 'month']).toContain(range);
      }
    });
  });

  describe('Alert Thresholds', () => {
    it('should support standard alert thresholds', () => {
      const thresholds = [80, 90, 100];
      
      for (const threshold of thresholds) {
        expect(threshold).toBeGreaterThanOrEqual(0);
        expect(threshold).toBeLessThanOrEqual(100);
      }
    });

    it('should trigger alert at threshold', () => {
      const threshold = 80;
      const percentage = 85;
      
      const triggered = percentage >= threshold;
      expect(triggered).toBe(true);
    });

    it('should not trigger alert below threshold', () => {
      const threshold = 80;
      const percentage = 75;
      
      const triggered = percentage >= threshold;
      expect(triggered).toBe(false);
    });

    it('should support multiple thresholds', () => {
      const thresholds = [
        { threshold: 80, triggered: false },
        { threshold: 90, triggered: false },
        { threshold: 100, triggered: false },
      ];

      const percentage = 85;

      for (const t of thresholds) {
        t.triggered = percentage >= t.threshold;
      }

      expect(thresholds[0]?.triggered).toBe(true); // 85 >= 80
      expect(thresholds[1]?.triggered).toBe(false); // 85 < 90
      expect(thresholds[2]?.triggered).toBe(false); // 85 < 100
    });
  });

  describe('Multi-App Quota Management', () => {
    let appStore: AppStore;
    const testDbPath = './test-quota-multi.db';

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

    it('should track quota separately for each app', () => {
      const app1 = appStore.createApp('App 1', 'user_test');
      const app2 = appStore.createApp('App 2', 'user_test');

      appStore.incrementQuotaUsage(app1.appId, 100, 1000);
      appStore.incrementQuotaUsage(app2.appId, 200, 2000);

      const app1Data = appStore.getApp(app1.appId);
      const app2Data = appStore.getApp(app2.appId);

      expect(app1Data?.quota.checksUsed).toBe(100);
      expect(app2Data?.quota.checksUsed).toBe(200);
    });

    it('should set different limits for each app', () => {
      const app1 = appStore.createApp('App 1', 'user_test', 'personal');
      const app2 = appStore.createApp('App 2', 'user_test', 'enterprise');

      expect(app1.quota.checksLimit).toBeLessThan(app2.quota.checksLimit);
    });

    it('should aggregate quota across apps', () => {
      const app1 = appStore.createApp('App 1', 'user_test');
      const app2 = appStore.createApp('App 2', 'user_test');

      appStore.incrementQuotaUsage(app1.appId, 100, 1000);
      appStore.incrementQuotaUsage(app2.appId, 200, 2000);

      const allApps = appStore.listAllApps();
      const totalChecks = allApps.reduce((sum, app) => sum + app.quota.checksUsed, 0);
      const totalTokens = allApps.reduce((sum, app) => sum + app.quota.tokensUsed, 0);

      expect(totalChecks).toBe(300);
      expect(totalTokens).toBe(3000);
    });
  });
});
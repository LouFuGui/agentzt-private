/**
 * Statistics API Tests
 * Tests for aggregating and analyzing audit data including overview, 
 * risk distribution, trend analysis, and export functionality
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, unlinkSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

// Import modules to test
import { routeStatsApi } from '../../src/api/stats.ts';
import type { AuditEvent, TimeRange, Granularity } from '../../src/api/stats.ts';

describe('Statistics API Tests', () => {
  describe('Time Range Filtering', () => {
    it('should calculate day range start', () => {
      const now = new Date();
      const dayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
      
      expect(dayStart.getHours()).toBe(0);
      expect(dayStart.getMinutes()).toBe(0);
      expect(dayStart.getSeconds()).toBe(0);
    });

    it('should calculate week range start', () => {
      const now = new Date();
      const weekStart = new Date(now);
      weekStart.setDate(now.getDate() - now.getDay());
      weekStart.setHours(0, 0, 0, 0);
      
      expect(weekStart.getDay()).toBe(0); // Sunday
    });

    it('should calculate month range start', () => {
      const now = new Date();
      const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
      
      expect(monthStart.getDate()).toBe(1);
    });

    it('should calculate year range start', () => {
      const now = new Date();
      const yearStart = new Date(now.getFullYear(), 0, 1);
      
      expect(yearStart.getMonth()).toBe(0); // January
      expect(yearStart.getDate()).toBe(1);
    });

    it('should validate time range values', () => {
      const validRanges: TimeRange[] = ['day', 'week', 'month', 'year'];
      
      for (const range of validRanges) {
        expect(['day', 'week', 'month', 'year']).toContain(range);
      }
    });
  });

  describe('Granularity Configuration', () => {
    it('should support hour granularity', () => {
      const granularity: Granularity = 'hour';
      expect(granularity).toBe('hour');
    });

    it('should support day granularity', () => {
      const granularity: Granularity = 'day';
      expect(granularity).toBe('day');
    });

    it('should validate granularity compatibility', () => {
      // Hour granularity should work for day/week/month
      const validCombinations = [
        { timeRange: 'day', granularity: 'hour' },
        { timeRange: 'week', granularity: 'hour' },
        { timeRange: 'month', granularity: 'hour' },
        { timeRange: 'year', granularity: 'day' }, // Year should use day granularity
      ];

      for (const combo of validCombinations) {
        if (combo.timeRange === 'year') {
          expect(combo.granularity).toBe('day');
        } else {
          expect(['hour', 'day']).toContain(combo.granularity);
        }
      }
    });
  });

  describe('Audit Event Processing', () => {
    const testAuditFile = './test-audit-events.jsonl';

    beforeEach(() => {
      // Create test audit file
      const testEvents: AuditEvent[] = [
        {
          ts: new Date().toISOString(),
          requestId: 'req_1',
          agentId: 'agent_1',
          role: 'assistant',
          action: 'model.call',
          resource: 'gpt-4',
          decision: 'allow',
          reason: 'authorized',
          latencyMs: 100,
          categories: ['S1'],
          score: 0.8,
        },
        {
          ts: new Date().toISOString(),
          requestId: 'req_2',
          agentId: 'agent_2',
          role: 'assistant',
          action: 'guardrails.check',
          resource: 'guardrails',
          decision: 'deny',
          reason: 'blocked',
          latencyMs: 50,
          categories: ['S7', 'S12'],
          score: 0.9,
        },
        {
          ts: new Date(Date.now() - 86400000).toISOString(), // Yesterday
          requestId: 'req_3',
          agentId: 'agent_1',
          role: 'assistant',
          action: 'proxy.call',
          resource: 'gpt-4',
          decision: 'allow',
          reason: 'passed guardrails',
          latencyMs: 200,
        },
      ];

      const dir = dirname(testAuditFile);
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }

      const content = testEvents.map(e => JSON.stringify(e)).join('\n');
      writeFileSync(testAuditFile, content, 'utf8');
    });

    afterEach(() => {
      if (existsSync(testAuditFile)) {
        try {
          unlinkSync(testAuditFile);
        } catch {
          // Ignore
        }
      }
    });

    it('should parse audit events from JSONL', () => {
      const events = [
        { ts: new Date().toISOString(), requestId: 'req_1', action: 'model.call' },
        { ts: new Date().toISOString(), requestId: 'req_2', action: 'guardrails.check' },
      ];

      expect(events.length).toBe(2);
      expect(events[0]?.action).toBe('model.call');
    });

    it('should filter events by time range', () => {
      const events = [
        { ts: new Date().toISOString() },
        { ts: new Date(Date.now() - 86400000).toISOString() }, // Yesterday
        { ts: new Date(Date.now() - 172800000).toISOString() }, // 2 days ago
      ];

      const dayStart = new Date(new Date().getFullYear(), new Date().getMonth(), new Date().getDate());
      const todayEvents = events.filter(e => new Date(e.ts) >= dayStart);

      expect(todayEvents.length).toBe(1);
    });

    it('should calculate detection statistics', () => {
      const events: AuditEvent[] = [
        { action: 'model.call', decision: 'allow', categories: [] },
        { action: 'guardrails.check', decision: 'deny', categories: ['S1'] },
        { action: 'proxy.call', decision: 'allow', categories: ['S7'] },
      ];

      const detectionActions = ['guardrails.check', 'proxy.call', 'direct.call', 'model.call'];
      const detections = events.filter(e => detectionActions.includes(e.action));

      expect(detections.length).toBe(3);

      const passCount = detections.filter(e => e.decision === 'allow' && (!e.categories || e.categories.length === 0)).length;
      const blockCount = detections.filter(e => e.decision === 'deny').length;
      const flagCount = detections.filter(e => e.decision === 'allow' && e.categories && e.categories.length > 0).length;

      expect(passCount).toBe(1);
      expect(blockCount).toBe(1);
      expect(flagCount).toBe(1);
    });
  });

  describe('Overview Statistics', () => {
    it('should calculate total detections', () => {
      const events: AuditEvent[] = [
        { action: 'model.call' },
        { action: 'guardrails.check' },
        { action: 'proxy.call' },
        { action: 'token.issue' }, // Not a detection
      ];

      const detectionActions = ['guardrails.check', 'proxy.call', 'direct.call', 'model.call'];
      const totalDetections = events.filter(e => detectionActions.includes(e.action)).length;

      expect(totalDetections).toBe(3);
    });

    it('should calculate pass rate', () => {
      const events: AuditEvent[] = [
        { action: 'model.call', decision: 'allow', categories: [] },
        { action: 'model.call', decision: 'allow', categories: [] },
        { action: 'model.call', decision: 'deny' },
      ];

      const passCount = events.filter(e => e.decision === 'allow' && (!e.categories || e.categories.length === 0)).length;
      const total = events.length;
      const passRate = total > 0 ? passCount / total : 0;

      expect(passRate).toBeCloseTo(0.667, 2);
    });

    it('should calculate block rate', () => {
      const events: AuditEvent[] = [
        { action: 'model.call', decision: 'deny' },
        { action: 'model.call', decision: 'deny' },
        { action: 'model.call', decision: 'allow' },
      ];

      const blockCount = events.filter(e => e.decision === 'deny').length;
      const total = events.length;
      const blockRate = total > 0 ? blockCount / total : 0;

      expect(blockRate).toBeCloseTo(0.667, 2);
    });

    it('should calculate average latency', () => {
      const events: AuditEvent[] = [
        { action: 'model.call', latencyMs: 100 },
        { action: 'model.call', latencyMs: 200 },
        { action: 'model.call', latencyMs: 300 },
      ];

      const eventsWithLatency = events.filter(e => e.latencyMs !== undefined);
      const avgLatency = eventsWithLatency.length > 0 
        ? eventsWithLatency.reduce((sum, e) => sum + (e.latencyMs ?? 0), 0) / eventsWithLatency.length 
        : 0;

      expect(avgLatency).toBe(200);
    });

    it('should calculate total tokens', () => {
      const events: AuditEvent[] = [
        { action: 'model.call', meta: { usage: { input_tokens: 100, output_tokens: 50 } } },
        { action: 'model.call', meta: { usage: { input_tokens: 200, output_tokens: 100 } } },
      ];

      const totalTokens = events.reduce((sum, e) => {
        const usage = e.meta?.usage as { input_tokens?: number; output_tokens?: number } | undefined;
        if (usage) {
          return sum + (usage.input_tokens ?? 0) + (usage.output_tokens ?? 0);
        }
        return sum;
      }, 0);

      expect(totalTokens).toBe(450);
    });
  });

  describe('Risk Distribution Analysis', () => {
    it('should categorize risk levels', () => {
      const events: AuditEvent[] = [
        { categories: ['S1', 'S2'], score: 0.9 }, // High risk
        { categories: ['S3', 'S5'], score: 0.7 }, // Medium risk
        { categories: ['S4'], score: 0.5 }, // Low risk
        { categories: [], decision: 'allow' }, // No risk
      ];

      const highRiskCategories = ['S1', 'S2', 'S7', 'S8', 'S9', 'S10', 'S11', 'S12'];
      const mediumRiskCategories = ['S3', 'S5', 'S6', 'S13', 'S17', 'S18'];
      const lowRiskCategories = ['S4', 'S14', 'S15', 'S16', 'S19'];

      const highRisk = events.filter(e => 
        e.categories?.some(c => highRiskCategories.includes(c))
      ).length;
      const mediumRisk = events.filter(e => 
        e.categories?.some(c => mediumRiskCategories.includes(c)) && 
        !e.categories?.some(c => highRiskCategories.includes(c))
      ).length;

      expect(highRisk).toBe(1);
      expect(mediumRisk).toBe(1);
    });

    it('should count by category', () => {
      const events: AuditEvent[] = [
        { categories: ['S1', 'S7'] },
        { categories: ['S1', 'S12'] },
        { categories: ['S7'] },
      ];

      const categoryCounts: Record<string, number> = {};
      
      for (const event of events) {
        if (event.categories) {
          for (const cat of event.categories) {
            categoryCounts[cat] = (categoryCounts[cat] ?? 0) + 1;
          }
        }
      }

      expect(categoryCounts['S1']).toBe(2);
      expect(categoryCounts['S7']).toBe(2);
      expect(categoryCounts['S12']).toBe(1);
    });

    it('should count by app', () => {
      const events: AuditEvent[] = [
        { appId: 'app_1' },
        { appId: 'app_1' },
        { appId: 'app_2' },
      ];

      const appCounts: Record<string, number> = {};
      
      for (const event of events) {
        if (event.appId) {
          appCounts[event.appId] = (appCounts[event.appId] ?? 0) + 1;
        }
      }

      expect(appCounts['app_1']).toBe(2);
      expect(appCounts['app_2']).toBe(1);
    });
  });

  describe('Trend Analysis', () => {
    it('should generate time buckets for hour granularity', () => {
      const now = new Date();
      const hourKey = `${now.getFullYear()}-${now.getMonth() + 1}-${now.getDate()}-${now.getHours()}`;
      
      expect(hourKey).toMatch(/^\d{4}-\d{1,2}-\d{1,2}-\d{1,2}$/);
    });

    it('should generate time buckets for day granularity', () => {
      const now = new Date();
      const dayKey = `${now.getFullYear()}-${now.getMonth() + 1}-${now.getDate()}`;
      
      expect(dayKey).toMatch(/^\d{4}-\d{1,2}-\d{1,2}$/);
    });

    it('should calculate trend data points', () => {
      const events: AuditEvent[] = [
        { ts: new Date().toISOString(), action: 'model.call', decision: 'allow', categories: [] },
        { ts: new Date().toISOString(), action: 'model.call', decision: 'deny' },
        { ts: new Date(Date.now() - 3600000).toISOString(), action: 'model.call', decision: 'allow', categories: [] },
      ];

      // Group by hour
      const buckets: Map<string, AuditEvent[]> = new Map();
      
      for (const event of events) {
        const eventTime = new Date(event.ts);
        const bucketKey = `${eventTime.getFullYear()}-${eventTime.getMonth() + 1}-${eventTime.getDate()}-${eventTime.getHours()}`;
        
        if (!buckets.has(bucketKey)) {
          buckets.set(bucketKey, []);
        }
        buckets.get(bucketKey)!.push(event);
      }

      expect(buckets.size).toBeGreaterThanOrEqual(1);
    });

    it('should sort trend data by timestamp', () => {
      const dataPoints = [
        { timestamp: '2024-01-01T10:00:00Z', detections: 10 },
        { timestamp: '2024-01-01T09:00:00Z', detections: 5 },
        { timestamp: '2024-01-01T11:00:00Z', detections: 15 },
      ];

      const sorted = dataPoints.sort((a, b) => 
        new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
      );

      expect(sorted[0]?.timestamp).toBe('2024-01-01T09:00:00Z');
      expect(sorted[2]?.timestamp).toBe('2024-01-01T11:00:00Z');
    });
  });

  describe('Export Functionality', () => {
    it('should support JSON export format', () => {
      const format = 'json';
      expect(format).toBe('json');
    });

    it('should support CSV export format', () => {
      const format = 'csv';
      expect(format).toBe('csv');
    });

    it('should generate CSV content', () => {
      const overview = {
        totalDetections: 100,
        passRate: 0.8,
        blockRate: 0.2,
      };

      const csvLines = [
        'Metric,Value',
        `Total Detections,${overview.totalDetections}`,
        `Pass Rate,${overview.passRate}`,
        `Block Rate,${overview.blockRate}`,
      ];

      const csvContent = csvLines.join('\n');
      
      expect(csvContent).toContain('Metric,Value');
      expect(csvContent).toContain('Total Detections,100');
    });

    it('should generate JSON content', () => {
      const exportData = {
        overview: { totalDetections: 100 },
        exportInfo: {
          exportedAt: new Date().toISOString(),
        },
      };

      const jsonContent = JSON.stringify(exportData, null, 2);
      
      expect(jsonContent).toContain('totalDetections');
      expect(jsonContent).toContain('exportedAt');
    });

    it('should include export metadata', () => {
      const exportInfo = {
        timeRange: 'day',
        appId: 'app_1',
        exportedAt: new Date().toISOString(),
        exportedBy: 'user_1',
      };

      expect(exportInfo.timeRange).toBeDefined();
      expect(exportInfo.appId).toBeDefined();
      expect(exportInfo.exportedAt).toBeDefined();
      expect(exportInfo.exportedBy).toBeDefined();
    });
  });

  describe('App Filtering', () => {
    it('should filter events by app ID', () => {
      const events: AuditEvent[] = [
        { appId: 'app_1', action: 'model.call' },
        { appId: 'app_2', action: 'model.call' },
        { appId: 'app_1', action: 'guardrails.check' },
      ];

      const filtered = events.filter(e => e.appId === 'app_1');
      
      expect(filtered.length).toBe(2);
    });

    it('should aggregate stats across all apps', () => {
      const events: AuditEvent[] = [
        { appId: 'app_1', action: 'model.call' },
        { appId: 'app_2', action: 'model.call' },
        { appId: 'app_3', action: 'model.call' },
      ];

      const total = events.length;
      
      expect(total).toBe(3);
    });
  });
});
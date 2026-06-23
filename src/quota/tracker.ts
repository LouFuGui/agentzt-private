import { DatabaseSync } from 'node:sqlite';
import { existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { resolve } from 'node:path';
import { makeLogger } from '../shared/log.ts';
import type { QuotaHistoryEntry, QuotaType, QuotaUsage } from '../shared/types.ts';
import { getAppStore } from '../api/app-store.ts';

const log = makeLogger('quota-tracker');

// Database file path
const QUOTA_DB_FILE = resolve(process.env.AGENTZT_ROOT || '.', '.agentzt', 'quota.db');

// ============================================================================
// Quota Tracker - Real-time Usage Tracking
// ============================================================================

/**
 * QuotaTracker: SQLite-based quota usage tracking with history storage
 * 
 * Features:
 * - Records usage for each API call
 * - Updates quota balance in real-time
 * - Stores usage history for analytics
 * - Supports tracking by application and user
 */
export class QuotaTracker {
  private db: DatabaseSync;

  constructor(dbPath: string = QUOTA_DB_FILE) {
    // Ensure the directory exists
    const dir = dirname(dbPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    this.db = new DatabaseSync(dbPath);
    this.initTables();
    log.info(`QuotaTracker initialized at ${dbPath}`);
  }

  private initTables(): void {
    // Usage history table - stores each usage event
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS quota_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        app_id TEXT NOT NULL,
        user_id TEXT,
        type TEXT NOT NULL,
        delta INTEGER NOT NULL,
        total_used INTEGER NOT NULL,
        "limit" INTEGER NOT NULL,
        request_id TEXT,
        resource TEXT
      )
    `);

    // Create indexes for faster queries
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_quota_history_app_id ON quota_history(app_id)`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_quota_history_timestamp ON quota_history(timestamp)`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_quota_history_type ON quota_history(type)`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_quota_history_user_id ON quota_history(user_id)`);
  }

  /**
   * Record usage for an API call
   * This updates both the app's quota balance and stores history
   */
  recordUsage(
    appId: string,
    type: QuotaType,
    delta: number,
    options?: {
      userId?: string | null;
      requestId?: string;
      resource?: string;
    },
  ): QuotaUsage {
    const timestamp = new Date().toISOString();
    const appStore = getAppStore();
    const app = appStore.getApp(appId);

    if (!app) {
      throw new Error(`App not found: ${appId}`);
    }

    // Get current usage and limit
    const currentUsage = type === 'checks' ? app.quota.checksUsed : app.quota.tokensUsed;
    const limit = type === 'checks' ? app.quota.checksLimit : app.quota.tokensLimit;
    const newTotalUsed = currentUsage + delta;

    // Update app's quota balance
    if (type === 'checks') {
      appStore.incrementQuotaUsage(appId, delta, 0);
    } else if (type === 'tokens') {
      appStore.incrementQuotaUsage(appId, 0, delta);
    }

    // Store history entry
    const insert = this.db.prepare(`
      INSERT INTO quota_history (timestamp, app_id, user_id, type, delta, total_used, "limit", request_id, resource)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    insert.run(
      timestamp,
      appId,
      options?.userId ?? null,
      type,
      delta,
      newTotalUsed,
      limit,
      options?.requestId ?? null,
      options?.resource ?? null,
    );

    log.info(`Recorded usage: appId=${appId}, type=${type}, delta=${delta}, total=${newTotalUsed}`);

    return {
      type,
      used: newTotalUsed,
      limit,
      percentage: Math.round((newTotalUsed / limit) * 100),
      remaining: Math.max(0, limit - newTotalUsed),
    };
  }

  /**
   * Get current usage for an application
   */
  getUsage(appId: string): { checks: QuotaUsage; tokens: QuotaUsage } {
    const appStore = getAppStore();
    const app = appStore.getApp(appId);

    if (!app) {
      throw new Error(`App not found: ${appId}`);
    }

    return {
      checks: {
        type: 'checks',
        used: app.quota.checksUsed,
        limit: app.quota.checksLimit,
        percentage: Math.round((app.quota.checksUsed / app.quota.checksLimit) * 100),
        remaining: Math.max(0, app.quota.checksLimit - app.quota.checksUsed),
      },
      tokens: {
        type: 'tokens',
        used: app.quota.tokensUsed,
        limit: app.quota.tokensLimit,
        percentage: Math.round((app.quota.tokensUsed / app.quota.tokensLimit) * 100),
        remaining: Math.max(0, app.quota.tokensLimit - app.quota.tokensUsed),
      },
    };
  }

  /**
   * Get usage history for an application
   */
  getHistory(
    appId: string,
    options?: {
      type?: QuotaType;
      userId?: string;
      timeRange?: 'day' | 'week' | 'month';
      limit?: number;
    },
  ): QuotaHistoryEntry[] {
    const now = new Date();
    let startDate: Date;

    switch (options?.timeRange) {
      case 'day':
        startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        break;
      case 'week':
        startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        break;
      case 'month':
        startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        break;
      default:
        startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000); // default to month
    }

    const startTimestamp = startDate.toISOString();
    const limitCount = options?.limit ?? 1000;

    let query = `
      SELECT timestamp, app_id, user_id, type, delta, total_used, "limit", request_id, resource
      FROM quota_history
      WHERE app_id = ? AND timestamp >= ?
    `;
    const params: (string | number)[] = [appId, startTimestamp];

    if (options?.type) {
      query += ' AND type = ?';
      params.push(options.type);
    }

    if (options?.userId) {
      query += ' AND user_id = ?';
      params.push(options.userId);
    }

    query += ' ORDER BY timestamp DESC LIMIT ?';
    params.push(limitCount);

    const rows = this.db.prepare(query).all(...params) as Array<{
      timestamp: string;
      app_id: string;
      user_id: string | null;
      type: string;
      delta: number;
      total_used: number;
      limit: number;
      request_id: string | null;
      resource: string | null;
    }>;

    return rows.map((row) => ({
      timestamp: row.timestamp,
      appId: row.app_id,
      userId: row.user_id ?? undefined,
      type: row.type as QuotaType,
      delta: row.delta,
      totalUsed: row.total_used,
      limit: row.limit,
      requestId: row.request_id ?? undefined,
      resource: row.resource ?? undefined,
    }));
  }

  /**
   * Get aggregated usage statistics for an application
   */
  getAggregatedStats(
    appId: string,
    timeRange: 'day' | 'week' | 'month' = 'month',
  ): {
    checks: { total: number; count: number; avgDelta: number };
    tokens: { total: number; count: number; avgDelta: number };
  } {
    const now = new Date();
    let startDate: Date;

    switch (timeRange) {
      case 'day':
        startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        break;
      case 'week':
        startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        break;
      case 'month':
        startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        break;
    }

    const startTimestamp = startDate.toISOString();

    const rows = this.db.prepare(`
      SELECT type, SUM(delta) as total, COUNT(*) as count
      FROM quota_history
      WHERE app_id = ? AND timestamp >= ?
      GROUP BY type
    `).all(appId, startTimestamp) as Array<{
      type: string;
      total: number;
      count: number;
    }>;

    const result = {
      checks: { total: 0, count: 0, avgDelta: 0 },
      tokens: { total: 0, count: 0, avgDelta: 0 },
    };

    for (const row of rows) {
      if (row.type === 'checks') {
        result.checks = {
          total: row.total,
          count: row.count,
          avgDelta: row.count > 0 ? Math.round(row.total / row.count) : 0,
        };
      } else if (row.type === 'tokens') {
        result.tokens = {
          total: row.total,
          count: row.count,
          avgDelta: row.count > 0 ? Math.round(row.total / row.count) : 0,
        };
      }
    }

    return result;
  }

  /**
   * Reset usage for an application (admin operation)
   */
  resetUsage(appId: string): boolean {
    const appStore = getAppStore();
    const app = appStore.getApp(appId);

    if (!app) {
      return false;
    }

    // Reset quota in app store
    appStore.updateAppQuota(appId, {
      checksUsed: 0,
      tokensUsed: 0,
    });

    // Clear history for this app
    this.db.prepare(`DELETE FROM quota_history WHERE app_id = ?`).run(appId);

    log.info(`Reset usage for app ${appId}`);
    return true;
  }

  /**
   * Close the database connection
   */
  close(): void {
    this.db.close();
    log.info('QuotaTracker closed');
  }
}

// Singleton instance
let quotaTrackerInstance: QuotaTracker | null = null;

/**
 * Get the singleton QuotaTracker instance
 */
export function getQuotaTracker(): QuotaTracker {
  if (!quotaTrackerInstance) {
    quotaTrackerInstance = new QuotaTracker();
  }
  return quotaTrackerInstance;
}

/**
 * Reset the singleton (for testing)
 */
export function resetQuotaTracker(): void {
  if (quotaTrackerInstance) {
    quotaTrackerInstance.close();
    quotaTrackerInstance = null;
  }
}
import { DatabaseSync } from 'node:sqlite';
import { existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { resolve } from 'node:path';
import { makeLogger } from '../shared/log.ts';
import type { QuotaAlert, QuotaAlertThreshold, QuotaType, QuotaUsage } from '../shared/types.ts';
import { getAppStore } from '../api/app-store.ts';

const log = makeLogger('quota-alerts');

// Database file path
const ALERTS_DB_FILE = resolve(process.env.AGENTZT_ROOT || '.', '.agentzt', 'alerts.db');

// Default alert thresholds
const DEFAULT_THRESHOLDS: QuotaAlertThreshold[] = [
  { threshold: 80, triggered: false },
  { threshold: 90, triggered: false },
  { threshold: 100, triggered: false },
];

// Alert subscribers (for integration with external alert systems)
type AlertSubscriber = (alert: QuotaAlert) => void;
const alertSubscribers: AlertSubscriber[] = [];

// ============================================================================
// Quota Alerts - Alert Threshold Management and Triggering
// ============================================================================

/**
 * QuotaAlertsManager: SQLite-based quota alert management
 * 
 * Features:
 * - 80% threshold warning alert
 * - 90% threshold critical alert
 * - 100% threshold exceeded alert
 * - Alert history storage
 * - Integration with external alert systems via subscribers
 */
export class QuotaAlertsManager {
  private db: DatabaseSync;
  private thresholdStates: Map<string, Map<QuotaType, Map<number, QuotaAlertThreshold>>> = new Map();

  constructor(dbPath: string = ALERTS_DB_FILE) {
    // Ensure the directory exists
    const dir = dirname(dbPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    this.db = new DatabaseSync(dbPath);
    this.initTables();
    this.loadThresholdStates();
    log.info(`QuotaAlertsManager initialized at ${dbPath}`);
  }

  private initTables(): void {
    // Alert history table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS quota_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        app_id TEXT NOT NULL,
        user_id TEXT,
        type TEXT NOT NULL,
        threshold INTEGER NOT NULL,
        percentage INTEGER NOT NULL,
        used INTEGER NOT NULL,
        limit INTEGER NOT NULL,
        message TEXT NOT NULL
      )
    `);

    // Threshold states table (tracks which thresholds have been triggered)
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS threshold_states (
        app_id TEXT NOT NULL,
        type TEXT NOT NULL,
        threshold INTEGER NOT NULL,
        triggered INTEGER NOT NULL DEFAULT 0,
        triggered_at TEXT,
        PRIMARY KEY (app_id, type, threshold)
      )
    `);

    // Create indexes
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_quota_alerts_app_id ON quota_alerts(app_id)`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_quota_alerts_timestamp ON quota_alerts(timestamp)`);
  }

  private loadThresholdStates(): void {
    const rows = this.db.prepare(`
      SELECT app_id, type, threshold, triggered, triggered_at
      FROM threshold_states
    `).all() as Array<{
      app_id: string;
      type: string;
      threshold: number;
      triggered: number;
      triggered_at: string | null;
    }>;

    for (const row of rows) {
      if (!this.thresholdStates.has(row.app_id)) {
        this.thresholdStates.set(row.app_id, new Map());
      }
      const appMap = this.thresholdStates.get(row.app_id)!;
      if (!appMap.has(row.type as QuotaType)) {
        appMap.set(row.type as QuotaType, new Map());
      }
      const typeMap = appMap.get(row.type as QuotaType)!;
      typeMap.set(row.threshold, {
        threshold: row.threshold,
        triggered: row.triggered === 1,
        triggeredAt: row.triggered_at ?? undefined,
      });
    }
  }

  /**
   * Get threshold states for an app and type
   */
  getThresholdStates(appId: string, type: QuotaType): Map<number, QuotaAlertThreshold> {
    if (!this.thresholdStates.has(appId)) {
      this.thresholdStates.set(appId, new Map());
    }
    const appMap = this.thresholdStates.get(appId)!;
    if (!appMap.has(type)) {
      // Initialize with default thresholds
      const typeMap = new Map<number, QuotaAlertThreshold>();
      for (const threshold of DEFAULT_THRESHOLDS) {
        typeMap.set(threshold.threshold, { ...threshold });
      }
      appMap.set(type, typeMap);
    }
    return appMap.get(type)!;
  }

  /**
   * Trigger an alert for a threshold
   */
  triggerAlert(
    appId: string,
    type: QuotaType,
    threshold: number,
    usage: QuotaUsage,
    userId?: string | null,
  ): QuotaAlert {
    const timestamp = new Date().toISOString();
    const message = this.generateAlertMessage(type, threshold, usage);

    // Update threshold state
    const typeMap = this.getThresholdStates(appId, type);
    typeMap.set(threshold, {
      threshold,
      triggered: true,
      triggeredAt: timestamp,
    });

    // Persist to database
    this.db.prepare(`
      INSERT OR REPLACE INTO threshold_states (app_id, type, threshold, triggered, triggered_at)
      VALUES (?, ?, ?, 1, ?)
    `).run(appId, type, threshold, timestamp);

    // Store alert history
    this.db.prepare(`
      INSERT INTO quota_alerts (timestamp, app_id, user_id, type, threshold, percentage, used, limit, message)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      timestamp,
      appId,
      userId ?? null,
      type,
      threshold,
      usage.percentage,
      usage.used,
      usage.limit,
      message,
    );

    const alert: QuotaAlert = {
      appId,
      userId: userId ?? undefined,
      type,
      threshold,
      percentage: usage.percentage,
      used: usage.used,
      limit: usage.limit,
      triggeredAt: timestamp,
      message,
    };

    log.warn(`Quota alert triggered: appId=${appId}, type=${type}, threshold=${threshold}%, used=${usage.used}/${usage.limit}`);

    // Notify subscribers
    for (const subscriber of alertSubscribers) {
      try {
        subscriber(alert);
      } catch (error) {
        log.error(`Alert subscriber error: ${error}`);
      }
    }

    return alert;
  }

  /**
   * Generate alert message based on threshold level
   */
  private generateAlertMessage(type: QuotaType, threshold: number, usage: QuotaUsage): string {
    const resourceName = type === 'checks' ? 'API checks' : 'tokens';
    
    if (threshold === 100) {
      return `CRITICAL: ${resourceName} quota exceeded for application. Used: ${usage.used}/${usage.limit} (${usage.percentage}%). Requests will be rejected until quota is reset or increased.`;
    } else if (threshold === 90) {
      return `WARNING: ${resourceName} quota at ${usage.percentage}% (${usage.used}/${usage.limit}). Approaching limit - consider upgrading or optimizing usage.`;
    } else if (threshold === 80) {
      return `NOTICE: ${resourceName} quota at ${usage.percentage}% (${usage.used}/${usage.limit}). Monitoring usage patterns recommended.`;
    }
    
    return `${resourceName} quota alert at ${threshold}% threshold. Used: ${usage.used}/${usage.limit}`;
  }

  /**
   * Check if threshold should trigger an alert
   */
  shouldTriggerAlert(appId: string, type: QuotaType, threshold: number, percentage: number): boolean {
    const typeMap = this.getThresholdStates(appId, type);
    const state = typeMap.get(threshold);
    
    // Trigger if percentage reaches threshold and not already triggered
    if (percentage >= threshold && (!state || !state.triggered)) {
      return true;
    }
    
    // Reset trigger state if percentage drops below threshold
    if (percentage < threshold && state && state.triggered) {
      this.resetThresholdState(appId, type, threshold);
    }
    
    return false;
  }

  /**
   * Reset threshold state (when usage drops below threshold)
   */
  resetThresholdState(appId: string, type: QuotaType, threshold: number): void {
    const typeMap = this.getThresholdStates(appId, type);
    typeMap.set(threshold, {
      threshold,
      triggered: false,
      triggeredAt: undefined,
    });

    this.db.prepare(`
      INSERT OR REPLACE INTO threshold_states (app_id, type, threshold, triggered, triggered_at)
      VALUES (?, ?, ?, 0, NULL)
    `).run(appId, type, threshold);

    log.info(`Reset threshold state: appId=${appId}, type=${type}, threshold=${threshold}`);
  }

  /**
   * Reset all threshold states for an app (after quota reset)
   */
  resetAllThresholdStates(appId: string): void {
    const appMap = this.thresholdStates.get(appId);
    if (appMap) {
      for (const [type, typeMap] of appMap) {
        for (const [threshold] of typeMap) {
          this.resetThresholdState(appId, type, threshold);
        }
      }
    }

    log.info(`Reset all threshold states for app ${appId}`);
  }

  /**
   * Get alert history for an application
   */
  getAlertHistory(
    appId: string,
    options?: {
      type?: QuotaType;
      limit?: number;
    },
  ): QuotaAlert[] {
    let query = `SELECT * FROM quota_alerts WHERE app_id = ?`;
    const params: (string | number)[] = [appId];

    if (options?.type) {
      query += ' AND type = ?';
      params.push(options.type);
    }

    query += ' ORDER BY timestamp DESC LIMIT ?';
    params.push(options?.limit ?? 100);

    const rows = this.db.prepare(query).all(...params) as Array<{
      timestamp: string;
      app_id: string;
      user_id: string | null;
      type: string;
      threshold: number;
      percentage: number;
      used: number;
      limit: number;
      message: string;
    }>;

    return rows.map((row) => ({
      appId: row.app_id,
      userId: row.user_id ?? undefined,
      type: row.type as QuotaType,
      threshold: row.threshold,
      percentage: row.percentage,
      used: row.used,
      limit: row.limit,
      triggeredAt: row.timestamp,
      message: row.message,
    }));
  }

  /**
   * Close the database connection
   */
  close(): void {
    this.db.close();
    log.info('QuotaAlertsManager closed');
  }
}

// Singleton instance
let alertsManagerInstance: QuotaAlertsManager | null = null;

/**
 * Get the singleton QuotaAlertsManager instance
 */
export function getAlertsManager(): QuotaAlertsManager {
  if (!alertsManagerInstance) {
    alertsManagerInstance = new QuotaAlertsManager();
  }
  return alertsManagerInstance;
}

/**
 * Reset the singleton (for testing)
 */
export function resetAlertsManager(): void {
  if (alertsManagerInstance) {
    alertsManagerInstance.close();
    alertsManagerInstance = null;
  }
}

/**
 * Get default alert thresholds
 */
export function getAlertThresholds(): QuotaAlertThreshold[] {
  return DEFAULT_THRESHOLDS;
}

/**
 * Trigger a quota alert
 */
export function triggerQuotaAlert(
  appId: string,
  type: QuotaType,
  threshold: number,
  usage: QuotaUsage,
  userId?: string | null,
): QuotaAlert {
  const manager = getAlertsManager();
  return manager.triggerAlert(appId, type, threshold, usage, userId);
}

/**
 * Check and trigger alerts if thresholds are reached
 */
export function checkAndTriggerAlerts(
  appId: string,
  type: QuotaType,
  usage: QuotaUsage,
  userId?: string | null,
): QuotaAlert[] {
  const manager = getAlertsManager();
  const triggeredAlerts: QuotaAlert[] = [];

  for (const threshold of DEFAULT_THRESHOLDS) {
    if (manager.shouldTriggerAlert(appId, type, threshold.threshold, usage.percentage)) {
      const alert = manager.triggerAlert(appId, type, threshold.threshold, usage, userId);
      triggeredAlerts.push(alert);
    }
  }

  return triggeredAlerts;
}

/**
 * Subscribe to quota alerts
 */
export function subscribeToQuotaAlerts(subscriber: AlertSubscriber): void {
  alertSubscribers.push(subscriber);
}

/**
 * Unsubscribe from quota alerts
 */
export function unsubscribeFromQuotaAlerts(subscriber: AlertSubscriber): void {
  const index = alertSubscribers.indexOf(subscriber);
  if (index > -1) {
    alertSubscribers.splice(index, 1);
  }
}
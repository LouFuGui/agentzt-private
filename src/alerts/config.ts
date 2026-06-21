/**
 * Alert Configuration Manager
 * Manages alert rules, notification settings, and alert history.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type {
  Alert,
  AlertRule,
  AlertConfiguration,
  AlertSettings,
  AlertQuery,
  AlertHistoryResult,
  AlertStats,
  AlertType,
  AlertSeverity,
  AlertStatus,
  NotificationChannel,
} from './types.ts';
import { createDefaultAlertConfiguration, DEFAULT_ALERT_RULES, DEFAULT_ALERT_SETTINGS } from './types.ts';
import { makeLogger } from '../shared/log.ts';

const log = makeLogger('alert-config');

// ============================================================================
// Alert Configuration Store
// ============================================================================

/**
 * Manages alert configurations with persistence support.
 */
export class AlertConfigStore {
  private configs: Map<string, AlertConfiguration> = new Map();
  private alertHistory: Map<string, Alert[]> = new Map(); // configId -> alerts
  private configFile: string | null = null;

  /**
   * Initialize store with optional file persistence
   */
  initialize(configFile?: string): void {
    if (configFile) {
      this.configFile = configFile;
      this.loadFromFile();
    }
    log.info('Alert config store initialized');
  }

  /**
   * Load configurations from file
   */
  private loadFromFile(): void {
    if (!this.configFile || !existsSync(this.configFile)) {
      return;
    }

    try {
      const data = readFileSync(this.configFile, 'utf8');
      const configs = JSON.parse(data) as AlertConfiguration[];
      configs.forEach((config) => {
        this.configs.set(config.id, config);
      });
      log.info(`Loaded ${configs.length} alert configurations from file`);
    } catch (error) {
      log.error(`Failed to load alert configurations: ${error}`);
    }
  }

  /**
   * Save configurations to file
   */
  private saveToFile(): void {
    if (!this.configFile) return;

    try {
      mkdirSync(dirname(this.configFile), { recursive: true });
      const configs = Array.from(this.configs.values());
      writeFileSync(this.configFile, JSON.stringify(configs, null, 2));
      log.info(`Saved ${configs.length} alert configurations to file`);
    } catch (error) {
      log.error(`Failed to save alert configurations: ${error}`);
    }
  }

  /**
   * Get configuration by ID
   */
  getConfiguration(configId: string): AlertConfiguration | null {
    return this.configs.get(configId) ?? null;
  }

  /**
   * Get configuration for an application
   */
  getAppConfiguration(appId: string): AlertConfiguration | null {
    for (const config of this.configs.values()) {
      if (config.appId === appId) {
        return config;
      }
    }
    return null;
  }

  /**
   * Get configuration for a user
   */
  getUserConfiguration(userId: string): AlertConfiguration | null {
    for (const config of this.configs.values()) {
      if (config.userId === userId) {
        return config;
      }
    }
    return null;
  }

  /**
   * Create or update configuration
   */
  saveConfiguration(config: AlertConfiguration): AlertConfiguration {
    config.updatedAt = new Date().toISOString();
    this.configs.set(config.id, config);
    this.saveToFile();
    log.info(`Saved alert configuration: ${config.id}`);
    return config;
  }

  /**
   * Create default configuration for an app
   */
  createAppConfiguration(appId: string, userId?: string): AlertConfiguration {
    const existing = this.getAppConfiguration(appId);
    if (existing) {
      return existing;
    }

    const config = createDefaultAlertConfiguration(appId, userId);
    this.saveConfiguration(config);
    return config;
  }

  /**
   * Delete configuration
   */
  deleteConfiguration(configId: string): boolean {
    const deleted = this.configs.delete(configId);
    if (deleted) {
      this.alertHistory.delete(configId);
      this.saveToFile();
      log.info(`Deleted alert configuration: ${configId}`);
    }
    return deleted;
  }

  /**
   * Get all configurations
   */
  getAllConfigurations(): AlertConfiguration[] {
    return Array.from(this.configs.values());
  }

  // ============================================================================
  // Rule Management
  // ============================================================================

  /**
   * Get rules for a configuration
   */
  getRules(configId: string): AlertRule[] {
    const config = this.getConfiguration(configId);
    return config?.rules ?? [];
  }

  /**
   * Add a rule to configuration
   */
  addRule(configId: string, rule: AlertRule): AlertRule | null {
    const config = this.getConfiguration(configId);
    if (!config) return null;

    config.rules.push(rule);
    this.saveConfiguration(config);
    log.info(`Added rule ${rule.id} to configuration ${configId}`);
    return rule;
  }

  /**
   * Update a rule
   */
  updateRule(configId: string, ruleId: string, updates: Partial<AlertRule>): AlertRule | null {
    const config = this.getConfiguration(configId);
    if (!config) return null;

    const ruleIndex = config.rules.findIndex((r) => r.id === ruleId);
    if (ruleIndex === -1) return null;

    const existingRule = config.rules[ruleIndex];
    if (!existingRule) return null;
    
    const updatedRule: AlertRule = {
      id: updates.id ?? existingRule.id,
      type: updates.type ?? existingRule.type,
      name: updates.name ?? existingRule.name,
      description: updates.description ?? existingRule.description,
      threshold: updates.threshold ?? existingRule.threshold,
      enabled: updates.enabled ?? existingRule.enabled,
      channels: updates.channels ?? existingRule.channels,
      cooldownSeconds: updates.cooldownSeconds ?? existingRule.cooldownSeconds,
      conditions: updates.conditions ?? existingRule.conditions,
    };
    config.rules[ruleIndex] = updatedRule;
    this.saveConfiguration(config);
    log.info(`Updated rule ${ruleId} in configuration ${configId}`);
    return updatedRule;
  }

  /**
   * Delete a rule
   */
  deleteRule(configId: string, ruleId: string): boolean {
    const config = this.getConfiguration(configId);
    if (!config) return false;

    const ruleIndex = config.rules.findIndex((r) => r.id === ruleId);
    if (ruleIndex === -1) return false;

    config.rules.splice(ruleIndex, 1);
    this.saveConfiguration(config);
    log.info(`Deleted rule ${ruleId} from configuration ${configId}`);
    return true;
  }

  /**
   * Enable/disable a rule
   */
  setRuleEnabled(configId: string, ruleId: string, enabled: boolean): AlertRule | null {
    return this.updateRule(configId, ruleId, { enabled });
  }

  // ============================================================================
  // Notification Channel Management
  // ============================================================================

  /**
   * Get notification channels for a configuration
   */
  getChannels(configId: string): NotificationChannel[] {
    const config = this.getConfiguration(configId);
    return config?.channels ?? [];
  }

  /**
   * Add a notification channel
   */
  addChannel(configId: string, channel: NotificationChannel): NotificationChannel | null {
    const config = this.getConfiguration(configId);
    if (!config) return null;

    config.channels.push(channel);
    this.saveConfiguration(config);
    log.info(`Added channel ${channel.type} to configuration ${configId}`);
    return channel;
  }

  /**
   * Update a notification channel
   */
  updateChannel(
    configId: string,
    channelType: string,
    updates: Partial<NotificationChannel>
  ): NotificationChannel | null {
    const config = this.getConfiguration(configId);
    if (!config) return null;

    const channelIndex = config.channels.findIndex((c) => c.type === channelType);
    if (channelIndex === -1) return null;

    const existingChannel = config.channels[channelIndex];
    if (!existingChannel) return null;
    
    const updatedChannel: NotificationChannel = {
      type: updates.type ?? existingChannel.type,
      enabled: updates.enabled ?? existingChannel.enabled,
      config: updates.config ?? existingChannel.config,
    };
    config.channels[channelIndex] = updatedChannel;
    this.saveConfiguration(config);
    log.info(`Updated channel ${channelType} in configuration ${configId}`);
    return updatedChannel;
  }

  /**
   * Delete a notification channel
   */
  deleteChannel(configId: string, channelType: string): boolean {
    const config = this.getConfiguration(configId);
    if (!config) return false;

    const channelIndex = config.channels.findIndex((c) => c.type === channelType);
    if (channelIndex === -1) return false;

    config.channels.splice(channelIndex, 1);
    this.saveConfiguration(config);
    log.info(`Deleted channel ${channelType} from configuration ${configId}`);
    return true;
  }

  // ============================================================================
  // Settings Management
  // ============================================================================

  /**
   * Get settings for a configuration
   */
  getSettings(configId: string): AlertSettings | null {
    const config = this.getConfiguration(configId);
    return config?.settings ?? null;
  }

  /**
   * Update settings
   */
  updateSettings(configId: string, updates: Partial<AlertSettings>): AlertSettings | null {
    const config = this.getConfiguration(configId);
    if (!config) return null;

    config.settings = { ...config.settings, ...updates };
    this.saveConfiguration(config);
    log.info(`Updated settings for configuration ${configId}`);
    return config.settings;
  }

  // ============================================================================
  // Alert History Management
  // ============================================================================

  /**
   * Record an alert in history
   */
  recordAlert(configId: string, alert: Alert): void {
    let history = this.alertHistory.get(configId) ?? [];
    history.unshift(alert);

    // Limit history size
    const config = this.getConfiguration(configId);
    const maxSize = config?.settings.maxHistorySize ?? 1000;
    if (history.length > maxSize) {
      history = history.slice(0, maxSize);
    }

    this.alertHistory.set(configId, history);
  }

  /**
   * Query alert history
   */
  queryHistory(configId: string, query: AlertQuery): AlertHistoryResult {
    let alerts = this.alertHistory.get(configId) ?? [];

    // Apply filters
    if (query.type) {
      alerts = alerts.filter((a) => a.type === query.type);
    }
    if (query.severity) {
      alerts = alerts.filter((a) => a.severity === query.severity);
    }
    if (query.status) {
      alerts = alerts.filter((a) => a.status === query.status);
    }
    if (query.appId) {
      alerts = alerts.filter((a) => a.appId === query.appId);
    }
    if (query.userId) {
      alerts = alerts.filter((a) => a.userId === query.userId);
    }
    if (query.agentId) {
      alerts = alerts.filter((a) => a.agentId === query.agentId);
    }
    if (query.startTime) {
      alerts = alerts.filter((a) => a.timestamp >= query.startTime!);
    }
    if (query.endTime) {
      alerts = alerts.filter((a) => a.timestamp <= query.endTime!);
    }
    if (query.search) {
      const searchLower = query.search.toLowerCase();
      alerts = alerts.filter(
        (a) => a.title.toLowerCase().includes(searchLower) || 
               a.message.toLowerCase().includes(searchLower)
      );
    }

    // Sort
    const sortBy = query.sortBy ?? 'timestamp';
    const sortOrder = query.sortOrder ?? 'desc';
    alerts.sort((a, b) => {
      let comparison = 0;
      if (sortBy === 'timestamp') {
        comparison = a.timestamp.localeCompare(b.timestamp);
      } else if (sortBy === 'severity') {
        const severityOrder = { critical: 4, error: 3, warning: 2, info: 1 };
        comparison = severityOrder[a.severity] - severityOrder[b.severity];
      } else if (sortBy === 'type') {
        comparison = a.type.localeCompare(b.type);
      }
      return sortOrder === 'desc' ? -comparison : comparison;
    });

    // Paginate
    const page = query.page ?? 1;
    const pageSize = query.pageSize ?? 50;
    const startIndex = (page - 1) * pageSize;
    const endIndex = startIndex + pageSize;
    const paginatedAlerts = alerts.slice(startIndex, endIndex);

    return {
      alerts: paginatedAlerts,
      total: alerts.length,
      page,
      pageSize,
      totalPages: Math.ceil(alerts.length / pageSize),
    };
  }

  /**
   * Get alert by ID
   */
  getAlert(configId: string, alertId: string): Alert | null {
    const history = this.alertHistory.get(configId) ?? [];
    return history.find((a) => a.id === alertId) ?? null;
  }

  /**
   * Acknowledge an alert
   */
  acknowledgeAlert(configId: string, alertId: string, acknowledgedBy: string): Alert | null {
    const alert = this.getAlert(configId, alertId);
    if (!alert) return null;

    alert.status = 'acknowledged';
    alert.acknowledgedBy = acknowledgedBy;
    alert.acknowledgedAt = new Date().toISOString();
    alert.updatedAt = new Date().toISOString();

    log.info(`Alert ${alertId} acknowledged by ${acknowledgedBy}`);
    return alert;
  }

  /**
   * Resolve an alert
   */
  resolveAlert(configId: string, alertId: string, resolutionNotes?: string): Alert | null {
    const alert = this.getAlert(configId, alertId);
    if (!alert) return null;

    alert.status = 'resolved';
    alert.resolutionNotes = resolutionNotes;
    alert.updatedAt = new Date().toISOString();

    log.info(`Alert ${alertId} resolved`);
    return alert;
  }

  /**
   * Get alert statistics
   */
  getStats(configId: string, startTime?: string, endTime?: string): AlertStats {
    let alerts = this.alertHistory.get(configId) ?? [];

    // Apply time filter
    if (startTime) {
      alerts = alerts.filter((a) => a.timestamp >= startTime);
    }
    if (endTime) {
      alerts = alerts.filter((a) => a.timestamp <= endTime);
    }

    const byType: Record<AlertType, number> = {
      risk_event: 0,
      quota_warning: 0,
      quota_exceeded: 0,
      anomaly: 0,
    };
    const bySeverity: Record<AlertSeverity, number> = {
      info: 0,
      warning: 0,
      error: 0,
      critical: 0,
    };
    const byStatus: Record<AlertStatus, number> = {
      active: 0,
      acknowledged: 0,
      resolved: 0,
    };

    alerts.forEach((a) => {
      byType[a.type]++;
      bySeverity[a.severity]++;
      byStatus[a.status]++;
    });

    // Calculate average times
    const acknowledgedAlerts = alerts.filter((a) => a.acknowledgedAt);
    const resolvedAlerts = alerts.filter((a) => a.status === 'resolved');

    let avgAckTimeSeconds: number | undefined;
    let avgResolveTimeSeconds: number | undefined;

    if (acknowledgedAlerts.length > 0) {
      const ackTimes = acknowledgedAlerts.map((a) => {
        const created = new Date(a.timestamp).getTime();
        const acked = new Date(a.acknowledgedAt!).getTime();
        return (acked - created) / 1000;
      });
      avgAckTimeSeconds = ackTimes.reduce((sum, t) => sum + t, 0) / ackTimes.length;
    }

    if (resolvedAlerts.length > 0) {
      const resolveTimes = resolvedAlerts.map((a) => {
        const created = new Date(a.timestamp).getTime();
        const resolved = new Date(a.updatedAt!).getTime();
        return (resolved - created) / 1000;
      });
      avgResolveTimeSeconds = resolveTimes.reduce((sum, t) => sum + t, 0) / resolveTimes.length;
    }

    return {
      total: alerts.length,
      byType,
      bySeverity,
      byStatus,
      activeCount: byStatus.active,
      avgAckTimeSeconds,
      avgResolveTimeSeconds,
    };
  }

  /**
   * Clear alert history
   */
  clearHistory(configId: string): void {
    this.alertHistory.delete(configId);
    log.info(`Cleared alert history for configuration ${configId}`);
  }
}

// ============================================================================
// Factory Functions
// ============================================================================

let defaultConfigStore: AlertConfigStore | null = null;

/**
 * Get or create the default alert configuration store
 */
export function getAlertConfigStore(configFile?: string): AlertConfigStore {
  if (!defaultConfigStore) {
    defaultConfigStore = new AlertConfigStore();
    if (configFile) {
      defaultConfigStore.initialize(configFile);
    }
  }
  return defaultConfigStore;
}

/**
 * Reset config store (for testing)
 */
export function resetAlertConfigStore(): void {
  defaultConfigStore = null;
}
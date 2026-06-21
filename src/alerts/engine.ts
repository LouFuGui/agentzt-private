/**
 * Alert Engine
 * Core logic for evaluating conditions and triggering alerts.
 */

import type {
  Alert,
  AlertRule,
  AlertType,
  AlertSeverity,
  AlertDetails,
  AlertConfiguration,
  NotificationChannel,
} from './types.ts';
import { createDefaultAlertConfiguration } from './types.ts';
import { getWebSocketAlertService } from './websocket.ts';
import { getWebhookSender, getWebhookHistoryTracker } from './webhook.ts';
import { getEmailSender } from './email.ts';
import { makeLogger } from '../shared/log.ts';
import type { AuditEvent, RiskLevel, AppQuota } from '../shared/types.ts';

const log = makeLogger('alert-engine');

// ============================================================================
// Alert Trigger Context
// ============================================================================

/** Context data for evaluating alert triggers */
export interface AlertTriggerContext {
  /** Application ID */
  appId?: string;
  /** User ID */
  userId?: string;
  /** Agent ID */
  agentId?: string;
  /** Current quota usage */
  quota?: AppQuota;
  /** Recent audit events */
  recentEvents?: AuditEvent[];
  /** Time window for anomaly detection (seconds) */
  anomalyTimeWindow?: number;
  /** Threshold for anomaly detection */
  anomalyThreshold?: number;
}

// ============================================================================
// Alert Engine
// ============================================================================

/**
 * Core alert engine that evaluates conditions and triggers notifications.
 */
export class AlertEngine {
  private configuration: AlertConfiguration;
  private alertHistory: Alert[] = [];
  private cooldownTracker: Map<string, number> = new Map(); // ruleId -> lastTriggerTime
  private highRiskEventTracker: Map<string, number[]> = new Map(); // appId -> timestamps
  private maxHistorySize: number = 1000;

  constructor(configuration: AlertConfiguration) {
    this.configuration = configuration;
    this.maxHistorySize = configuration.settings.maxHistorySize;
  }

  /**
   * Update alert configuration
   */
  updateConfiguration(config: AlertConfiguration): void {
    this.configuration = config;
    this.maxHistorySize = config.settings.maxHistorySize;
    log.info('Alert configuration updated');
  }

  /**
   * Get current configuration
   */
  getConfiguration(): AlertConfiguration {
    return this.configuration;
  }

  /**
   * Evaluate and trigger alerts based on context
   */
  evaluate(context: AlertTriggerContext): Alert[] {
    if (!this.configuration.settings.enabled) {
      return [];
    }

    const triggeredAlerts: Alert[] = [];

    for (const rule of this.configuration.rules) {
      if (!rule.enabled) continue;

      const alert = this.evaluateRule(rule, context);
      if (alert) {
        triggeredAlerts.push(alert);
        this.processAlert(alert, rule.channels);
      }
    }

    return triggeredAlerts;
  }

  /**
   * Evaluate a single rule against context
   */
  private evaluateRule(rule: AlertRule, context: AlertTriggerContext): Alert | null {
    // Check cooldown
    if (this.isInCooldown(rule)) {
      log.info(`Rule ${rule.id} is in cooldown, skipping`);
      return null;
    }

    let alert: Alert | null = null;

    switch (rule.type) {
      case 'risk_event':
        alert = this.evaluateRiskEvent(rule, context);
        break;
      case 'quota_warning':
        alert = this.evaluateQuotaWarning(rule, context);
        break;
      case 'quota_exceeded':
        alert = this.evaluateQuotaExceeded(rule, context);
        break;
      case 'anomaly':
        alert = this.evaluateAnomaly(rule, context);
        break;
    }

    if (alert) {
      // Update cooldown tracker
      this.cooldownTracker.set(rule.id, Date.now());
      // Add to history
      this.addToHistory(alert);
    }

    return alert;
  }

  /**
   * Check if rule is in cooldown period
   */
  private isInCooldown(rule: AlertRule): boolean {
    const lastTrigger = this.cooldownTracker.get(rule.id);
    if (!lastTrigger) return false;

    const cooldownMs = rule.cooldownSeconds * 1000;
    return Date.now() - lastTrigger < cooldownMs;
  }

  /**
   * Evaluate risk event rule
   */
  private evaluateRiskEvent(rule: AlertRule, context: AlertTriggerContext): Alert | null {
    const recentEvents = context.recentEvents ?? [];
    const highRiskEvents = recentEvents.filter(
      (e) => e.meta?.riskLevel === 'high_risk' || e.categories?.some((c) => c.includes('high'))
    );

    if (highRiskEvents.length < rule.threshold) {
      return null;
    }

    const latestEvent = highRiskEvents[highRiskEvents.length - 1];
    if (!latestEvent) return null;
    
    const details: AlertDetails = {
      riskLevel: 'high_risk',
      categories: latestEvent.categories ?? [],
      score: latestEvent.score,
      eventData: latestEvent.meta,
    };

    return this.createAlert(rule, 'High Risk Event Detected', details, context, 'error');
  }

  /**
   * Evaluate quota warning rule
   */
  private evaluateQuotaWarning(rule: AlertRule, context: AlertTriggerContext): Alert | null {
    const quota = context.quota;
    if (!quota) return null;

    const checksPercentage = (quota.checksUsed / quota.checksLimit) * 100;
    const tokensPercentage = (quota.tokensUsed / quota.tokensLimit) * 100;
    const maxPercentage = Math.max(checksPercentage, tokensPercentage);

    if (maxPercentage < rule.threshold) {
      return null;
    }

    const details: AlertDetails = {
      quotaPercentage: maxPercentage,
      quotaType: checksPercentage >= tokensPercentage ? 'checks' : 'tokens',
    };

    const severity = maxPercentage >= 90 ? 'warning' : 'info';
    const message = `Quota usage at ${maxPercentage.toFixed(1)}% (${quota.checksUsed}/${quota.checksLimit} checks, ${quota.tokensUsed}/${quota.tokensLimit} tokens)`;

    return this.createAlert(rule, message, details, context, severity);
  }

  /**
   * Evaluate quota exceeded rule
   */
  private evaluateQuotaExceeded(rule: AlertRule, context: AlertTriggerContext): Alert | null {
    const quota = context.quota;
    if (!quota) return null;

    const checksExceeded = quota.checksUsed >= quota.checksLimit;
    const tokensExceeded = quota.tokensUsed >= quota.tokensLimit;

    if (!checksExceeded && !tokensExceeded) {
      return null;
    }

    const details: AlertDetails = {
      quotaPercentage: 100,
      quotaType: checksExceeded ? 'checks' : 'tokens',
    };

    const exceededType = checksExceeded ? 'checks' : 'tokens';
    const message = `Quota limit exceeded for ${exceededType}`;

    return this.createAlert(rule, message, details, context, 'critical');
  }

  /**
   * Evaluate anomaly rule
   */
  private evaluateAnomaly(rule: AlertRule, context: AlertTriggerContext): Alert | null {
    const recentEvents = context.recentEvents ?? [];
    const timeWindowMs = (context.anomalyTimeWindow ?? 60) * 1000;
    const threshold = context.anomalyThreshold ?? rule.threshold;

    // Track high-risk events for anomaly detection
    const appId = context.appId ?? 'default';
    const now = Date.now();
    const windowStart = now - timeWindowMs;

    // Get existing timestamps and filter to current window
    const existingTimestamps = this.highRiskEventTracker.get(appId) ?? [];
    const windowTimestamps = existingTimestamps.filter((t) => t >= windowStart);

    // Add new high-risk events
    const newHighRiskEvents = recentEvents.filter(
      (e) => e.meta?.riskLevel === 'high_risk' || e.decision === 'deny'
    );
    newHighRiskEvents.forEach(() => windowTimestamps.push(now));

    // Update tracker
    this.highRiskEventTracker.set(appId, windowTimestamps);

    // Check if threshold exceeded
    if (windowTimestamps.length < threshold) {
      return null;
    }

    const details: AlertDetails = {
      anomalyType: 'high_risk_burst',
      eventCount: windowTimestamps.length,
      timeWindowSeconds: context.anomalyTimeWindow ?? 60,
    };

    const message = `Anomaly detected: ${windowTimestamps.length} high-risk events in ${context.anomalyTimeWindow ?? 60} seconds`;

    return this.createAlert(rule, message, details, context, 'error');
  }

  /**
   * Create an alert instance
   */
  private createAlert(
    rule: AlertRule,
    message: string,
    details: AlertDetails,
    context: AlertTriggerContext,
    severity: AlertSeverity
  ): Alert {
    return {
      id: this.generateAlertId(),
      type: rule.type,
      severity,
      status: 'active',
      title: rule.name,
      message,
      timestamp: new Date().toISOString(),
      appId: context.appId,
      userId: context.userId,
      agentId: context.agentId,
      details,
      ruleId: rule.id,
    };
  }

  /**
   * Process and send alert through notification channels
   */
  private processAlert(alert: Alert, channels: NotificationChannel[]): void {
    log.info(`Processing alert: ${alert.id} (${alert.type})`);

    for (const channel of channels) {
      if (!channel.enabled) continue;

      switch (channel.type) {
        case 'dashboard':
          this.sendDashboardAlert(alert, channel.config as any);
          break;
        case 'webhook':
          this.sendWebhookAlert(alert, channel.config as any);
          break;
        case 'email':
          this.sendEmailAlert(alert, channel.config as any);
          break;
      }
    }
  }

  /**
   * Send alert to Dashboard via WebSocket
   */
  private sendDashboardAlert(alert: Alert, config: any): void {
    const wsService = getWebSocketAlertService();
    if (wsService.isRunning()) {
      wsService.broadcastAlert(alert, config);
      log.info(`Alert sent to Dashboard: ${alert.id}`);
    } else {
      log.warn('WebSocket service not running, skipping Dashboard alert');
    }
  }

  /**
   * Send alert via Webhook
   */
  private async sendWebhookAlert(alert: Alert, config: any): Promise<void> {
    const sender = getWebhookSender();
    const success = await sender.sendAlert(alert, config);
    if (success) {
      log.info(`Alert sent via Webhook: ${alert.id}`);
    } else {
      log.warn(`Webhook delivery failed for alert: ${alert.id}`);
    }
  }

  /**
   * Send alert via Email
   */
  private async sendEmailAlert(alert: Alert, config: any): Promise<void> {
    const sender = getEmailSender();
    if (sender.isEnabled()) {
      const success = await sender.sendAlert(alert, config);
      if (success) {
        log.info(`Alert sent via Email: ${alert.id}`);
      } else {
        log.warn(`Email delivery failed for alert: ${alert.id}`);
      }
    } else {
      log.warn('Email sender not configured, skipping email alert');
    }
  }

  /**
   * Add alert to history
   */
  private addToHistory(alert: Alert): void {
    this.alertHistory.unshift(alert);
    if (this.alertHistory.length > this.maxHistorySize) {
      this.alertHistory = this.alertHistory.slice(0, this.maxHistorySize);
    }
  }

  /**
   * Get alert history
   */
  getHistory(limit?: number): Alert[] {
    return this.alertHistory.slice(0, limit ?? 100);
  }

  /**
   * Get active alerts
   */
  getActiveAlerts(): Alert[] {
    return this.alertHistory.filter((a) => a.status === 'active');
  }

  /**
   * Acknowledge an alert
   */
  acknowledgeAlert(alertId: string, acknowledgedBy: string): Alert | null {
    const alert = this.alertHistory.find((a) => a.id === alertId);
    if (!alert) return null;

    alert.status = 'acknowledged';
    alert.acknowledgedBy = acknowledgedBy;
    alert.acknowledgedAt = new Date().toISOString();
    alert.updatedAt = new Date().toISOString();

    log.info(`Alert acknowledged: ${alertId} by ${acknowledgedBy}`);
    return alert;
  }

  /**
   * Resolve an alert
   */
  resolveAlert(alertId: string, resolutionNotes?: string): Alert | null {
    const alert = this.alertHistory.find((a) => a.id === alertId);
    if (!alert) return null;

    alert.status = 'resolved';
    alert.resolutionNotes = resolutionNotes;
    alert.updatedAt = new Date().toISOString();

    log.info(`Alert resolved: ${alertId}`);
    return alert;
  }

  /**
   * Generate unique alert ID
   */
  private generateAlertId(): string {
    return `alert-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  }

  /**
   * Clear cooldown for a rule (for testing)
   */
  clearCooldown(ruleId: string): void {
    this.cooldownTracker.delete(ruleId);
  }

  /**
   * Clear all cooldowns (for testing)
   */
  clearAllCooldowns(): void {
    this.cooldownTracker.clear();
  }

  /**
   * Clear high-risk event tracker (for testing)
   */
  clearEventTracker(): void {
    this.highRiskEventTracker.clear();
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Create an alert from an audit event
 */
export function createAlertFromAuditEvent(
  event: AuditEvent,
  ruleId: string
): Alert {
  const riskLevel = (event.meta?.riskLevel as RiskLevel) ?? 'unknown';
  const severity: AlertSeverity = riskLevel === 'high_risk' ? 'error' : 
                                   riskLevel === 'medium_risk' ? 'warning' : 'info';

  const details: AlertDetails = {
    riskLevel: riskLevel === 'unknown' ? undefined : riskLevel,
    categories: event.categories ?? [],
    score: event.score,
    eventData: event.meta,
  };

  return {
    id: `alert-${event.requestId}`,
    type: 'risk_event',
    severity,
    status: 'active',
    title: `Risk Event: ${event.action}`,
    message: event.reason,
    timestamp: event.ts,
    appId: event.appId ?? undefined,
    userId: event.userId ?? undefined,
    agentId: event.agentId ?? undefined,
    details,
    ruleId,
  };
}

/**
 * Create a quota alert
 */
export function createQuotaAlert(
  quota: AppQuota,
  appId: string,
  userId: string,
  threshold: number,
  ruleId: string
): Alert {
  const checksPercentage = (quota.checksUsed / quota.checksLimit) * 100;
  const tokensPercentage = (quota.tokensUsed / quota.tokensLimit) * 100;
  const maxPercentage = Math.max(checksPercentage, tokensPercentage);

  const type: AlertType = maxPercentage >= 100 ? 'quota_exceeded' : 'quota_warning';
  const severity: AlertSeverity = maxPercentage >= 100 ? 'critical' : 
                                   maxPercentage >= 90 ? 'warning' : 'info';

  const details: AlertDetails = {
    quotaPercentage: maxPercentage,
    quotaType: checksPercentage >= tokensPercentage ? 'checks' : 'tokens',
  };

  const message = maxPercentage >= 100 
    ? 'Quota limit exceeded' 
    : `Quota usage at ${maxPercentage.toFixed(1)}%`;

  return {
    id: `quota-alert-${appId}-${Date.now()}`,
    type,
    severity,
    status: 'active',
    title: 'Quota Alert',
    message,
    timestamp: new Date().toISOString(),
    appId,
    userId,
    details,
    ruleId,
  };
}

// ============================================================================
// Factory Functions
// ============================================================================

let defaultAlertEngine: AlertEngine | null = null;

/**
 * Get or create the default alert engine
 */
export function getAlertEngine(config?: AlertConfiguration): AlertEngine {
  if (!defaultAlertEngine && config) {
    defaultAlertEngine = new AlertEngine(config);
  }
  if (!defaultAlertEngine) {
    // Create with default configuration (sync import)
    defaultAlertEngine = new AlertEngine(createDefaultAlertConfiguration());
  }
  return defaultAlertEngine;
}

/**
 * Reset alert engine (for testing)
 */
export function resetAlertEngine(): void {
  defaultAlertEngine = null;
}
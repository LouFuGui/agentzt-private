/**
 * Alert System Module
 * Provides comprehensive alert management for the AgentZT Gateway.
 */

// Types
export type {
  AlertType,
  AlertSeverity,
  AlertStatus,
  AlertRule,
  AlertCondition,
  Alert,
  AlertDetails,
  NotificationChannel,
  NotificationChannelType,
  EmailConfig,
  WebhookConfig,
  DashboardConfig,
  AlertConfiguration,
  AlertSettings,
  AlertQuery,
  AlertHistoryResult,
  AlertStats,
} from './types.ts';

export {
  DEFAULT_ALERT_RULES,
  DEFAULT_ALERT_SETTINGS,
  createDefaultAlertConfiguration,
} from './types.ts';

// Email Sender
export {
  EmailAlertSender,
  getEmailSender,
  resetEmailSender,
} from './email.ts';

export type { EmailSenderConfig } from './email.ts';

// Webhook Sender
export type {
  WebhookPayload,
  WebhookDeliveryResult,
} from './webhook.ts';

export {
  WebhookAlertSender,
  WebhookHistoryTracker,
  getWebhookSender,
  getWebhookHistoryTracker,
  resetWebhookSender,
  sendToWebhooks,
} from './webhook.ts';

// WebSocket Service
export type {
  WebSocketMessage,
  DashboardAlertMessage,
  SubscriptionRequest,
} from './websocket.ts';

export {
  WebSocketAlertService,
  getWebSocketAlertService,
  resetWebSocketAlertService,
} from './websocket.ts';

// Alert Engine
export type {
  AlertTriggerContext,
} from './engine.ts';

export {
  AlertEngine,
  createAlertFromAuditEvent,
  createQuotaAlert,
  getAlertEngine,
  resetAlertEngine,
} from './engine.ts';

// Configuration Manager
export {
  AlertConfigStore,
  getAlertConfigStore,
  resetAlertConfigStore,
} from './config.ts';

// ============================================================================
// Convenience Functions
// ============================================================================

import type { Alert, AlertConfiguration } from './types.ts';
import type { AlertTriggerContext } from './engine.ts';
import type { AuditEvent, AppQuota } from '../shared/types.ts';
import { getAlertEngine } from './engine.ts';
import { getAlertConfigStore } from './config.ts';
import { getWebSocketAlertService } from './websocket.ts';
import { createDefaultAlertConfiguration } from './types.ts';

/**
 * Initialize the alert system with default configuration
 */
export function initializeAlertSystem(configFile?: string): void {
  const configStore = getAlertConfigStore(configFile);
  const wsService = getWebSocketAlertService();
  
  // WebSocket service needs to be started separately with the HTTP server
  // wsService.start() or wsService.handleUpgrade()
}

/**
 * Process an audit event and trigger alerts if needed
 */
export async function processAuditEvent(
  event: AuditEvent,
  appId?: string,
  userId?: string
): Promise<Alert[]> {
  const configStore = getAlertConfigStore();
  
  // Get configuration for the app or user
  let config: AlertConfiguration | null = null;
  if (appId) {
    config = configStore.getAppConfiguration(appId);
  }
  if (!config && userId) {
    config = configStore.getUserConfiguration(userId);
  }
  
  // If no configuration exists, create default
  if (!config) {
    config = configStore.createAppConfiguration(appId ?? 'default', userId);
  }
  
  // Get alert engine and evaluate
  const engine = getAlertEngine(config);
  const context: AlertTriggerContext = {
    appId: event.appId ?? appId,
    userId: event.userId ?? userId,
    agentId: event.agentId ?? undefined,
    recentEvents: [event],
  };
  
  const alerts = engine.evaluate(context);
  
  // Record alerts in history
  alerts.forEach((alert) => {
    configStore.recordAlert(config!.id, alert);
  });
  
  return alerts;
}

/**
 * Check quota and trigger alerts if thresholds exceeded
 */
export async function checkQuotaAlerts(
  quota: AppQuota,
  appId: string,
  userId: string
): Promise<Alert[]> {
  const configStore = getAlertConfigStore();
  
  // Get or create configuration
  let config = configStore.getAppConfiguration(appId);
  if (!config) {
    config = configStore.createAppConfiguration(appId, userId);
  }
  
  // Get alert engine and evaluate
  const engine = getAlertEngine(config);
  const context: AlertTriggerContext = {
    appId,
    userId,
    quota,
  };
  
  const alerts = engine.evaluate(context);
  
  // Record alerts in history
  alerts.forEach((alert) => {
    configStore.recordAlert(config!.id, alert);
  });
  
  return alerts;
}

/**
 * Start WebSocket alert service on a specific port
 */
export function startWebSocketAlertService(port?: number): void {
  const wsService = getWebSocketAlertService();
  wsService.start(port);
}

/**
 * Stop WebSocket alert service
 */
export function stopWebSocketAlertService(): void {
  const wsService = getWebSocketAlertService();
  wsService.stop();
}
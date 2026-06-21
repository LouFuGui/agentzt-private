/**
 * Webhook Alert Sender
 * Sends alert notifications via HTTP POST to configured URLs.
 */

import type { Alert, WebhookConfig } from './types.ts';
import { makeLogger } from '../shared/log.ts';
import { createHmac } from 'node:crypto';

const log = makeLogger('alert-webhook');

// ============================================================================
// Webhook Payload
// ============================================================================

/** Standard webhook payload structure */
export interface WebhookPayload {
  /** Webhook event type */
  event: 'alert.created' | 'alert.acknowledged' | 'alert.resolved';
  /** Alert data */
  alert: Alert;
  /** Timestamp of webhook delivery */
  deliveredAt: string;
  /** Signature for payload verification (if secretKey configured) */
  signature?: string;
  /** Gateway identifier */
  source: string;
}

// ============================================================================
// Webhook Sender Class
// ============================================================================

/**
 * Webhook alert sender with retry support and payload signing.
 */
export class WebhookAlertSender {
  private defaultTimeoutMs: number = 10000;
  private defaultRetryAttempts: number = 3;
  private defaultRetryDelayMs: number = 1000;

  /**
   * Send an alert via webhook
   */
  async sendAlert(alert: Alert, webhookConfig: WebhookConfig): Promise<boolean> {
    if (!webhookConfig.url) {
      log.warn('Webhook URL not configured');
      return false;
    }

    const payload = this.createPayload(alert);
    const headers = this.prepareHeaders(webhookConfig, payload);

    const timeoutMs = webhookConfig.timeoutMs ?? this.defaultTimeoutMs;
    const retryAttempts = webhookConfig.retryAttempts ?? this.defaultRetryAttempts;
    const retryDelayMs = webhookConfig.retryDelayMs ?? this.defaultRetryDelayMs;

    // Attempt delivery with retries
    for (let attempt = 0; attempt <= retryAttempts; attempt++) {
      try {
        const success = await this.deliver(webhookConfig.url, payload, headers, timeoutMs);
        if (success) {
          log.info(`Webhook delivered successfully to ${webhookConfig.url} (attempt ${attempt + 1})`);
          return true;
        }
      } catch (error) {
        log.warn(`Webhook delivery failed (attempt ${attempt + 1}): ${error}`);
      }

      // Wait before retry (except on last attempt)
      if (attempt < retryAttempts) {
        await this.delay(retryDelayMs * Math.pow(2, attempt)); // Exponential backoff
      }
    }

    log.error(`Webhook delivery failed after ${retryAttempts + 1} attempts: ${webhookConfig.url}`);
    return false;
  }

  /**
   * Create webhook payload from alert
   */
  private createPayload(alert: Alert): WebhookPayload {
    return {
      event: 'alert.created',
      alert,
      deliveredAt: new Date().toISOString(),
      source: 'agentzt-gateway',
    };
  }

  /**
   * Prepare HTTP headers for webhook request
   */
  private prepareHeaders(webhookConfig: WebhookConfig, payload: WebhookPayload): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'AgentZT-Alerts/1.0',
      'X-Alert-ID': payload.alert.id,
      'X-Alert-Type': payload.alert.type,
      'X-Alert-Severity': payload.alert.severity,
      'X-Delivered-At': payload.deliveredAt,
    };

    // Add custom headers
    if (webhookConfig.headers) {
      Object.assign(headers, webhookConfig.headers);
    }

    // Add signature if secret key configured
    if (webhookConfig.secretKey) {
      const signature = this.signPayload(payload, webhookConfig.secretKey);
      headers['X-Signature'] = signature;
      headers['X-Signature-Algorithm'] = 'sha256';
    }

    return headers;
  }

  /**
   * Sign payload using HMAC-SHA256
   */
  private signPayload(payload: WebhookPayload, secretKey: string): string {
    const payloadJson = JSON.stringify(payload);
    const hmac = createHmac('sha256', secretKey);
    hmac.update(payloadJson);
    return hmac.digest('hex');
  }

  /**
   * Deliver webhook via HTTP POST
   */
  private async deliver(
    url: string,
    payload: WebhookPayload,
    headers: Record<string, string>,
    timeoutMs: number
  ): Promise<boolean> {
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(timeoutMs),
      });

      // Consider 2xx status codes as success
      if (response.status >= 200 && response.status < 300) {
        return true;
      }

      // Log non-2xx responses
      const responseText = await response.text().catch(() => '');
      log.warn(`Webhook returned status ${response.status}: ${responseText.slice(0, 200)}`);
      return false;
    } catch (error) {
      if (error instanceof Error) {
        if (error.name === 'AbortError' || error.name === 'TimeoutError') {
          log.warn(`Webhook request timed out after ${timeoutMs}ms`);
        } else {
          log.warn(`Webhook request error: ${error.message}`);
        }
      }
      return false;
    }
  }

  /**
   * Delay helper for retries
   */
  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Verify webhook signature (for receiving webhooks)
   */
  static verifySignature(
    payload: string,
    signature: string,
    secretKey: string
  ): boolean {
    const hmac = createHmac('sha256', secretKey);
    hmac.update(payload);
    const expectedSignature = hmac.digest('hex');
    return signature === expectedSignature;
  }
}

// ============================================================================
// Webhook Delivery Result
// ============================================================================

export interface WebhookDeliveryResult {
  /** Whether delivery was successful */
  success: boolean;
  /** URL that was called */
  url: string;
  /** Number of attempts made */
  attempts: number;
  /** Final HTTP status code (if available) */
  statusCode?: number;
  /** Error message (if failed) */
  error?: string;
  /** Timestamp of delivery attempt */
  timestamp: string;
}

// ============================================================================
// Webhook History Tracker
// ============================================================================

/**
 * Tracks webhook delivery history for debugging and monitoring.
 */
export class WebhookHistoryTracker {
  private history: WebhookDeliveryResult[] = [];
  private maxSize: number = 100;

  /**
   * Record a webhook delivery result
   */
  record(result: WebhookDeliveryResult): void {
    this.history.unshift(result);
    if (this.history.length > this.maxSize) {
      this.history = this.history.slice(0, this.maxSize);
    }
  }

  /**
   * Get recent delivery history
   */
  getHistory(limit?: number): WebhookDeliveryResult[] {
    return this.history.slice(0, limit ?? 50);
  }

  /**
   * Get failed deliveries
   */
  getFailedDeliveries(): WebhookDeliveryResult[] {
    return this.history.filter((r) => !r.success);
  }

  /**
   * Clear history
   */
  clear(): void {
    this.history = [];
  }
}

// ============================================================================
// Factory Functions
// ============================================================================

let defaultWebhookSender: WebhookAlertSender | null = null;
let webhookHistoryTracker: WebhookHistoryTracker | null = null;

/**
 * Get or create the default webhook sender
 */
export function getWebhookSender(): WebhookAlertSender {
  if (!defaultWebhookSender) {
    defaultWebhookSender = new WebhookAlertSender();
  }
  return defaultWebhookSender;
}

/**
 * Get or create the webhook history tracker
 */
export function getWebhookHistoryTracker(): WebhookHistoryTracker {
  if (!webhookHistoryTracker) {
    webhookHistoryTracker = new WebhookHistoryTracker();
  }
  return webhookHistoryTracker;
}

/**
 * Reset webhook sender and tracker (for testing)
 */
export function resetWebhookSender(): void {
  defaultWebhookSender = null;
  webhookHistoryTracker = null;
}

/**
 * Send alert to multiple webhooks
 */
export async function sendToWebhooks(
  alert: Alert,
  webhookConfigs: WebhookConfig[]
): Promise<WebhookDeliveryResult[]> {
  const sender = getWebhookSender();
  const tracker = getWebhookHistoryTracker();
  const results: WebhookDeliveryResult[] = [];

  for (const config of webhookConfigs) {
    if (!config.url) continue;

    const success = await sender.sendAlert(alert, config);
    const result: WebhookDeliveryResult = {
      success,
      url: config.url,
      attempts: (config.retryAttempts ?? 3) + 1,
      timestamp: new Date().toISOString(),
    };

    tracker.record(result);
    results.push(result);
  }

  return results;
}
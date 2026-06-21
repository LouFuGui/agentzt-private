import type { ServerResponse } from 'node:http';
import { makeLogger } from '../shared/log.ts';
import { sendError, sendJson } from '../shared/http.ts';
import type { QuotaCheckResult, QuotaType, QuotaUsage } from '../shared/types.ts';
import { getAppStore } from '../api/app-store.ts';
import { getQuotaTracker } from './tracker.ts';
import { triggerQuotaAlert, getAlertThresholds } from './alerts.ts';

const log = makeLogger('quota-checker');

// ============================================================================
// Quota Checker - Quota Limit Checking and Enforcement
// ============================================================================

/** Default soft limit thresholds (warning levels) */
const SOFT_LIMIT_THRESHOLDS = [80, 90];

/**
 * Check quota limit for an application
 * 
 * @param appId - Application ID
 * @param type - Quota type (checks or tokens)
 * @param requestedAmount - Amount being requested (optional, for pre-check)
 * @returns QuotaCheckResult with allowance status and usage info
 */
export function checkQuota(
  appId: string,
  type: QuotaType,
  requestedAmount: number = 1,
): QuotaCheckResult {
  const appStore = getAppStore();
  const app = appStore.getApp(appId);

  if (!app) {
    return {
      allowed: false,
      type,
      used: 0,
      limit: 0,
      percentage: 0,
      remaining: 0,
      reason: `Application not found: ${appId}`,
    };
  }

  const used = type === 'checks' ? app.quota.checksUsed : app.quota.tokensUsed;
  const limit = type === 'checks' ? app.quota.checksLimit : app.quota.tokensLimit;
  const percentage = Math.round((used / limit) * 100);
  const remaining = Math.max(0, limit - used);

  // Check hard limit (100%)
  if (used + requestedAmount > limit) {
    return {
      allowed: false,
      type,
      used,
      limit,
      percentage,
      remaining,
      reason: `Quota exceeded: ${type} usage (${used + requestedAmount}) would exceed limit (${limit})`,
      isSoftLimit: false,
    };
  }

  // Check soft limits (warning thresholds)
  const newPercentage = Math.round(((used + requestedAmount) / limit) * 100);
  const isSoftLimit = SOFT_LIMIT_THRESHOLDS.some(
    (threshold) => percentage < threshold && newPercentage >= threshold,
  );

  return {
    allowed: true,
    type,
    used,
    limit,
    percentage,
    remaining,
    isSoftLimit,
    reason: isSoftLimit
      ? `Warning: ${type} usage approaching limit (${newPercentage}% used)`
      : undefined,
  };
}

/**
 * Check and record usage, triggering alerts if thresholds are reached
 * 
 * @param appId - Application ID
 * @param type - Quota type
 * @param delta - Amount to record
 * @param options - Additional options (userId, requestId, resource)
 * @returns QuotaUsage after recording
 */
export function checkAndRecordUsage(
  appId: string,
  type: QuotaType,
  delta: number,
  options?: {
    userId?: string | null;
    requestId?: string;
    resource?: string;
  },
): { success: boolean; usage?: QuotaUsage; error?: string; checkResult?: QuotaCheckResult } {
  // Pre-check quota
  const checkResult = checkQuota(appId, type, delta);

  if (!checkResult.allowed) {
    log.warn(`Quota check failed for app ${appId}: ${checkResult.reason}`);
    return {
      success: false,
      error: checkResult.reason,
      checkResult,
    };
  }

  // Record usage
  const tracker = getQuotaTracker();
  const usage = tracker.recordUsage(appId, type, delta, options);

  // Trigger alerts if thresholds are reached
  const thresholds = getAlertThresholds();
  for (const threshold of thresholds) {
    if (usage.percentage >= threshold.threshold && !threshold.triggered) {
      triggerQuotaAlert(appId, type, threshold.threshold, usage, options?.userId);
    }
  }

  return {
    success: true,
    usage,
    checkResult,
  };
}

/**
 * Send quota exceeded error response
 * 
 * @param res - ServerResponse
 * @param checkResult - QuotaCheckResult
 * @param errorCode - HTTP status code (402 or 429)
 */
export function sendQuotaExceededError(
  res: ServerResponse,
  checkResult: QuotaCheckResult,
  errorCode: number = 429,
): void {
  const errorType = errorCode === 402 ? 'payment_required' : 'rate_limit_exceeded';
  const message = checkResult.reason || `Quota exceeded for ${checkResult.type}`;

  // Include quota info in response headers
  const headers = {
    'x-quota-type': checkResult.type,
    'x-quota-used': String(checkResult.used),
    'x-quota-limit': String(checkResult.limit),
    'x-quota-remaining': String(checkResult.remaining),
    'x-quota-percentage': String(checkResult.percentage),
  };

  sendJson(res, errorCode, {
    type: 'error',
    error: {
      type: errorType,
      message,
      quota: {
        type: checkResult.type,
        used: checkResult.used,
        limit: checkResult.limit,
        remaining: checkResult.remaining,
        percentage: checkResult.percentage,
      },
    },
  }, headers);
}

/**
 * Send quota warning response (soft limit reached, but still allowed)
 * 
 * @param res - ServerResponse
 * @param checkResult - QuotaCheckResult
 */
export function sendQuotaWarningHeaders(
  res: ServerResponse,
  checkResult: QuotaCheckResult,
): void {
  // Add warning headers without blocking the request
  res.setHeader('x-quota-warning', `true`);
  res.setHeader('x-quota-warning-threshold', String(checkResult.percentage));
  res.setHeader('x-quota-type', checkResult.type);
  res.setHeader('x-quota-used', String(checkResult.used));
  res.setHeader('x-quota-limit', String(checkResult.limit));
  res.setHeader('x-quota-remaining', String(checkResult.remaining));
}

/**
 * Get quota balance info for an application
 * 
 * @param appId - Application ID
 * @returns QuotaUsage for both checks and tokens
 */
export function getQuotaBalance(appId: string): {
  checks: QuotaUsage;
  tokens: QuotaUsage;
} | null {
  const tracker = getQuotaTracker();
  try {
    return tracker.getUsage(appId);
  } catch (error) {
    log.error(`Failed to get quota balance for app ${appId}: ${error}`);
    return null;
  }
}

/**
 * Check if application has sufficient quota for a request
 * This is a lightweight pre-check that doesn't record usage
 * 
 * @param appId - Application ID
 * @param estimatedChecks - Estimated checks needed
 * @param estimatedTokens - Estimated tokens needed
 * @returns true if sufficient quota, false otherwise
 */
export function hasSufficientQuota(
  appId: string,
  estimatedChecks: number = 1,
  estimatedTokens: number = 0,
): boolean {
  const checksResult = checkQuota(appId, 'checks', estimatedChecks);
  if (!checksResult.allowed) return false;

  if (estimatedTokens > 0) {
    const tokensResult = checkQuota(appId, 'tokens', estimatedTokens);
    if (!tokensResult.allowed) return false;
  }

  return true;
}

/**
 * Middleware-style quota check for gateway requests
 * 
 * @param appId - Application ID
 * @param res - ServerResponse to send error if quota exceeded
 * @param estimatedChecks - Estimated checks (default 1)
 * @param estimatedTokens - Estimated tokens (default 0)
 * @returns true if allowed, false if quota exceeded (error already sent)
 */
export function quotaCheckMiddleware(
  appId: string,
  res: ServerResponse,
  estimatedChecks: number = 1,
  estimatedTokens: number = 0,
): boolean {
  // Check checks quota
  const checksResult = checkQuota(appId, 'checks', estimatedChecks);
  if (!checksResult.allowed) {
    sendQuotaExceededError(res, checksResult, 429);
    return false;
  }

  // Check tokens quota if needed
  if (estimatedTokens > 0) {
    const tokensResult = checkQuota(appId, 'tokens', estimatedTokens);
    if (!tokensResult.allowed) {
      sendQuotaExceededError(res, tokensResult, 429);
      return false;
    }
  }

  // Add warning headers if soft limit reached
  if (checksResult.isSoftLimit) {
    sendQuotaWarningHeaders(res, checksResult);
  }

  return true;
}
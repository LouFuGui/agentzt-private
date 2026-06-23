import type { IncomingMessage, ServerResponse } from 'node:http';
import { readJson, sendJson, sendError, bearerToken } from '../shared/http.ts';
import { getSessionTokenService } from './session.ts';
import { makeLogger } from '../shared/log.ts';
import type { QuotaHistoryEntry, QuotaLimitUpdateRequest, QuotaTimeRange, QuotaUsage } from '../shared/types.ts';
import { getAppStore } from './app-store.ts';
import { getQuotaTracker } from '../quota/tracker.ts';
import { getAlertsManager } from '../quota/alerts.ts';

const log = makeLogger('quota-api');

// ============================================================================
// Types
// ============================================================================

export type QuotaUsageResponse = {
  appId: string;
  checks: QuotaUsage;
  tokens: QuotaUsage;
  alerts: {
    checks: { threshold: number; triggered: boolean }[];
    tokens: { threshold: number; triggered: boolean }[];
  };
};

export type QuotaHistoryResponse = {
  appId: string;
  timeRange: QuotaTimeRange;
  entries: QuotaHistoryEntry[];
  aggregated: {
    checks: { total: number; count: number; avgDelta: number };
    tokens: { total: number; count: number; avgDelta: number };
  };
};

export type QuotaResetResponse = {
  success: boolean;
  message: string;
  appId: string;
};

export type QuotaLimitUpdateResponse = {
  success: boolean;
  message: string;
  appId: string;
  quota: {
    checksLimit: number;
    tokensLimit: number;
  };
};

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Extract user ID from a verified session token.
 * Accepts the x-user-id test header when no session service is configured.
 */
function extractUserId(req: IncomingMessage): string | null {
  // x-user-id test header (used in tests and development)
  const testHeader = req.headers['x-user-id'];
  if (typeof testHeader === 'string') {
    return testHeader;
  }

  const token = bearerToken(req);
  if (!token) return null;

  const svc = getSessionTokenService();
  if (!svc) return null;

  try {
    const claims = svc.verifyToken(token);
    return claims.sub;
  } catch {
    return null;
  }
}

/**
 * Check if user is admin via AGENTZT_ADMIN_USER_IDS env var.
 */
function isAdmin(userId: string): boolean {
  const env = process.env.AGENTZT_ADMIN_USER_IDS?.trim();
  if (!env) return false;
  const adminIds = env.split(',').map((id) => id.trim()).filter(Boolean);
  return adminIds.includes(userId);
}

/**
 * Get app ID from request (header or query param)
 */
function getAppIdFromRequest(req: IncomingMessage): string | null {
  const url = new URL(req.url ?? '/', 'http://localhost');
  
  // Check header first
  const headerAppId = req.headers['x-agentzt-app-id'];
  if (typeof headerAppId === 'string') {
    return headerAppId;
  }
  
  // Check query param
  const queryAppId = url.searchParams.get('appId');
  if (queryAppId) {
    return queryAppId;
  }
  
  return null;
}

/**
 * Validate app access
 */
function validateAppAccess(appId: string, userId: string): { valid: boolean; error?: string } {
  const store = getAppStore();
  const app = store.getApp(appId);
  
  if (!app) {
    return { valid: false, error: `Application "${appId}" not found` };
  }
  
  // Check ownership (admin can access any app)
  if (app.ownerId !== userId && !isAdmin(userId)) {
    return { valid: false, error: 'You do not have access to this application' };
  }
  
  return { valid: true };
}

// ============================================================================
// API Handlers
// ============================================================================

/**
 * GET /api/quota/usage - Get current quota usage
 */
export async function handleGetQuotaUsage(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const userId = extractUserId(req);
  if (!userId) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }

  const appId = getAppIdFromRequest(req);
  if (!appId) {
    return sendError(res, 400, 'invalid_request', 'Missing appId (provide via x-agentzt-app-id header or appId query param)');
  }

  const accessCheck = validateAppAccess(appId, userId);
  if (!accessCheck.valid) {
    return sendError(res, 403, 'permission_error', accessCheck.error!);
  }

  const tracker = getQuotaTracker();
  const alertsManager = getAlertsManager();

  try {
    const usage = tracker.getUsage(appId);
    const checksThresholds = alertsManager.getThresholdStates(appId, 'checks');
    const tokensThresholds = alertsManager.getThresholdStates(appId, 'tokens');

    const response: QuotaUsageResponse = {
      appId,
      checks: usage.checks,
      tokens: usage.tokens,
      alerts: {
        checks: Array.from(checksThresholds.values()).map((t) => ({
          threshold: t.threshold,
          triggered: t.triggered,
        })),
        tokens: Array.from(tokensThresholds.values()).map((t) => ({
          threshold: t.threshold,
          triggered: t.triggered,
        })),
      },
    };

    return sendJson(res, 200, response);
  } catch (error) {
    log.error(`Failed to get quota usage: ${error}`);
    return sendError(res, 500, 'internal_error', 'Failed to retrieve quota usage');
  }
}

/**
 * GET /api/quota/history - Get quota usage history
 */
export async function handleGetQuotaHistory(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const userId = extractUserId(req);
  if (!userId) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }

  const appId = getAppIdFromRequest(req);
  if (!appId) {
    return sendError(res, 400, 'invalid_request', 'Missing appId');
  }

  const accessCheck = validateAppAccess(appId, userId);
  if (!accessCheck.valid) {
    return sendError(res, 403, 'permission_error', accessCheck.error!);
  }

  const url = new URL(req.url ?? '/', 'http://localhost');
  const timeRange = (url.searchParams.get('timeRange') as QuotaTimeRange) || 'month';
  const type = url.searchParams.get('type') as 'checks' | 'tokens' | undefined;
  const limit = parseInt(url.searchParams.get('limit') || '100', 10);

  if (!['day', 'week', 'month'].includes(timeRange)) {
    return sendError(res, 400, 'invalid_request', 'Invalid timeRange. Must be one of: day, week, month');
  }

  const tracker = getQuotaTracker();

  try {
    const entries = tracker.getHistory(appId, {
      timeRange,
      type,
      limit,
    });
    const aggregated = tracker.getAggregatedStats(appId, timeRange);

    const response: QuotaHistoryResponse = {
      appId,
      timeRange,
      entries,
      aggregated,
    };

    return sendJson(res, 200, response);
  } catch (error) {
    log.error(`Failed to get quota history: ${error}`);
    return sendError(res, 500, 'internal_error', 'Failed to retrieve quota history');
  }
}

/**
 * POST /api/quota/reset - Reset quota usage (admin only)
 */
export async function handleResetQuota(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const userId = extractUserId(req);
  if (!userId) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }

  if (!isAdmin(userId)) {
    return sendError(res, 403, 'permission_error', 'Admin access required');
  }

  const appId = getAppIdFromRequest(req);
  if (!appId) {
    return sendError(res, 400, 'invalid_request', 'Missing appId');
  }

  const accessCheck = validateAppAccess(appId, userId);
  if (!accessCheck.valid) {
    return sendError(res, 403, 'permission_error', accessCheck.error!);
  }

  const tracker = getQuotaTracker();
  const alertsManager = getAlertsManager();

  try {
    const success = tracker.resetUsage(appId);
    if (success) {
      // Reset all threshold states
      alertsManager.resetAllThresholdStates(appId);
      
      const response: QuotaResetResponse = {
        success: true,
        message: `Quota usage reset for application "${appId}"`,
        appId,
      };
      
      log.info(`Admin ${userId} reset quota for app ${appId}`);
      return sendJson(res, 200, response);
    } else {
      return sendError(res, 500, 'internal_error', 'Failed to reset quota usage');
    }
  } catch (error) {
    log.error(`Failed to reset quota: ${error}`);
    return sendError(res, 500, 'internal_error', 'Failed to reset quota usage');
  }
}

/**
 * PUT /api/quota/limit - Set quota limits (admin only)
 */
export async function handleUpdateQuotaLimit(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const userId = extractUserId(req);
  if (!userId) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }

  if (!isAdmin(userId)) {
    return sendError(res, 403, 'permission_error', 'Admin access required');
  }

  const appId = getAppIdFromRequest(req);
  if (!appId) {
    return sendError(res, 400, 'invalid_request', 'Missing appId');
  }

  const accessCheck = validateAppAccess(appId, userId);
  if (!accessCheck.valid) {
    return sendError(res, 403, 'permission_error', accessCheck.error!);
  }

  const body = await readJson<QuotaLimitUpdateRequest>(req);
  if (!body) {
    return sendError(res, 400, 'invalid_request', 'Invalid request body');
  }

  // Validate limits
  if (body.checksLimit !== undefined && (body.checksLimit < 0 || !Number.isInteger(body.checksLimit))) {
    return sendError(res, 400, 'invalid_request', 'checksLimit must be a non-negative integer');
  }

  if (body.tokensLimit !== undefined && (body.tokensLimit < 0 || !Number.isInteger(body.tokensLimit))) {
    return sendError(res, 400, 'invalid_request', 'tokensLimit must be a non-negative integer');
  }

  const store = getAppStore();
  const alertsManager = getAlertsManager();

  try {
    const app = store.getApp(appId);
    if (!app) {
      return sendError(res, 404, 'not_found', `Application "${appId}" not found`);
    }

    // Update limits
    const newQuota = {
      checksLimit: body.checksLimit ?? app.quota.checksLimit,
      tokensLimit: body.tokensLimit ?? app.quota.tokensLimit,
    };

    store.updateAppQuota(appId, newQuota);

    // Reset threshold states if limits increased
    if (body.checksLimit && body.checksLimit > app.quota.checksLimit) {
      alertsManager.resetAllThresholdStates(appId);
    }
    if (body.tokensLimit && body.tokensLimit > app.quota.tokensLimit) {
      alertsManager.resetAllThresholdStates(appId);
    }

    const response: QuotaLimitUpdateResponse = {
      success: true,
      message: `Quota limits updated for application "${appId}"`,
      appId,
      quota: newQuota,
    };

    log.info(`Admin ${userId} updated quota limits for app ${appId}: checks=${newQuota.checksLimit}, tokens=${newQuota.tokensLimit}`);
    return sendJson(res, 200, response);
  } catch (error) {
    log.error(`Failed to update quota limits: ${error}`);
    return sendError(res, 500, 'internal_error', 'Failed to update quota limits');
  }
}

/**
 * GET /api/quota/alerts - Get quota alerts history
 */
export async function handleGetQuotaAlerts(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const userId = extractUserId(req);
  if (!userId) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }

  const appId = getAppIdFromRequest(req);
  if (!appId) {
    return sendError(res, 400, 'invalid_request', 'Missing appId');
  }

  const accessCheck = validateAppAccess(appId, userId);
  if (!accessCheck.valid) {
    return sendError(res, 403, 'permission_error', accessCheck.error!);
  }

  const url = new URL(req.url ?? '/', 'http://localhost');
  const type = url.searchParams.get('type') as 'checks' | 'tokens' | undefined;
  const limit = parseInt(url.searchParams.get('limit') || '50', 10);

  const alertsManager = getAlertsManager();

  try {
    const alerts = alertsManager.getAlertHistory(appId, {
      type,
      limit,
    });

    return sendJson(res, 200, {
      appId,
      alerts,
      total: alerts.length,
    });
  } catch (error) {
    log.error(`Failed to get quota alerts: ${error}`);
    return sendError(res, 500, 'internal_error', 'Failed to retrieve quota alerts');
  }
}

// ============================================================================
// Router
// ============================================================================

/**
 * Route quota API requests
 */
export async function routeQuotaApi(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const url = new URL(req.url ?? '/', 'http://localhost');
  const path = url.pathname;
  const method = req.method ?? 'GET';

  // GET /api/quota/usage - Get current usage
  if (method === 'GET' && path === '/api/quota/usage') {
    await handleGetQuotaUsage(req, res);
    return true;
  }

  // GET /api/quota/history - Get usage history
  if (method === 'GET' && path === '/api/quota/history') {
    await handleGetQuotaHistory(req, res);
    return true;
  }

  // POST /api/quota/reset - Reset usage (admin)
  if (method === 'POST' && path === '/api/quota/reset') {
    await handleResetQuota(req, res);
    return true;
  }

  // PUT /api/quota/limit - Set quota limits (admin)
  if (method === 'PUT' && path === '/api/quota/limit') {
    await handleUpdateQuotaLimit(req, res);
    return true;
  }

  // GET /api/quota/alerts - Get alerts history
  if (method === 'GET' && path === '/api/quota/alerts') {
    await handleGetQuotaAlerts(req, res);
    return true;
  }

  return false;
}
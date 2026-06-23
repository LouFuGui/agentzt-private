/**
 * Alerts Management API
 * REST endpoints for listing alerts, managing rules, and alert settings.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { readJson, sendJson, sendError, bearerToken } from '../shared/http.ts';
import { makeLogger } from '../shared/log.ts';
import { getAlertEngine } from '../alerts/engine.ts';
import { getAlertConfigStore } from '../alerts/config.ts';
import type { AlertRule, AlertSettings, AlertConfiguration } from '../alerts/types.ts';
import { getSessionTokenService } from './session.ts';

const log = makeLogger('alerts-api');

// ============================================================================
// Auth helper
// ============================================================================

function extractUserId(req: IncomingMessage): string | null {
  const testHeader = req.headers['x-user-id'];
  if (typeof testHeader === 'string') return testHeader;

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

// ============================================================================
// Handlers
// ============================================================================

/**
 * GET /api/alerts — list recent alerts (active + acknowledged)
 * Query params: appId, status, limit
 */
export async function handleListAlerts(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const userId = extractUserId(req);
  if (!userId) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }

  const url = new URL(req.url ?? '/', 'http://localhost');
  const appId = url.searchParams.get('appId') ?? undefined;
  const status = url.searchParams.get('status') ?? undefined;
  const limit = Math.min(parseInt(url.searchParams.get('limit') ?? '100', 10), 500);

  const engine = getAlertEngine();
  let alerts = engine.getHistory(limit);

  if (appId) {
    alerts = alerts.filter((a) => a.appId === appId);
  }
  if (status) {
    alerts = alerts.filter((a) => a.status === status);
  }

  return sendJson(res, 200, { alerts, total: alerts.length });
}

/**
 * GET /api/alerts/:alertId — get a single alert by ID
 */
export async function handleGetAlert(
  req: IncomingMessage,
  res: ServerResponse,
  alertId: string,
): Promise<void> {
  const userId = extractUserId(req);
  if (!userId) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }

  const engine = getAlertEngine();
  const alerts = engine.getHistory();
  const alert = alerts.find((a) => a.id === alertId);

  if (!alert) {
    return sendError(res, 404, 'not_found', `Alert "${alertId}" not found`);
  }

  return sendJson(res, 200, alert);
}

/**
 * POST /api/alerts/:alertId/acknowledge — acknowledge an alert
 */
export async function handleAcknowledgeAlert(
  req: IncomingMessage,
  res: ServerResponse,
  alertId: string,
): Promise<void> {
  const userId = extractUserId(req);
  if (!userId) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }

  const engine = getAlertEngine();
  const alert = engine.acknowledgeAlert(alertId, userId);

  if (!alert) {
    return sendError(res, 404, 'not_found', `Alert "${alertId}" not found`);
  }

  log.info(`Alert ${alertId} acknowledged by ${userId}`);
  return sendJson(res, 200, alert);
}

/**
 * POST /api/alerts/:alertId/resolve — resolve an alert
 */
export async function handleResolveAlert(
  req: IncomingMessage,
  res: ServerResponse,
  alertId: string,
): Promise<void> {
  const userId = extractUserId(req);
  if (!userId) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }

  const body = await readJson<{ notes?: string }>(req);
  const engine = getAlertEngine();
  const alert = engine.resolveAlert(alertId, body?.notes);

  if (!alert) {
    return sendError(res, 404, 'not_found', `Alert "${alertId}" not found`);
  }

  log.info(`Alert ${alertId} resolved by ${userId}`);
  return sendJson(res, 200, alert);
}

/**
 * GET /api/alerts/rules — get alert rules
 * Query param: appId (optional, defaults to default config)
 */
export async function handleGetRules(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const userId = extractUserId(req);
  if (!userId) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }

  const url = new URL(req.url ?? '/', 'http://localhost');
  const appId = url.searchParams.get('appId') ?? undefined;

  const store = getAlertConfigStore();
  const config = appId
    ? (store.getAppConfiguration(appId) ?? store.createAppConfiguration(appId, userId))
    : store.createAppConfiguration('default', userId);

  return sendJson(res, 200, { rules: config.rules });
}

/**
 * PUT /api/alerts/rules — update alert rules
 */
export async function handleUpdateRules(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const userId = extractUserId(req);
  if (!userId) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }

  const url = new URL(req.url ?? '/', 'http://localhost');
  const appId = url.searchParams.get('appId') ?? 'default';

  const body = await readJson<{ rules?: AlertRule[] }>(req);
  if (!body?.rules || !Array.isArray(body.rules)) {
    return sendError(res, 400, 'invalid_request', '"rules" array is required');
  }

  const store = getAlertConfigStore();
  let config = store.getAppConfiguration(appId);
  if (!config) {
    config = store.createAppConfiguration(appId, userId);
  }

  // Replace all rules by saving the mutated configuration
  config.rules = body.rules;
  store.saveConfiguration(config);

  log.info(`Alert rules updated for app ${appId} by ${userId}`);
  return sendJson(res, 200, { rules: body.rules });
}

/**
 * GET /api/alerts/settings — get alert notification settings
 */
export async function handleGetSettings(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const userId = extractUserId(req);
  if (!userId) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }

  const url = new URL(req.url ?? '/', 'http://localhost');
  const appId = url.searchParams.get('appId') ?? undefined;

  const store = getAlertConfigStore();
  const config = appId
    ? (store.getAppConfiguration(appId) ?? store.createAppConfiguration(appId, userId))
    : store.createAppConfiguration('default', userId);

  return sendJson(res, 200, { settings: config.settings });
}

/**
 * PUT /api/alerts/settings — update alert notification settings
 */
export async function handleUpdateSettings(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const userId = extractUserId(req);
  if (!userId) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }

  const url = new URL(req.url ?? '/', 'http://localhost');
  const appId = url.searchParams.get('appId') ?? 'default';

  const body = await readJson<{ settings?: Partial<AlertSettings> }>(req);
  if (!body?.settings || typeof body.settings !== 'object') {
    return sendError(res, 400, 'invalid_request', '"settings" object is required');
  }

  const store = getAlertConfigStore();
  let config = store.getAppConfiguration(appId);
  if (!config) {
    config = store.createAppConfiguration(appId, userId);
  }

  const updated = store.updateSettings(config.id, body.settings);

  log.info(`Alert settings updated for app ${appId} by ${userId}`);
  return sendJson(res, 200, { settings: updated ?? { ...config.settings, ...body.settings } });
}

// ============================================================================
// Router
// ============================================================================

/**
 * Route alerts API requests. Returns true if the request was handled.
 */
export async function routeAlertsApi(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const url = new URL(req.url ?? '/', 'http://localhost');
  const path = url.pathname;
  const method = req.method ?? 'GET';

  // GET /api/alerts/rules
  if (method === 'GET' && path === '/api/alerts/rules') {
    await handleGetRules(req, res);
    return true;
  }

  // PUT /api/alerts/rules
  if (method === 'PUT' && path === '/api/alerts/rules') {
    await handleUpdateRules(req, res);
    return true;
  }

  // GET /api/alerts/settings
  if (method === 'GET' && path === '/api/alerts/settings') {
    await handleGetSettings(req, res);
    return true;
  }

  // PUT /api/alerts/settings
  if (method === 'PUT' && path === '/api/alerts/settings') {
    await handleUpdateSettings(req, res);
    return true;
  }

  // GET /api/alerts
  if (method === 'GET' && path === '/api/alerts') {
    await handleListAlerts(req, res);
    return true;
  }

  // POST /api/alerts/:alertId/acknowledge
  const ackMatch = path.match(/^\/api\/alerts\/([^/]+)\/acknowledge$/);
  if (ackMatch && method === 'POST') {
    await handleAcknowledgeAlert(req, res, ackMatch[1]!);
    return true;
  }

  // POST /api/alerts/:alertId/resolve
  const resolveMatch = path.match(/^\/api\/alerts\/([^/]+)\/resolve$/);
  if (resolveMatch && method === 'POST') {
    await handleResolveAlert(req, res, resolveMatch[1]!);
    return true;
  }

  // GET /api/alerts/:alertId
  const getAlertMatch = path.match(/^\/api\/alerts\/([^/]+)$/);
  if (getAlertMatch && method === 'GET') {
    await handleGetAlert(req, res, getAlertMatch[1]!);
    return true;
  }

  return false;
}

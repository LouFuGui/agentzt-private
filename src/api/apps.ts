import type { IncomingMessage, ServerResponse } from 'node:http';
import { readJson, sendJson, sendError, bearerToken, headerValue, APP_ID_HEADER, API_KEY_HEADER } from '../shared/http.ts';
import { makeLogger } from '../shared/log.ts';
import { getAppStore } from './app-store.ts';
import type { App, AppConfig, AppQuota, UserTier } from '../shared/types.ts';

const log = makeLogger('apps-api');

// ============================================================================
// Types
// ============================================================================

export type CreateAppRequest = {
  name: string;
  tier?: UserTier;
};

export type UpdateAppRequest = {
  name?: string;
  config?: Partial<AppConfig>;
  quota?: Partial<AppQuota>;
};

export type AppResponse = {
  appId: string;
  name: string;
  apiKey: string;
  modelApiKey: string;
  config: AppConfig;
  quota: AppQuota;
  createdAt: string;
  ownerId: string;
};

export type AppListResponse = {
  apps: AppResponse[];
  total: number;
};

export type RegenerateKeyResponse = {
  apiKey: string;
  modelApiKey: string;
};

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Convert App to AppResponse (public-facing format)
 */
function toAppResponse(app: App): AppResponse {
  return {
    appId: app.appId,
    name: app.name,
    apiKey: app.apiKey,
    modelApiKey: app.modelApiKey,
    config: app.config,
    quota: app.quota,
    createdAt: app.createdAt,
    ownerId: app.ownerId,
  };
}

/**
 * Extract user ID from JWT token (placeholder - will be integrated with user auth)
 * For now, this returns a placeholder user ID
 */
function extractUserId(req: IncomingMessage): string | null {
  // TODO: Integrate with actual user authentication
  // For now, check for a test header or return a default
  const authHeader = req.headers['x-user-id'];
  if (typeof authHeader === 'string') {
    return authHeader;
  }
  
  // Check for Bearer token (placeholder)
  const token = bearerToken(req);
  if (token) {
    // TODO: Verify JWT and extract user ID
    // For development, we'll use a placeholder
    return 'user_placeholder';
  }
  
  return null;
}

/**
 * Get application from request headers (Header application selector)
 * Supports two methods:
 * 1. x-agentzt-app-id header - directly specify app ID
 * 2. x-agentzt-api-key header - use API key to identify app
 * 
 * This enables application switching without changing the URL path.
 */
export function getAppFromHeader(req: IncomingMessage): App | null {
  const store = getAppStore();
  
  // Method 1: Direct app ID header
  const appId = headerValue(req, APP_ID_HEADER);
  if (appId) {
    const app = store.getApp(appId);
    if (app) {
      log.info(`App selected via header: ${appId}`);
      return app;
    }
    log.warn(`App ID in header not found: ${appId}`);
    return null;
  }
  
  // Method 2: API Key header
  const apiKey = headerValue(req, API_KEY_HEADER);
  if (apiKey) {
    const app = store.getAppByApiKey(apiKey);
    if (app) {
      log.info(`App selected via API key header: ${app.appId}`);
      return app;
    }
    log.warn(`API key in header not found: ${apiKey}`);
    return null;
  }
  
  return null;
}

/**
 * Validate API Key and get associated application
 * Used for gateway authentication
 */
export function validateApiKeyAndGetApp(apiKey: string): App | null {
  const store = getAppStore();
  
  // Check if it's a regular API key
  const app = store.getAppByApiKey(apiKey);
  if (app) {
    return app;
  }
  
  // Check if it's a model API key
  const appByModelKey = store.getAppByModelApiKey(apiKey);
  if (appByModelKey) {
    return appByModelKey;
  }
  
  return null;
}

/**
 * Check if user is admin (placeholder)
 */
function isAdmin(_userId: string): boolean {
  // TODO: Implement actual admin check
  return _userId === 'admin';
}

// ============================================================================
// API Handlers
// ============================================================================

/**
 * POST /api/apps - Create a new application
 */
export async function handleCreateApp(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const userId = extractUserId(req);
  if (!userId) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }

  const body = await readJson<CreateAppRequest>(req);
  if (!body || !body.name || typeof body.name !== 'string') {
    return sendError(res, 400, 'invalid_request', 'Missing or invalid "name" field');
  }

  if (body.name.length < 1 || body.name.length > 100) {
    return sendError(res, 400, 'invalid_request', 'App name must be between 1 and 100 characters');
  }

  const tier: UserTier = body.tier || 'personal';
  if (!['personal', 'business', 'enterprise'].includes(tier)) {
    return sendError(res, 400, 'invalid_request', 'Invalid tier. Must be one of: personal, business, enterprise');
  }

  const store = getAppStore();
  const app = store.createApp(body.name, userId, tier);

  log.info(`Created app ${app.appId} "${app.name}" for user ${userId}`);

  return sendJson(res, 201, toAppResponse(app));
}

/**
 * GET /api/apps - List applications for the authenticated user
 */
export async function handleListApps(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const userId = extractUserId(req);
  if (!userId) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }

  const store = getAppStore();
  
  // Admin can see all apps, regular users see only their own
  const apps = isAdmin(userId) ? store.listAllApps() : store.listAppsByOwner(userId);

  const response: AppListResponse = {
    apps: apps.map(toAppResponse),
    total: apps.length,
  };

  return sendJson(res, 200, response);
}

/**
 * GET /api/apps/:appId - Get application details
 */
export async function handleGetApp(
  req: IncomingMessage,
  res: ServerResponse,
  appId: string,
): Promise<void> {
  const userId = extractUserId(req);
  if (!userId) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }

  const store = getAppStore();
  const app = store.getApp(appId);

  if (!app) {
    return sendError(res, 404, 'not_found', `Application "${appId}" not found`);
  }

  // Check ownership (admin can access any app)
  if (app.ownerId !== userId && !isAdmin(userId)) {
    return sendError(res, 403, 'permission_error', 'You do not have access to this application');
  }

  return sendJson(res, 200, toAppResponse(app));
}

/**
 * PUT /api/apps/:appId - Update application
 */
export async function handleUpdateApp(
  req: IncomingMessage,
  res: ServerResponse,
  appId: string,
): Promise<void> {
  const userId = extractUserId(req);
  if (!userId) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }

  const store = getAppStore();
  const app = store.getApp(appId);

  if (!app) {
    return sendError(res, 404, 'not_found', `Application "${appId}" not found`);
  }

  // Check ownership (admin can update any app)
  if (app.ownerId !== userId && !isAdmin(userId)) {
    return sendError(res, 403, 'permission_error', 'You do not have access to this application');
  }

  const body = await readJson<UpdateAppRequest>(req);
  if (!body) {
    return sendError(res, 400, 'invalid_request', 'Invalid request body');
  }

  // Update name if provided
  if (body.name !== undefined) {
    if (typeof body.name !== 'string' || body.name.length < 1 || body.name.length > 100) {
      return sendError(res, 400, 'invalid_request', 'App name must be between 1 and 100 characters');
    }
    store.updateAppName(appId, body.name);
    log.info(`Updated app ${appId} name to "${body.name}"`);
  }

  // Update config if provided
  if (body.config !== undefined) {
    store.updateAppConfig(appId, body.config);
    log.info(`Updated app ${appId} config`);
  }

  // Update quota if provided (admin only)
  if (body.quota !== undefined) {
    if (!isAdmin(userId)) {
      return sendError(res, 403, 'permission_error', 'Only admins can update quota');
    }
    store.updateAppQuota(appId, body.quota);
    log.info(`Updated app ${appId} quota`);
  }

  // Return updated app
  const updatedApp = store.getApp(appId);
  if (!updatedApp) {
    return sendError(res, 500, 'internal_error', 'Failed to retrieve updated application');
  }

  return sendJson(res, 200, toAppResponse(updatedApp));
}

/**
 * DELETE /api/apps/:appId - Delete application
 */
export async function handleDeleteApp(
  req: IncomingMessage,
  res: ServerResponse,
  appId: string,
): Promise<void> {
  const userId = extractUserId(req);
  if (!userId) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }

  const store = getAppStore();
  const app = store.getApp(appId);

  if (!app) {
    return sendError(res, 404, 'not_found', `Application "${appId}" not found`);
  }

  // Check ownership (admin can delete any app)
  if (app.ownerId !== userId && !isAdmin(userId)) {
    return sendError(res, 403, 'permission_error', 'You do not have access to this application');
  }

  const deleted = store.deleteApp(appId);
  if (!deleted) {
    return sendError(res, 500, 'internal_error', 'Failed to delete application');
  }

  log.info(`Deleted app ${appId}`);

  return sendJson(res, 200, { success: true, message: `Application "${appId}" deleted` });
}

/**
 * POST /api/apps/:appId/regenerate-key - Regenerate API keys
 */
export async function handleRegenerateKey(
  req: IncomingMessage,
  res: ServerResponse,
  appId: string,
): Promise<void> {
  const userId = extractUserId(req);
  if (!userId) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }

  const store = getAppStore();
  const app = store.getApp(appId);

  if (!app) {
    return sendError(res, 404, 'not_found', `Application "${appId}" not found`);
  }

  // Check ownership (admin can regenerate any app's keys)
  if (app.ownerId !== userId && !isAdmin(userId)) {
    return sendError(res, 403, 'permission_error', 'You do not have access to this application');
  }

  const newKeys = store.regenerateApiKey(appId);
  if (!newKeys) {
    return sendError(res, 500, 'internal_error', 'Failed to regenerate API keys');
  }

  log.info(`Regenerated API keys for app ${appId}`);

  const response: RegenerateKeyResponse = newKeys;
  return sendJson(res, 200, response);
}

/**
 * GET /api/apps/by-key/:apiKey - Get application by API key (internal use)
 */
export async function handleGetAppByApiKey(
  req: IncomingMessage,
  res: ServerResponse,
  apiKey: string,
): Promise<void> {
  // This endpoint is for internal gateway use, requires admin privileges
  const userId = extractUserId(req);
  if (!userId || !isAdmin(userId)) {
    return sendError(res, 403, 'permission_error', 'Admin access required');
  }

  const store = getAppStore();
  const app = store.getAppByApiKey(apiKey);

  if (!app) {
    return sendError(res, 404, 'not_found', 'Application not found for the provided API key');
  }

  return sendJson(res, 200, toAppResponse(app));
}

// ============================================================================
// Router
// ============================================================================

/**
 * Route app API requests
 */
export async function routeAppsApi(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const url = new URL(req.url ?? '/', 'http://localhost');
  const path = url.pathname;
  const method = req.method ?? 'GET';

  // POST /api/apps - Create app
  if (method === 'POST' && path === '/api/apps') {
    await handleCreateApp(req, res);
    return true;
  }

  // GET /api/apps - List apps
  if (method === 'GET' && path === '/api/apps') {
    await handleListApps(req, res);
    return true;
  }

  // GET /api/apps/:appId - Get app
  const getAppMatch = path.match(/^\/api\/apps\/([^/]+)$/);
  if (getAppMatch && method === 'GET') {
    await handleGetApp(req, res, getAppMatch[1]!);
    return true;
  }

  // PUT /api/apps/:appId - Update app
  if (getAppMatch && method === 'PUT') {
    await handleUpdateApp(req, res, getAppMatch[1]!);
    return true;
  }

  // DELETE /api/apps/:appId - Delete app
  if (getAppMatch && method === 'DELETE') {
    await handleDeleteApp(req, res, getAppMatch[1]!);
    return true;
  }

  // POST /api/apps/:appId/regenerate-key - Regenerate keys
  const regenKeyMatch = path.match(/^\/api\/apps\/([^/]+)\/regenerate-key$/);
  if (regenKeyMatch && method === 'POST') {
    await handleRegenerateKey(req, res, regenKeyMatch[1]!);
    return true;
  }

  // GET /api/apps/by-key/:apiKey - Get app by API key (internal)
  const byKeyMatch = path.match(/^\/api\/apps\/by-key\/(.+)$/);
  if (byKeyMatch && method === 'GET') {
    await handleGetAppByApiKey(req, res, decodeURIComponent(byKeyMatch[1]!));
    return true;
  }

  return false;
}
/**
 * Configuration Management API
 * Provides endpoints for managing application configurations.
 * 
 * Permission rules:
 * - viewer: can only read configurations
 * - admin: can read and modify configurations
 * - owner: can read and modify configurations
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { readJson, sendJson, sendError, bearerToken } from '../shared/http.ts';
import { makeLogger } from '../shared/log.ts';
import { getAppStore } from './app-store.ts';
import type {
  App,
  AppConfig,
  RiskTypeConfig,
  RiskCategoriesConfig,
  BlacklistWhitelist,
  ResponseTemplates,
  SensitivityConfig,
  BanPolicy,
  KnowledgeBase,
  KnowledgeBaseEntry,
  UserRole,
} from '../shared/types.ts';
import { createAuthMiddleware, getAuthContext, type AuthContext } from './auth-middleware.ts';
import { SessionTokenService } from './auth.ts';

const log = makeLogger('config-api');

// ============================================================================
// Sensitivity Level Threshold Mapping
// ============================================================================

const SENSITIVITY_THRESHOLDS: Record<'high' | 'medium' | 'low', number> = {
  high: 0.40,
  medium: 0.60,
  low: 0.80,
};

// ============================================================================
// Request/Response Types
// ============================================================================

export type UpdateRiskTypesRequest = {
  security?: boolean;
  compliance?: boolean;
  dataSecurity?: boolean;
};

export type UpdateRiskCategoriesRequest = Partial<RiskCategoriesConfig>;

export type AddBlacklistRequest = {
  keywords?: string[];
  patterns?: string[];
};

export type AddWhitelistRequest = {
  keywords?: string[];
};

export type RemoveBlacklistRequest = {
  keywords?: string[];
};

export type RemoveWhitelistRequest = {
  keywords?: string[];
};

export type UpdateResponseTemplatesRequest = {
  reject?: string;
  replace?: string;
};

export type UpdateSensitivityRequest = {
  level?: 'high' | 'medium' | 'low';
  threshold?: number;
};

export type UpdateBanPolicyRequest = {
  bannedUsers?: string[];
  autoBanThreshold?: number;
};

export type BanUserRequest = {
  userId: string;
  reason: string;
};

export type UnbanUserRequest = {
  userId: string;
};

export type AddKnowledgeBaseEntryRequest = {
  question: string;
  answer: string;
};

export type UpdateKnowledgeBaseEntryRequest = {
  question?: string;
  answer?: string;
};

export type KnowledgeBaseEntryResponse = {
  entryId: string;
  question: string;
  answer: string;
};

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Get authenticated user from request
 */
function getAuthenticatedUser(req: IncomingMessage): AuthContext | null {
  const auth = getAuthContext(req);
  return auth ?? null;
}

/**
 * Check if user has permission to modify (admin or owner)
 */
function canModify(role: UserRole): boolean {
  return role === 'owner' || role === 'admin';
}

/**
 * Get app and verify ownership/access
 */
function getAppAndVerifyAccess(
  appId: string,
  auth: AuthContext,
): App | null {
  const store = getAppStore();
  const app = store.getApp(appId);
  
  if (!app) {
    return null;
  }
  
  // Check if user owns the app or is admin/owner
  if (app.ownerId !== auth.userId && !canModify(auth.role)) {
    return null;
  }
  
  return app;
}

/**
 * Generate unique entry ID for knowledge base
 */
function generateEntryId(): string {
  return `kb-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
}

// ============================================================================
// Risk Types Configuration API
// ============================================================================

/**
 * GET /api/apps/:appId/config/risk-types
 * Get risk types configuration
 */
export async function handleGetRiskTypes(
  req: IncomingMessage,
  res: ServerResponse,
  appId: string,
): Promise<void> {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }
  
  const app = getAppAndVerifyAccess(appId, auth);
  if (!app) {
    return sendError(res, 404, 'not_found', `Application "${appId}" not found or access denied`);
  }
  
  return sendJson(res, 200, app.config.riskTypes);
}

/**
 * PUT /api/apps/:appId/config/risk-types
 * Update risk types configuration
 */
export async function handleUpdateRiskTypes(
  req: IncomingMessage,
  res: ServerResponse,
  appId: string,
): Promise<void> {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }
  
  if (!canModify(auth.role)) {
    return sendError(res, 403, 'permission_error', 'Only admin or owner can modify configurations');
  }
  
  const app = getAppAndVerifyAccess(appId, auth);
  if (!app) {
    return sendError(res, 404, 'not_found', `Application "${appId}" not found or access denied`);
  }
  
  const body = await readJson<UpdateRiskTypesRequest>(req);
  if (!body) {
    return sendError(res, 400, 'invalid_request', 'Invalid request body');
  }
  
  // Validate input
  if (body.security !== undefined && typeof body.security !== 'boolean') {
    return sendError(res, 400, 'invalid_request', 'security must be a boolean');
  }
  if (body.compliance !== undefined && typeof body.compliance !== 'boolean') {
    return sendError(res, 400, 'invalid_request', 'compliance must be a boolean');
  }
  if (body.dataSecurity !== undefined && typeof body.dataSecurity !== 'boolean') {
    return sendError(res, 400, 'invalid_request', 'dataSecurity must be a boolean');
  }
  
  // Update configuration
  const newRiskTypes: RiskTypeConfig = {
    security: body.security ?? app.config.riskTypes.security,
    compliance: body.compliance ?? app.config.riskTypes.compliance,
    dataSecurity: body.dataSecurity ?? app.config.riskTypes.dataSecurity,
  };
  
  const store = getAppStore();
  const updated = store.updateAppConfig(appId, { riskTypes: newRiskTypes });
  
  if (!updated) {
    return sendError(res, 500, 'internal_error', 'Failed to update risk types configuration');
  }
  
  log.info(`Updated risk types for app ${appId} by user ${auth.userId}`);
  
  return sendJson(res, 200, newRiskTypes);
}

// ============================================================================
// Risk Categories Configuration API
// ============================================================================

/**
 * GET /api/apps/:appId/config/risk-categories
 * Get risk categories configuration (S1-S19)
 */
export async function handleGetRiskCategories(
  req: IncomingMessage,
  res: ServerResponse,
  appId: string,
): Promise<void> {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }
  
  const app = getAppAndVerifyAccess(appId, auth);
  if (!app) {
    return sendError(res, 404, 'not_found', `Application "${appId}" not found or access denied`);
  }
  
  return sendJson(res, 200, app.config.riskCategories);
}

/**
 * PUT /api/apps/:appId/config/risk-categories
 * Update risk categories configuration
 */
export async function handleUpdateRiskCategories(
  req: IncomingMessage,
  res: ServerResponse,
  appId: string,
): Promise<void> {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }
  
  if (!canModify(auth.role)) {
    return sendError(res, 403, 'permission_error', 'Only admin or owner can modify configurations');
  }
  
  const app = getAppAndVerifyAccess(appId, auth);
  if (!app) {
    return sendError(res, 404, 'not_found', `Application "${appId}" not found or access denied`);
  }
  
  const body = await readJson<UpdateRiskCategoriesRequest>(req);
  if (!body) {
    return sendError(res, 400, 'invalid_request', 'Invalid request body');
  }
  
  // Validate input - all values must be boolean
  const validKeys = ['S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7', 'S8', 'S9', 'S10',
                     'S11', 'S12', 'S13', 'S14', 'S15', 'S16', 'S17', 'S18', 'S19'];
  
  for (const [key, value] of Object.entries(body)) {
    if (!validKeys.includes(key)) {
      return sendError(res, 400, 'invalid_request', `Invalid risk category: ${key}. Must be one of S1-S19`);
    }
    if (typeof value !== 'boolean') {
      return sendError(res, 400, 'invalid_request', `${key} must be a boolean`);
    }
  }
  
  // Update configuration
  const newRiskCategories: RiskCategoriesConfig = {
    ...app.config.riskCategories,
    ...body,
  };
  
  const store = getAppStore();
  const updated = store.updateAppConfig(appId, { riskCategories: newRiskCategories });
  
  if (!updated) {
    return sendError(res, 500, 'internal_error', 'Failed to update risk categories configuration');
  }
  
  log.info(`Updated risk categories for app ${appId} by user ${auth.userId}`);
  
  return sendJson(res, 200, newRiskCategories);
}

// ============================================================================
// Blacklist/Whitelist Management API
// ============================================================================

/**
 * GET /api/apps/:appId/config/blacklist-whitelist
 * Get blacklist/whitelist configuration
 */
export async function handleGetBlacklistWhitelist(
  req: IncomingMessage,
  res: ServerResponse,
  appId: string,
): Promise<void> {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }
  
  const app = getAppAndVerifyAccess(appId, auth);
  if (!app) {
    return sendError(res, 404, 'not_found', `Application "${appId}" not found or access denied`);
  }
  
  return sendJson(res, 200, app.config.blacklistWhitelist);
}

/**
 * POST /api/apps/:appId/config/blacklist
 * Add keywords to blacklist
 */
export async function handleAddBlacklist(
  req: IncomingMessage,
  res: ServerResponse,
  appId: string,
): Promise<void> {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }
  
  if (!canModify(auth.role)) {
    return sendError(res, 403, 'permission_error', 'Only admin or owner can modify configurations');
  }
  
  const app = getAppAndVerifyAccess(appId, auth);
  if (!app) {
    return sendError(res, 404, 'not_found', `Application "${appId}" not found or access denied`);
  }
  
  const body = await readJson<AddBlacklistRequest>(req);
  if (!body) {
    return sendError(res, 400, 'invalid_request', 'Invalid request body');
  }
  
  if (!body.keywords && !body.patterns) {
    return sendError(res, 400, 'invalid_request', 'keywords or patterns must be provided');
  }
  
  // Validate keywords
  if (body.keywords) {
    if (!Array.isArray(body.keywords)) {
      return sendError(res, 400, 'invalid_request', 'keywords must be an array');
    }
    for (const kw of body.keywords) {
      if (typeof kw !== 'string' || kw.length === 0) {
        return sendError(res, 400, 'invalid_request', 'Each keyword must be a non-empty string');
      }
    }
  }
  
  // Validate patterns
  if (body.patterns) {
    if (!Array.isArray(body.patterns)) {
      return sendError(res, 400, 'invalid_request', 'patterns must be an array');
    }
    for (const p of body.patterns) {
      if (typeof p !== 'string' || p.length === 0) {
        return sendError(res, 400, 'invalid_request', 'Each pattern must be a non-empty string');
      }
    }
  }
  
  // Combine keywords and patterns (patterns are prefixed with 'pattern:' for distinction)
  const newItems: string[] = [];
  if (body.keywords) {
    newItems.push(...body.keywords);
  }
  if (body.patterns) {
    newItems.push(...body.patterns.map(p => `pattern:${p}`));
  }
  
  // Update blacklist (avoid duplicates)
  const currentBlacklist = app.config.blacklistWhitelist.blacklist;
  const updatedBlacklist = [...new Set([...currentBlacklist, ...newItems])];
  
  const newBlacklistWhitelist: BlacklistWhitelist = {
    ...app.config.blacklistWhitelist,
    blacklist: updatedBlacklist,
  };
  
  const store = getAppStore();
  const updated = store.updateAppConfig(appId, { blacklistWhitelist: newBlacklistWhitelist });
  
  if (!updated) {
    return sendError(res, 500, 'internal_error', 'Failed to add to blacklist');
  }
  
  log.info(`Added ${newItems.length} items to blacklist for app ${appId} by user ${auth.userId}`);
  
  return sendJson(res, 200, {
    added: newItems.length,
    blacklist: updatedBlacklist,
    whitelist: app.config.blacklistWhitelist.whitelist,
  });
}

/**
 * DELETE /api/apps/:appId/config/blacklist
 * Remove keywords from blacklist
 */
export async function handleRemoveBlacklist(
  req: IncomingMessage,
  res: ServerResponse,
  appId: string,
): Promise<void> {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }
  
  if (!canModify(auth.role)) {
    return sendError(res, 403, 'permission_error', 'Only admin or owner can modify configurations');
  }
  
  const app = getAppAndVerifyAccess(appId, auth);
  if (!app) {
    return sendError(res, 404, 'not_found', `Application "${appId}" not found or access denied`);
  }
  
  const body = await readJson<RemoveBlacklistRequest>(req);
  if (!body || !body.keywords) {
    return sendError(res, 400, 'invalid_request', 'keywords must be provided');
  }
  
  const keywords = body.keywords;
  
  if (!Array.isArray(keywords)) {
    return sendError(res, 400, 'invalid_request', 'keywords must be an array');
  }
  
  // Remove keywords from blacklist
  const currentBlacklist = app.config.blacklistWhitelist.blacklist;
  const updatedBlacklist = currentBlacklist.filter(kw => !keywords.includes(kw));
  
  const newBlacklistWhitelist: BlacklistWhitelist = {
    ...app.config.blacklistWhitelist,
    blacklist: updatedBlacklist,
  };
  
  const store = getAppStore();
  const updated = store.updateAppConfig(appId, { blacklistWhitelist: newBlacklistWhitelist });
  
  if (!updated) {
    return sendError(res, 500, 'internal_error', 'Failed to remove from blacklist');
  }
  
  const removedCount = currentBlacklist.length - updatedBlacklist.length;
  log.info(`Removed ${removedCount} items from blacklist for app ${appId} by user ${auth.userId}`);
  
  return sendJson(res, 200, {
    removed: removedCount,
    blacklist: updatedBlacklist,
    whitelist: app.config.blacklistWhitelist.whitelist,
  });
}

/**
 * POST /api/apps/:appId/config/whitelist
 * Add keywords to whitelist
 */
export async function handleAddWhitelist(
  req: IncomingMessage,
  res: ServerResponse,
  appId: string,
): Promise<void> {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }
  
  if (!canModify(auth.role)) {
    return sendError(res, 403, 'permission_error', 'Only admin or owner can modify configurations');
  }
  
  const app = getAppAndVerifyAccess(appId, auth);
  if (!app) {
    return sendError(res, 404, 'not_found', `Application "${appId}" not found or access denied`);
  }
  
  const body = await readJson<AddWhitelistRequest>(req);
  if (!body || !body.keywords) {
    return sendError(res, 400, 'invalid_request', 'keywords must be provided');
  }
  
  if (!Array.isArray(body.keywords)) {
    return sendError(res, 400, 'invalid_request', 'keywords must be an array');
  }
  
  for (const kw of body.keywords) {
    if (typeof kw !== 'string' || kw.length === 0) {
      return sendError(res, 400, 'invalid_request', 'Each keyword must be a non-empty string');
    }
  }
  
  // Update whitelist (avoid duplicates)
  const currentWhitelist = app.config.blacklistWhitelist.whitelist;
  const updatedWhitelist = [...new Set([...currentWhitelist, ...body.keywords])];
  
  const newBlacklistWhitelist: BlacklistWhitelist = {
    ...app.config.blacklistWhitelist,
    whitelist: updatedWhitelist,
  };
  
  const store = getAppStore();
  const updated = store.updateAppConfig(appId, { blacklistWhitelist: newBlacklistWhitelist });
  
  if (!updated) {
    return sendError(res, 500, 'internal_error', 'Failed to add to whitelist');
  }
  
  log.info(`Added ${body.keywords.length} items to whitelist for app ${appId} by user ${auth.userId}`);
  
  return sendJson(res, 200, {
    added: body.keywords.length,
    blacklist: app.config.blacklistWhitelist.blacklist,
    whitelist: updatedWhitelist,
  });
}

/**
 * DELETE /api/apps/:appId/config/whitelist
 * Remove keywords from whitelist
 */
export async function handleRemoveWhitelist(
  req: IncomingMessage,
  res: ServerResponse,
  appId: string,
): Promise<void> {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }
  
  if (!canModify(auth.role)) {
    return sendError(res, 403, 'permission_error', 'Only admin or owner can modify configurations');
  }
  
  const app = getAppAndVerifyAccess(appId, auth);
  if (!app) {
    return sendError(res, 404, 'not_found', `Application "${appId}" not found or access denied`);
  }
  
  const body = await readJson<RemoveWhitelistRequest>(req);
  if (!body || !body.keywords) {
    return sendError(res, 400, 'invalid_request', 'keywords must be provided');
  }
  
  const keywords = body.keywords;
  
  if (!Array.isArray(keywords)) {
    return sendError(res, 400, 'invalid_request', 'keywords must be an array');
  }
  
  // Remove keywords from whitelist
  const currentWhitelist = app.config.blacklistWhitelist.whitelist;
  const updatedWhitelist = currentWhitelist.filter(kw => !keywords.includes(kw));
  
  const newBlacklistWhitelist: BlacklistWhitelist = {
    ...app.config.blacklistWhitelist,
    whitelist: updatedWhitelist,
  };
  
  const store = getAppStore();
  const updated = store.updateAppConfig(appId, { blacklistWhitelist: newBlacklistWhitelist });
  
  if (!updated) {
    return sendError(res, 500, 'internal_error', 'Failed to remove from whitelist');
  }
  
  const removedCount = currentWhitelist.length - updatedWhitelist.length;
  log.info(`Removed ${removedCount} items from whitelist for app ${appId} by user ${auth.userId}`);
  
  return sendJson(res, 200, {
    removed: removedCount,
    blacklist: app.config.blacklistWhitelist.blacklist,
    whitelist: updatedWhitelist,
  });
}

// ============================================================================
// Response Templates Configuration API
// ============================================================================

/**
 * GET /api/apps/:appId/config/response-templates
 * Get response templates configuration
 */
export async function handleGetResponseTemplates(
  req: IncomingMessage,
  res: ServerResponse,
  appId: string,
): Promise<void> {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }
  
  const app = getAppAndVerifyAccess(appId, auth);
  if (!app) {
    return sendError(res, 404, 'not_found', `Application "${appId}" not found or access denied`);
  }
  
  return sendJson(res, 200, app.config.responseTemplates);
}

/**
 * PUT /api/apps/:appId/config/response-templates
 * Update response templates configuration
 */
export async function handleUpdateResponseTemplates(
  req: IncomingMessage,
  res: ServerResponse,
  appId: string,
): Promise<void> {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }
  
  if (!canModify(auth.role)) {
    return sendError(res, 403, 'permission_error', 'Only admin or owner can modify configurations');
  }
  
  const app = getAppAndVerifyAccess(appId, auth);
  if (!app) {
    return sendError(res, 404, 'not_found', `Application "${appId}" not found or access denied`);
  }
  
  const body = await readJson<UpdateResponseTemplatesRequest>(req);
  if (!body) {
    return sendError(res, 400, 'invalid_request', 'Invalid request body');
  }
  
  // Validate input
  if (body.reject !== undefined) {
    if (typeof body.reject !== 'string' || body.reject.length === 0) {
      return sendError(res, 400, 'invalid_request', 'reject must be a non-empty string');
    }
  }
  if (body.replace !== undefined) {
    if (typeof body.replace !== 'string' || body.replace.length === 0) {
      return sendError(res, 400, 'invalid_request', 'replace must be a non-empty string');
    }
  }
  
  // Update configuration
  const newResponseTemplates: ResponseTemplates = {
    reject: body.reject ?? app.config.responseTemplates.reject,
    replace: body.replace ?? app.config.responseTemplates.replace,
  };
  
  const store = getAppStore();
  const updated = store.updateAppConfig(appId, { responseTemplates: newResponseTemplates });
  
  if (!updated) {
    return sendError(res, 500, 'internal_error', 'Failed to update response templates');
  }
  
  log.info(`Updated response templates for app ${appId} by user ${auth.userId}`);
  
  return sendJson(res, 200, newResponseTemplates);
}

// ============================================================================
// Sensitivity Configuration API
// ============================================================================

/**
 * GET /api/apps/:appId/config/sensitivity
 * Get sensitivity configuration
 */
export async function handleGetSensitivity(
  req: IncomingMessage,
  res: ServerResponse,
  appId: string,
): Promise<void> {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }
  
  const app = getAppAndVerifyAccess(appId, auth);
  if (!app) {
    return sendError(res, 404, 'not_found', `Application "${appId}" not found or access denied`);
  }
  
  return sendJson(res, 200, app.config.sensitivity);
}

/**
 * PUT /api/apps/:appId/config/sensitivity
 * Update sensitivity configuration
 */
export async function handleUpdateSensitivity(
  req: IncomingMessage,
  res: ServerResponse,
  appId: string,
): Promise<void> {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }
  
  if (!canModify(auth.role)) {
    return sendError(res, 403, 'permission_error', 'Only admin or owner can modify configurations');
  }
  
  const app = getAppAndVerifyAccess(appId, auth);
  if (!app) {
    return sendError(res, 404, 'not_found', `Application "${appId}" not found or access denied`);
  }
  
  const body = await readJson<UpdateSensitivityRequest>(req);
  if (!body) {
    return sendError(res, 400, 'invalid_request', 'Invalid request body');
  }
  
  // Validate input
  if (body.level !== undefined) {
    if (!['high', 'medium', 'low'].includes(body.level)) {
      return sendError(res, 400, 'invalid_request', 'level must be one of: high, medium, low');
    }
  }
  if (body.threshold !== undefined) {
    if (typeof body.threshold !== 'number' || body.threshold < 0 || body.threshold > 1) {
      return sendError(res, 400, 'invalid_request', 'threshold must be a number between 0 and 1');
    }
  }
  
  // Determine new level and threshold
  const newLevel = body.level ?? app.config.sensitivity.level;
  const newThreshold = body.threshold ?? SENSITIVITY_THRESHOLDS[newLevel];
  
  const newSensitivity: SensitivityConfig = {
    level: newLevel,
    threshold: newThreshold,
  };
  
  const store = getAppStore();
  const updated = store.updateAppConfig(appId, { sensitivity: newSensitivity });
  
  if (!updated) {
    return sendError(res, 500, 'internal_error', 'Failed to update sensitivity configuration');
  }
  
  log.info(`Updated sensitivity for app ${appId} to level ${newLevel} (threshold: ${newThreshold}) by user ${auth.userId}`);
  
  return sendJson(res, 200, newSensitivity);
}

// ============================================================================
// Ban Policy Configuration API
// ============================================================================

/**
 * GET /api/apps/:appId/config/ban-policy
 * Get ban policy configuration
 */
export async function handleGetBanPolicy(
  req: IncomingMessage,
  res: ServerResponse,
  appId: string,
): Promise<void> {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }
  
  const app = getAppAndVerifyAccess(appId, auth);
  if (!app) {
    return sendError(res, 404, 'not_found', `Application "${appId}" not found or access denied`);
  }
  
  return sendJson(res, 200, app.config.banPolicy);
}

/**
 * PUT /api/apps/:appId/config/ban-policy
 * Update ban policy configuration
 */
export async function handleUpdateBanPolicy(
  req: IncomingMessage,
  res: ServerResponse,
  appId: string,
): Promise<void> {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }
  
  if (!canModify(auth.role)) {
    return sendError(res, 403, 'permission_error', 'Only admin or owner can modify configurations');
  }
  
  const app = getAppAndVerifyAccess(appId, auth);
  if (!app) {
    return sendError(res, 404, 'not_found', `Application "${appId}" not found or access denied`);
  }
  
  const body = await readJson<UpdateBanPolicyRequest>(req);
  if (!body) {
    return sendError(res, 400, 'invalid_request', 'Invalid request body');
  }
  
  // Validate input
  if (body.bannedUsers !== undefined) {
    if (!Array.isArray(body.bannedUsers)) {
      return sendError(res, 400, 'invalid_request', 'bannedUsers must be an array');
    }
    for (const userId of body.bannedUsers) {
      if (typeof userId !== 'string' || userId.length === 0) {
        return sendError(res, 400, 'invalid_request', 'Each banned user ID must be a non-empty string');
      }
    }
  }
  if (body.autoBanThreshold !== undefined) {
    if (typeof body.autoBanThreshold !== 'number' || body.autoBanThreshold < 0) {
      return sendError(res, 400, 'invalid_request', 'autoBanThreshold must be a non-negative number');
    }
  }
  
  // Update configuration
  const newBanPolicy: BanPolicy = {
    bannedUsers: body.bannedUsers ?? app.config.banPolicy.bannedUsers,
    autoBanThreshold: body.autoBanThreshold ?? app.config.banPolicy.autoBanThreshold,
  };
  
  const store = getAppStore();
  const updated = store.updateAppConfig(appId, { banPolicy: newBanPolicy });
  
  if (!updated) {
    return sendError(res, 500, 'internal_error', 'Failed to update ban policy');
  }
  
  log.info(`Updated ban policy for app ${appId} by user ${auth.userId}`);
  
  return sendJson(res, 200, newBanPolicy);
}

/**
 * POST /api/apps/:appId/config/ban-policy/ban
 * Add a user to the banned list
 */
export async function handleBanUser(
  req: IncomingMessage,
  res: ServerResponse,
  appId: string,
): Promise<void> {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }
  
  if (!canModify(auth.role)) {
    return sendError(res, 403, 'permission_error', 'Only admin or owner can modify configurations');
  }
  
  const app = getAppAndVerifyAccess(appId, auth);
  if (!app) {
    return sendError(res, 404, 'not_found', `Application "${appId}" not found or access denied`);
  }
  
  const body = await readJson<BanUserRequest>(req);
  if (!body || !body.userId) {
    return sendError(res, 400, 'invalid_request', 'userId is required');
  }
  
  if (typeof body.userId !== 'string' || body.userId.length === 0) {
    return sendError(res, 400, 'invalid_request', 'userId must be a non-empty string');
  }
  
  // Check if already banned
  if (app.config.banPolicy.bannedUsers.includes(body.userId)) {
    return sendError(res, 400, 'invalid_request', `User "${body.userId}" is already banned`);
  }
  
  // Add to banned list
  const newBannedUsers = [...app.config.banPolicy.bannedUsers, body.userId];
  const newBanPolicy: BanPolicy = {
    ...app.config.banPolicy,
    bannedUsers: newBannedUsers,
  };
  
  const store = getAppStore();
  const updated = store.updateAppConfig(appId, { banPolicy: newBanPolicy });
  
  if (!updated) {
    return sendError(res, 500, 'internal_error', 'Failed to ban user');
  }
  
  log.info(`Banned user ${body.userId} for app ${appId} by user ${auth.userId}. Reason: ${body.reason || 'N/A'}`);
  
  return sendJson(res, 200, {
    banned: body.userId,
    reason: body.reason || 'No reason provided',
    bannedUsers: newBannedUsers,
  });
}

/**
 * DELETE /api/apps/:appId/config/ban-policy/ban
 * Remove a user from the banned list
 */
export async function handleUnbanUser(
  req: IncomingMessage,
  res: ServerResponse,
  appId: string,
): Promise<void> {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }
  
  if (!canModify(auth.role)) {
    return sendError(res, 403, 'permission_error', 'Only admin or owner can modify configurations');
  }
  
  const app = getAppAndVerifyAccess(appId, auth);
  if (!app) {
    return sendError(res, 404, 'not_found', `Application "${appId}" not found or access denied`);
  }
  
  const body = await readJson<UnbanUserRequest>(req);
  if (!body || !body.userId) {
    return sendError(res, 400, 'invalid_request', 'userId is required');
  }
  
  // Check if user is banned
  if (!app.config.banPolicy.bannedUsers.includes(body.userId)) {
    return sendError(res, 400, 'invalid_request', `User "${body.userId}" is not banned`);
  }
  
  // Remove from banned list
  const newBannedUsers = app.config.banPolicy.bannedUsers.filter(id => id !== body.userId);
  const newBanPolicy: BanPolicy = {
    ...app.config.banPolicy,
    bannedUsers: newBannedUsers,
  };
  
  const store = getAppStore();
  const updated = store.updateAppConfig(appId, { banPolicy: newBanPolicy });
  
  if (!updated) {
    return sendError(res, 500, 'internal_error', 'Failed to unban user');
  }
  
  log.info(`Unbanned user ${body.userId} for app ${appId} by user ${auth.userId}`);
  
  return sendJson(res, 200, {
    unbanned: body.userId,
    bannedUsers: newBannedUsers,
  });
}

// ============================================================================
// Knowledge Base Configuration API
// ============================================================================

/**
 * GET /api/apps/:appId/config/knowledge-base
 * Get knowledge base entries
 */
export async function handleGetKnowledgeBase(
  req: IncomingMessage,
  res: ServerResponse,
  appId: string,
): Promise<void> {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }
  
  const app = getAppAndVerifyAccess(appId, auth);
  if (!app) {
    return sendError(res, 404, 'not_found', `Application "${appId}" not found or access denied`);
  }
  
  // Transform entries to include entryId
  const entries: KnowledgeBaseEntryResponse[] = app.config.knowledgeBase.entries.map((entry, index) => ({
    entryId: `kb-${appId}-${index}`,
    question: entry.question,
    answer: entry.answer,
  }));
  
  return sendJson(res, 200, { entries, total: entries.length });
}

/**
 * POST /api/apps/:appId/config/knowledge-base
 * Add a new knowledge base entry
 */
export async function handleAddKnowledgeBaseEntry(
  req: IncomingMessage,
  res: ServerResponse,
  appId: string,
): Promise<void> {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }
  
  if (!canModify(auth.role)) {
    return sendError(res, 403, 'permission_error', 'Only admin or owner can modify configurations');
  }
  
  const app = getAppAndVerifyAccess(appId, auth);
  if (!app) {
    return sendError(res, 404, 'not_found', `Application "${appId}" not found or access denied`);
  }
  
  const body = await readJson<AddKnowledgeBaseEntryRequest>(req);
  if (!body || !body.question || !body.answer) {
    return sendError(res, 400, 'invalid_request', 'question and answer are required');
  }
  
  if (typeof body.question !== 'string' || body.question.length === 0) {
    return sendError(res, 400, 'invalid_request', 'question must be a non-empty string');
  }
  if (typeof body.answer !== 'string' || body.answer.length === 0) {
    return sendError(res, 400, 'invalid_request', 'answer must be a non-empty string');
  }
  
  // Add new entry
  const entryId = generateEntryId();
  const newEntry: KnowledgeBaseEntry = {
    question: body.question,
    answer: body.answer,
  };
  
  const newEntries = [...app.config.knowledgeBase.entries, newEntry];
  const newKnowledgeBase: KnowledgeBase = {
    entries: newEntries,
  };
  
  const store = getAppStore();
  const updated = store.updateAppConfig(appId, { knowledgeBase: newKnowledgeBase });
  
  if (!updated) {
    return sendError(res, 500, 'internal_error', 'Failed to add knowledge base entry');
  }
  
  log.info(`Added knowledge base entry for app ${appId} by user ${auth.userId}`);
  
  return sendJson(res, 201, {
    entryId,
    question: body.question,
    answer: body.answer,
  });
}

/**
 * PUT /api/apps/:appId/config/knowledge-base/:entryId
 * Update a knowledge base entry
 */
export async function handleUpdateKnowledgeBaseEntry(
  req: IncomingMessage,
  res: ServerResponse,
  appId: string,
  entryId: string,
): Promise<void> {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }
  
  if (!canModify(auth.role)) {
    return sendError(res, 403, 'permission_error', 'Only admin or owner can modify configurations');
  }
  
  const app = getAppAndVerifyAccess(appId, auth);
  if (!app) {
    return sendError(res, 404, 'not_found', `Application "${appId}" not found or access denied`);
  }
  
  const body = await readJson<UpdateKnowledgeBaseEntryRequest>(req);
  if (!body) {
    return sendError(res, 400, 'invalid_request', 'Invalid request body');
  }
  
  // Validate input
  if (body.question !== undefined && (typeof body.question !== 'string' || body.question.length === 0)) {
    return sendError(res, 400, 'invalid_request', 'question must be a non-empty string');
  }
  if (body.answer !== undefined && (typeof body.answer !== 'string' || body.answer.length === 0)) {
    return sendError(res, 400, 'invalid_request', 'answer must be a non-empty string');
  }
  
  // Find entry by ID (entryId format: kb-{appId}-{index} or kb-{timestamp}-{random})
  // We need to match by content since entries don't have IDs stored
  const entryIndex = parseInt(entryId.split('-').pop() || '-1', 10);
  
  if (entryIndex < 0 || entryIndex >= app.config.knowledgeBase.entries.length) {
    // Try to find by matching the generated ID pattern
    const foundIndex = app.config.knowledgeBase.entries.findIndex((entry, idx) => 
      `kb-${appId}-${idx}` === entryId || entryId.startsWith('kb-')
    );
    
    if (foundIndex === -1) {
      return sendError(res, 404, 'not_found', `Knowledge base entry "${entryId}" not found`);
    }
    
    const existingEntry = app.config.knowledgeBase.entries[foundIndex];
    if (!existingEntry) {
      return sendError(res, 500, 'internal_error', 'Failed to find entry');
    }
    
    // Update the found entry
    const updatedEntry: KnowledgeBaseEntry = {
      question: body.question ?? existingEntry.question,
      answer: body.answer ?? existingEntry.answer,
    };
    
    const newEntries = [...app.config.knowledgeBase.entries];
    newEntries[foundIndex] = updatedEntry;
    
    const store = getAppStore();
    const success = store.updateAppConfig(appId, { 
      knowledgeBase: { entries: newEntries } 
    });
    
    if (!success) {
      return sendError(res, 500, 'internal_error', 'Failed to update knowledge base entry');
    }
    
    log.info(`Updated knowledge base entry ${entryId} for app ${appId} by user ${auth.userId}`);
    
    return sendJson(res, 200, {
      entryId,
      question: updatedEntry.question,
      answer: updatedEntry.answer,
    });
  }
  
  // Update by index
  const existingEntry = app.config.knowledgeBase.entries[entryIndex];
  if (!existingEntry) {
    return sendError(res, 404, 'not_found', `Knowledge base entry "${entryId}" not found`);
  }
  
  const updatedEntry: KnowledgeBaseEntry = {
    question: body.question ?? existingEntry.question,
    answer: body.answer ?? existingEntry.answer,
  };
  
  const newEntries = [...app.config.knowledgeBase.entries];
  newEntries[entryIndex] = updatedEntry;
  
  const store = getAppStore();
  const success = store.updateAppConfig(appId, { knowledgeBase: { entries: newEntries } });
  
  if (!success) {
    return sendError(res, 500, 'internal_error', 'Failed to update knowledge base entry');
  }
  
  log.info(`Updated knowledge base entry ${entryId} for app ${appId} by user ${auth.userId}`);
  
  return sendJson(res, 200, {
    entryId,
    question: updatedEntry.question,
    answer: updatedEntry.answer,
  });
}

/**
 * DELETE /api/apps/:appId/config/knowledge-base/:entryId
 * Delete a knowledge base entry
 */
export async function handleDeleteKnowledgeBaseEntry(
  req: IncomingMessage,
  res: ServerResponse,
  appId: string,
  entryId: string,
): Promise<void> {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }
  
  if (!canModify(auth.role)) {
    return sendError(res, 403, 'permission_error', 'Only admin or owner can modify configurations');
  }
  
  const app = getAppAndVerifyAccess(appId, auth);
  if (!app) {
    return sendError(res, 404, 'not_found', `Application "${appId}" not found or access denied`);
  }
  
  // Find entry by index
  const entryIndex = parseInt(entryId.split('-').pop() || '-1', 10);
  
  if (entryIndex < 0 || entryIndex >= app.config.knowledgeBase.entries.length) {
    return sendError(res, 404, 'not_found', `Knowledge base entry "${entryId}" not found`);
  }
  
  // Remove entry
  const newEntries = app.config.knowledgeBase.entries.filter((_, idx) => idx !== entryIndex);
  
  const store = getAppStore();
  const success = store.updateAppConfig(appId, { 
    knowledgeBase: { entries: newEntries } 
  });
  
  if (!success) {
    return sendError(res, 500, 'internal_error', 'Failed to delete knowledge base entry');
  }
  
  log.info(`Deleted knowledge base entry ${entryId} for app ${appId} by user ${auth.userId}`);
  
  return sendJson(res, 200, {
    deleted: entryId,
    remaining: newEntries.length,
  });
}

// ============================================================================
// Router
// ============================================================================

/**
 * Route configuration API requests
 */
export async function routeConfigApi(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const url = new URL(req.url ?? '/', 'http://localhost');
  const path = url.pathname;
  const method = req.method ?? 'GET';
  
  // Base pattern: /api/apps/:appId/config/*
  const configBaseMatch = path.match(/^\/api\/apps\/([^/]+)\/config(?:\/(.+))?$/);
  if (!configBaseMatch) {
    return false;
  }
  
  const appId = configBaseMatch[1]!;
  const subPath = configBaseMatch[2] || '';
  
  // Risk Types
  if (subPath === 'risk-types') {
    if (method === 'GET') {
      await handleGetRiskTypes(req, res, appId);
      return true;
    }
    if (method === 'PUT') {
      await handleUpdateRiskTypes(req, res, appId);
      return true;
    }
  }
  
  // Risk Categories
  if (subPath === 'risk-categories') {
    if (method === 'GET') {
      await handleGetRiskCategories(req, res, appId);
      return true;
    }
    if (method === 'PUT') {
      await handleUpdateRiskCategories(req, res, appId);
      return true;
    }
  }
  
  // Blacklist/Whitelist
  if (subPath === 'blacklist-whitelist') {
    if (method === 'GET') {
      await handleGetBlacklistWhitelist(req, res, appId);
      return true;
    }
  }
  
  // Blacklist operations
  if (subPath === 'blacklist') {
    if (method === 'POST') {
      await handleAddBlacklist(req, res, appId);
      return true;
    }
    if (method === 'DELETE') {
      await handleRemoveBlacklist(req, res, appId);
      return true;
    }
  }
  
  // Whitelist operations
  if (subPath === 'whitelist') {
    if (method === 'POST') {
      await handleAddWhitelist(req, res, appId);
      return true;
    }
    if (method === 'DELETE') {
      await handleRemoveWhitelist(req, res, appId);
      return true;
    }
  }
  
  // Response Templates
  if (subPath === 'response-templates') {
    if (method === 'GET') {
      await handleGetResponseTemplates(req, res, appId);
      return true;
    }
    if (method === 'PUT') {
      await handleUpdateResponseTemplates(req, res, appId);
      return true;
    }
  }
  
  // Sensitivity
  if (subPath === 'sensitivity') {
    if (method === 'GET') {
      await handleGetSensitivity(req, res, appId);
      return true;
    }
    if (method === 'PUT') {
      await handleUpdateSensitivity(req, res, appId);
      return true;
    }
  }
  
  // Ban Policy
  if (subPath === 'ban-policy') {
    if (method === 'GET') {
      await handleGetBanPolicy(req, res, appId);
      return true;
    }
    if (method === 'PUT') {
      await handleUpdateBanPolicy(req, res, appId);
      return true;
    }
  }
  
  // Ban Policy - Ban/Unban user
  if (subPath === 'ban-policy/ban') {
    if (method === 'POST') {
      await handleBanUser(req, res, appId);
      return true;
    }
    if (method === 'DELETE') {
      await handleUnbanUser(req, res, appId);
      return true;
    }
  }
  
  // Knowledge Base
  if (subPath === 'knowledge-base') {
    if (method === 'GET') {
      await handleGetKnowledgeBase(req, res, appId);
      return true;
    }
    if (method === 'POST') {
      await handleAddKnowledgeBaseEntry(req, res, appId);
      return true;
    }
  }
  
  // Knowledge Base - Entry operations
  const kbEntryMatch = subPath.match(/^knowledge-base\/([^/]+)$/);
  if (kbEntryMatch) {
    const entryId = kbEntryMatch[1]!;
    if (method === 'PUT') {
      await handleUpdateKnowledgeBaseEntry(req, res, appId, entryId);
      return true;
    }
    if (method === 'DELETE') {
      await handleDeleteKnowledgeBaseEntry(req, res, appId, entryId);
      return true;
    }
  }
  
  // No matching route found
  sendError(res, 404, 'not_found', `no route for ${method} ${path}`);
  return false;
}
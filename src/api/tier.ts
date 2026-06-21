/**
 * Tier Management API
 * REST endpoints for tier operations.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { readJson, sendJson, sendError, bearerToken } from '../shared/http.ts';
import { makeLogger } from '../shared/log.ts';
import type {
  TierLevel,
  TierChangeRequest,
  TierChangeHistoryEntry,
  TierUsageReport,
} from '../shared/types.ts';
import { getUserStore } from './user-store.ts';
import { getTierManager } from '../tier/manager.ts';
import { getAllTierConfigs, getTierConfig } from '../tier/features.ts';
import { generateUsageReport, exportReportJson, exportReportCsv, getUsageSummary } from '../tier/report.ts';

const log = makeLogger('tier-api');

// ============================================================================
// Types
// ============================================================================

export type TierOptionsResponse = {
  tiers: Array<{
    tier: TierLevel;
    displayName: string;
    description: string;
    price: { monthly: number; yearly: number; currency: string };
    features: string[];
  }>;
};

export type CurrentTierResponse = {
  tier: TierLevel;
  displayName: string;
  features: ReturnType<typeof getTierConfig>['features'];
  limits: ReturnType<typeof getTierConfig>['limits'];
  usage?: {
    checks: { used: number; limit: number; percentage: number };
    tokens: { used: number; limit: number; percentage: number };
    agents: { count: number; limit: number };
  };
  estimatedCost: number;
};

export type TierChangeResponse = {
  success: boolean;
  fromTier: TierLevel;
  toTier: TierLevel;
  changedAt: string;
  message: string;
};

export type TierHistoryResponse = {
  history: TierChangeHistoryEntry[];
  total: number;
};

export type TierReportResponse = TierUsageReport;

export type TierReportExportResponse = {
  format: 'json' | 'csv';
  content: string;
  filename: string;
};

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Extract user ID from JWT token or session
 */
function extractUserId(req: IncomingMessage): string | null {
  // Check for test header
  const userIdHeader = req.headers['x-user-id'];
  if (typeof userIdHeader === 'string') {
    return userIdHeader;
  }

  // Check for Bearer token
  const token = bearerToken(req);
  if (token) {
    // TODO: Verify JWT and extract user ID
    // For development, use placeholder
    return 'user_placeholder';
  }

  return null;
}

/**
 * Check if user is admin
 */
function isAdmin(userId: string): boolean {
  const userStore = getUserStore();
  const user = userStore.getById(userId);
  return user?.role === 'owner' || user?.role === 'admin';
}

// ============================================================================
// API Handlers
// ============================================================================

/**
 * GET /api/tier/options - Get all tier options
 */
export async function handleGetTierOptions(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const userId = extractUserId(req);
  if (!userId) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }

  const allConfigs = getAllTierConfigs();

  const response: TierOptionsResponse = {
    tiers: allConfigs.map((config) => ({
      tier: config.tier,
      displayName: config.displayName,
      description: config.description,
      price: {
        monthly: config.price.monthly,
        yearly: config.price.yearly,
        currency: config.price.currency,
      },
      features: config.price.featuresDescription,
    })),
  };

  return sendJson(res, 200, response);
}

/**
 * GET /api/tier/current - Get current tier status
 */
export async function handleGetCurrentTier(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const userId = extractUserId(req);
  if (!userId) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }

  const userStore = getUserStore();
  const user = userStore.getById(userId);

  if (!user) {
    return sendError(res, 404, 'not_found', 'User not found');
  }

  const tier = user.tier as TierLevel;
  const tierConfig = getTierConfig(tier);
  const usageSummary = getUsageSummary(userId);

  const response: CurrentTierResponse = {
    tier,
    displayName: tierConfig.displayName,
    features: tierConfig.features,
    limits: tierConfig.limits,
    usage: usageSummary ? {
      checks: usageSummary.checks,
      tokens: usageSummary.tokens,
      agents: usageSummary.agents,
    } : undefined,
    estimatedCost: usageSummary?.estimatedCost ?? tierConfig.price.monthly,
  };

  return sendJson(res, 200, response);
}

/**
 * POST /api/tier/change - Change tier
 */
export async function handleTierChange(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const userId = extractUserId(req);
  if (!userId) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }

  const body = await readJson<TierChangeRequest>(req);
  if (!body || !body.targetTier) {
    return sendError(res, 400, 'invalid_request', 'Missing targetTier field');
  }

  if (!['personal', 'business', 'enterprise'].includes(body.targetTier)) {
    return sendError(res, 400, 'invalid_request', 'Invalid tier. Must be one of: personal, business, enterprise');
  }

  if (!body.confirmed) {
    return sendError(res, 400, 'invalid_request', 'Tier change must be confirmed. Set confirmed: true');
  }

  const tierManager = getTierManager();

  // Validate first
  const validation = tierManager.validateTierChange(userId, body);
  if (!validation.allowed) {
    const errorMessage = validation.reason || 'Tier change not allowed';
    const additionalInfo = validation.warnings ? ` Warnings: ${validation.warnings.join('; ')}` : '';
    return sendError(res, 400, 'tier_change_denied', errorMessage + additionalInfo);
  }

  // Process change
  const result = await tierManager.processTierChange(userId, body, userId);

  if (!result.ok) {
    return sendError(res, 500, 'tier_change_failed', result.error);
  }

  const response: TierChangeResponse = {
    success: true,
    fromTier: result.historyEntry.fromTier,
    toTier: result.historyEntry.toTier,
    changedAt: result.historyEntry.changedAt,
    message: `Successfully changed tier from ${result.historyEntry.fromTier} to ${result.historyEntry.toTier}`,
  };

  log.info(`Tier changed for user ${userId}: ${result.historyEntry.fromTier} -> ${result.historyEntry.toTier}`);

  return sendJson(res, 200, response);
}

/**
 * GET /api/tier/history - Get tier change history
 */
export async function handleGetTierHistory(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const userId = extractUserId(req);
  if (!userId) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }

  const url = new URL(req.url ?? '/', 'http://localhost');
  const limitParam = url.searchParams.get('limit');
  const limit = limitParam ? parseInt(limitParam, 10) : 50;

  const tierManager = getTierManager();
  const history = tierManager.getTierChangeHistory(userId, { limit });

  const response: TierHistoryResponse = {
    history,
    total: history.length,
  };

  return sendJson(res, 200, response);
}

/**
 * GET /api/tier/report - Get usage report
 */
export async function handleGetTierReport(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const userId = extractUserId(req);
  if (!userId) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }

  const url = new URL(req.url ?? '/', 'http://localhost');
  const periodStart = url.searchParams.get('periodStart') ?? undefined;
  const periodEnd = url.searchParams.get('periodEnd') ?? undefined;
  const format = url.searchParams.get('format') as 'json' | 'csv' | null;

  const report = generateUsageReport(userId, periodStart, periodEnd);

  if (!report) {
    return sendError(res, 404, 'not_found', 'Could not generate report for user');
  }

  // If format is specified, return exported content
  if (format === 'csv') {
    const csvContent = exportReportCsv(report);
    const filename = `tier-report-${userId}-${new Date().toISOString().split('T')[0]}.csv`;

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.end(csvContent);
    return;
  }

  if (format === 'json') {
    const jsonContent = exportReportJson(report);
    const filename = `tier-report-${userId}-${new Date().toISOString().split('T')[0]}.json`;

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.end(jsonContent);
    return;
  }

  // Default: return JSON response
  const response: TierReportResponse = report;
  return sendJson(res, 200, response);
}

/**
 * POST /api/tier/validate - Validate tier change (preview)
 */
export async function handleValidateTierChange(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const userId = extractUserId(req);
  if (!userId) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }

  const body = await readJson<TierChangeRequest>(req);
  if (!body || !body.targetTier) {
    return sendError(res, 400, 'invalid_request', 'Missing targetTier field');
  }

  const tierManager = getTierManager();
  const validation = tierManager.validateTierChange(userId, { ...body, confirmed: false });

  return sendJson(res, 200, validation);
}

// ============================================================================
// Router
// ============================================================================

/**
 * Route tier API requests
 */
export async function routeTierApi(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const url = new URL(req.url ?? '/', 'http://localhost');
  const path = url.pathname;
  const method = req.method ?? 'GET';

  // GET /api/tier/options - Get tier options
  if (method === 'GET' && path === '/api/tier/options') {
    await handleGetTierOptions(req, res);
    return true;
  }

  // GET /api/tier/current - Get current tier
  if (method === 'GET' && path === '/api/tier/current') {
    await handleGetCurrentTier(req, res);
    return true;
  }

  // POST /api/tier/change - Change tier
  if (method === 'POST' && path === '/api/tier/change') {
    await handleTierChange(req, res);
    return true;
  }

  // POST /api/tier/validate - Validate tier change
  if (method === 'POST' && path === '/api/tier/validate') {
    await handleValidateTierChange(req, res);
    return true;
  }

  // GET /api/tier/history - Get tier history
  if (method === 'GET' && path === '/api/tier/history') {
    await handleGetTierHistory(req, res);
    return true;
  }

  // GET /api/tier/report - Get usage report
  if (method === 'GET' && path === '/api/tier/report') {
    await handleGetTierReport(req, res);
    return true;
  }

  return false;
}
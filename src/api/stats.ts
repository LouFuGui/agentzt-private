/**
 * Statistics Analysis API
 * Provides endpoints for aggregating and analyzing audit data.
 * 
 * Features:
 * - Time range filtering (day/week/month/year)
 * - Detection statistics overview
 * - Risk distribution analysis
 * - Trend time series data
 * - Export functionality (CSV/JSON)
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { readFileSync, existsSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { sendJson, sendError, headerValue } from '../shared/http.ts';
import { makeLogger } from '../shared/log.ts';
import { AUDIT_DIR } from '../shared/paths.ts';
import type { AuditEvent, RiskLevel } from '../shared/types.ts';
import { getAuthContext, type AuthContext } from './auth-middleware.ts';
import { getAppStore } from './app-store.ts';

const log = makeLogger('stats-api');

// ============================================================================
// Time Range Types
// ============================================================================

export type TimeRange = 'day' | 'week' | 'month' | 'year';

export type Granularity = 'hour' | 'day';

// ============================================================================
// Response Types
// ============================================================================

export type StatsOverviewResponse = {
  totalDetections: number;
  todayDetections: number;
  passRate: number;
  blockRate: number;
  flagRate: number;
  avgLatencyMs: number;
  totalTokens: number;
};

export type RiskDistributionResponse = {
  byLevel: {
    no_risk: number;
    low_risk: number;
    medium_risk: number;
    high_risk: number;
  };
  byCategory: {
    S1: number; S2: number; S3: number; S4: number; S5: number;
    S6: number; S7: number; S8: number; S9: number; S10: number;
    S11: number; S12: number; S13: number; S14: number; S15: number;
    S16: number; S17: number; S18: number; S19: number;
  };
  byApp: Record<string, number>;
};

export type TrendDataPoint = {
  timestamp: string;
  detections: number;
  passRate: number;
  blockRate: number;
};

export type TrendResponse = {
  data: TrendDataPoint[];
  timeRange: TimeRange;
  granularity: Granularity;
};

export type ExportFormat = 'csv' | 'json';

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Get time range start date based on current time and range type
 */
function getTimeRangeStart(timeRange: TimeRange): Date {
  const now = new Date();
  switch (timeRange) {
    case 'day':
      return new Date(now.getFullYear(), now.getMonth(), now.getDate());
    case 'week':
      const weekStart = new Date(now);
      weekStart.setDate(now.getDate() - now.getDay());
      weekStart.setHours(0, 0, 0, 0);
      return weekStart;
    case 'month':
      return new Date(now.getFullYear(), now.getMonth(), 1);
    case 'year':
      return new Date(now.getFullYear(), 0, 1);
    default:
      return new Date(now.getFullYear(), now.getMonth(), now.getDate());
  }
}

/**
 * Get today's start date
 */
function getTodayStart(): Date {
  const now = new Date();
  return new Date(now.getFullYear(), now.getMonth(), now.getDate());
}

/**
 * Parse audit events from JSONL file
 */
function loadAuditEvents(appId?: string): AuditEvent[] {
  const auditFile = resolve(AUDIT_DIR, 'gateway-audit.jsonl');
  
  if (!existsSync(auditFile)) {
    log.info('No audit file found, returning empty array');
    return [];
  }
  
  const content = readFileSync(auditFile, 'utf8');
  const lines = content.trim().split('\n').filter(Boolean);
  
  const events: AuditEvent[] = [];
  for (const line of lines) {
    try {
      const event = JSON.parse(line) as AuditEvent;
      // Filter by appId if specified
      if (appId && event.appId !== appId) {
        continue;
      }
      events.push(event);
    } catch {
      log.warn('Failed to parse audit event line');
    }
  }
  
  return events;
}

/**
 * Filter events by time range
 */
function filterByTimeRange(events: AuditEvent[], timeRange: TimeRange): AuditEvent[] {
  const start = getTimeRangeStart(timeRange);
  return events.filter(event => {
    const eventTime = new Date(event.ts);
    return eventTime >= start;
  });
}

/**
 * Filter events by today
 */
function filterByToday(events: AuditEvent[]): AuditEvent[] {
  const todayStart = getTodayStart();
  return events.filter(event => {
    const eventTime = new Date(event.ts);
    return eventTime >= todayStart;
  });
}

/**
 * Determine risk level from event
 */
function getRiskLevelFromEvent(event: AuditEvent): 'no_risk' | 'low_risk' | 'medium_risk' | 'high_risk' {
  // Check categories for risk indicators
  if (event.categories && event.categories.length > 0) {
    // High risk categories
    const highRiskCategories = ['S1', 'S2', 'S7', 'S8', 'S9', 'S10', 'S11', 'S12'];
    const mediumRiskCategories = ['S3', 'S5', 'S6', 'S13', 'S17', 'S18'];
    const lowRiskCategories = ['S4', 'S14', 'S15', 'S16', 'S19'];
    
    for (const cat of event.categories) {
      if (highRiskCategories.includes(cat)) return 'high_risk';
    }
    for (const cat of event.categories) {
      if (mediumRiskCategories.includes(cat)) return 'medium_risk';
    }
    for (const cat of event.categories) {
      if (lowRiskCategories.includes(cat)) return 'low_risk';
    }
  }
  
  // Check score
  if (event.score !== undefined) {
    if (event.score >= 0.8) return 'high_risk';
    if (event.score >= 0.6) return 'medium_risk';
    if (event.score >= 0.4) return 'low_risk';
  }
  
  // Check decision
  if (event.decision === 'deny') {
    return 'medium_risk';
  }
  
  return 'no_risk';
}

/**
 * Get authenticated user and verify access
 */
function getAuthenticatedUser(req: IncomingMessage): AuthContext | null {
  const auth = getAuthContext(req);
  return auth ?? null;
}

/**
 * Get appId from query or header
 */
function getAppIdFromRequest(req: IncomingMessage): string | undefined {
  const url = new URL(req.url ?? '/', 'http://localhost');
  const appIdQuery = url.searchParams.get('appId');
  if (appIdQuery) return appIdQuery;
  
  const appIdHeader = headerValue(req, 'x-agentzt-app-id');
  if (appIdHeader) return appIdHeader;
  
  return undefined;
}

/**
 * Verify user has access to the specified app
 */
function verifyAppAccess(appId: string, auth: AuthContext): boolean {
  const store = getAppStore();
  const app = store.getApp(appId);
  
  if (!app) return false;
  
  // Owner/admin can access any app, viewer can only access their own apps
  if (auth.role === 'owner' || auth.role === 'admin') {
    return true;
  }
  
  return app.ownerId === auth.userId;
}

// ============================================================================
// Statistics Aggregation Functions
// ============================================================================

/**
 * Calculate overview statistics
 */
function calculateOverviewStats(events: AuditEvent[]): StatsOverviewResponse {
  // Detection actions: guardrails.check, proxy.call, direct.call, model.call
  const detectionActions = ['guardrails.check', 'proxy.call', 'direct.call', 'model.call'];
  
  const totalEvents = events.filter(e => detectionActions.includes(e.action));
  const totalDetections = totalEvents.length;
  
  // Count decisions
  const passCount = totalEvents.filter(e => e.decision === 'allow' && 
    (!e.categories || e.categories.length === 0)).length;
  const blockCount = totalEvents.filter(e => e.decision === 'deny').length;
  const flagCount = totalEvents.filter(e => e.decision === 'allow' && 
    e.categories && e.categories.length > 0).length;
  
  // Calculate rates
  const passRate = totalDetections > 0 ? passCount / totalDetections : 0;
  const blockRate = totalDetections > 0 ? blockCount / totalDetections : 0;
  const flagRate = totalDetections > 0 ? flagCount / totalDetections : 0;
  
  // Calculate average latency
  const eventsWithLatency = totalEvents.filter(e => e.latencyMs !== undefined);
  const avgLatencyMs = eventsWithLatency.length > 0 
    ? eventsWithLatency.reduce((sum, e) => sum + (e.latencyMs ?? 0), 0) / eventsWithLatency.length 
    : 0;
  
  // Calculate total tokens from meta.usage
  const totalTokens = totalEvents.reduce((sum, e) => {
    const usage = e.meta?.usage as { input_tokens?: number; output_tokens?: number } | undefined;
    if (usage) {
      return sum + (usage.input_tokens ?? 0) + (usage.output_tokens ?? 0);
    }
    return sum;
  }, 0);
  
  return {
    totalDetections,
    todayDetections: 0, // Will be set separately
    passRate: Math.round(passRate * 1000) / 1000, // Round to 3 decimals
    blockRate: Math.round(blockRate * 1000) / 1000,
    flagRate: Math.round(flagRate * 1000) / 1000,
    avgLatencyMs: Math.round(avgLatencyMs),
    totalTokens,
  };
}

/**
 * Calculate risk distribution statistics
 */
function calculateRiskDistribution(events: AuditEvent[]): RiskDistributionResponse {
  // Initialize counters
  const byLevel = {
    no_risk: 0,
    low_risk: 0,
    medium_risk: 0,
    high_risk: 0,
  };
  
  const byCategory: Record<string, number> = {
    S1: 0, S2: 0, S3: 0, S4: 0, S5: 0,
    S6: 0, S7: 0, S8: 0, S9: 0, S10: 0,
    S11: 0, S12: 0, S13: 0, S14: 0, S15: 0,
    S16: 0, S17: 0, S18: 0, S19: 0,
  };
  
  const byApp: Record<string, number> = {};
  
  // Process events
  for (const event of events) {
    // Count by risk level
    const riskLevel = getRiskLevelFromEvent(event);
    byLevel[riskLevel]++;
    
    // Count by category
    if (event.categories) {
      for (const cat of event.categories) {
        if (byCategory[cat] !== undefined) {
          byCategory[cat]++;
        }
      }
    }
    
    // Count by app
    if (event.appId) {
      byApp[event.appId] = (byApp[event.appId] ?? 0) + 1;
    }
  }
  
  return {
    byLevel,
    byCategory: byCategory as RiskDistributionResponse['byCategory'],
    byApp,
  };
}

/**
 * Calculate trend data points
 */
function calculateTrendData(
  events: AuditEvent[],
  timeRange: TimeRange,
  granularity: Granularity,
): TrendDataPoint[] {
  const start = getTimeRangeStart(timeRange);
  const now = new Date();
  
  // Generate time buckets
  const buckets: Map<string, AuditEvent[]> = new Map();
  
  for (const event of events) {
    const eventTime = new Date(event.ts);
    if (eventTime < start || eventTime > now) continue;
    
    // Determine bucket key based on granularity
    let bucketKey: string;
    if (granularity === 'hour') {
      bucketKey = `${eventTime.getFullYear()}-${eventTime.getMonth() + 1}-${eventTime.getDate()}-${eventTime.getHours()}`;
    } else {
      bucketKey = `${eventTime.getFullYear()}-${eventTime.getMonth() + 1}-${eventTime.getDate()}`;
    }
    
    if (!buckets.has(bucketKey)) {
      buckets.set(bucketKey, []);
    }
    buckets.get(bucketKey)!.push(event);
  }
  
  // Calculate stats for each bucket
  const data: TrendDataPoint[] = [];
  const sortedKeys = Array.from(buckets.keys()).sort();
  
  for (const key of sortedKeys) {
    const bucketEvents = buckets.get(key) ?? [];
    
    // Parse timestamp
    const parts = key.split('-');
    let timestamp: string;
    if (granularity === 'hour') {
      const [year, month, day, hour] = parts;
      timestamp = new Date(parseInt(year!), parseInt(month!) - 1, parseInt(day!), parseInt(hour!)).toISOString();
    } else {
      const [year, month, day] = parts;
      timestamp = new Date(parseInt(year!), parseInt(month!) - 1, parseInt(day!)).toISOString();
    }
    
    // Calculate stats for bucket
    const detectionActions = ['guardrails.check', 'proxy.call', 'direct.call', 'model.call'];
    const detections = bucketEvents.filter(e => detectionActions.includes(e.action)).length;
    
    const passCount = bucketEvents.filter(e => e.decision === 'allow' && 
      (!e.categories || e.categories.length === 0)).length;
    const blockCount = bucketEvents.filter(e => e.decision === 'deny').length;
    
    const passRate = detections > 0 ? passCount / detections : 0;
    const blockRate = detections > 0 ? blockCount / detections : 0;
    
    data.push({
      timestamp,
      detections,
      passRate: Math.round(passRate * 1000) / 1000,
      blockRate: Math.round(blockRate * 1000) / 1000,
    });
  }
  
  return data;
}

// ============================================================================
// API Handlers
// ============================================================================

/**
 * GET /api/stats/overview?timeRange=day|week|month&appId=xxx
 * Get statistics overview
 */
export async function handleGetStatsOverview(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }
  
  const url = new URL(req.url ?? '/', 'http://localhost');
  const timeRangeParam = url.searchParams.get('timeRange') ?? 'day';
  
  // Validate time range
  if (!['day', 'week', 'month', 'year'].includes(timeRangeParam)) {
    return sendError(res, 400, 'invalid_request', 
      'Invalid timeRange. Must be one of: day, week, month, year');
  }
  
  const timeRange: TimeRange = timeRangeParam as TimeRange;
  
  // Get appId filter
  const appId = getAppIdFromRequest(req);
  
  // Verify app access if appId specified
  if (appId && !verifyAppAccess(appId, auth)) {
    return sendError(res, 403, 'permission_error', 
      'You do not have access to this application');
  }
  
  // Load and filter events
  const allEvents = loadAuditEvents(appId);
  const filteredEvents = filterByTimeRange(allEvents, timeRange);
  const todayEvents = filterByToday(allEvents);
  
  // Calculate stats
  const overview = calculateOverviewStats(filteredEvents);
  const todayOverview = calculateOverviewStats(todayEvents);
  
  // Set today detections
  overview.todayDetections = todayOverview.totalDetections;
  
  log.info(`Stats overview requested: timeRange=${timeRange}, appId=${appId ?? 'all'}`);
  
  return sendJson(res, 200, overview);
}

/**
 * GET /api/stats/risk-distribution?timeRange=day|week|month&appId=xxx
 * Get risk distribution statistics
 */
export async function handleGetRiskDistribution(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }
  
  const url = new URL(req.url ?? '/', 'http://localhost');
  const timeRangeParam = url.searchParams.get('timeRange') ?? 'day';
  
  // Validate time range
  if (!['day', 'week', 'month', 'year'].includes(timeRangeParam)) {
    return sendError(res, 400, 'invalid_request', 
      'Invalid timeRange. Must be one of: day, week, month, year');
  }
  
  const timeRange: TimeRange = timeRangeParam as TimeRange;
  
  // Get appId filter
  const appId = getAppIdFromRequest(req);
  
  // Verify app access if appId specified
  if (appId && !verifyAppAccess(appId, auth)) {
    return sendError(res, 403, 'permission_error', 
      'You do not have access to this application');
  }
  
  // Load and filter events
  const allEvents = loadAuditEvents(appId);
  const filteredEvents = filterByTimeRange(allEvents, timeRange);
  
  // Calculate risk distribution
  const distribution = calculateRiskDistribution(filteredEvents);
  
  log.info(`Risk distribution requested: timeRange=${timeRange}, appId=${appId ?? 'all'}`);
  
  return sendJson(res, 200, distribution);
}

/**
 * GET /api/stats/trend?timeRange=day|week|month&granularity=hour|day&appId=xxx
 * Get trend time series data
 */
export async function handleGetStatsTrend(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }
  
  const url = new URL(req.url ?? '/', 'http://localhost');
  const timeRangeParam = url.searchParams.get('timeRange') ?? 'day';
  const granularityParam = url.searchParams.get('granularity') ?? 'hour';
  
  // Validate time range
  if (!['day', 'week', 'month', 'year'].includes(timeRangeParam)) {
    return sendError(res, 400, 'invalid_request', 
      'Invalid timeRange. Must be one of: day, week, month, year');
  }
  
  // Validate granularity
  if (!['hour', 'day'].includes(granularityParam)) {
    return sendError(res, 400, 'invalid_request', 
      'Invalid granularity. Must be one of: hour, day');
  }
  
  // Validate granularity compatibility with time range
  if (timeRangeParam === 'year' && granularityParam === 'hour') {
    return sendError(res, 400, 'invalid_request', 
      'Hour granularity is not supported for year time range');
  }
  
  const timeRange: TimeRange = timeRangeParam as TimeRange;
  const granularity: Granularity = granularityParam as Granularity;
  
  // Get appId filter
  const appId = getAppIdFromRequest(req);
  
  // Verify app access if appId specified
  if (appId && !verifyAppAccess(appId, auth)) {
    return sendError(res, 403, 'permission_error', 
      'You do not have access to this application');
  }
  
  // Load and filter events
  const allEvents = loadAuditEvents(appId);
  const filteredEvents = filterByTimeRange(allEvents, timeRange);
  
  // Calculate trend data
  const data = calculateTrendData(filteredEvents, timeRange, granularity);
  
  const response: TrendResponse = {
    data,
    timeRange,
    granularity,
  };
  
  log.info(`Trend data requested: timeRange=${timeRange}, granularity=${granularity}, appId=${appId ?? 'all'}`);
  
  return sendJson(res, 200, response);
}

/**
 * GET /api/stats/export?format=csv|json&timeRange=day|week|month&appId=xxx
 * Export statistics data
 */
export async function handleExportStats(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return sendError(res, 401, 'authentication_error', 'User not authenticated');
  }
  
  const url = new URL(req.url ?? '/', 'http://localhost');
  const formatParam = url.searchParams.get('format') ?? 'json';
  const timeRangeParam = url.searchParams.get('timeRange') ?? 'day';
  
  // Validate format
  if (!['csv', 'json'].includes(formatParam)) {
    return sendError(res, 400, 'invalid_request', 
      'Invalid format. Must be one of: csv, json');
  }
  
  // Validate time range
  if (!['day', 'week', 'month', 'year'].includes(timeRangeParam)) {
    return sendError(res, 400, 'invalid_request', 
      'Invalid timeRange. Must be one of: day, week, month, year');
  }
  
  const format: ExportFormat = formatParam as ExportFormat;
  const timeRange: TimeRange = timeRangeParam as TimeRange;
  
  // Get appId filter
  const appId = getAppIdFromRequest(req);
  
  // Verify app access if appId specified
  if (appId && !verifyAppAccess(appId, auth)) {
    return sendError(res, 403, 'permission_error', 
      'You do not have access to this application');
  }
  
  // Load and filter events
  const allEvents = loadAuditEvents(appId);
  const filteredEvents = filterByTimeRange(allEvents, timeRange);
  
  // Calculate all stats
  const overview = calculateOverviewStats(filteredEvents);
  const todayEvents = filterByToday(allEvents);
  overview.todayDetections = calculateOverviewStats(todayEvents).totalDetections;
  
  const distribution = calculateRiskDistribution(filteredEvents);
  const trendData = calculateTrendData(filteredEvents, timeRange, 'day');
  
  // Prepare export data
  const exportData = {
    overview,
    riskDistribution: distribution,
    trend: trendData,
    exportInfo: {
      timeRange,
      appId: appId ?? 'all',
      exportedAt: new Date().toISOString(),
      exportedBy: auth.userId,
    },
  };
  
  if (format === 'json') {
    // Return JSON
    res.writeHead(200, {
      'content-type': 'application/json',
      'content-disposition': `attachment; filename="stats-export-${timeRange}-${Date.now()}.json"`,
    });
    res.end(JSON.stringify(exportData, null, 2));
  } else {
    // Return CSV
    const csvLines: string[] = [];
    
    // Overview section
    csvLines.push('# Statistics Export');
    csvLines.push(`# Time Range: ${timeRange}`);
    csvLines.push(`# Exported At: ${exportData.exportInfo.exportedAt}`);
    csvLines.push('');
    csvLines.push('## Overview');
    csvLines.push('Metric,Value');
    csvLines.push(`Total Detections,${overview.totalDetections}`);
    csvLines.push(`Today Detections,${overview.todayDetections}`);
    csvLines.push(`Pass Rate,${overview.passRate}`);
    csvLines.push(`Block Rate,${overview.blockRate}`);
    csvLines.push(`Flag Rate,${overview.flagRate}`);
    csvLines.push(`Avg Latency (ms),${overview.avgLatencyMs}`);
    csvLines.push(`Total Tokens,${overview.totalTokens}`);
    csvLines.push('');
    
    // Risk Distribution section
    csvLines.push('## Risk Distribution by Level');
    csvLines.push('Risk Level,Count');
    csvLines.push(`No Risk,${distribution.byLevel.no_risk}`);
    csvLines.push(`Low Risk,${distribution.byLevel.low_risk}`);
    csvLines.push(`Medium Risk,${distribution.byLevel.medium_risk}`);
    csvLines.push(`High Risk,${distribution.byLevel.high_risk}`);
    csvLines.push('');
    
    csvLines.push('## Risk Distribution by Category');
    csvLines.push('Category,Count');
    for (const [cat, count] of Object.entries(distribution.byCategory)) {
      csvLines.push(`${cat},${count}`);
    }
    csvLines.push('');
    
    // Trend section
    csvLines.push('## Trend Data');
    csvLines.push('Timestamp,Detections,Pass Rate,Block Rate');
    for (const point of trendData) {
      csvLines.push(`${point.timestamp},${point.detections},${point.passRate},${point.blockRate}`);
    }
    
    const csvContent = csvLines.join('\n');
    
    res.writeHead(200, {
      'content-type': 'text/csv',
      'content-disposition': `attachment; filename="stats-export-${timeRange}-${Date.now()}.csv"`,
    });
    res.end(csvContent);
  }
  
  log.info(`Stats exported: format=${format}, timeRange=${timeRange}, appId=${appId ?? 'all'}`);
}

// ============================================================================
// Router
// ============================================================================

/**
 * Route statistics API requests
 */
export async function routeStatsApi(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const url = new URL(req.url ?? '/', 'http://localhost');
  const path = url.pathname;
  const method = req.method ?? 'GET';
  
  // All stats endpoints require GET method
  if (method !== 'GET') {
    return false;
  }
  
  // GET /api/stats/overview
  if (path === '/api/stats/overview') {
    await handleGetStatsOverview(req, res);
    return true;
  }
  
  // GET /api/stats/risk-distribution
  if (path === '/api/stats/risk-distribution') {
    await handleGetRiskDistribution(req, res);
    return true;
  }
  
  // GET /api/stats/trend
  if (path === '/api/stats/trend') {
    await handleGetStatsTrend(req, res);
    return true;
  }
  
  // GET /api/stats/export
  if (path === '/api/stats/export') {
    await handleExportStats(req, res);
    return true;
  }
  
  return false;
}
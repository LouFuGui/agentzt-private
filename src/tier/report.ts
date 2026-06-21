/**
 * Tier Report
 * Generates usage reports and cost estimates for billing.
 */

import { makeLogger } from '../shared/log.ts';
import type { TierLevel, TierUsageReport, QuotaHistoryEntry } from '../shared/types.ts';
import { getUserStore } from '../api/user-store.ts';
import { getAppStore } from '../api/app-store.ts';
import { getQuotaTracker } from '../quota/tracker.ts';
import { getTierConfig, getTierPrice } from './features.ts';

const log = makeLogger('tier-report');

// ============================================================================
// Usage Report Generation
// ============================================================================

/**
 * Pricing constants for usage-based billing
 */
const USAGE_PRICING = {
  // Per 1000 checks over base limit
  checksOverageRate: 0.01, // $0.01 per 1000 checks
  // Per 100000 tokens over base limit
  tokensOverageRate: 0.05, // $0.05 per 100000 tokens
  // Currency
  currency: 'USD',
};

/**
 * Generate usage report for a user
 */
export function generateUsageReport(
  userId: string,
  periodStart?: string,
  periodEnd?: string,
): TierUsageReport | null {
  const userStore = getUserStore();
  const user = userStore.getById(userId);

  if (!user) {
    log.warn(`User not found: ${userId}`);
    return null;
  }

  const tier = user.tier as TierLevel;
  const appStore = getAppStore();
  const apps = appStore.listAppsByOwner(userId);
  const quotaTracker = getQuotaTracker();

  // Default period: current month
  const now = new Date();
  const defaultPeriodStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();
  const defaultPeriodEnd = now.toISOString();

  const start = periodStart ?? defaultPeriodStart;
  const end = periodEnd ?? defaultPeriodEnd;

  // Aggregate usage across all apps
  const checksByApp: Record<string, number> = {};
  const tokensByApp: Record<string, number> = {};
  const checksByDay: Array<{ date: string; count: number }> = [];
  const tokensByDay: Array<{ date: string; count: number }> = [];

  let totalChecks = 0;
  let totalTokens = 0;
  let activeAgents = 0;

  for (const app of apps) {
    // Get usage from quota tracker
    const history = quotaTracker.getHistory(app.appId, { timeRange: 'month' });
    
    // Aggregate by app
    const appChecks = history
      .filter((h) => h.type === 'checks')
      .reduce((sum, h) => sum + h.delta, 0);
    const appTokens = history
      .filter((h) => h.type === 'tokens')
      .reduce((sum, h) => sum + h.delta, 0);

    checksByApp[app.appId] = appChecks;
    tokensByApp[app.appId] = appTokens;
    totalChecks += appChecks;
    totalTokens += appTokens;

    // Count active agents (apps with recent activity)
    if (history.length > 0) {
      activeAgents++;
    }

    // Aggregate by day
    const checksByDate = aggregateByDate(history.filter((h) => h.type === 'checks'));
    const tokensByDate = aggregateByDate(history.filter((h) => h.type === 'tokens'));

    // Merge into overall by-day arrays
    for (const entry of checksByDate) {
      const existing = checksByDay.find((d) => d.date === entry.date);
      if (existing) {
        existing.count += entry.count;
      } else {
        checksByDay.push(entry);
      }
    }

    for (const entry of tokensByDate) {
      const existing = tokensByDay.find((d) => d.date === entry.date);
      if (existing) {
        existing.count += entry.count;
      } else {
        tokensByDay.push(entry);
      }
    }
  }

  // Sort by date
  checksByDay.sort((a, b) => a.date.localeCompare(b.date));
  tokensByDay.sort((a, b) => a.date.localeCompare(b.date));

  // Calculate cost estimate
  const costEstimate = calculateCostEstimate(tier, totalChecks, totalTokens);

  return {
    userId,
    tier,
    periodStart: start,
    periodEnd: end,
    usage: {
      checks: {
        total: totalChecks,
        byApp: checksByApp,
        byDay: checksByDay,
      },
      tokens: {
        total: totalTokens,
        byApp: tokensByApp,
        byDay: tokensByDay,
      },
      agents: {
        total: apps.length,
        active: activeAgents,
      },
    },
    costEstimate,
  };
}

/**
 * Aggregate usage by date
 */
function aggregateByDate(history: QuotaHistoryEntry[]): Array<{ date: string; count: number }> {
  const byDate: Record<string, number> = {};

  for (const entry of history) {
    const date = entry.timestamp.split('T')[0] ?? '';
    byDate[date] = (byDate[date] ?? 0) + entry.delta;
  }

  return Object.entries(byDate).map(([date, count]) => ({ date, count }));
}

/**
 * Calculate cost estimate based on tier and usage
 */
function calculateCostEstimate(
  tier: TierLevel,
  totalChecks: number,
  totalTokens: number,
): TierUsageReport['costEstimate'] {
  const tierConfig = getTierConfig(tier);
  const basePrice = getTierPrice(tier, 'monthly');
  const limits = tierConfig.limits;

  // Calculate overage
  const checksOverage = Math.max(0, totalChecks - limits.checksLimit);
  const tokensOverage = Math.max(0, totalTokens - limits.tokensLimit);

  // Calculate overage cost
  const checksOverageCost = (checksOverage / 1000) * USAGE_PRICING.checksOverageRate;
  const tokensOverageCost = (tokensOverage / 100000) * USAGE_PRICING.tokensOverageRate;
  const usagePrice = checksOverageCost + tokensOverageCost;

  const totalPrice = basePrice + usagePrice;

  const breakdown: Array<{ item: string; amount: number }> = [
    { item: `Base (${tierConfig.displayName})`, amount: basePrice },
  ];

  if (checksOverage > 0) {
    breakdown.push({
      item: `Checks overage (${checksOverage} over limit)`,
      amount: checksOverageCost,
    });
  }

  if (tokensOverage > 0) {
    breakdown.push({
      item: `Tokens overage (${tokensOverage} over limit)`,
      amount: tokensOverageCost,
    });
  }

  return {
    basePrice,
    usagePrice,
    totalPrice,
    currency: USAGE_PRICING.currency,
    breakdown,
  };
}

/**
 * Export report to JSON format
 */
export function exportReportJson(report: TierUsageReport): string {
  return JSON.stringify(report, null, 2);
}

/**
 * Export report to CSV format
 */
export function exportReportCsv(report: TierUsageReport): string {
  const lines: string[] = [];

  // Header
  lines.push('User ID,Tier,Period Start,Period End');
  lines.push(`${report.userId},${report.tier},${report.periodStart},${report.periodEnd}`);

  // Usage summary
  lines.push('');
  lines.push('Usage Summary');
  lines.push('Type,Total,By App');
  lines.push(`Checks,${report.usage.checks.total},${JSON.stringify(report.usage.checks.byApp)}`);
  lines.push(`Tokens,${report.usage.tokens.total},${JSON.stringify(report.usage.tokens.byApp)}`);
  lines.push(`Agents Total,${report.usage.agents.total},`);
  lines.push(`Agents Active,${report.usage.agents.active},`);

  // Daily usage
  lines.push('');
  lines.push('Daily Checks');
  lines.push('Date,Count');
  for (const entry of report.usage.checks.byDay) {
    lines.push(`${entry.date},${entry.count}`);
  }

  lines.push('');
  lines.push('Daily Tokens');
  lines.push('Date,Count');
  for (const entry of report.usage.tokens.byDay) {
    lines.push(`${entry.date},${entry.count}`);
  }

  // Cost estimate
  lines.push('');
  lines.push('Cost Estimate');
  lines.push('Item,Amount,Currency');
  for (const item of report.costEstimate.breakdown) {
    lines.push(`${item.item},${item.amount},${report.costEstimate.currency}`);
  }
  lines.push(`Total,${report.costEstimate.totalPrice},${report.costEstimate.currency}`);

  return lines.join('\n');
}

/**
 * Get usage summary for quick display
 */
export function getUsageSummary(userId: string): {
  tier: TierLevel;
  checks: { used: number; limit: number; percentage: number };
  tokens: { used: number; limit: number; percentage: number };
  agents: { count: number; limit: number };
  estimatedCost: number;
} | null {
  const userStore = getUserStore();
  const user = userStore.getById(userId);

  if (!user) {
    return null;
  }

  const tier = user.tier as TierLevel;
  const tierConfig = getTierConfig(tier);
  const appStore = getAppStore();
  const apps = appStore.listAppsByOwner(userId);

  let totalChecksUsed = 0;
  let totalTokensUsed = 0;

  for (const app of apps) {
    totalChecksUsed += app.quota.checksUsed;
    totalTokensUsed += app.quota.tokensUsed;
  }

  const checksLimit = tierConfig.limits.checksLimit;
  const tokensLimit = tierConfig.limits.tokensLimit;
  const agentsLimit = tierConfig.limits.agentsLimit;

  const costEstimate = calculateCostEstimate(tier, totalChecksUsed, totalTokensUsed);

  return {
    tier,
    checks: {
      used: totalChecksUsed,
      limit: checksLimit,
      percentage: Math.round((totalChecksUsed / checksLimit) * 100),
    },
    tokens: {
      used: totalTokensUsed,
      limit: tokensLimit,
      percentage: Math.round((totalTokensUsed / tokensLimit) * 100),
    },
    agents: {
      count: apps.length,
      limit: agentsLimit === -1 ? Infinity : agentsLimit,
    },
    estimatedCost: costEstimate.totalPrice,
  };
}
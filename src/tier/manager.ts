/**
 * Tier Manager
 * Handles tier upgrade/downgrade operations with quota validation.
 */

import { DatabaseSync } from 'node:sqlite';
import { existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { resolve } from 'node:path';
import { makeLogger } from '../shared/log.ts';
import type {
  TierLevel,
  TierChangeRequest,
  TierChangeHistoryEntry,
  TierChangeValidation,
  UserTier,
} from '../shared/types.ts';
import { getUserStore } from '../api/user-store.ts';
import { getAppStore } from '../api/app-store.ts';
import { getQuotaTracker } from '../quota/tracker.ts';
import {
  getTierConfig,
  isUpgrade,
  isDowngrade,
  getTierLimit,
  isUnlimited,
} from './features.ts';
import { newId } from '../shared/crypto.ts';

const log = makeLogger('tier-manager');

// Database file path
const TIER_DB_FILE = resolve(process.env.AGENTZT_ROOT || '.', '.agentzt', 'tier.db');

// ============================================================================
// Tier Manager - Upgrade/Downgrade Operations
// ============================================================================

/**
 * TierManager: SQLite-based tier change management
 * 
 * Features:
 * - Validates tier change requests
 * - Checks quota usage for downgrade
 * - Records tier change history
 * - Updates user permissions and limits
 */
export class TierManager {
  private db: DatabaseSync;

  constructor(dbPath: string = TIER_DB_FILE) {
    // Ensure the directory exists
    const dir = dirname(dbPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    this.db = new DatabaseSync(dbPath);
    this.initTables();
    log.info(`TierManager initialized at ${dbPath}`);
  }

  private initTables(): void {
    // Tier change history table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS tier_change_history (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        from_tier TEXT NOT NULL,
        to_tier TEXT NOT NULL,
        reason TEXT,
        changed_at TEXT NOT NULL,
        changed_by TEXT NOT NULL,
        status TEXT NOT NULL
      )
    `);

    // Create indexes
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_tier_history_user_id ON tier_change_history(user_id)`);
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_tier_history_changed_at ON tier_change_history(changed_at)`);
  }

  /**
   * Validate tier change request
   * Checks if the change is allowed based on current usage
   */
  validateTierChange(
    userId: string,
    request: TierChangeRequest,
  ): TierChangeValidation {
    const userStore = getUserStore();
    const user = userStore.getById(userId);

    if (!user) {
      return {
        allowed: false,
        reason: 'User not found',
      };
    }

    const currentTier = user.tier as TierLevel;
    const targetTier = request.targetTier;

    // Cannot change to same tier
    if (currentTier === targetTier) {
      return {
        allowed: false,
        reason: 'Cannot change to the same tier',
      };
    }

    // Must be confirmed
    if (!request.confirmed) {
      return {
        allowed: false,
        reason: 'Tier change must be confirmed',
      };
    }

    // For downgrade, check if current usage exceeds new tier limits
    if (isDowngrade(currentTier, targetTier)) {
      const quotaCheck = this.checkQuotaForDowngrade(userId, targetTier);
      
      if (quotaCheck.willExceedLimit) {
        return {
          allowed: false,
          reason: 'Current usage exceeds the target tier limits. Please reduce usage before downgrade.',
          warnings: [
            `Checks used: ${quotaCheck.checksUsed} / Target limit: ${quotaCheck.checksLimit}`,
            `Tokens used: ${quotaCheck.tokensUsed} / Target limit: ${quotaCheck.tokensLimit}`,
            `Agents count: ${quotaCheck.agentsCount} / Target limit: ${quotaCheck.agentsLimit}`,
          ],
          quotaCheck,
        };
      }

      return {
        allowed: true,
        warnings: [
          'Downgrade will reduce your available limits.',
          'Some features may become unavailable.',
          'Please review the tier comparison before proceeding.',
        ],
        quotaCheck,
      };
    }

    // For upgrade, always allowed
    return {
      allowed: true,
      warnings: isUpgrade(currentTier, targetTier) ? [
        'Upgrade will increase your billing.',
        'New features will be available immediately.',
      ] : undefined,
    };
  }

  /**
   * Check quota usage for downgrade validation
   */
  private checkQuotaForDowngrade(
    userId: string,
    targetTier: TierLevel,
  ): TierChangeValidation['quotaCheck'] & { willExceedLimit: boolean } {
    const appStore = getAppStore();
    const apps = appStore.listAppsByOwner(userId);

    // Calculate total usage across all apps
    let totalChecksUsed = 0;
    let totalTokensUsed = 0;
    const agentsCount = apps.length; // Each app can have agents

    for (const app of apps) {
      totalChecksUsed += app.quota.checksUsed;
      totalTokensUsed += app.quota.tokensUsed;
    }

    const targetLimits = getTierConfig(targetTier).limits;
    const checksLimit = isUnlimited(targetTier, 'checksLimit') ? Infinity : targetLimits.checksLimit;
    const tokensLimit = isUnlimited(targetTier, 'tokensLimit') ? Infinity : targetLimits.tokensLimit;
    const agentsLimit = isUnlimited(targetTier, 'agentsLimit') ? Infinity : targetLimits.agentsLimit;

    const willExceedLimit = 
      totalChecksUsed > checksLimit ||
      totalTokensUsed > tokensLimit ||
      agentsCount > agentsLimit;

    return {
      checksUsed: totalChecksUsed,
      checksLimit: targetLimits.checksLimit,
      tokensUsed: totalTokensUsed,
      tokensLimit: targetLimits.tokensLimit,
      agentsCount,
      agentsLimit: targetLimits.agentsLimit,
      willExceedLimit,
    };
  }

  /**
   * Process tier change request
   * Updates user tier and adjusts quotas
   */
  async processTierChange(
    userId: string,
    request: TierChangeRequest,
    changedBy: string = userId,
  ): Promise<{ ok: true; historyEntry: TierChangeHistoryEntry } | { ok: false; error: string }> {
    // Validate first
    const validation = this.validateTierChange(userId, request);
    if (!validation.allowed) {
      return { ok: false, error: validation.reason || 'Tier change not allowed' };
    }

    const userStore = getUserStore();
    const user = userStore.getById(userId);
    if (!user) {
      return { ok: false, error: 'User not found' };
    }

    const currentTier = user.tier as TierLevel;
    const targetTier = request.targetTier;

    // Update user tier
    const updateResult = await userStore.update(userId, { tier: targetTier as UserTier });
    if (!updateResult.ok) {
      return { ok: false, error: updateResult.error };
    }

    // Adjust app quotas based on new tier
    this.adjustQuotasForTierChange(userId, currentTier, targetTier);

    // Record history
    const historyEntry = this.recordTierChange({
      userId,
      fromTier: currentTier,
      toTier: targetTier,
      reason: request.reason,
      changedBy,
      status: 'completed',
    });

    log.info(`Tier changed for user ${userId}: ${currentTier} -> ${targetTier}`);

    return { ok: true, historyEntry };
  }

  /**
   * Adjust quotas for all apps when tier changes
   */
  private adjustQuotasForTierChange(
    userId: string,
    fromTier: TierLevel,
    toTier: TierLevel,
  ): void {
    const appStore = getAppStore();
    const apps = appStore.listAppsByOwner(userId);
    const newLimits = getTierConfig(toTier).limits;

    for (const app of apps) {
      // For upgrade: increase limits
      // For downgrade: keep current usage but cap limits
      const newQuota = {
        checksLimit: isUnlimited(toTier, 'checksLimit') 
          ? app.quota.checksLimit 
          : Math.max(app.quota.checksUsed, newLimits.checksLimit),
        tokensLimit: isUnlimited(toTier, 'tokensLimit') 
          ? app.quota.tokensLimit 
          : Math.max(app.quota.tokensUsed, newLimits.tokensLimit),
        // Keep current usage
        checksUsed: app.quota.checksUsed,
        tokensUsed: app.quota.tokensUsed,
      };

      appStore.updateAppQuota(app.appId, newQuota);
      log.info(`Adjusted quota for app ${app.appId} for tier change`);
    }
  }

  /**
   * Record tier change in history
   */
  private recordTierChange(entry: Omit<TierChangeHistoryEntry, 'id' | 'changedAt'>): TierChangeHistoryEntry {
    const id = newId('tier-change');
    const changedAt = new Date().toISOString();

    const insert = this.db.prepare(`
      INSERT INTO tier_change_history (id, user_id, from_tier, to_tier, reason, changed_at, changed_by, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    insert.run(
      id,
      entry.userId,
      entry.fromTier,
      entry.toTier,
      entry.reason ?? null,
      changedAt,
      entry.changedBy,
      entry.status,
    );

    return {
      id,
      userId: entry.userId,
      fromTier: entry.fromTier,
      toTier: entry.toTier,
      reason: entry.reason,
      changedAt,
      changedBy: entry.changedBy,
      status: entry.status,
    };
  }

  /**
   * Get tier change history for a user
   */
  getTierChangeHistory(
    userId: string,
    options?: { limit?: number },
  ): TierChangeHistoryEntry[] {
    const limit = options?.limit ?? 50;

    const rows = this.db.prepare(`
      SELECT id, user_id, from_tier, to_tier, reason, changed_at, changed_by, status
      FROM tier_change_history
      WHERE user_id = ?
      ORDER BY changed_at DESC
      LIMIT ?
    `).all(userId, limit) as Array<{
      id: string;
      user_id: string;
      from_tier: string;
      to_tier: string;
      reason: string | null;
      changed_at: string;
      changed_by: string;
      status: string;
    }>;

    return rows.map((row) => ({
      id: row.id,
      userId: row.user_id,
      fromTier: row.from_tier as TierLevel,
      toTier: row.to_tier as TierLevel,
      reason: row.reason ?? undefined,
      changedAt: row.changed_at,
      changedBy: row.changed_by,
      status: row.status as 'completed' | 'pending' | 'rejected',
    }));
  }

  /**
   * Get current tier for a user
   */
  getCurrentTier(userId: string): TierLevel | null {
    const userStore = getUserStore();
    const user = userStore.getById(userId);
    return user ? (user.tier as TierLevel) : null;
  }

  /**
   * Get tier config for a user
   */
  getUserTierConfig(userId: string): ReturnType<typeof getTierConfig> | null {
    const tier = this.getCurrentTier(userId);
    return tier ? getTierConfig(tier) : null;
  }

  /**
   * Close the database connection
   */
  close(): void {
    this.db.close();
    log.info('TierManager closed');
  }
}

// Singleton instance
let tierManagerInstance: TierManager | null = null;

/**
 * Get the singleton TierManager instance
 */
export function getTierManager(): TierManager {
  if (!tierManagerInstance) {
    tierManagerInstance = new TierManager();
  }
  return tierManagerInstance;
}

/**
 * Reset the singleton (for testing)
 */
export function resetTierManager(): void {
  if (tierManagerInstance) {
    tierManagerInstance.close();
    tierManagerInstance = null;
  }
}
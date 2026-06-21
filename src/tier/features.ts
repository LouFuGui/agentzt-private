/**
 * Tier Features Configuration
 * Defines the capabilities and limits for each service tier.
 */

import type { TierLevel, TierFeatures, TierLimits, TierPrice, TierConfig } from '../shared/types.ts';

// ============================================================================
// Tier Features Definitions
// ============================================================================

/**
 * Personal Tier Features
 * Basic security protection for individual users
 */
const PERSONAL_FEATURES: TierFeatures = {
  // Agent Management
  maxAgents: 1,
  multiAgentDashboard: false,
  agentBehaviorAnalysis: false,
  agentInventory: false,

  // Security Features
  personalAiAssistantProtection: true,
  runtimeMonitoring: true,
  configScanning: true,
  vulnerabilityDetection: true,
  redTeamTesting: true,
  blastRadiusAnalysis: false,
  threatDiscovery: false,

  // Policy & Governance
  realTimePolicyExecution: false,
  customDetectionRules: false,
  governancePolicyExecution: false,
  organizationAiGovernance: false,

  // Integrations
  integrationPluginSupport: false,

  // Support
  prioritySupport: false,
};

/**
 * Business Tier Features
 * Enhanced capabilities for small to medium teams
 */
const BUSINESS_FEATURES: TierFeatures = {
  // Agent Management
  maxAgents: 5,
  multiAgentDashboard: true,
  agentBehaviorAnalysis: true,
  agentInventory: false,

  // Security Features
  personalAiAssistantProtection: true,
  runtimeMonitoring: true,
  configScanning: true,
  vulnerabilityDetection: true,
  redTeamTesting: true,
  blastRadiusAnalysis: false,
  threatDiscovery: false,

  // Policy & Governance
  realTimePolicyExecution: true,
  customDetectionRules: true,
  governancePolicyExecution: false,
  organizationAiGovernance: false,

  // Integrations
  integrationPluginSupport: true,

  // Support
  prioritySupport: false,
};

/**
 * Enterprise Tier Features
 * Full capabilities for large organizations
 */
const ENTERPRISE_FEATURES: TierFeatures = {
  // Agent Management
  maxAgents: -1, // Unlimited
  multiAgentDashboard: true,
  agentBehaviorAnalysis: true,
  agentInventory: true,

  // Security Features
  personalAiAssistantProtection: true,
  runtimeMonitoring: true,
  configScanning: true,
  vulnerabilityDetection: true,
  redTeamTesting: true,
  blastRadiusAnalysis: true,
  threatDiscovery: true,

  // Policy & Governance
  realTimePolicyExecution: true,
  customDetectionRules: true,
  governancePolicyExecution: true,
  organizationAiGovernance: true,

  // Integrations
  integrationPluginSupport: true,

  // Support
  prioritySupport: true,
};

// ============================================================================
// Tier Limits Definitions
// ============================================================================

const PERSONAL_LIMITS: TierLimits = {
  checksLimit: 1000,
  tokensLimit: 100000,
  agentsLimit: 1,
  apiKeysLimit: 2,
  customRulesLimit: 0,
};

const BUSINESS_LIMITS: TierLimits = {
  checksLimit: 10000,
  tokensLimit: 1000000,
  agentsLimit: 5,
  apiKeysLimit: 10,
  customRulesLimit: 20,
};

const ENTERPRISE_LIMITS: TierLimits = {
  checksLimit: 100000,
  tokensLimit: 10000000,
  agentsLimit: -1, // Unlimited
  apiKeysLimit: -1, // Unlimited
  customRulesLimit: -1, // Unlimited
};

// ============================================================================
// Tier Pricing Definitions
// ============================================================================

const PERSONAL_PRICE: TierPrice = {
  monthly: 0, // Free
  yearly: 0,
  currency: 'USD',
  featuresDescription: [
    '个人 AI 助手保护',
    '运行时监控',
    '配置扫描',
    '漏洞检测',
    '红队测试',
    '最多 1 个 Agent',
  ],
};

const BUSINESS_PRICE: TierPrice = {
  monthly: 99,
  yearly: 999, // ~17% discount
  currency: 'USD',
  featuresDescription: [
    '最多 5 个 Agent',
    '多 Agent 可观测性 Dashboard',
    '实时策略执行',
    'Agent 行为分析',
    '自定义检测规则',
    '集成插件支持',
  ],
};

const ENTERPRISE_PRICE: TierPrice = {
  monthly: 499,
  yearly: 4990, // ~17% discount
  currency: 'USD',
  featuresDescription: [
    '无限 Agent',
    '组织级 AI 治理',
    'Agent 清单',
    'Blast radius 分析',
    '威胁发现',
    '治理策略执行',
    '优先支持',
  ],
};

// ============================================================================
// Complete Tier Configurations
// ============================================================================

export const TIER_CONFIGS: Record<TierLevel, TierConfig> = {
  personal: {
    tier: 'personal',
    features: PERSONAL_FEATURES,
    limits: PERSONAL_LIMITS,
    price: PERSONAL_PRICE,
    displayName: 'Personal',
    description: '适合个人用户的基础安全保护方案',
  },
  business: {
    tier: 'business',
    features: BUSINESS_FEATURES,
    limits: BUSINESS_LIMITS,
    price: BUSINESS_PRICE,
    displayName: 'Business',
    description: '适合中小型团队的增强安全方案',
  },
  enterprise: {
    tier: 'enterprise',
    features: ENTERPRISE_FEATURES,
    limits: ENTERPRISE_LIMITS,
    price: ENTERPRISE_PRICE,
    displayName: 'Enterprise',
    description: '适合大型企业的完整安全治理方案',
  },
};

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Get tier configuration by level
 */
export function getTierConfig(tier: TierLevel): TierConfig {
  return TIER_CONFIGS[tier];
}

/**
 * Get all tier options for display
 */
export function getAllTierConfigs(): TierConfig[] {
  return Object.values(TIER_CONFIGS);
}

/**
 * Check if a feature is available for a tier
 */
export function hasFeature(tier: TierLevel, feature: keyof TierFeatures): boolean {
  const config = TIER_CONFIGS[tier];
  const value = config.features[feature];
  // For numeric features like maxAgents, check if > 0 or -1 (unlimited)
  if (typeof value === 'number') {
    return value > 0 || value === -1;
  }
  return Boolean(value);
}

/**
 * Get the limit value for a tier
 */
export function getTierLimit(tier: TierLevel, limit: keyof TierLimits): number {
  return TIER_CONFIGS[tier].limits[limit];
}

/**
 * Check if a tier has unlimited value for a limit
 */
export function isUnlimited(tier: TierLevel, limit: keyof TierLimits): boolean {
  return TIER_CONFIGS[tier].limits[limit] === -1;
}

/**
 * Compare tier levels (returns -1 if a < b, 0 if equal, 1 if a > b)
 */
export function compareTiers(a: TierLevel, b: TierLevel): number {
  const order: TierLevel[] = ['personal', 'business', 'enterprise'];
  return order.indexOf(a) - order.indexOf(b);
}

/**
 * Check if upgrade is needed from current tier to target tier
 */
export function isUpgrade(currentTier: TierLevel, targetTier: TierLevel): boolean {
  return compareTiers(targetTier, currentTier) > 0;
}

/**
 * Check if downgrade is needed from current tier to target tier
 */
export function isDowngrade(currentTier: TierLevel, targetTier: TierLevel): boolean {
  return compareTiers(targetTier, currentTier) < 0;
}

/**
 * Get tier display name
 */
export function getTierDisplayName(tier: TierLevel): string {
  return TIER_CONFIGS[tier].displayName;
}

/**
 * Get tier price for billing period
 */
export function getTierPrice(tier: TierLevel, period: 'monthly' | 'yearly'): number {
  return TIER_CONFIGS[tier].price[period];
}

/**
 * Check if tier allows custom rules
 */
export function allowsCustomRules(tier: TierLevel): boolean {
  const limit = TIER_CONFIGS[tier].limits.customRulesLimit;
  return limit > 0 || limit === -1;
}

/**
 * Get max agents for tier (returns Infinity for unlimited)
 */
export function getMaxAgents(tier: TierLevel): number {
  const limit = TIER_CONFIGS[tier].limits.agentsLimit;
  return limit === -1 ? Infinity : limit;
}
// API module exports
export { AppStore, getAppStore, resetAppStore, generateApiKey, generateModelApiKey, generateAppId } from './app-store.ts';
export { routeAppsApi, handleCreateApp, handleListApps, handleGetApp, handleUpdateApp, handleDeleteApp, handleRegenerateKey, getAppFromHeader, validateApiKeyAndGetApp } from './apps.ts';
export type { CreateAppRequest, UpdateAppRequest, AppResponse, AppListResponse, RegenerateKeyResponse } from './apps.ts';

// Configuration Management API exports
export { routeConfigApi } from './config.ts';
export {
  handleGetRiskTypes,
  handleUpdateRiskTypes,
  handleGetRiskCategories,
  handleUpdateRiskCategories,
  handleGetBlacklistWhitelist,
  handleAddBlacklist,
  handleRemoveBlacklist,
  handleAddWhitelist,
  handleRemoveWhitelist,
  handleGetResponseTemplates,
  handleUpdateResponseTemplates,
  handleGetSensitivity,
  handleUpdateSensitivity,
  handleGetBanPolicy,
  handleUpdateBanPolicy,
  handleBanUser,
  handleUnbanUser,
  handleGetKnowledgeBase,
  handleAddKnowledgeBaseEntry,
  handleUpdateKnowledgeBaseEntry,
  handleDeleteKnowledgeBaseEntry,
} from './config.ts';
export type {
  UpdateRiskTypesRequest,
  UpdateRiskCategoriesRequest,
  AddBlacklistRequest,
  AddWhitelistRequest,
  RemoveBlacklistRequest,
  RemoveWhitelistRequest,
  UpdateResponseTemplatesRequest,
  UpdateSensitivityRequest,
  UpdateBanPolicyRequest,
  BanUserRequest,
  UnbanUserRequest,
  AddKnowledgeBaseEntryRequest,
  UpdateKnowledgeBaseEntryRequest,
  KnowledgeBaseEntryResponse,
} from './config.ts';

// Quota Management API exports
export { routeQuotaApi } from './quota.ts';
export {
  handleGetQuotaUsage,
  handleGetQuotaHistory,
  handleResetQuota,
  handleUpdateQuotaLimit,
  handleGetQuotaAlerts,
} from './quota.ts';
export type {
  QuotaUsageResponse,
  QuotaHistoryResponse,
  QuotaResetResponse,
  QuotaLimitUpdateResponse,
} from './quota.ts';

// Statistics Analysis API exports
export { routeStatsApi } from './stats.ts';
export {
  handleGetStatsOverview,
  handleGetRiskDistribution,
  handleGetStatsTrend,
  handleExportStats,
} from './stats.ts';
export type {
  TimeRange,
  Granularity,
  StatsOverviewResponse,
  RiskDistributionResponse,
  TrendDataPoint,
  TrendResponse,
  ExportFormat,
} from './stats.ts';

// Tier Management API exports
export { routeTierApi } from './tier.ts';
export {
  handleGetTierOptions,
  handleGetCurrentTier,
  handleTierChange,
  handleValidateTierChange,
  handleGetTierHistory,
  handleGetTierReport,
} from './tier.ts';
export type {
  TierOptionsResponse,
  CurrentTierResponse,
  TierChangeResponse,
  TierHistoryResponse,
  TierReportResponse,
  TierReportExportResponse,
} from './tier.ts';

// Alert Management API exports
export { routeAlertsApi } from './alerts.ts';
export {
  handleListAlerts,
  handleGetAlert,
  handleAcknowledgeAlert,
  handleResolveAlert,
  handleGetRules,
  handleUpdateRules,
  handleGetSettings,
  handleUpdateSettings,
} from './alerts.ts';

// Session token service singleton
export { setSessionTokenService, getSessionTokenService, resetSessionTokenService } from './session.ts';
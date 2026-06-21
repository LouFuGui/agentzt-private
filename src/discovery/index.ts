// Agent Discovery Module
// Export all discovery components for external use.

// Types
export type {
  AgentType,
  AgentRiskLevel,
  ProcessPattern,
  FileIndicator,
  NetworkIndicator,
  AgentSignature,
  ProcessEvent,
  NetworkConnection,
  FileOperation,
  DetectedAgent,
  EDRProviderConfig,
  DiscoveryConfig,
  DiscoveryResult,
} from './types.ts';

export { DEFAULT_DISCOVERY_CONFIG } from './types.ts';

// EDR Interface
export type { EDRQueryOptions, EDRQueryResult } from './edr-interface.ts';
export { BaseEDRProvider, createTimeRange, formatDuration, validateConfig } from './edr-interface.ts';
export type { EDRProvider } from './edr-interface.ts';

// EDR Providers
export { CrowdStrikeProvider, createCrowdStrikeProvider } from './crowdstrike.ts';
export { DefenderProvider, createDefenderProvider } from './defender.ts';
export { LocalFileProvider, createLocalFileProvider } from './local.ts';

// Discovery Engine
export { DiscoveryEngine, createDiscoveryEngine } from './engine.ts';

// CLI (for programmatic use)
export { createDiscoveryEngine as initEngine } from './engine.ts';
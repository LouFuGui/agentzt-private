// EDR Provider Interface
// Defines the common interface for EDR (Endpoint Detection and Response) integrations.

import type { ProcessEvent, EDRProviderConfig } from './types.ts';

/** EDR query options */
export type EDRQueryOptions = {
  /** Start time for the query (ISO 8601) */
  startTime: string;
  /** End time for the query (ISO 8601) */
  endTime: string;
  /** Maximum number of results to return */
  limit?: number;
  /** Filter by hostname */
  hostname?: string;
  /** Filter by process name */
  processName?: string;
  /** Filter by user */
  user?: string;
  /** Additional provider-specific filters */
  filters?: Record<string, unknown>;
};

/** EDR query result */
export type EDRQueryResult = {
  /** Provider that produced the result */
  provider: string;
  /** Whether the query was successful */
  success: boolean;
  /** Error message if failed */
  error?: string;
  /** Process events returned */
  events: ProcessEvent[];
  /** Total number of matching events (may be more than returned) */
  total: number;
  /** Query duration in milliseconds */
  durationMs: number;
  /** Timestamp when the query was executed */
  timestamp: string;
};

/** EDR provider interface */
export interface EDRProvider {
  /** Provider name */
  readonly name: string;

  /** Provider type */
  readonly type: 'crowdstrike' | 'defender' | 'local';

  /** Provider configuration */
  readonly config: EDRProviderConfig;

  /** Check if the provider is properly configured and authenticated */
  isConfigured(): Promise<boolean>;

  /** Test the connection to the EDR */
  testConnection(): Promise<{ success: boolean; error?: string }>;

  /** Query process execution events */
  queryProcesses(options: EDRQueryOptions): Promise<EDRQueryResult>;

  /** Query network connection events */
  queryNetworkConnections?(options: EDRQueryOptions): Promise<EDRQueryResult>;

  /** Query file operation events */
  queryFileOperations?(options: EDRQueryOptions): Promise<EDRQueryResult>;

  /** Get available hosts/endpoints */
  getEndpoints?(): Promise<Array<{ hostname: string; ip: string; lastSeen: string }>>;

  /** Dispose of any resources */
  dispose?(): Promise<void>;
}

/** Base class for EDR providers */
export abstract class BaseEDRProvider implements EDRProvider {
  abstract readonly name: string;
  abstract readonly type: 'crowdstrike' | 'defender' | 'local';
  abstract readonly config: EDRProviderConfig;

  abstract isConfigured(): Promise<boolean>;
  abstract testConnection(): Promise<{ success: boolean; error?: string }>;
  abstract queryProcesses(options: EDRQueryOptions): Promise<EDRQueryResult>;

  async queryNetworkConnections?(options: EDRQueryOptions): Promise<EDRQueryResult> {
    return {
      provider: this.name,
      success: false,
      error: 'Network connection queries not supported by this provider',
      events: [],
      total: 0,
      durationMs: 0,
      timestamp: new Date().toISOString(),
    };
  }

  async queryFileOperations?(options: EDRQueryOptions): Promise<EDRQueryResult> {
    return {
      provider: this.name,
      success: false,
      error: 'File operation queries not supported by this provider',
      events: [],
      total: 0,
      durationMs: 0,
      timestamp: new Date().toISOString(),
    };
  }

  async getEndpoints?(): Promise<Array<{ hostname: string; ip: string; lastSeen: string }>> {
    return [];
  }

  async dispose?(): Promise<void> {
    // No-op by default
  }
}

/** Create a time range for queries */
export function createTimeRange(hoursAgo: number): { startTime: string; endTime: string } {
  const endTime = new Date();
  const startTime = new Date(endTime.getTime() - hoursAgo * 60 * 60 * 1000);
  return {
    startTime: startTime.toISOString(),
    endTime: endTime.toISOString(),
  };
}

/** Format a duration in milliseconds to human readable */
export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(2)}s`;
  return `${(ms / 60000).toFixed(2)}m`;
}

/** Validate EDR provider configuration */
export function validateConfig(config: EDRProviderConfig): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!config.enabled) {
    errors.push('Provider is disabled');
  }

  if (config.type === 'crowdstrike') {
    if (!config.apiUrl) {
      errors.push('CrowdStrike API URL is required');
    }
    if (!config.clientIdEnv) {
      errors.push('CrowdStrike client ID environment variable is required');
    }
    if (!config.clientSecretEnv) {
      errors.push('CrowdStrike client secret environment variable is required');
    }
  } else if (config.type === 'defender') {
    if (!config.tenantId) {
      errors.push('Microsoft Defender tenant ID is required');
    }
    if (!config.clientIdEnv) {
      errors.push('Microsoft Defender client ID environment variable is required');
    }
    if (!config.clientSecretEnv) {
      errors.push('Microsoft Defender client secret environment variable is required');
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}
// Microsoft Defender for Endpoint EDR Integration
// Uses Advanced Hunting KQL API to query process execution events.

import type { ProcessEvent, EDRProviderConfig, NetworkConnection } from './types.ts';
import { BaseEDRProvider, type EDRQueryOptions, type EDRQueryResult, validateConfig } from './edr-interface.ts';

/** Microsoft Defender API configuration */
type DefenderConfig = EDRProviderConfig & {
  type: 'defender';
  tenantId: string;
  clientIdEnv: string;
  clientSecretEnv: string;
  apiUrl?: string;
};

/** Microsoft Entra ID OAuth token */
type EntraToken = {
  access_token: string;
  token_type: string;
  expires_in: number;
  expires_at?: number;
};

/** Microsoft Defender Advanced Hunting result */
type DefenderHuntingResult = {
  Schema: Array<{ Name: string; Type: string }>;
  Results: Array<Record<string, unknown>>;
};

/** Microsoft Defender for Endpoint provider implementation */
export class DefenderProvider extends BaseEDRProvider {
  readonly name = 'Microsoft Defender for Endpoint';
  readonly type = 'defender' as const;
  readonly config: DefenderConfig;

  private token: EntraToken | null = null;
  private tokenPromise: Promise<string> | null = null;

  constructor(config: DefenderConfig) {
    super();
    this.config = config;
  }

  async isConfigured(): Promise<boolean> {
    const validation = validateConfig(this.config);
    if (!validation.valid) {
      return false;
    }

    const clientId = process.env[this.config.clientIdEnv];
    const clientSecret = process.env[this.config.clientSecretEnv];

    return !!(clientId && clientSecret && this.config.tenantId);
  }

  async testConnection(): Promise<{ success: boolean; error?: string }> {
    try {
      const token = await this.getAccessToken();
      return { success: !!token };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  async queryProcesses(options: EDRQueryOptions): Promise<EDRQueryResult> {
    const startTime = Date.now();

    try {
      const token = await this.getAccessToken();

      // Build KQL query for process events
      const kqlQuery = this.buildKQLQuery(options);

      // Execute Advanced Hunting query
      const results = await this.executeHuntingQuery(token, kqlQuery);

      return {
        provider: this.name,
        success: true,
        events: results.map((r) => this.parseResult(r)),
        total: results.length,
        durationMs: Date.now() - startTime,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      return {
        provider: this.name,
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        events: [],
        total: 0,
        durationMs: Date.now() - startTime,
        timestamp: new Date().toISOString(),
      };
    }
  }

  async queryNetworkConnections(options: EDRQueryOptions): Promise<EDRQueryResult> {
    const startTime = Date.now();

    try {
      const token = await this.getAccessToken();

      // Build KQL query for network events
      const kqlQuery = this.buildNetworkKQLQuery(options);

      const results = await this.executeHuntingQuery(token, kqlQuery);

      return {
        provider: this.name,
        success: true,
        events: results.map((r) => this.parseNetworkResult(r)),
        total: results.length,
        durationMs: Date.now() - startTime,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      return {
        provider: this.name,
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        events: [],
        total: 0,
        durationMs: Date.now() - startTime,
        timestamp: new Date().toISOString(),
      };
    }
  }

  async getEndpoints(): Promise<Array<{ hostname: string; ip: string; lastSeen: string }>> {
    try {
      const token = await this.getAccessToken();
      const apiUrl = this.config.apiUrl || 'https://api.securitycenter.microsoft.com';

      const response = await fetch(`${apiUrl}/api/machines`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to get endpoints: ${response.statusText}`);
      }

      const data = await response.json() as { value?: Array<{
        computerDnsName?: string;
        lastIpAddress?: string;
        lastSeen?: string;
      }> };

      return (data.value || []).map((m) => ({
        hostname: m.computerDnsName || 'unknown',
        ip: m.lastIpAddress || 'unknown',
        lastSeen: m.lastSeen || new Date().toISOString(),
      }));
    } catch {
      return [];
    }
  }

  async dispose(): Promise<void> {
    this.token = null;
    this.tokenPromise = null;
  }

  /** Get OAuth access token from Microsoft Entra ID */
  private async getAccessToken(): Promise<string> {
    // Return cached token if still valid
    if (this.token && this.token.expires_at && Date.now() < this.token.expires_at) {
      return this.token.access_token;
    }

    // Deduplicate token requests
    if (this.tokenPromise) {
      return this.tokenPromise;
    }

    this.tokenPromise = this.fetchNewToken();
    try {
      return await this.tokenPromise;
    } finally {
      this.tokenPromise = null;
    }
  }

  /** Fetch a new OAuth token from Microsoft Entra ID */
  private async fetchNewToken(): Promise<string> {
    const clientId = process.env[this.config.clientIdEnv];
    const clientSecret = process.env[this.config.clientSecretEnv];

    if (!clientId || !clientSecret) {
      throw new Error('Microsoft Defender credentials not configured');
    }

    const tokenUrl = `https://login.microsoftonline.com/${this.config.tenantId}/oauth2/v2.0/token`;

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        scope: 'https://api.securitycenter.microsoft.com/.default',
        grant_type: 'client_credentials',
      }),
    });

    if (!response.ok) {
      throw new Error(`Failed to get Microsoft Entra token: ${response.statusText}`);
    }

    const data = await response.json() as EntraToken;
    this.token = {
      ...data,
      expires_at: Date.now() + (data.expires_in - 60) * 1000, // Refresh 1 minute early
    };

    return this.token.access_token;
  }

  /** Build KQL query for process events */
  private buildKQLQuery(options: EDRQueryOptions): string {
    const startTime = new Date(options.startTime).toISOString();
    const endTime = new Date(options.endTime).toISOString();
    const limit = options.limit || this.config.maxResults || 1000;

    let query = `DeviceProcessEvents
| where Timestamp between (datetime(${startTime}) .. datetime(${endTime}))`;

    if (options.hostname) {
      query += `\n| where DeviceName has "${options.hostname}"`;
    }
    if (options.processName) {
      query += `\n| where FileName has "${options.processName}"`;
    }
    if (options.user) {
      query += `\n| where AccountName has "${options.user}"`;
    }

    query += `\n| project Timestamp, DeviceName, ProcessId, InitiatingProcessId, FileName, FolderPath, ProcessCommandLine, AccountName, AccountDomain, SHA1, MD5, SHA256`;
    query += `\n| limit ${limit}`;

    return query;
  }

  /** Build KQL query for network connection events */
  private buildNetworkKQLQuery(options: EDRQueryOptions): string {
    const startTime = new Date(options.startTime).toISOString();
    const endTime = new Date(options.endTime).toISOString();
    const limit = options.limit || this.config.maxResults || 1000;

    let query = `DeviceNetworkEvents
| where Timestamp between (datetime(${startTime}) .. datetime(${endTime}))`;

    if (options.hostname) {
      query += `\n| where DeviceName has "${options.hostname}"`;
    }

    query += `\n| project Timestamp, DeviceName, ProcessId, InitiatingProcessId, RemoteIP, RemotePort, LocalIP, LocalPort, Protocol, RemoteUrl`;
    query += `\n| limit ${limit}`;

    return query;
  }

  /** Execute Advanced Hunting query */
  private async executeHuntingQuery(
    token: string,
    query: string
  ): Promise<Array<Record<string, unknown>>> {
    const apiUrl = this.config.apiUrl || 'https://api.securitycenter.microsoft.com';

    const response = await fetch(`${apiUrl}/api/advancedqueries/run`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ Query: query }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Advanced Hunting query failed: ${response.statusText} - ${errorText}`);
    }

    const data = await response.json() as DefenderHuntingResult;
    return data.Results || [];
  }

  /** Parse Defender result to common format */
  private parseResult(result: Record<string, unknown>): ProcessEvent {
    return {
      eventId: crypto.randomUUID(),
      timestamp: result.Timestamp as string || new Date().toISOString(),
      hostname: result.DeviceName as string || 'unknown',
      pid: result.ProcessId as number || 0,
      ppid: result.InitiatingProcessId as number | undefined,
      processName: result.FileName as string || 'unknown',
      commandLine: result.ProcessCommandLine as string | undefined,
      executablePath: result.FolderPath as string | undefined,
      user: result.AccountName as string | undefined,
      hash: result.SHA256 || result.SHA1 || result.MD5 ? {
        md5: result.MD5 as string | undefined,
        sha1: result.SHA1 as string | undefined,
        sha256: result.SHA256 as string | undefined,
      } : undefined,
    };
  }

  /** Parse network result to common format */
  private parseNetworkResult(result: Record<string, unknown>): ProcessEvent {
    const networkConnections: NetworkConnection[] = [{
      localIp: result.LocalIP as string || '0.0.0.0',
      localPort: result.LocalPort as number || 0,
      remoteIp: result.RemoteIP as string | undefined,
      remotePort: result.RemotePort as number | undefined,
      protocol: (result.Protocol as string)?.toUpperCase() === 'UDP' ? 'UDP' : 'TCP',
      domain: result.RemoteUrl as string | undefined,
    }];

    return {
      eventId: crypto.randomUUID(),
      timestamp: result.Timestamp as string || new Date().toISOString(),
      hostname: result.DeviceName as string || 'unknown',
      pid: result.ProcessId as number || 0,
      ppid: result.InitiatingProcessId as number | undefined,
      processName: 'unknown',
      networkConnections,
    };
  }
}

/** Create a Microsoft Defender provider from configuration */
export function createDefenderProvider(config: EDRProviderConfig): DefenderProvider {
  if (!config.tenantId) {
    throw new Error('Microsoft Defender tenant ID is required');
  }

  return new DefenderProvider({
    ...config,
    type: 'defender',
    tenantId: config.tenantId,
    clientIdEnv: config.clientIdEnv || 'AZURE_CLIENT_ID',
    clientSecretEnv: config.clientSecretEnv || 'AZURE_CLIENT_SECRET',
    apiUrl: config.apiUrl || 'https://api.securitycenter.microsoft.com',
  } as DefenderConfig);
}
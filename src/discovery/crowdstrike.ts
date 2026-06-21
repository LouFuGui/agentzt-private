// CrowdStrike Falcon EDR Integration
// Uses Humio (CrowdStrike LogScale) API to query process execution events.

import type { ProcessEvent, EDRProviderConfig, NetworkConnection } from './types.ts';
import { BaseEDRProvider, type EDRQueryOptions, type EDRQueryResult, validateConfig } from './edr-interface.ts';

/** CrowdStrike Falcon API configuration */
type CrowdStrikeConfig = EDRProviderConfig & {
  type: 'crowdstrike';
  apiUrl: string;
  clientIdEnv: string;
  clientSecretEnv: string;
};

/** CrowdStrike OAuth token response */
type CrowdStrikeToken = {
  access_token: string;
  token_type: string;
  expires_in: number;
  expires_at?: number;
};

/** CrowdStrike event from Humio query */
type CrowdStrikeEvent = {
  '@timestamp': string;
  '@id': string;
  event: {
    Category?: string;
    Subcategory?: string;
    Type?: number;
  };
  aid: string; // Agent ID
  ComputerName: string;
  ProcessId: number;
  ParentProcessId?: number;
  ImageFileName?: string;
  CommandLine?: string;
  UserSid?: string;
  UserName?: string;
  event_platform?: string;
  hashes?: {
    MD5?: string;
    SHA1?: string;
    SHA256?: string;
  };
  network_connections?: Array<{
    local_ip: string;
    local_port: number;
    remote_ip?: string;
    remote_port?: number;
    protocol: number;
    state?: string;
    domain?: string;
  }>;
};

/** CrowdStrike Falcon EDR provider implementation */
export class CrowdStrikeProvider extends BaseEDRProvider {
  readonly name = 'CrowdStrike Falcon';
  readonly type = 'crowdstrike' as const;
  readonly config: CrowdStrikeConfig;

  private token: CrowdStrikeToken | null = null;
  private tokenPromise: Promise<string> | null = null;

  constructor(config: CrowdStrikeConfig) {
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

    return !!(clientId && clientSecret);
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

      // Build Humio query for process events
      const query = this.buildProcessQuery(options);

      // Execute query against Humio API
      const events = await this.executeQuery(token, query, options);

      return {
        provider: this.name,
        success: true,
        events: events.map((e) => this.parseEvent(e)),
        total: events.length,
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
      const response = await fetch(`${this.config.apiUrl}/devices/queries/devices/v1`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(`Failed to get endpoints: ${response.statusText}`);
      }

      const data = await response.json() as { resources?: Array<{
        hostname?: string;
        local_ip?: string;
        last_seen?: string;
      }> };

      return (data.resources || []).map((d) => ({
        hostname: d.hostname || 'unknown',
        ip: d.local_ip || 'unknown',
        lastSeen: d.last_seen || new Date().toISOString(),
      }));
    } catch {
      return [];
    }
  }

  async dispose(): Promise<void> {
    this.token = null;
    this.tokenPromise = null;
  }

  /** Get OAuth access token */
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

  /** Fetch a new OAuth token */
  private async fetchNewToken(): Promise<string> {
    const clientId = process.env[this.config.clientIdEnv];
    const clientSecret = process.env[this.config.clientSecretEnv];

    if (!clientId || !clientSecret) {
      throw new Error('CrowdStrike credentials not configured');
    }

    const response = await fetch(`${this.config.apiUrl}/oauth2/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        grant_type: 'client_credentials',
      }),
    });

    if (!response.ok) {
      throw new Error(`Failed to get CrowdStrike token: ${response.statusText}`);
    }

    const data = await response.json() as CrowdStrikeToken;
    this.token = {
      ...data,
      expires_at: Date.now() + (data.expires_in - 60) * 1000, // Refresh 1 minute early
    };

    return this.token.access_token;
  }

  /** Build Humio query for process events */
  private buildProcessQuery(options: EDRQueryOptions): string {
    const conditions: string[] = [];

    // Time range
    conditions.push(`@timestamp >= "${options.startTime}"`);
    conditions.push(`@timestamp <= "${options.endTime}"`);

    // Event type: Process execution
    conditions.push('event.Category = "Process"');
    conditions.push('event.Type = 1'); // Process start

    // Optional filters
    if (options.hostname) {
      conditions.push(`ComputerName = "${options.hostname}"`);
    }
    if (options.processName) {
      conditions.push(`ImageFileName =~ /${options.processName}/`);
    }
    if (options.user) {
      conditions.push(`UserName =~ /${options.user}/`);
    }

    return conditions.join(' AND ');
  }

  /** Execute Humio query */
  private async executeQuery(
    token: string,
    query: string,
    options: EDRQueryOptions
  ): Promise<CrowdStrikeEvent[]> {
    const limit = options.limit || this.config.maxResults || 1000;

    const response = await fetch(`${this.config.apiUrl}/humio/api/v1/repositories/default/query`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        query,
        'start': options.startTime,
        'end': options.endTime,
        'isLive': false,
      }),
    });

    if (!response.ok) {
      throw new Error(`Humio query failed: ${response.statusText}`);
    }

    const data = await response.json() as { events?: CrowdStrikeEvent[] };
    return (data.events || []).slice(0, limit);
  }

  /** Parse CrowdStrike event to common format */
  private parseEvent(event: CrowdStrikeEvent): ProcessEvent {
    const networkConnections: NetworkConnection[] = (event.network_connections || []).map((nc) => ({
      localIp: nc.local_ip,
      localPort: nc.local_port,
      remoteIp: nc.remote_ip,
      remotePort: nc.remote_port,
      protocol: nc.protocol === 6 ? 'TCP' : 'UDP',
      state: nc.state,
      domain: nc.domain,
    }));

    return {
      eventId: event['@id'] || crypto.randomUUID(),
      timestamp: event['@timestamp'],
      hostname: event.ComputerName,
      pid: event.ProcessId,
      ppid: event.ParentProcessId,
      processName: event.ImageFileName?.split(/[/\\]/).pop() || 'unknown',
      commandLine: event.CommandLine,
      executablePath: event.ImageFileName,
      user: event.UserName,
      networkConnections: networkConnections.length > 0 ? networkConnections : undefined,
      hash: event.hashes ? {
        md5: event.hashes.MD5,
        sha1: event.hashes.SHA1,
        sha256: event.hashes.SHA256,
      } : undefined,
    };
  }
}

/** Create a CrowdStrike provider from configuration */
export function createCrowdStrikeProvider(config: EDRProviderConfig): CrowdStrikeProvider {
  return new CrowdStrikeProvider({
    ...config,
    type: 'crowdstrike',
    apiUrl: config.apiUrl || 'https://api.crowdstrike.com',
    clientIdEnv: config.clientIdEnv || 'CROWDSTRIKE_CLIENT_ID',
    clientSecretEnv: config.clientSecretEnv || 'CROWDSTRIKE_CLIENT_SECRET',
  } as CrowdStrikeConfig);
}
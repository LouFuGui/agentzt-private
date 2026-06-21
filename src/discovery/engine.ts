// Agent Discovery Engine
// Matches process events against signature library to detect AI agents.

import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { resolve, extname } from 'node:path';
import type {
  AgentSignature,
  AgentType,
  AgentRiskLevel,
  DetectedAgent,
  DiscoveryConfig,
  DiscoveryResult,
  ProcessEvent,
  FileIndicator,
  NetworkIndicator,
  NetworkConnection,
} from './types.ts';
import type { EDRProvider, EDRQueryOptions } from './edr-interface.ts';
import { createTimeRange } from './edr-interface.ts';
import { createCrowdStrikeProvider } from './crowdstrike.ts';
import { createDefenderProvider } from './defender.ts';
import { createLocalFileProvider } from './local.ts';

/** Signature library loaded from YAML files */
type SignatureLibrary = {
  signatures: AgentSignature[];
};

/** Match result for a process event */
type MatchResult = {
  signature: AgentSignature;
  confidence: number;
  matchedPatterns: string[];
};

/** Agent Discovery Engine */
export class DiscoveryEngine {
  private signatures: AgentSignature[] = [];
  private providers: EDRProvider[] = [];
  private config: DiscoveryConfig;

  constructor(config: DiscoveryConfig) {
    this.config = config;
    this.loadSignatures(config.signatureDirs);
    this.initializeProviders(config.providers);
  }

  /** Load signatures from YAML files */
  private loadSignatures(dirs: string[]): void {
    for (const dir of dirs) {
      const absoluteDir = resolve(dir);
      if (!existsSync(absoluteDir)) {
        console.warn(`Signature directory not found: ${absoluteDir}`);
        continue;
      }

      const files = readdirSync(absoluteDir);
      for (const file of files) {
        if (extname(file).toLowerCase() === '.yaml' || extname(file).toLowerCase() === '.yml') {
          const filePath = resolve(absoluteDir, file);
          this.loadSignatureFile(filePath);
        }
      }
    }

    console.log(`Loaded ${this.signatures.length} agent signatures`);
  }

  /** Load signatures from a YAML file */
  private loadSignatureFile(filePath: string): void {
    try {
      const content = readFileSync(filePath, 'utf8');
      const library = this.parseYaml(content) as SignatureLibrary;

      if (library.signatures && Array.isArray(library.signatures)) {
        this.signatures.push(...library.signatures);
      }
    } catch (error) {
      console.error(`Failed to load signature file ${filePath}:`, error);
    }
  }

  /** Simple YAML parser (handles basic structure) */
  private parseYaml(content: string): unknown {
    // Basic YAML parsing for our signature format
    // This is a simplified parser - in production, use a proper YAML library
    const result: Record<string, unknown> = {};
    const lines = content.split('\n');

    let currentKey = '';
    let currentArray: unknown[] | null = null;
    let currentObject: Record<string, unknown> | null = null;
    let indentLevel = 0;

    for (const line of lines) {
      const trimmed = line.trimEnd();
      if (!trimmed || trimmed.startsWith('#')) {
        continue;
      }

      // Calculate indentation
      const indent = line.length - line.trimStart().length;

      // Handle key-value pairs
      if (trimmed.includes(':')) {
        const parts = trimmed.split(':');
        const key = parts[0];
        const keyTrimmed = key ? key.trim() : '';
        const valueParts = parts.slice(1);
        const value = valueParts.join(':').trim();

        if (indent === 0) {
          // Top-level key
          currentKey = keyTrimmed;
          if (value === '' || value.startsWith('|')) {
            if (keyTrimmed === 'signatures') {
              result[keyTrimmed] = [];
              currentArray = result[keyTrimmed] as unknown[];
            } else {
              result[keyTrimmed] = {};
              currentObject = result[keyTrimmed] as Record<string, unknown>;
            }
          } else {
            result[keyTrimmed] = this.parseValue(value);
            currentObject = null;
            currentArray = null;
          }
          indentLevel = indent;
        } else if (currentArray !== null && indent > indentLevel) {
          // Inside signatures array
          if (keyTrimmed === 'id' && indent === 2) {
            // New signature object
            const sig: Record<string, unknown> = {};
            currentArray.push(sig);
            currentObject = sig;
            sig[keyTrimmed] = this.parseValue(value);
          } else if (currentObject) {
            // Property of current signature
            if (value === '' || value.startsWith('|')) {
              if (keyTrimmed === 'processes' || keyTrimmed === 'files' || keyTrimmed === 'network') {
                currentObject[keyTrimmed] = [];
              } else if (keyTrimmed === 'metadata' || keyTrimmed === 'envPatterns') {
                currentObject[keyTrimmed] = {};
              } else if (value.startsWith('|')) {
                // Multiline string
                currentObject[keyTrimmed] = '';
              }
            } else {
              currentObject[keyTrimmed] = this.parseValue(value);
            }
          }
        }
      } else if (trimmed.startsWith('-')) {
        // Array item
        const itemValue = trimmed.slice(1).trim();
        if (currentArray && currentObject) {
          // Check if this is a nested object in processes/files/network
          if (itemValue.startsWith('name:') || itemValue.startsWith('path:') || itemValue.startsWith('domains:')) {
            const itemParts = itemValue.split(':');
            const itemKey = itemParts[0];
            const itemVal = itemParts.slice(1).join(':').trim();
            const lastArray = this.findLastArray(currentObject);
            if (lastArray && itemKey) {
              const newItem: Record<string, unknown> = {};
              newItem[itemKey.trim()] = this.parseValue(itemVal);
              lastArray.push(newItem);
            }
          } else if (currentObject.processes && Array.isArray(currentObject.processes)) {
            const lastProcess = currentObject.processes[currentObject.processes.length - 1] as Record<string, unknown>;
            if (lastProcess && typeof lastProcess === 'object') {
              const procParts = itemValue.split(':');
              const procKey = procParts[0];
              const procVal = procParts.slice(1).join(':').trim();
              if (procKey) {
                lastProcess[procKey.trim()] = this.parseValue(procVal);
              }
            }
          }
        }
      }
    }

    return result;
  }

  /** Find the last array in an object */
  private findLastArray(obj: Record<string, unknown>): unknown[] | null {
    const keys = Object.keys(obj);
    for (let i = keys.length - 1; i >= 0; i--) {
      const key = keys[i];
      if (key) {
        const value = obj[key];
        if (Array.isArray(value) && value.length > 0) {
          return value;
        }
      }
    }
    return null;
  }

  /** Parse a YAML value */
  private parseValue(value: string): unknown {
    if (value === 'true') return true;
    if (value === 'false') return false;
    if (value === 'null') return null;

    // Number
    const num = parseFloat(value);
    if (!isNaN(num) && value === num.toString()) {
      return num;
    }

    // String (remove quotes)
    if (value.startsWith('"') && value.endsWith('"')) {
      return value.slice(1, -1);
    }
    if (value.startsWith("'") && value.endsWith("'")) {
      return value.slice(1, -1);
    }

    return value;
  }

  /** Initialize EDR providers */
  private initializeProviders(providerConfigs: DiscoveryConfig['providers']): void {
    for (const config of providerConfigs) {
      if (!config.enabled) {
        continue;
      }

      try {
        switch (config.type) {
          case 'crowdstrike':
            this.providers.push(createCrowdStrikeProvider(config));
            break;
          case 'defender':
            this.providers.push(createDefenderProvider(config));
            break;
          case 'local':
            this.providers.push(createLocalFileProvider(config));
            break;
        }
      } catch (error) {
        console.error(`Failed to initialize ${config.type} provider:`, error);
      }
    }

    console.log(`Initialized ${this.providers.length} EDR providers`);
  }

  /** Execute a discovery scan */
  async scan(): Promise<DiscoveryResult> {
    const scanId = crypto.randomUUID();
    const startTime = new Date().toISOString();
    const errors: Array<{ source: string; message: string; timestamp: string }> = [];

    // Collect process events from all providers
    const allEvents: ProcessEvent[] = [];
    const sources: string[] = [];

    const timeRange = createTimeRange(this.config.timeRangeHours);
    const queryOptions: EDRQueryOptions = {
      ...timeRange,
      limit: this.config.maxResults || 1000,
    };

    for (const provider of this.providers) {
      try {
        const configured = await provider.isConfigured();
        if (!configured) {
          console.warn(`Provider ${provider.name} is not properly configured`);
          continue;
        }

        const result = await provider.queryProcesses(queryOptions);

        if (result.success) {
          allEvents.push(...result.events);
          sources.push(provider.name);
        } else if (result.error) {
          errors.push({
            source: provider.name,
            message: result.error,
            timestamp: result.timestamp,
          });
        }
      } catch (error) {
        errors.push({
          source: provider.name,
          message: error instanceof Error ? error.message : 'Unknown error',
          timestamp: new Date().toISOString(),
        });
      }
    }

    // Match events against signatures
    const detectedAgents = this.matchEvents(allEvents);

    // Filter by confidence threshold
    const filteredAgents = detectedAgents.filter(
      (agent) => agent.confidence >= this.config.minConfidence
    );

    // Filter by risk level if configured
    if (!this.config.includeLowRisk) {
      filteredAgents.filter((agent) => agent.riskLevel !== 'low');
    }

    // Calculate statistics
    const endTime = new Date().toISOString();
    const byType: Record<AgentType, number> = {
      AUTONOMOUS: 0,
      ASSISTANT: 0,
      WORKFLOW: 0,
    };
    const byRiskLevel: Record<AgentRiskLevel, number> = {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
    };

    for (const agent of filteredAgents) {
      byType[agent.type]++;
      byRiskLevel[agent.riskLevel]++;
    }

    return {
      scanId,
      startTime,
      endTime,
      totalAgents: filteredAgents.length,
      byType,
      byRiskLevel,
      agents: filteredAgents,
      sources,
      errors,
    };
  }

  /** Match process events against signatures */
  private matchEvents(events: ProcessEvent[]): DetectedAgent[] {
    const detected: DetectedAgent[] = [];
    const agentMap = new Map<string, DetectedAgent>();

    for (const event of events) {
      const matches = this.findMatches(event);

      for (const match of matches) {
        const agentId = this.generateAgentId(event, match.signature);

        // Update or create detected agent
        if (agentMap.has(agentId)) {
          const existing = agentMap.get(agentId)!;
          // Update last activity if newer
          if (new Date(event.timestamp) > new Date(existing.lastActivity)) {
            existing.lastActivity = event.timestamp;
          }
          // Update confidence if higher
          if (match.confidence > existing.confidence) {
            existing.confidence = match.confidence;
          }
        } else {
          const agent: DetectedAgent = {
            agentId,
            type: match.signature.type,
            name: match.signature.name,
            endpoint: event.hostname,
            user: event.user,
            lastActivity: event.timestamp,
            riskLevel: match.signature.riskLevel,
            signature: match.signature,
            confidence: match.confidence,
            process: {
              pid: event.pid,
              name: event.processName,
              commandLine: event.commandLine,
              executablePath: event.executablePath,
            },
            networkEndpoints: this.extractNetworkEndpoints(event),
            source: 'crowdstrike', // Will be updated based on actual source
            firstSeen: event.timestamp,
          };
          agentMap.set(agentId, agent);
        }
      }
    }

    return Array.from(agentMap.values());
  }

  /** Find matching signatures for a process event */
  private findMatches(event: ProcessEvent): MatchResult[] {
    const matches: MatchResult[] = [];

    for (const signature of this.signatures) {
      const match = this.matchSignature(event, signature);
      if (match) {
        matches.push(match);
      }
    }

    // Sort by confidence (descending)
    matches.sort((a, b) => b.confidence - a.confidence);

    return matches;
  }

  /** Match a single signature against a process event */
  private matchSignature(event: ProcessEvent, signature: AgentSignature): MatchResult | null {
    const matchedPatterns: string[] = [];
    let totalConfidence = 0;
    let matchCount = 0;

    // Match process patterns
    for (const processPattern of signature.processes) {
      const processMatch = this.matchProcessPattern(event, processPattern);
      if (processMatch) {
        matchedPatterns.push(`process:${processPattern.name}`);
        totalConfidence += signature.confidence * 0.4; // Process match contributes 40%
        matchCount++;
      }
    }

    // Match file patterns (if files present)
    if (signature.files && event.executablePath) {
      for (const fileIndicator of signature.files) {
        if (this.matchFilePattern(event.executablePath, fileIndicator)) {
          matchedPatterns.push(`file:${fileIndicator.path}`);
          totalConfidence += signature.confidence * 0.2;
          matchCount++;
        }
      }
    }

    // Match network patterns (if network connections present)
    if (signature.network && event.networkConnections) {
      for (const conn of event.networkConnections) {
        for (const networkIndicator of signature.network) {
          if (this.matchNetworkPattern(conn, networkIndicator)) {
            matchedPatterns.push(`network:${conn.domain || conn.remoteIp}`);
            totalConfidence += signature.confidence * 0.3;
            matchCount++;
          }
        }
      }
    }

    // Require at least one process match
    if (matchCount === 0) {
      return null;
    }

    // Normalize confidence
    const confidence = Math.min(100, totalConfidence / matchCount);

    return {
      signature,
      confidence,
      matchedPatterns,
    };
  }

  /** Match process pattern against event */
  private matchProcessPattern(event: ProcessEvent, pattern: AgentSignature['processes'][0]): boolean {
    // Match process name (glob pattern)
    if (!this.globMatch(event.processName, pattern.name)) {
      return false;
    }

    // Match command line pattern (regex)
    if (pattern.cmdPattern && event.commandLine) {
      try {
        const regex = new RegExp(pattern.cmdPattern, 'i');
        if (!regex.test(event.commandLine)) {
          return false;
        }
      } catch {
        // Invalid regex pattern
        return false;
      }
    }

    // Match environment variables
    if (pattern.envPatterns && event.environment) {
      for (const [envKey, envPattern] of Object.entries(pattern.envPatterns)) {
        const envValue = event.environment[envKey];
        if (!envValue) {
          return false;
        }
        try {
          const regex = new RegExp(envPattern, 'i');
          if (!regex.test(envValue)) {
            return false;
          }
        } catch {
          return false;
        }
      }
    }

    return true;
  }

  /** Match file pattern against path */
  private matchFilePattern(path: string, indicator: FileIndicator): boolean {
    return this.globMatch(path, indicator.path);
  }

  /** Match network pattern against connection */
  private matchNetworkPattern(
    conn: NetworkConnection,
    indicator: NetworkIndicator
  ): boolean {
    // Match domains
    if (indicator.domains && conn.domain) {
      for (const domain of indicator.domains) {
        if (this.globMatch(conn.domain, domain)) {
          return true;
        }
      }
    }

    // Match ports
    if (indicator.ports && conn.remotePort) {
      if (indicator.ports.includes(conn.remotePort)) {
        return true;
      }
    }

    // Match URL patterns
    if (indicator.urlPatterns && conn.domain) {
      for (const pattern of indicator.urlPatterns) {
        try {
          const regex = new RegExp(pattern, 'i');
          if (regex.test(conn.domain)) {
            return true;
          }
        } catch {
          // Invalid regex
        }
      }
    }

    return false;
  }

  /** Glob pattern matching */
  private globMatch(text: string, pattern: string): boolean {
    // Convert glob pattern to regex
    const regexPattern = pattern
      .replace(/\*\*/g, '.*')
      .replace(/\*/g, '[^/\\\\]*')
      .replace(/\?/g, '[^/\\\\]')
      .replace(/\./g, '\\.');

    try {
      const regex = new RegExp(`^${regexPattern}$`, 'i');
      return regex.test(text);
    } catch {
      return false;
    }
  }

  /** Generate unique agent ID */
  private generateAgentId(event: ProcessEvent, signature: AgentSignature): string {
    // Create a stable ID based on endpoint, process, and signature
    const components = [
      event.hostname,
      signature.id,
      event.user || 'unknown',
    ];
    const hashInput = components.join(':');
    // Simple hash for ID generation
    const hash = this.simpleHash(hashInput);
    return `agent-${signature.id}-${hash}`;
  }

  /** Simple hash function for ID generation */
  private simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(16).slice(0, 8);
  }

  /** Extract network endpoints from event */
  private extractNetworkEndpoints(event: ProcessEvent): DetectedAgent['networkEndpoints'] {
    if (!event.networkConnections) {
      return undefined;
    }

    return event.networkConnections.map((conn) => ({
      domain: conn.domain,
      ip: conn.remoteIp,
      port: conn.remotePort,
    }));
  }

  /** Get loaded signatures */
  getSignatures(): AgentSignature[] {
    return this.signatures;
  }

  /** Get initialized providers */
  getProviders(): EDRProvider[] {
    return this.providers;
  }

  /** Add a custom signature */
  addSignature(signature: AgentSignature): void {
    this.signatures.push(signature);
  }

  /** Add a custom provider */
  addProvider(provider: EDRProvider): void {
    this.providers.push(provider);
  }

  /** Dispose of all providers */
  async dispose(): Promise<void> {
    for (const provider of this.providers) {
      if (provider.dispose) {
        await provider.dispose();
      }
    }
  }
}

/** Create a discovery engine with default configuration */
export function createDiscoveryEngine(config?: Partial<DiscoveryConfig>): DiscoveryEngine {
  const fullConfig: DiscoveryConfig = {
    providers: config?.providers || [],
    signatureDirs: config?.signatureDirs || ['./signatures'],
    timeRangeHours: config?.timeRangeHours || 24,
    minConfidence: config?.minConfidence || 50,
    includeLowRisk: config?.includeLowRisk ?? true,
    outputFormat: config?.outputFormat || 'table',
    dashboardPort: config?.dashboardPort || 3456,
  };

  return new DiscoveryEngine(fullConfig);
}
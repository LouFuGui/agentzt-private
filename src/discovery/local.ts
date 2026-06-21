// Local File Import Integration
// Imports and parses process events from local log files.

import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { resolve, extname } from 'node:path';
import type { ProcessEvent, EDRProviderConfig, NetworkConnection } from './types.ts';
import { BaseEDRProvider, type EDRQueryOptions, type EDRQueryResult } from './edr-interface.ts';

/** Local file import configuration */
type LocalConfig = EDRProviderConfig & {
  type: 'local';
  logDir?: string;
  filePattern?: string;
};

/** Supported log formats */
type LogFormat = 'jsonl' | 'csv' | 'syslog' | 'evtx';

/** Parsed log entry */
type LogEntry = Record<string, unknown>;

/** Local file import provider implementation */
export class LocalFileProvider extends BaseEDRProvider {
  readonly name = 'Local File Import';
  readonly type = 'local' as const;
  readonly config: LocalConfig;

  constructor(config: LocalConfig) {
    super();
    this.config = config;
  }

  async isConfigured(): Promise<boolean> {
    const logDir = this.config.logDir || process.env.AGENT_DISCOVERY_LOG_DIR;
    if (!logDir) {
      return false;
    }
    return existsSync(logDir);
  }

  async testConnection(): Promise<{ success: boolean; error?: string }> {
    const logDir = this.config.logDir || process.env.AGENT_DISCOVERY_LOG_DIR;
    if (!logDir) {
      return { success: false, error: 'Log directory not configured' };
    }

    if (!existsSync(logDir)) {
      return { success: false, error: `Log directory does not exist: ${logDir}` };
    }

    try {
      const files = readdirSync(logDir);
      return { success: files.length > 0 || true }; // Success even if empty
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  async queryProcesses(options: EDRQueryOptions): Promise<EDRQueryResult> {
    const startTime = Date.now();
    const logDir = this.config.logDir || process.env.AGENT_DISCOVERY_LOG_DIR || './logs';

    try {
      if (!existsSync(logDir)) {
        throw new Error(`Log directory does not exist: ${logDir}`);
      }

      // Find and read log files
      const files = this.findLogFiles(logDir);
      const events: ProcessEvent[] = [];

      for (const file of files) {
        const fileEvents = this.parseLogFile(file, options);
        events.push(...fileEvents);
      }

      // Apply time range filter
      const filteredEvents = this.filterByTimeRange(events, options);

      // Apply limit
      const limitedEvents = filteredEvents.slice(0, options.limit || this.config.maxResults || 1000);

      return {
        provider: this.name,
        success: true,
        events: limitedEvents,
        total: filteredEvents.length,
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
    // For local files, we can extract unique hostnames from the logs
    const result = await this.queryProcesses({
      startTime: new Date(0).toISOString(),
      endTime: new Date().toISOString(),
      limit: 10000,
    });

    const hostnames = new Map<string, { ip: string; lastSeen: string }>();

    for (const event of result.events) {
      if (!hostnames.has(event.hostname)) {
        hostnames.set(event.hostname, {
          ip: event.networkConnections?.[0]?.localIp || 'unknown',
          lastSeen: event.timestamp,
        });
      } else {
        const existing = hostnames.get(event.hostname)!;
        if (new Date(event.timestamp) > new Date(existing.lastSeen)) {
          existing.lastSeen = event.timestamp;
        }
      }
    }

    return Array.from(hostnames.entries()).map(([hostname, data]) => ({
      hostname,
      ip: data.ip,
      lastSeen: data.lastSeen,
    }));
  }

  /** Find log files in directory */
  private findLogFiles(dir: string): string[] {
    const files: string[] = [];
    const pattern = this.config.filePattern || '*.log';

    const entries = readdirSync(dir);
    for (const entry of entries) {
      const fullPath = resolve(dir, entry);
      const stat = statSync(fullPath);

      if (stat.isDirectory()) {
        // Recursively search subdirectories
        files.push(...this.findLogFiles(fullPath));
      } else if (this.matchesPattern(entry, pattern)) {
        files.push(fullPath);
      }
    }

    return files;
  }

  /** Check if filename matches pattern */
  private matchesPattern(filename: string, pattern: string): boolean {
    const ext = extname(filename).toLowerCase();
    const supportedExtensions = ['.json', '.jsonl', '.csv', '.log', '.evtx'];

    if (!supportedExtensions.includes(ext)) {
      return false;
    }

    // Simple glob matching
    const regex = new RegExp(
      '^' + pattern.replace(/\*/g, '.*').replace(/\?/g, '.') + '$'
    );
    return regex.test(filename);
  }

  /** Detect log format from file extension and content */
  private detectFormat(filePath: string): LogFormat {
    const ext = extname(filePath).toLowerCase();

    if (ext === '.json' || ext === '.jsonl') {
      return 'jsonl';
    }
    if (ext === '.csv') {
      return 'csv';
    }
    if (ext === '.evtx') {
      return 'evtx';
    }

    // Try to detect from content
    try {
      const content = readFileSync(filePath, 'utf8');
      const lines = content.split('\n');
      const firstLine = lines[0]?.trim() ?? '';

      if (firstLine.startsWith('{') || firstLine.startsWith('[')) {
        return 'jsonl';
      }
      if (firstLine.includes(',') && !firstLine.includes(':')) {
        return 'csv';
      }
    } catch {
      // Ignore read errors
    }

    return 'syslog';
  }

  /** Parse a log file and extract process events */
  private parseLogFile(filePath: string, options: EDRQueryOptions): ProcessEvent[] {
    const format = this.detectFormat(filePath);

    try {
      const content = readFileSync(filePath, 'utf8');

      switch (format) {
        case 'jsonl':
          return this.parseJsonl(content, options);
        case 'csv':
          return this.parseCsv(content, options);
        case 'syslog':
          return this.parseSyslog(content, options);
        case 'evtx':
          // EVTX requires special handling on Windows
          return this.parseEvtx(filePath, options);
        default:
          return [];
      }
    } catch (error) {
      console.error(`Failed to parse log file ${filePath}:`, error);
      return [];
    }
  }

  /** Parse JSON Lines format */
  private parseJsonl(content: string, options: EDRQueryOptions): ProcessEvent[] {
    const events: ProcessEvent[] = [];
    const lines = content.split('\n').filter((line) => line.trim());

    for (const line of lines) {
      try {
        const entry = JSON.parse(line) as LogEntry;
        const event = this.parseJsonEntry(entry);
        if (event && this.matchesFilters(event, options)) {
          events.push(event);
        }
      } catch {
        // Skip invalid JSON lines
      }
    }

    return events;
  }

  /** Parse JSON entry to ProcessEvent */
  private parseJsonEntry(entry: LogEntry): ProcessEvent | null {
    // Try common field names
    const timestamp = this.extractTimestamp(entry);
    const hostname = this.extractString(entry, ['hostname', 'host', 'computer_name', 'ComputerName', 'device_name']);
    const processName = this.extractString(entry, ['process_name', 'process', 'name', 'ImageFileName', 'FileName']);
    const pid = this.extractNumber(entry, ['pid', 'process_id', 'ProcessId']);
    const ppid = this.extractNumber(entry, ['ppid', 'parent_process_id', 'InitiatingProcessId']);
    const commandLine = this.extractString(entry, ['command_line', 'cmdline', 'CommandLine', 'ProcessCommandLine']);
    const executablePath = this.extractString(entry, ['executable_path', 'path', 'FolderPath', 'exe']);
    const user = this.extractString(entry, ['user', 'username', 'UserName', 'AccountName']);

    if (!timestamp || !hostname) {
      return null;
    }

    // Extract network connections if present
    const networkConnections = this.extractNetworkConnections(entry);

    return {
      eventId: (entry.event_id || entry['@id'] || entry.id || crypto.randomUUID()) as string,
      timestamp,
      hostname,
      pid: pid ?? 0,
      ppid,
      processName: processName || 'unknown',
      commandLine,
      executablePath,
      user,
      networkConnections: networkConnections.length > 0 ? networkConnections : undefined,
      hash: this.extractHash(entry),
    };
  }

  /** Parse CSV format */
  private parseCsv(content: string, options: EDRQueryOptions): ProcessEvent[] {
    const events: ProcessEvent[] = [];
    const lines = content.split('\n').filter((line) => line.trim());

    if (lines.length < 2) {
      return events;
    }

    // Parse header
    const firstLine = lines[0] ?? '';
    const headers = this.parseCsvLine(firstLine);
    const fieldMap = this.buildFieldMap(headers);

    // Parse rows
    for (let i = 1; i < lines.length; i++) {
      const values = this.parseCsvLine(lines[i] ?? '');
      const entry: LogEntry = {};

      for (let j = 0; j < headers.length && j < values.length; j++) {
        const header = headers[j];
        if (header) {
          entry[header] = values[j] ?? '';
        }
      }

      const event = this.parseJsonEntry(entry);
      if (event && this.matchesFilters(event, options)) {
        events.push(event);
      }
    }

    return events;
  }

  /** Parse CSV line handling quotes */
  private parseCsvLine(line: string): string[] {
    const result: string[] = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < line.length; i++) {
      const char = line[i];

      if (char === '"') {
        inQuotes = !inQuotes;
      } else if (char === ',' && !inQuotes) {
        result.push(current.trim());
        current = '';
      } else {
        current += char;
      }
    }

    result.push(current.trim());
    return result;
  }

  /** Build field map for CSV parsing */
  private buildFieldMap(headers: string[]): Record<string, number> {
    const map: Record<string, number> = {};
    for (let i = 0; i < headers.length; i++) {
      const header = headers[i];
      if (header) {
        map[header.toLowerCase()] = i;
      }
    }
    return map;
  }

  /** Parse syslog format */
  private parseSyslog(content: string, options: EDRQueryOptions): ProcessEvent[] {
    const events: ProcessEvent[] = [];
    const lines = content.split('\n').filter((line) => line.trim());

    for (const line of lines) {
      const event = this.parseSyslogLine(line);
      if (event && this.matchesFilters(event, options)) {
        events.push(event);
      }
    }

    return events;
  }

  /** Parse a single syslog line */
  private parseSyslogLine(line: string): ProcessEvent | null {
    // Common syslog format: Mon DD HH:MM:SS hostname process[pid]: message
    const syslogRegex = /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$/;
    const match = line.match(syslogRegex);

    if (!match) {
      return null;
    }

    const [, , hostname, processName, pidStr] = match;
    const pid = pidStr ? parseInt(pidStr, 10) : 0;

    return {
      eventId: crypto.randomUUID(),
      timestamp: new Date().toISOString(), // Syslog timestamp needs year inference
      hostname: hostname || 'unknown',
      pid,
      processName: processName || 'unknown',
      commandLine: line,
    };
  }

  /** Parse Windows EVTX format (requires Windows-specific handling) */
  private parseEvtx(filePath: string, options: EDRQueryOptions): ProcessEvent[] {
    // EVTX parsing requires native Windows APIs or external tools
    // This is a placeholder - in production, use a library like evtx
    console.warn(`EVTX parsing not implemented for ${filePath}. Use a tool to convert to JSON/CSV first.`);
    return [];
  }

  /** Filter events by time range */
  private filterByTimeRange(events: ProcessEvent[], options: EDRQueryOptions): ProcessEvent[] {
    const startTime = new Date(options.startTime).getTime();
    const endTime = new Date(options.endTime).getTime();

    return events.filter((event) => {
      const eventTime = new Date(event.timestamp).getTime();
      return eventTime >= startTime && eventTime <= endTime;
    });
  }

  /** Check if event matches query filters */
  private matchesFilters(event: ProcessEvent, options: EDRQueryOptions): boolean {
    if (options.hostname && !event.hostname.toLowerCase().includes(options.hostname.toLowerCase())) {
      return false;
    }
    if (options.processName && !event.processName.toLowerCase().includes(options.processName.toLowerCase())) {
      return false;
    }
    if (options.user && event.user && !event.user.toLowerCase().includes(options.user.toLowerCase())) {
      return false;
    }
    return true;
  }

  /** Extract timestamp from entry */
  private extractTimestamp(entry: LogEntry): string | null {
    const fields = ['timestamp', '@timestamp', 'time', 'datetime', 'Timestamp', 'date', 'created_at'];
    for (const field of fields) {
      const value = entry[field];
      if (typeof value === 'string' || typeof value === 'number') {
        const date = new Date(value);
        if (!isNaN(date.getTime())) {
          return date.toISOString();
        }
      }
    }
    return null;
  }

  /** Extract string from entry */
  private extractString(entry: LogEntry, fields: string[]): string | undefined {
    for (const field of fields) {
      const value = entry[field];
      if (typeof value === 'string') {
        return value;
      }
    }
    return undefined;
  }

  /** Extract number from entry */
  private extractNumber(entry: LogEntry, fields: string[]): number | undefined {
    for (const field of fields) {
      const value = entry[field];
      if (typeof value === 'number') {
        return value;
      }
      if (typeof value === 'string') {
        const num = parseInt(value, 10);
        if (!isNaN(num)) {
          return num;
        }
      }
    }
    return undefined;
  }

  /** Extract network connections from entry */
  private extractNetworkConnections(entry: LogEntry): NetworkConnection[] {
    const connections: NetworkConnection[] = [];
    const ncFields = ['network_connections', 'networkConnections', 'connections', 'NetworkEvents'];

    for (const field of ncFields) {
      const value = entry[field];
      if (Array.isArray(value)) {
        for (const conn of value) {
          if (typeof conn === 'object' && conn !== null) {
            connections.push({
              localIp: (conn as LogEntry).local_ip as string || (conn as LogEntry).LocalIP as string || '0.0.0.0',
              localPort: (conn as LogEntry).local_port as number || (conn as LogEntry).LocalPort as number || 0,
              remoteIp: (conn as LogEntry).remote_ip as string | undefined || (conn as LogEntry).RemoteIP as string | undefined,
              remotePort: (conn as LogEntry).remote_port as number | undefined || (conn as LogEntry).RemotePort as number | undefined,
              protocol: ((conn as LogEntry).protocol as string || (conn as LogEntry).Protocol as string)?.toUpperCase() === 'UDP' ? 'UDP' : 'TCP',
              domain: (conn as LogEntry).domain as string | undefined || (conn as LogEntry).RemoteUrl as string | undefined,
            });
          }
        }
      }
    }

    return connections;
  }

  /** Extract hash from entry */
  private extractHash(entry: LogEntry): { md5?: string; sha1?: string; sha256?: string } | undefined {
    const hashFields = ['hash', 'hashes', 'Hash'];
    for (const field of hashFields) {
      const value = entry[field];
      if (typeof value === 'object' && value !== null) {
        return {
          md5: (value as LogEntry).md5 as string | undefined || (value as LogEntry).MD5 as string | undefined,
          sha1: (value as LogEntry).sha1 as string | undefined || (value as LogEntry).SHA1 as string | undefined,
          sha256: (value as LogEntry).sha256 as string | undefined || (value as LogEntry).SHA256 as string | undefined,
        };
      }
    }
    return undefined;
  }
}

/** Create a local file provider from configuration */
export function createLocalFileProvider(config: EDRProviderConfig): LocalFileProvider {
  return new LocalFileProvider({
    ...config,
    type: 'local',
    logDir: config.logDir || process.env.AGENT_DISCOVERY_LOG_DIR,
  } as LocalConfig);
}
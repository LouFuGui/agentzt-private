// Agent Discovery Module Types
// Defines the taxonomy for classifying AI agents and their detection signatures.

/** Agent type classification */
export type AgentType = 'AUTONOMOUS' | 'ASSISTANT' | 'WORKFLOW';

/** Risk level for detected agents */
export type AgentRiskLevel = 'low' | 'medium' | 'high' | 'critical';

/** Process pattern for signature matching */
export type ProcessPattern = {
  /** Process name or pattern (supports glob patterns) */
  name: string;
  /** Command line arguments pattern (regex supported) */
  cmdPattern?: string;
  /** Environment variable patterns */
  envPatterns?: Record<string, string>;
};

/** File system indicator for agent detection */
export type FileIndicator = {
  /** File path pattern */
  path: string;
  /** File content pattern (regex) */
  contentPattern?: string;
  /** Check if file exists */
  exists?: boolean;
};

/** Network indicator for agent detection */
export type NetworkIndicator = {
  /** Domain patterns to match */
  domains?: string[];
  /** Port patterns */
  ports?: number[];
  /** URL patterns (regex) */
  urlPatterns?: string[];
  /** API endpoint patterns */
  apiEndpoints?: string[];
};

/** Agent detection signature */
export type AgentSignature = {
  /** Unique signature ID */
  id: string;
  /** Agent name */
  name: string;
  /** Agent type classification */
  type: AgentType;
  /** Human-readable description */
  description: string;
  /** Vendor or project URL */
  vendor?: string;
  /** Detection version */
  version: string;
  /** Process patterns to match */
  processes: ProcessPattern[];
  /** File system indicators */
  files?: FileIndicator[];
  /** Network indicators */
  network?: NetworkIndicator[];
  /** Additional metadata */
  metadata?: Record<string, unknown>;
  /** Risk level if detected */
  riskLevel: AgentRiskLevel;
  /** Detection confidence weight */
  confidence: number;
};

/** Process event from EDR */
export type ProcessEvent = {
  /** Unique event ID */
  eventId: string;
  /** Timestamp (ISO 8601) */
  timestamp: string;
  /** Hostname where event occurred */
  hostname: string;
  /** Process ID */
  pid: number;
  /** Parent process ID */
  ppid?: number;
  /** Process name */
  processName: string;
  /** Full command line */
  commandLine?: string;
  /** Executable path */
  executablePath?: string;
  /** User who started the process */
  user?: string;
  /** Environment variables */
  environment?: Record<string, string>;
  /** Network connections */
  networkConnections?: NetworkConnection[];
  /** File operations */
  fileOperations?: FileOperation[];
  /** Hash of the executable */
  hash?: {
    md5?: string;
    sha1?: string;
    sha256?: string;
  };
};

/** Network connection information */
export type NetworkConnection = {
  /** Local IP address */
  localIp: string;
  /** Local port */
  localPort: number;
  /** Remote IP address */
  remoteIp?: string;
  /** Remote port */
  remotePort?: number;
  /** Protocol (TCP/UDP) */
  protocol: 'TCP' | 'UDP';
  /** Connection state */
  state?: string;
  /** Domain name (if DNS resolved) */
  domain?: string;
};

/** File operation event */
export type FileOperation = {
  /** Operation type */
  operation: 'read' | 'write' | 'create' | 'delete' | 'execute';
  /** File path */
  path: string;
  /** Timestamp */
  timestamp: string;
};

/** Detected agent information */
export type DetectedAgent = {
  /** Unique agent identifier */
  agentId: string;
  /** Agent type classification */
  type: AgentType;
  /** Agent name (from signature match) */
  name: string;
  /** Detected endpoint/hostname */
  endpoint: string;
  /** User running the agent */
  user?: string;
  /** Last activity timestamp */
  lastActivity: string;
  /** Risk level assessment */
  riskLevel: AgentRiskLevel;
  /** Matched signature */
  signature: AgentSignature;
  /** Detection confidence score (0-100) */
  confidence: number;
  /** Process information */
  process?: {
    pid: number;
    name: string;
    commandLine?: string;
    executablePath?: string;
  };
  /** Network endpoints used */
  networkEndpoints?: Array<{
    domain?: string;
    ip?: string;
    port?: number;
  }>;
  /** Detection source */
  source: 'crowdstrike' | 'defender' | 'local' | 'manual';
  /** First detection timestamp */
  firstSeen: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
};

/** EDR provider configuration */
export type EDRProviderConfig = {
  /** Provider type */
  type: 'crowdstrike' | 'defender' | 'local';
  /** Whether the provider is enabled */
  enabled: boolean;
  /** API endpoint URL */
  apiUrl?: string;
  /** API key or token (from environment) */
  apiKeyEnv?: string;
  /** Client ID (for OAuth) */
  clientIdEnv?: string;
  /** Client secret (for OAuth) */
  clientSecretEnv?: string;
  /** Tenant ID (for cloud providers) */
  tenantId?: string;
  /** Query timeout in milliseconds */
  timeoutMs?: number;
  /** Maximum results per query */
  maxResults?: number;
  /** Log directory for local file provider */
  logDir?: string;
  /** File pattern for local file provider */
  filePattern?: string;
  /** Additional provider-specific settings */
  settings?: Record<string, unknown>;
};

/** Discovery scan configuration */
export type DiscoveryConfig = {
  /** EDR providers configuration */
  providers: EDRProviderConfig[];
  /** Signature directories to load */
  signatureDirs: string[];
  /** Time range for queries (in hours) */
  timeRangeHours: number;
  /** Minimum confidence threshold for reporting */
  minConfidence: number;
  /** Whether to include low-risk agents */
  includeLowRisk: boolean;
  /** Output format */
  outputFormat: 'json' | 'csv' | 'table';
  /** Dashboard server port */
  dashboardPort?: number;
  /** Maximum results per query */
  maxResults?: number;
};

/** Discovery scan result */
export type DiscoveryResult = {
  /** Scan ID */
  scanId: string;
  /** Scan start time */
  startTime: string;
  /** Scan end time */
  endTime: string;
  /** Total agents detected */
  totalAgents: number;
  /** Agents by type */
  byType: Record<AgentType, number>;
  /** Agents by risk level */
  byRiskLevel: Record<AgentRiskLevel, number>;
  /** Detected agents */
  agents: DetectedAgent[];
  /** Data sources used */
  sources: string[];
  /** Errors encountered */
  errors: Array<{
    source: string;
    message: string;
    timestamp: string;
  }>;
};

/** Default discovery configuration */
export const DEFAULT_DISCOVERY_CONFIG: DiscoveryConfig = {
  providers: [],
  signatureDirs: ['./signatures'],
  timeRangeHours: 24,
  minConfidence: 50,
  includeLowRisk: true,
  outputFormat: 'table',
  dashboardPort: 3456,
};
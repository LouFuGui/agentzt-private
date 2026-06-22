// Core types shared between agentzt-client and agentzt-gateway.

export type Tier = 'foundation' | 'enterprise' | 'advanced';

/** Public registry entry: binds a cryptographic identity to an agent and role. */
export type AgentRegistryEntry = {
  agentId: string;
  role: string;
  publicKeyJwk: JsonWebKey;
  description?: string;
  disabled?: boolean;
  createdAt?: string;
};

export type AgentRegistry = {
  agents: AgentRegistryEntry[];
};

/** Private identity material kept on the agent host (never sent to the gateway). */
export type AgentIdentityFile = {
  agentId: string;
  role: string;
  publicKeyJwk: JsonWebKey;
  privateKeyJwk: JsonWebKey;
  createdAt: string;
};

export type RoleLimits = {
  maxOutputTokens?: number;
  requestsPerMinute?: number;
};

export type RiskLevel = 'no_risk' | 'low_risk' | 'medium_risk' | 'high_risk' | 'unknown';

/** Attribute-based access control: context conditions layered on top of RBAC. */
export type AbacPolicy = {
  // Operating hours in UTC as [start, end) on a 0-24 clock. Calls outside the
  // window are denied ("restrict an agent to operating hours").
  allowedHoursUTC?: { start: number; end: number };
  // Risk-adaptive: deny when the request's guardrail risk level reaches/exceeds this.
  denyAboveRiskLevel?: 'low_risk' | 'medium_risk' | 'high_risk';
};

/** Just-in-time elevation: resources a role may temporarily acquire on demand. */
export type JitPolicy = {
  elevatableModels?: string[];
  elevatableTools?: string[];
  maxTtlSeconds: number;
};

export type RolePolicy = {
  description?: string;
  models: string[];
  tools: string[];
  limits?: RoleLimits;
  abac?: AbacPolicy;
  jit?: JitPolicy;
};

export type PolicyDoc = {
  version: number;
  defaultDeny: boolean;
  roles: Record<string, RolePolicy>;
};

export type OpenGuardrailsConfig = {
  baseUrl: string;
  apiKeyEnv: string;
  model: string;
  timeoutMs: number;
  // On detector error/timeout: false = fail closed (treat as blocked), true = fail open (allow + audit).
  failOpen: boolean;
};

export type GuardrailConfig = {
  // auto: use OpenGuardrails when its API key env is set, else the local detector.
  provider: 'auto' | 'local' | 'openguardrails';
  input: {
    // block: reject flagged prompts; flag: allow but audit; off: disabled.
    mode: 'block' | 'flag' | 'off';
  };
  output: {
    redactSecrets: boolean;
    // When true and the provider supports it, run a context-aware output check.
    check: boolean;
  };
  openguardrails: OpenGuardrailsConfig;
};

export type GuardrailVerdict = {
  provider: string;
  flagged: boolean;
  action: 'pass' | 'reject' | 'replace';
  riskLevel: string;
  categories: string[];
  suggestAnswer?: string;
  patterns?: string[];
  error?: string;
};

export type GatewayTlsConfig = {
  // When enabled, the gateway serves HTTPS and requires mutual TLS: clients must
  // present a certificate signed by the agentzt CA (requestCert + rejectUnauthorized).
  enabled: boolean;
  keyFile: string;
  certFile: string;
  caFile: string;
  // Channel binding: require the client cert CN to equal the token subject, so a
  // stolen token cannot be replayed over a different TLS channel.
  channelBinding: boolean;
};

export type OpaConfig = {
  enabled: boolean;
  baseUrl: string;
  policyPath: string;
  timeoutMs: number;
  // On OPA error/timeout: false = fail closed, true = keep the local policy decision.
  failOpen: boolean;
};

export type SignozConfig = {
  enabled: boolean;
  endpoint?: string;
  serviceName?: string;
  ingestionKeyEnv?: string;
  headers?: Record<string, string>;
  timeoutMs?: number;
  exportIntervalMs?: number;
};

export type GatewayConfig = {
  port: number;
  issuer: string;
  tokenTtlSeconds: number;
  assertionMaxAgeSeconds: number;
  upstream: {
    mode: 'mock' | 'passthrough';
    anthropicBaseUrl: string;
    apiKeyEnv: string;
  };
  guardrails?: GuardrailConfig;
  opa?: OpaConfig;
  signoz?: SignozConfig;
  tls?: GatewayTlsConfig;
  sandbox?: {
    enabled: boolean;
    baseUrl: string;
    autoStart: boolean;
  };
};

/** Short-lived access token issued by the gateway (signed EdDSA, gateway key). */
export type AccessTokenClaims = {
  iss: string;
  sub: string; // agentId
  role: string;
  scope: { models: string[]; tools: string[] };
  iat: number;
  exp: number;
  jti: string;
};

/** JIT elevation grant (signed EdDSA, gateway key): a single-resource, short-lived capability. */
export type ElevationGrantClaims = {
  iss: string;
  sub: string; // agentId
  role: string;
  resource: { kind: 'model' | 'tool'; name: string };
  reason: string;
  iat: number;
  exp: number;
  jti: string;
};

/** Client assertion (signed EdDSA, agent key) presented to obtain an access token. */
export type ClientAssertionClaims = {
  iss: string; // agentId
  sub: string; // agentId
  aud: string; // gateway token endpoint
  iat: number;
  exp: number;
  jti: string;
};

export type Decision = {
  allow: boolean;
  reason: string;
};

export type AuditAction =
  | 'token.issue'
  | 'token.reject'
  | 'model.call'
  | 'tool.call'
  | 'guardrail.block'
  | 'elevation.grant'
  | 'elevation.reject'
  | 'proxy.call'
  | 'guardrails.check'
  | 'direct.call'
  | 'quota.exceeded';

export type AuditEvent = {
  ts: string;
  requestId: string;
  agentId: string | null;
  role: string | null;
  action: AuditAction;
  resource: string; // model id or tool name
  decision: 'allow' | 'deny';
  reason: string;
  latencyMs?: number;
  meta?: Record<string, unknown>;
  // Application context (for multi-app management)
  appId?: string | null;
  userId?: string | null;
  categories?: string[];
  score?: number;
  // Tamper-evident chain (set by AuditLogger): monotonically increasing seq and
  // a hash linking each event to the previous one.
  seq?: number;
  hash?: string;
};

// ============================================================================
// Multi-App Management Types
// ============================================================================

/** Risk type configuration: enable/disable different risk detection types */
export type RiskTypeConfig = {
  security: boolean;
  compliance: boolean;
  dataSecurity: boolean;
};

/** Risk categories configuration: S1-S19 enable/disable flags */
export type RiskCategoriesConfig = {
  S1: boolean;  // Prompt Injection
  S2: boolean;  // Jailbreak
  S3: boolean;  // Toxic Content
  S4: boolean;  // Bias & Fairness
  S5: boolean;  // PII Leakage
  S6: boolean;  // Sensitive Data
  S7: boolean;  // Harmful Content
  S8: boolean;  // Sexual Content
  S9: boolean;  // Hate Speech
  S10: boolean; // Violence
  S11: boolean; // Self-Harm
  S12: boolean; // Malware
  S13: boolean; // Fraud
  S14: boolean; // Misinformation
  S15: boolean; // Political Manipulation
  S16: boolean; // Competitive Intelligence
  S17: boolean; // Code Vulnerability
  S18: boolean; // Data Exfiltration
  S19: boolean; // Unauthorized Actions
};

/** Blacklist/Whitelist configuration */
export type BlacklistWhitelist = {
  blacklist: string[];
  whitelist: string[];
};

/** Response templates for different actions */
export type ResponseTemplates = {
  reject: string;
  replace: string;
};

/** Sensitivity configuration */
export type SensitivityConfig = {
  level: 'high' | 'medium' | 'low';
  threshold: number;
};

/** Ban policy configuration */
export type BanPolicy = {
  bannedUsers: string[];
  autoBanThreshold: number;
};

/** Knowledge base entry */
export type KnowledgeBaseEntry = {
  question: string;
  answer: string;
};

/** Knowledge base configuration */
export type KnowledgeBase = {
  entries: KnowledgeBaseEntry[];
};

/** Complete application configuration */
export type AppConfig = {
  riskTypes: RiskTypeConfig;
  riskCategories: RiskCategoriesConfig;
  blacklistWhitelist: BlacklistWhitelist;
  responseTemplates: ResponseTemplates;
  sensitivity: SensitivityConfig;
  banPolicy: BanPolicy;
  knowledgeBase: KnowledgeBase;
};

/** Application quota limits and usage */
export type AppQuota = {
  checksLimit: number;
  checksUsed: number;
  tokensLimit: number;
  tokensUsed: number;
};

/** User tier for quota defaults */
export type UserTier = 'personal' | 'business' | 'enterprise';

/** Application entity */
export type App = {
  appId: string;
  name: string;
  apiKey: string;
  modelApiKey: string;
  config: AppConfig;
  quota: AppQuota;
  createdAt: string;
  ownerId: string;
};

/** Default quota limits by tier */
export const DEFAULT_QUOTA_BY_TIER: Record<UserTier, Omit<AppQuota, 'checksUsed' | 'tokensUsed'>> = {
  personal: { checksLimit: 1000, tokensLimit: 100000 },
  business: { checksLimit: 10000, tokensLimit: 1000000 },
  enterprise: { checksLimit: 100000, tokensLimit: 10000000 },
};

/** Default application configuration */
export const DEFAULT_APP_CONFIG: AppConfig = {
  riskTypes: {
    security: true,
    compliance: true,
    dataSecurity: true,
  },
  riskCategories: {
    S1: true, S2: true, S3: true, S4: true, S5: true,
    S6: true, S7: true, S8: true, S9: true, S10: true,
    S11: true, S12: true, S13: true, S14: true, S15: true,
    S16: true, S17: true, S18: true, S19: true,
  },
  blacklistWhitelist: {
    blacklist: [],
    whitelist: [],
  },
  responseTemplates: {
    reject: 'Your request cannot be processed due to security policy.',
    replace: 'I apologize, but I cannot provide that information.',
  },
  sensitivity: {
    level: 'medium',
    threshold: 0.7,
  },
  banPolicy: {
    bannedUsers: [],
    autoBanThreshold: 3,
  },
  knowledgeBase: {
    entries: [],
  },
};

// ============================================================================
// User Account Types
// ============================================================================

/** User role for access control */
export type UserRole = 'owner' | 'admin' | 'viewer';

/** User account stored in database */
export type User = {
  userId: string;
  email: string;
  passwordHash: string;
  role: UserRole;
  createdAt: string; // ISO timestamp
  tier: UserTier;
};

/** JWT session token payload for user authentication */
export type SessionTokenClaims = {
  iss: string; // issuer (gateway)
  sub: string; // userId
  email: string;
  role: UserRole;
  tier: UserTier;
  iat: number; // issued at (Unix timestamp)
  exp: number; // expiration (Unix timestamp)
  jti: string; // unique token ID for revocation
};

// ============================================================================
// Gateway Deployment Modes Types
// ============================================================================

/** API Call Mode: Guardrails check request */
export type GuardrailsCheckRequest = {
  model?: string;
  messages: SimpleMessage[];
  enable_security?: boolean;
  enable_compliance?: boolean;
  enable_data_security?: boolean;
};

/** API Call Mode: Guardrails check response */
export type GuardrailsCheckResponse = {
  id: string;
  action: 'pass' | 'reject' | 'replace';
  risk_level: 'no_risk' | 'low_risk' | 'medium_risk' | 'high_risk';
  categories: string[];
  suggest_answer?: string;
  hit_keywords?: string[];
  score: number;
  processed_content?: string;
  has_warning: boolean;
  was_replaced: boolean;
};

/** OpenAI-compatible chat completion request */
export type ChatCompletionRequest = {
  model: string;
  messages: SimpleMessage[];
  max_tokens?: number;
  temperature?: number;
  stream?: boolean;
};

/** OpenAI-compatible chat completion response */
export type ChatCompletionResponse = {
  id: string;
  object: 'chat.completion';
  created: number;
  model: string;
  choices: Array<{
    index: number;
    message: {
      role: 'assistant';
      content: string;
    };
    finish_reason: 'stop' | 'length' | 'content_filter';
  }>;
  usage: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
};

/** Authentication result: either Agent Token or API Key */
export type AuthResult = {
  type: 'agent_token' | 'api_key';
  agentId?: string | null;
  role?: string | null;
  scope?: { models: string[]; tools: string[] };
  app?: App;
  userId?: string | null;
};

/** Simple message format for guardrails check */
export type SimpleMessage = { role: string; content: string };

// ============================================================================
// Quota Tracking Types
// ============================================================================

/** Quota type: different resource types that can be tracked */
export type QuotaType = 'checks' | 'tokens' | 'agents';

/** Quota usage snapshot for a specific resource type */
export type QuotaUsage = {
  type: QuotaType;
  used: number;
  limit: number;
  percentage: number;
  remaining: number;
};

/** Quota alert threshold configuration */
export type QuotaAlertThreshold = {
  threshold: number; // percentage (e.g., 80, 90, 100)
  triggered: boolean;
  triggeredAt?: string; // ISO timestamp
};

/** Quota alert event */
export type QuotaAlert = {
  appId: string;
  userId?: string | null;
  type: QuotaType;
  threshold: number;
  percentage: number;
  used: number;
  limit: number;
  triggeredAt: string;
  message: string;
};

/** Quota usage history entry */
export type QuotaHistoryEntry = {
  timestamp: string;
  appId: string;
  userId?: string | null;
  type: QuotaType;
  delta: number; // amount used in this call
  totalUsed: number; // cumulative usage after this call
  limit: number;
  requestId?: string;
  resource?: string; // model or tool name
};

/** Quota check result */
export type QuotaCheckResult = {
  allowed: boolean;
  type: QuotaType;
  used: number;
  limit: number;
  percentage: number;
  remaining: number;
  reason?: string;
  isSoftLimit?: boolean; // warning threshold reached but not hard limit
};

/** Time range for history queries */
export type QuotaTimeRange = 'day' | 'week' | 'month';

/** Quota limit update request (admin) */
export type QuotaLimitUpdateRequest = {
  checksLimit?: number;
  tokensLimit?: number;
};

// ============================================================================
// Tier Management Types
// ============================================================================

/** Tier level for service plans */
export type TierLevel = 'personal' | 'business' | 'enterprise';

/** Tier features and capabilities */
export type TierFeatures = {
  // Agent Management
  maxAgents: number;
  multiAgentDashboard: boolean;
  agentBehaviorAnalysis: boolean;
  agentInventory: boolean;

  // Security Features
  personalAiAssistantProtection: boolean;
  runtimeMonitoring: boolean;
  configScanning: boolean;
  vulnerabilityDetection: boolean;
  redTeamTesting: boolean;
  blastRadiusAnalysis: boolean;
  threatDiscovery: boolean;

  // Policy & Governance
  realTimePolicyExecution: boolean;
  customDetectionRules: boolean;
  governancePolicyExecution: boolean;
  organizationAiGovernance: boolean;

  // Integrations
  integrationPluginSupport: boolean;

  // Support
  prioritySupport: boolean;
};

/** Tier limits and quotas */
export type TierLimits = {
  checksLimit: number;
  tokensLimit: number;
  agentsLimit: number;
  apiKeysLimit: number;
  customRulesLimit: number;
};

/** Tier pricing information */
export type TierPrice = {
  monthly: number;
  yearly: number;
  currency: string;
  featuresDescription: string[];
};

/** Complete tier configuration */
export type TierConfig = {
  tier: TierLevel;
  features: TierFeatures;
  limits: TierLimits;
  price: TierPrice;
  displayName: string;
  description: string;
};

/** Tier change request */
export type TierChangeRequest = {
  targetTier: TierLevel;
  reason?: string;
  confirmed: boolean;
};

/** Tier change history entry */
export type TierChangeHistoryEntry = {
  id: string;
  userId: string;
  fromTier: TierLevel;
  toTier: TierLevel;
  reason?: string;
  changedAt: string;
  changedBy: string; // userId of admin or 'self'
  status: 'completed' | 'pending' | 'rejected';
};

/** Tier change validation result */
export type TierChangeValidation = {
  allowed: boolean;
  reason?: string;
  warnings?: string[];
  quotaCheck?: {
    checksUsed: number;
    checksLimit: number;
    tokensUsed: number;
    tokensLimit: number;
    agentsCount: number;
    agentsLimit: number;
    willExceedLimit: boolean;
  };
};

/** Usage report for tier billing */
export type TierUsageReport = {
  userId: string;
  tier: TierLevel;
  periodStart: string;
  periodEnd: string;
  usage: {
    checks: {
      total: number;
      byApp: Record<string, number>;
      byDay: Array<{ date: string; count: number }>;
    };
    tokens: {
      total: number;
      byApp: Record<string, number>;
      byDay: Array<{ date: string; count: number }>;
    };
    agents: {
      total: number;
      active: number;
    };
  };
  costEstimate: {
    basePrice: number;
    usagePrice: number;
    totalPrice: number;
    currency: string;
    breakdown: Array<{ item: string; amount: number }>;
  };
};

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
  | 'elevation.reject';

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
  // Tamper-evident chain (set by AuditLogger): monotonically increasing seq and
  // a hash linking each event to the previous one.
  seq?: number;
  hash?: string;
};

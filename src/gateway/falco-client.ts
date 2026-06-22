import type { Decision, FalcoConfig, FalcoPriority } from '../shared/types.ts';

export type FalcoEventInput = {
  output?: unknown;
  priority?: unknown;
  rule?: unknown;
  time?: unknown;
  output_fields?: Record<string, unknown>;
};

export type FalcoRuntimeAlert = {
  agentId: string | null;
  rule: string;
  priority: FalcoPriority;
  output: string;
  time: Date;
  fields: Record<string, unknown>;
};

export type FalcoRuntimeDecision = Decision & {
  alert?: FalcoRuntimeAlert;
};

const PRIORITY_RANK: Record<FalcoPriority, number> = {
  emergency: 0,
  alert: 1,
  critical: 2,
  error: 3,
  warning: 4,
  notice: 5,
  informational: 6,
  debug: 7,
};

const DEFAULT_FALCO: FalcoConfig = {
  enabled: false,
  webhookPath: '/v1/falco/events',
  sharedSecretEnv: 'AGENTZT_FALCO_WEBHOOK_SECRET',
  minimumPriority: 'warning',
  denyWindowSeconds: 300,
  agentIdFields: ['agentzt.agent_id', 'container.name', 'k8s.pod.name'],
};

export function resolveFalcoConfig(config?: FalcoConfig): FalcoConfig | null {
  const enabled = process.env.AGENTZT_FALCO === '1' || config?.enabled === true;
  if (!enabled) return null;
  return {
    ...DEFAULT_FALCO,
    ...config,
    enabled: true,
    agentIdFields: config?.agentIdFields?.length ? config.agentIdFields : DEFAULT_FALCO.agentIdFields,
  };
}

export function normalizeFalcoPriority(value: unknown): FalcoPriority {
  const priority = String(value ?? 'debug').toLowerCase();
  if (priority in PRIORITY_RANK) return priority as FalcoPriority;
  return 'debug';
}

function isBlockingPriority(priority: FalcoPriority, minimum: FalcoPriority): boolean {
  return PRIORITY_RANK[priority] <= PRIORITY_RANK[minimum];
}

function fieldString(fields: Record<string, unknown>, names: string[]): string | null {
  for (const name of names) {
    const value = fields[name];
    if (typeof value === 'string' && value) return value;
    if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  }
  return null;
}

function parseTime(value: unknown): Date {
  if (typeof value !== 'string') return new Date();
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? new Date() : parsed;
}

export class FalcoRuntimeMonitor {
  readonly config: FalcoConfig;
  private alerts: FalcoRuntimeAlert[] = [];
  private maxAlerts = 1000;

  constructor(config: FalcoConfig) {
    this.config = config;
  }

  verifySecret(authHeader: string | null, secretHeader: string | null): Decision {
    const expected = process.env[this.config.sharedSecretEnv];
    if (!expected) return { allow: true, reason: 'Falco webhook secret not configured' };
    if (secretHeader === expected) return { allow: true, reason: 'Falco webhook secret matched' };
    const bearer = authHeader?.replace(/^Bearer\s+/i, '');
    if (bearer === expected) return { allow: true, reason: 'Falco bearer secret matched' };
    return { allow: false, reason: 'invalid Falco webhook secret' };
  }

  record(input: FalcoEventInput): FalcoRuntimeAlert {
    const fields = input.output_fields && typeof input.output_fields === 'object'
      ? input.output_fields
      : {};
    const alert: FalcoRuntimeAlert = {
      agentId: fieldString(fields, this.config.agentIdFields),
      rule: typeof input.rule === 'string' && input.rule ? input.rule : 'unknown',
      priority: normalizeFalcoPriority(input.priority),
      output: typeof input.output === 'string' ? input.output : '',
      time: parseTime(input.time),
      fields,
    };
    this.alerts.push(alert);
    if (this.alerts.length > this.maxAlerts) {
      this.alerts.splice(0, this.alerts.length - this.maxAlerts);
    }
    return alert;
  }

  recordMany(input: FalcoEventInput | FalcoEventInput[]): FalcoRuntimeAlert[] {
    return (Array.isArray(input) ? input : [input]).map((event) => this.record(event));
  }

  decideAgent(agentId: string, now = new Date()): FalcoRuntimeDecision {
    const minTime = now.getTime() - this.config.denyWindowSeconds * 1000;
    const match = [...this.alerts].reverse().find((alert) =>
      alert.agentId === agentId &&
      alert.time.getTime() >= minTime &&
      isBlockingPriority(alert.priority, this.config.minimumPriority)
    );
    if (!match) return { allow: true, reason: 'no active Falco runtime alert' };
    return {
      allow: false,
      reason: `Falco ${match.priority} alert "${match.rule}" is active for agent ${agentId}`,
      alert: match,
    };
  }
}

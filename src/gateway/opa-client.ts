import type { Decision, OpaConfig, RiskLevel } from '../shared/types.ts';

export type OpaDecisionInput = {
  agentId: string;
  role: string;
  action: 'model.call' | 'tool.call';
  resource: {
    kind: 'model' | 'tool';
    name: string;
  };
  authVia: 'scope' | 'jit';
  riskLevel?: RiskLevel;
  now: string;
};

type OpaDataResponse = {
  result?: boolean | {
    allow?: unknown;
    reason?: unknown;
  };
};

const DEFAULT_OPA: OpaConfig = {
  enabled: false,
  baseUrl: 'http://localhost:8181',
  policyPath: 'agentzt/authz/decision',
  timeoutMs: 1000,
  failOpen: false,
};

function joinOpaUrl(baseUrl: string, policyPath: string): string {
  const base = baseUrl.replace(/\/+$/, '');
  const path = policyPath.replace(/^\/+/, '');
  return `${base}/v1/data/${path}`;
}

function coerceDecision(body: OpaDataResponse): Decision {
  const result = body.result;
  if (typeof result === 'boolean') {
    return { allow: result, reason: `OPA ${result ? 'allowed' : 'denied'}` };
  }
  if (result && typeof result === 'object' && typeof result.allow === 'boolean') {
    return {
      allow: result.allow,
      reason: typeof result.reason === 'string' && result.reason ? result.reason : `OPA ${result.allow ? 'allowed' : 'denied'}`,
    };
  }
  return { allow: false, reason: 'OPA response missing boolean result or decision.allow' };
}

export function resolveOpaConfig(config?: OpaConfig): OpaConfig | null {
  const enabled = process.env.AGENTZT_OPA === '1' || config?.enabled === true;
  if (!enabled) return null;
  return {
    ...DEFAULT_OPA,
    ...config,
    enabled: true,
  };
}

export class OpaClient {
  readonly config: OpaConfig;
  readonly url: string;

  constructor(config: OpaConfig) {
    this.config = config;
    this.url = joinOpaUrl(config.baseUrl, config.policyPath);
  }

  async decide(input: OpaDecisionInput): Promise<Decision> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.timeoutMs);
    try {
      const res = await fetch(this.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ input }),
        signal: controller.signal,
      });
      if (!res.ok) {
        return this.outage(`OPA returned HTTP ${res.status}`);
      }
      const body = await res.json().catch(() => null) as OpaDataResponse | null;
      if (!body || typeof body !== 'object') {
        return this.outage('OPA returned invalid JSON');
      }
      return coerceDecision(body);
    } catch (err) {
      const reason = err instanceof Error && err.name === 'AbortError'
        ? `OPA timed out after ${this.config.timeoutMs}ms`
        : `OPA unavailable: ${(err as Error).message}`;
      return this.outage(reason);
    } finally {
      clearTimeout(timer);
    }
  }

  private outage(reason: string): Decision {
    if (this.config.failOpen) {
      return { allow: true, reason: `${reason}; fail-open` };
    }
    return { allow: false, reason };
  }
}

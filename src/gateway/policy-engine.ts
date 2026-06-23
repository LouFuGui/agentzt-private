import type {
  AgentRegistryEntry,
  EnterprisePolicyModel,
  EnterpriseResourceClass,
  GovernanceBoundary,
  PolicyDoc,
  RolePolicy,
  Decision,
  RiskLevel,
} from '../shared/types.ts';

const RISK_ORDINAL: Record<string, number> = {
  no_risk: 0,
  low_risk: 1,
  medium_risk: 2,
  high_risk: 3,
};

const RESOURCE_WILDCARD = '*';

const DEFAULT_ENTERPRISE_DECISION_ORDER = [
  'mtls',
  'token',
  'agent_lifecycle',
  'runtime_signal',
  'rbac_or_jit',
  'rate_limit',
  'input_guardrail',
  'abac',
  'opa',
  'execution',
  'output_guardrail',
];

export function defaultEnterprisePolicy(): EnterprisePolicyModel {
  return {
    version: 1,
    agentLifecycle: { denyStatuses: ['disabled', 'revoked'] },
    decisionOrder: DEFAULT_ENTERPRISE_DECISION_ORDER,
  };
}

function cleanBoundary(boundary?: GovernanceBoundary): GovernanceBoundary | undefined {
  if (!boundary) return undefined;
  const clean: GovernanceBoundary = {};
  if (boundary.organizationId) clean.organizationId = boundary.organizationId;
  if (boundary.projectId) clean.projectId = boundary.projectId;
  if (boundary.environment) clean.environment = boundary.environment;
  return Object.keys(clean).length ? clean : undefined;
}

function validateBoundaryMatch(required: GovernanceBoundary, actual?: GovernanceBoundary): string | null {
  if (required.organizationId && required.organizationId !== actual?.organizationId) {
    return `organization "${actual?.organizationId ?? 'unassigned'}" does not match "${required.organizationId}"`;
  }
  if (required.projectId && required.projectId !== actual?.projectId) {
    return `project "${actual?.projectId ?? 'unassigned'}" does not match "${required.projectId}"`;
  }
  if (required.environment && required.environment !== actual?.environment) {
    return `environment "${actual?.environment ?? 'unassigned'}" does not match "${required.environment}"`;
  }
  return null;
}

/**
 * Deny-by-default RBAC policy engine (Foundation tier "least agency").
 *
 * A role grants an explicit allow-list of models and tools. Every access
 * decision starts from deny; access is granted only when the resource is
 * explicitly listed for the agent's role. `*` is supported as an escape hatch
 * but is intentionally never used in the shipped policy.
 */
export class PolicyEngine {
  private policy: PolicyDoc;

  constructor(policy: PolicyDoc) {
    this.policy = policy;
  }

  getRole(role: string): RolePolicy | undefined {
    return this.policy.roles[role];
  }

  enterprisePolicy(): EnterprisePolicyModel {
    return this.policy.enterprise ?? defaultEnterprisePolicy();
  }

  resourceClassFor(kind: 'model' | 'tool', name: string): EnterpriseResourceClass | null {
    const classes = this.enterprisePolicy().resourceClasses ?? {};
    for (const resourceClass of Object.values(classes)) {
      if (resourceClass.kind !== kind) continue;
      if (resourceClass.resources.includes('*') || resourceClass.resources.includes(name)) {
        return resourceClass;
      }
    }
    return null;
  }

  governanceForAgent(entry: AgentRegistryEntry): GovernanceBoundary | undefined {
    return cleanBoundary(entry.governance);
  }

  decideGovernance(entry: AgentRegistryEntry): Decision {
    const role = this.policy.roles[entry.role];
    if (!role) return { allow: false, reason: `role "${entry.role}" has no policy` };

    const required = cleanBoundary(role.governance);
    if (!required) return { allow: true, reason: 'no role governance boundary' };

    const actual = cleanBoundary(entry.governance);
    const mismatch = validateBoundaryMatch(required, actual);
    if (mismatch) {
      return { allow: false, reason: `governance boundary mismatch: ${mismatch}` };
    }
    return { allow: true, reason: 'governance boundary satisfied' };
  }

  /** Models/tools an agent in this role may use — used to scope its token. */
  scopeForRole(role: string): { models: string[]; tools: string[] } {
    const r = this.policy.roles[role];
    if (!r) return { models: [], tools: [] };
    return { models: [...r.models], tools: [...r.tools] };
  }

  private static listAllows(list: string[], resource: string): boolean {
    return list.includes(RESOURCE_WILDCARD) || list.includes(resource);
  }

  decideModel(role: string, model: string): Decision {
    const r = this.policy.roles[role];
    if (!r) return { allow: false, reason: `unknown role "${role}"` };
    if (PolicyEngine.listAllows(r.models, model)) {
      return { allow: true, reason: `role "${role}" permits model "${model}"` };
    }
    return {
      allow: false,
      reason: `deny-by-default: role "${role}" does not permit model "${model}"`,
    };
  }

  decideTool(role: string, tool: string): Decision {
    const r = this.policy.roles[role];
    if (!r) return { allow: false, reason: `unknown role "${role}"` };
    if (PolicyEngine.listAllows(r.tools, tool)) {
      return { allow: true, reason: `role "${role}" permits tool "${tool}"` };
    }
    return {
      allow: false,
      reason: `deny-by-default: role "${role}" does not permit tool "${tool}"`,
    };
  }

  limitsForRole(role: string) {
    return this.policy.roles[role]?.limits ?? {};
  }

  /**
   * Attribute-based access control evaluated at call time (not just at token
   * issuance) — the "continuous authorization" idea: context can revoke access
   * even when RBAC would allow it. Currently: operating hours + risk-adaptive.
   */
  decideAbac(
    role: string,
    ctx: { now: Date; riskLevel?: RiskLevel },
  ): Decision {
    const abac = this.policy.roles[role]?.abac;
    if (!abac) return { allow: true, reason: 'no ABAC conditions' };

    if (abac.allowedHoursUTC) {
      const { start, end } = abac.allowedHoursUTC;
      const hour = ctx.now.getUTCHours();
      const inWindow = start <= end ? hour >= start && hour < end : hour >= start || hour < end;
      if (!inWindow) {
        return {
          allow: false,
          reason: `ABAC: outside operating hours (UTC ${start}:00–${end}:00, now ${hour}:00)`,
        };
      }
    }

    if (abac.denyAboveRiskLevel && ctx.riskLevel && ctx.riskLevel !== 'unknown') {
      const limit = RISK_ORDINAL[abac.denyAboveRiskLevel] ?? 99;
      const actual = RISK_ORDINAL[ctx.riskLevel] ?? 0;
      if (actual >= limit) {
        return {
          allow: false,
          reason: `ABAC: risk ${ctx.riskLevel} >= threshold ${abac.denyAboveRiskLevel}`,
        };
      }
    }

    return { allow: true, reason: 'ABAC conditions satisfied' };
  }

  /** May this role elevate (JIT) to the given resource? */
  canElevate(role: string, kind: 'model' | 'tool', name: string): Decision {
    const jit = this.policy.roles[role]?.jit;
    if (!jit) return { allow: false, reason: `role "${role}" has no JIT policy` };
    const list = kind === 'model' ? jit.elevatableModels ?? [] : jit.elevatableTools ?? [];
    if (list.includes(RESOURCE_WILDCARD) || list.includes(name)) {
      return { allow: true, reason: `role "${role}" may elevate to ${kind} "${name}"` };
    }
    return { allow: false, reason: `role "${role}" may not elevate to ${kind} "${name}"` };
  }

  jitMaxTtl(role: string): number {
    return this.policy.roles[role]?.jit?.maxTtlSeconds ?? 0;
  }
}

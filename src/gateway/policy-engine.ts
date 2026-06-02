import type { PolicyDoc, RolePolicy, Decision } from '../shared/types.ts';

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

  /** Models/tools an agent in this role may use — used to scope its token. */
  scopeForRole(role: string): { models: string[]; tools: string[] } {
    const r = this.policy.roles[role];
    if (!r) return { models: [], tools: [] };
    return { models: [...r.models], tools: [...r.tools] };
  }

  private static listAllows(list: string[], resource: string): boolean {
    return list.includes('*') || list.includes(resource);
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
}

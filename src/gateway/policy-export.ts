import type {
  AgentLifecycleStatus,
  AgentRegistry,
  AgentRegistryEntry,
  GovernanceBoundary,
  PolicyDoc,
  RolePolicy,
} from '../shared/types.ts';
import { defaultEnterprisePolicy } from './policy-engine.ts';

export type PolicyStateExport = {
  schemaVersion: 1;
  exportedAt: string;
  policyVersion: number;
  defaultDeny: boolean;
  enterprise: {
    version: number;
    decisionOrder: string[];
    agentLifecycleDenyStatuses: AgentLifecycleStatus[];
    governance: unknown;
    resourceClasses: unknown;
  };
  roles: Record<string, {
    description?: string;
    models: string[];
    tools: string[];
    governance?: GovernanceBoundary;
    limits?: RolePolicy['limits'];
    abac?: RolePolicy['abac'];
    jit?: RolePolicy['jit'];
  }>;
  agents: Array<{
    agentId: string;
    role: string;
    status: AgentLifecycleStatus;
    description?: string;
    governance?: GovernanceBoundary;
    createdAt?: string;
    revokedAt?: string;
    revokedReason?: string;
  }>;
  summary: {
    roleCount: number;
    agentCount: number;
    resourceClassCount: number;
  };
};

function sortRecord<T>(record: Record<string, T> | undefined): Record<string, T> {
  const sorted: Record<string, T> = {};
  for (const key of Object.keys(record ?? {}).sort()) {
    sorted[key] = (record as Record<string, T>)[key];
  }
  return sorted;
}

function agentStatus(entry: AgentRegistryEntry): AgentLifecycleStatus {
  if (entry.disabled) return 'disabled';
  return entry.status ?? 'active';
}

function exportRole(role: RolePolicy): PolicyStateExport['roles'][string] {
  const out: PolicyStateExport['roles'][string] = {
    models: [...role.models].sort(),
    tools: [...role.tools].sort(),
  };
  if (role.description) out.description = role.description;
  if (role.governance) out.governance = role.governance;
  if (role.limits) out.limits = role.limits;
  if (role.abac) out.abac = role.abac;
  if (role.jit) out.jit = role.jit;
  return out;
}

function exportAgent(entry: AgentRegistryEntry): PolicyStateExport['agents'][number] {
  const out: PolicyStateExport['agents'][number] = {
    agentId: entry.agentId,
    role: entry.role,
    status: agentStatus(entry),
  };
  if (entry.description) out.description = entry.description;
  if (entry.governance) out.governance = entry.governance;
  if (entry.createdAt) out.createdAt = entry.createdAt;
  if (entry.revokedAt) out.revokedAt = entry.revokedAt;
  if (entry.revokedReason) out.revokedReason = entry.revokedReason;
  return out;
}

export function exportPolicyState(
  policy: PolicyDoc,
  registry: AgentRegistry,
  now = new Date(),
): PolicyStateExport {
  const enterprise = policy.enterprise ?? defaultEnterprisePolicy();
  const roles = sortRecord(policy.roles);
  const resourceClasses = sortRecord(enterprise.resourceClasses);

  const exportedRoles: PolicyStateExport['roles'] = {};
  for (const [name, role] of Object.entries(roles)) {
    exportedRoles[name] = exportRole(role);
  }

  return {
    schemaVersion: 1,
    exportedAt: now.toISOString(),
    policyVersion: policy.version,
    defaultDeny: policy.defaultDeny,
    enterprise: {
      version: enterprise.version,
      decisionOrder: [...enterprise.decisionOrder],
      agentLifecycleDenyStatuses: [...enterprise.agentLifecycle.denyStatuses],
      governance: enterprise.governance ?? null,
      resourceClasses,
    },
    roles: exportedRoles,
    agents: [...registry.agents]
      .sort((a, b) => a.agentId.localeCompare(b.agentId))
      .map(exportAgent),
    summary: {
      roleCount: Object.keys(exportedRoles).length,
      agentCount: registry.agents.length,
      resourceClassCount: Object.keys(resourceClasses).length,
    },
  };
}

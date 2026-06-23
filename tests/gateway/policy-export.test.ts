import { describe, expect, it } from 'vitest';
import { exportPolicyState } from '../../src/gateway/policy-export.ts';
import type { AgentRegistry, PolicyDoc } from '../../src/shared/types.ts';

describe('enterprise policy state export', () => {
  it('exports policy, governance, and lifecycle state without key material', () => {
    const policy: PolicyDoc = {
      version: 1,
      defaultDeny: true,
      enterprise: {
        version: 1,
        agentLifecycle: { denyStatuses: ['disabled', 'revoked'] },
        decisionOrder: ['token', 'agent_lifecycle', 'rbac_or_jit'],
        governance: {
          organizationIds: ['org-a'],
          projectIds: ['payments'],
          environments: ['production'],
        },
        resourceClasses: {
          highBlast: {
            kind: 'tool',
            resources: ['email.send'],
            governance: { organizationId: 'org-a', projectId: 'payments' },
            jitRequired: true,
          },
        },
      },
      roles: {
        'demo-agent': {
          models: ['claude-sonnet-4-6'],
          tools: ['kb.search'],
          governance: { organizationId: 'org-a', projectId: 'payments' },
          limits: { requestsPerMinute: 60 },
        },
      },
    };
    const registry: AgentRegistry = {
      agents: [{
        agentId: 'agent-01',
        role: 'demo-agent',
        publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'public-key' },
        governance: { organizationId: 'org-a', projectId: 'payments' },
        status: 'revoked',
        revokedReason: 'test',
      }],
    };

    const state = exportPolicyState(policy, registry, new Date('2026-01-02T03:04:05.000Z'));

    expect(state.exportedAt).toBe('2026-01-02T03:04:05.000Z');
    expect(state.enterprise.agentLifecycleDenyStatuses).toEqual(['disabled', 'revoked']);
    expect(state.enterprise.resourceClasses).toEqual(policy.enterprise?.resourceClasses);
    expect(state.roles['demo-agent'].governance).toEqual({ organizationId: 'org-a', projectId: 'payments' });
    expect(state.agents).toEqual([{
      agentId: 'agent-01',
      role: 'demo-agent',
      status: 'revoked',
      governance: { organizationId: 'org-a', projectId: 'payments' },
      revokedReason: 'test',
    }]);
    expect(JSON.stringify(state)).not.toContain('publicKeyJwk');
    expect(JSON.stringify(state)).not.toContain('public-key');
  });

  it('uses the default enterprise model when policy omits it', () => {
    const state = exportPolicyState({
      version: 1,
      defaultDeny: true,
      roles: {},
    }, { agents: [] }, new Date('2026-01-02T03:04:05.000Z'));

    expect(state.enterprise.agentLifecycleDenyStatuses).toContain('revoked');
    expect(state.enterprise.decisionOrder).toContain('output_guardrail');
    expect(state.summary).toEqual({
      roleCount: 0,
      agentCount: 0,
      resourceClassCount: 0,
    });
  });
});

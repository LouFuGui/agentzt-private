import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';

const roots: string[] = [];

function writeJson(path: string, value: unknown): void {
  writeFileSync(path, JSON.stringify(value, null, 2) + '\n');
}

async function makeHarness(status?: 'active' | 'disabled' | 'revoked', legacyDisabled = false) {
  const root = join(tmpdir(), `agentzt-lifecycle-${randomUUID()}`);
  roots.push(root);
  mkdirSync(join(root, 'config'), { recursive: true });
  process.env.AGENTZT_ROOT = root;
  vi.resetModules();

  const { generateEd25519 } = await import('../../src/shared/crypto.ts');
  const { AgentIdentity } = await import('../../src/client/identity.ts');
  const { IdentityStore } = await import('../../src/gateway/identity-store.ts');
  const { PolicyEngine } = await import('../../src/gateway/policy-engine.ts');
  const { TokenService } = await import('../../src/gateway/token-service.ts');
  const { loadGatewayKeyFromPrivateJwk } = await import('../../src/gateway/gateway-key.ts');
  const { loadPolicy } = await import('../../src/shared/config.ts');

  const agentKeys = generateEd25519();
  const gatewayKeys = generateEd25519();
  const agentId = 'agent-01';
  const role = 'demo-agent';
  const cfg = {
    port: 8700,
    issuer: 'agentzt-gateway',
    tokenTtlSeconds: 300,
    assertionMaxAgeSeconds: 60,
    upstream: {
      mode: 'mock' as const,
      anthropicBaseUrl: 'https://api.anthropic.com',
      apiKeyEnv: 'AGENTZT_UPSTREAM_ANTHROPIC_KEY',
    },
  };
  const policy = {
    version: 1,
    defaultDeny: true,
    enterprise: {
      version: 1,
      agentLifecycle: { denyStatuses: ['disabled', 'revoked'] },
      decisionOrder: ['token', 'agent_lifecycle', 'rbac_or_jit'],
      resourceClasses: {
        highBlast: {
          kind: 'tool',
          resources: ['email.send'],
          jitRequired: true,
        },
      },
    },
    roles: {
      [role]: {
        models: ['claude-sonnet-4-6'],
        tools: ['kb.search'],
        limits: { requestsPerMinute: 60 },
      },
    },
  };
  writeJson(join(root, 'config', 'gateway.json'), cfg);
  writeJson(join(root, 'config', 'policy.json'), policy);
  writeJson(join(root, 'config', 'agents.json'), {
    agents: [{
      agentId,
      role,
      publicKeyJwk: agentKeys.publicKeyJwk,
      status,
      disabled: legacyDisabled || undefined,
      revokedAt: status === 'revoked' ? new Date().toISOString() : undefined,
    }],
  });

  const identity = new AgentIdentity({
    agentId,
    role,
    publicKeyJwk: agentKeys.publicKeyJwk,
    privateKeyJwk: agentKeys.privateKeyJwk,
    createdAt: new Date().toISOString(),
  });
  const identities = new IdentityStore();
  const engine = new PolicyEngine(loadPolicy());
  const tokens = new TokenService(
    cfg,
    identities,
    engine,
    loadGatewayKeyFromPrivateJwk(gatewayKeys.privateKeyJwk),
  );

  return { agentId, engine, identity, identities, publicKeyJwk: agentKeys.publicKeyJwk, root, tokens };
}

afterEach(() => {
  delete process.env.AGENTZT_ROOT;
  vi.resetModules();
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe('agent lifecycle enforcement', () => {
  it('denies token issuance for disabled agents', async () => {
    const { identity, tokens } = await makeHarness('disabled');
    const result = tokens.issue(identity.makeAssertion('agentzt-gateway/v1/token'), 'agentzt-gateway/v1/token');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.status).toBe(403);
      expect(result.reason).toContain('disabled');
    }
  });

  it('denies token issuance for legacy disabled agents', async () => {
    const { identity, tokens } = await makeHarness(undefined, true);
    const result = tokens.issue(identity.makeAssertion('agentzt-gateway/v1/token'), 'agentzt-gateway/v1/token');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain('disabled');
  });

  it('denies existing access tokens after an agent is revoked', async () => {
    const { agentId, identity, identities, publicKeyJwk, root, tokens } = await makeHarness('active');
    const issued = tokens.issue(identity.makeAssertion('agentzt-gateway/v1/token'), 'agentzt-gateway/v1/token');
    expect(issued.ok).toBe(true);
    if (!issued.ok) throw new Error(issued.reason);

    writeJson(join(root, 'config', 'agents.json'), {
      agents: [{
        agentId,
        role: 'demo-agent',
        publicKeyJwk,
        status: 'revoked',
        revokedAt: new Date().toISOString(),
      }],
    });
    identities.reload();

    expect(() => tokens.verifyAccessToken(issued.token)).toThrow('revoked');
  });

  it('exposes enterprise resource classes from policy', async () => {
    const { engine } = await makeHarness('active');
    expect(engine.enterprisePolicy().agentLifecycle.denyStatuses).toContain('revoked');
    expect(engine.resourceClassFor('tool', 'email.send')?.jitRequired).toBe(true);
    expect(engine.resourceClassFor('model', 'claude-sonnet-4-6')).toBeNull();
  });
});

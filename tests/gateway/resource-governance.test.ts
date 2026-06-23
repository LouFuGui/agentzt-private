import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { GovernanceBoundary } from '../../src/shared/types.ts';

const roots: string[] = [];

function writeJsonFile(path: string, value: unknown): void {
  writeFileSync(path, JSON.stringify(value, null, 2) + '\n');
}

async function makeHarness(agentGovernance: GovernanceBoundary) {
  const root = join(tmpdir(), `agentzt-resource-governance-${randomUUID()}`);
  roots.push(root);
  mkdirSync(join(root, 'config'), { recursive: true });
  process.env.AGENTZT_ROOT = root;
  vi.resetModules();

  const { generateEd25519 } = await import('../../src/shared/crypto.ts');
  const { AgentIdentity } = await import('../../src/client/identity.ts');
  const { createGatewayServer } = await import('../../src/gateway/server.ts');

  const agentKeys = generateEd25519();
  const agentId = 'agent-01';
  const role = 'scoped-agent';
  const resourceGovernance = {
    organizationId: 'openguardrails',
    projectId: 'agentzt',
    environment: 'production',
  };

  writeJsonFile(join(root, 'config', 'gateway.json'), {
    port: 0,
    issuer: 'agentzt-gateway',
    tokenTtlSeconds: 300,
    assertionMaxAgeSeconds: 60,
    upstream: {
      mode: 'mock',
      anthropicBaseUrl: 'https://api.anthropic.com',
      apiKeyEnv: 'AGENTZT_UPSTREAM_ANTHROPIC_KEY',
    },
    guardrails: {
      provider: 'local',
      input: { mode: 'off' },
      output: { redactSecrets: false, check: false },
      openguardrails: {
        baseUrl: 'https://api.openguuardrails.com/v1',
        apiKeyEnv: 'OPENGUARDRAILS_API_KEY',
        model: 'OpenGuardrails-Text',
        timeoutMs: 5000,
        failOpen: false,
      },
    },
  });
  writeJsonFile(join(root, 'config', 'policy.json'), {
    version: 1,
    defaultDeny: true,
    enterprise: {
      version: 1,
      agentLifecycle: { denyStatuses: ['disabled', 'revoked'] },
      decisionOrder: ['token', 'agent_lifecycle', 'rbac_or_jit'],
      resourceClasses: {
        productionModels: {
          kind: 'model',
          resources: ['claude-sonnet-4-6'],
          governance: resourceGovernance,
        },
        productionTools: {
          kind: 'tool',
          resources: ['email.send'],
          governance: resourceGovernance,
          jitRequired: true,
          jit: { requireReason: true, maxTtlSeconds: 60 },
        },
      },
    },
    roles: {
      [role]: {
        models: ['claude-sonnet-4-6'],
        tools: ['email.send'],
        limits: { requestsPerMinute: 60 },
        jit: {
          elevatableTools: ['email.send'],
          maxTtlSeconds: 60,
        },
      },
    },
  });
  writeJsonFile(join(root, 'config', 'agents.json'), {
    agents: [{
      agentId,
      role,
      publicKeyJwk: agentKeys.publicKeyJwk,
      governance: agentGovernance,
      status: 'active',
    }],
  });

  const identity = new AgentIdentity({
    agentId,
    role,
    publicKeyJwk: agentKeys.publicKeyJwk,
    privateKeyJwk: agentKeys.privateKeyJwk,
    createdAt: new Date().toISOString(),
  });
  const gateway = await createGatewayServer();
  await new Promise<void>((resolve) => {
    gateway.server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = gateway.server.address();
  if (!address || typeof address === 'string') throw new Error('gateway did not bind a TCP port');
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const tokenResp = await fetch(`${baseUrl}/v1/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      assertion: identity.makeAssertion('agentzt-gateway/v1/token'),
    }),
  });
  const tokenBody = await tokenResp.json() as { access_token: string };
  expect(tokenResp.status).toBe(200);

  return {
    baseUrl,
    token: tokenBody.access_token,
    close: () => gateway.server.close(),
  };
}

afterEach(() => {
  delete process.env.AGENTZT_ROOT;
  vi.resetModules();
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe('resource governance enforcement', () => {
  it('denies standing resource access across environment boundaries', async () => {
    const { baseUrl, token, close } = await makeHarness({
      organizationId: 'openguardrails',
      projectId: 'agentzt',
      environment: 'development',
    });
    try {
      const denied = await fetch(`${baseUrl}/v1/messages`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: ['Bearer', token].join(' ') },
        body: JSON.stringify({
          model: 'claude-sonnet-4-6',
          messages: [{ role: 'user', content: 'hello' }],
          max_tokens: 32,
        }),
      });
      const deniedBody = await denied.json() as { error?: { message?: string } };
      expect(denied.status).toBe(403);
      expect(deniedBody.error?.message).toContain('resource governance boundary mismatch');
      expect(deniedBody.error?.message).toContain('environment "development" does not match "production"');
    } finally {
      close();
    }
  });

  it('denies JIT elevation across environment boundaries', async () => {
    const { baseUrl, token, close } = await makeHarness({
      organizationId: 'openguardrails',
      projectId: 'agentzt',
      environment: 'development',
    });
    try {
      const denied = await fetch(`${baseUrl}/v1/elevate`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: ['Bearer', token].join(' ') },
        body: JSON.stringify({ kind: 'tool', name: 'email.send', reason: 'customer update' }),
      });
      const deniedBody = await denied.json() as { error?: { message?: string } };
      expect(denied.status).toBe(403);
      expect(deniedBody.error?.message).toContain('resource governance boundary mismatch');
    } finally {
      close();
    }
  });
});

import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';

const roots: string[] = [];

function writeJsonFile(path: string, value: unknown): void {
  writeFileSync(path, JSON.stringify(value, null, 2) + '\n');
}

async function makeHarness() {
  const root = join(tmpdir(), `agentzt-elevation-${randomUUID()}`);
  roots.push(root);
  mkdirSync(join(root, 'config'), { recursive: true });
  process.env.AGENTZT_ROOT = root;
  vi.resetModules();

  const { generateEd25519 } = await import('../../src/shared/crypto.ts');
  const { AgentIdentity } = await import('../../src/client/identity.ts');
  const { createGatewayServer } = await import('../../src/gateway/server.ts');
  const { resetAppStore } = await import('../../src/api/app-store.ts');

  const agentKeys = generateEd25519();
  const agentId = 'agent-01';
  const role = 'jit-agent';
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
        baseUrl: 'https://api.openguardrails.com/v1',
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
        highBlast: {
          kind: 'tool',
          resources: ['email.send'],
          jitRequired: true,
          jit: {
            requireReason: true,
            maxTtlSeconds: 45,
            allowedRiskLevels: ['no_risk', 'low_risk'],
          },
        },
      },
    },
    roles: {
      [role]: {
        models: ['claude-sonnet-4-6'],
        tools: ['email.send'],
        limits: { requestsPerMinute: 60 },
        jit: {
          elevatableModels: ['claude-sonnet-4-6'],
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
    close: async () => {
      await new Promise<void>((resolve, reject) => {
        gateway.server.close((err) => err ? reject(err) : resolve());
      });
      resetAppStore();
    },
  };
}

afterEach(() => {
  delete process.env.AGENTZT_ROOT;
  vi.resetModules();
  for (const root of roots.splice(0)) {
    try {
      rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== 'EPERM' && code !== 'EBUSY' && code !== 'ENOTEMPTY') throw err;
    }
  }
});

describe('JIT elevation enforcement', () => {
  it('requires JIT even when a high-blast resource is present in standing scope', async () => {
    const { baseUrl, token, close } = await makeHarness();
    try {
      const denied = await fetch(`${baseUrl}/v1/tools/email.send`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: ['Bearer', token].join(' ') },
        body: JSON.stringify({ arguments: { to: 'customer@example.com', body: 'hello' } }),
      });
      const deniedBody = await denied.json() as { error?: { message?: string } };
      expect(denied.status).toBe(403);
      expect(deniedBody.error?.message).toContain('JIT-required resource class');

      const elevation = await fetch(`${baseUrl}/v1/elevate`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: ['Bearer', token].join(' ') },
        body: JSON.stringify({
          kind: 'tool',
          name: 'email.send',
          reason: 'customer update',
          ttlSeconds: 300,
          riskLevel: 'low_risk',
        }),
      });
      const elevationBody = await elevation.json() as { elevation_grant: string; expires_in: number };
      expect(elevation.status).toBe(200);
      expect(elevationBody.expires_in).toBe(45);

      const allowed = await fetch(`${baseUrl}/v1/tools/email.send`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: ['Bearer', token].join(' '),
          'x-agentzt-elevation': elevationBody.elevation_grant,
        },
        body: JSON.stringify({ arguments: { to: 'customer@example.com', body: 'hello' } }),
      });
      expect(allowed.status).toBe(200);
    } finally {
      close();
    }
  });

  it('rejects elevation grants for the wrong resource', async () => {
    const { baseUrl, token, close } = await makeHarness();
    try {
      const elevation = await fetch(`${baseUrl}/v1/elevate`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: ['Bearer', token].join(' ') },
        body: JSON.stringify({ kind: 'model', name: 'claude-sonnet-4-6', reason: 'model access' }),
      });
      const elevationBody = await elevation.json() as { elevation_grant: string };
      expect(elevation.status).toBe(200);

      const denied = await fetch(`${baseUrl}/v1/tools/email.send`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: ['Bearer', token].join(' '),
          'x-agentzt-elevation': elevationBody.elevation_grant,
        },
        body: JSON.stringify({ arguments: { to: 'customer@example.com', body: 'hello' } }),
      });
      const deniedBody = await denied.json() as { error?: { message?: string } };
      expect(denied.status).toBe(403);
      expect(deniedBody.error?.message).toContain('resource mismatch');
    } finally {
      close();
    }
  });

  it('enforces resource-class JIT reason and risk constraints', async () => {
    const { baseUrl, token, close } = await makeHarness();
    try {
      const missingReason = await fetch(`${baseUrl}/v1/elevate`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: ['Bearer', token].join(' ') },
        body: JSON.stringify({ kind: 'tool', name: 'email.send', riskLevel: 'low_risk' }),
      });
      const missingReasonBody = await missingReason.json() as { error?: { message?: string } };
      expect(missingReason.status).toBe(403);
      expect(missingReasonBody.error?.message).toContain('requires an approval reason');

      const highRisk = await fetch(`${baseUrl}/v1/elevate`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: ['Bearer', token].join(' ') },
        body: JSON.stringify({
          kind: 'tool',
          name: 'email.send',
          reason: 'customer update',
          riskLevel: 'high_risk',
        }),
      });
      const highRiskBody = await highRisk.json() as { error?: { message?: string } };
      expect(highRisk.status).toBe(403);
      expect(highRiskBody.error?.message).toContain('high_risk is not allowed');
    } finally {
      close();
    }
  });
});

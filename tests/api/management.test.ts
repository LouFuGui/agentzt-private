import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AgentRegistry, PolicyDoc } from '../../src/shared/types.ts';

const state = vi.hoisted(() => ({
  auditDir: '',
  policy: {
    version: 1,
    defaultDeny: true,
    enterprise: {
      version: 1,
      agentLifecycle: { denyStatuses: ['disabled', 'revoked'] },
      decisionOrder: ['token', 'rbac_or_jit'],
      governance: { projectIds: ['agentzt'] },
    },
    roles: {
      'demo-agent': {
        models: ['claude-sonnet-4-6'],
        tools: ['kb.search'],
      },
    },
  } as PolicyDoc,
  registry: {
    agents: [{
      agentId: 'agent-01',
      role: 'demo-agent',
      publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'public-key' },
      status: 'active',
      governance: { projectId: 'agentzt' },
    }],
  } as AgentRegistry,
}));

vi.mock('../../src/shared/paths.ts', () => ({
  AUDIT_DIR: state.auditDir,
}));

vi.mock('../../src/shared/config.ts', () => ({
  loadPolicy: () => state.policy,
  savePolicy: (policy: PolicyDoc) => {
    state.policy = JSON.parse(JSON.stringify(policy)) as PolicyDoc;
  },
  loadRegistry: () => state.registry,
  saveRegistry: (registry: AgentRegistry) => {
    state.registry = JSON.parse(JSON.stringify(registry)) as AgentRegistry;
  },
}));

const { routeManagementApi } = await import('../../src/api/management.ts');

async function request(port: number, method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
  const response = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: {
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return {
    status: response.status,
    body: await response.json(),
  };
}

describe('enterprise management API', () => {
  let server: ReturnType<typeof createServer>;
  let port: number;
  let root: string;

  beforeEach(async () => {
    root = mkdtempSync(join(tmpdir(), 'agentzt-management-'));
    state.auditDir = join(root, 'audit');
    state.policy = {
      version: 1,
      defaultDeny: true,
      enterprise: {
        version: 1,
        agentLifecycle: { denyStatuses: ['disabled', 'revoked'] },
        decisionOrder: ['token', 'rbac_or_jit'],
        governance: { projectIds: ['agentzt'] },
      },
      roles: {
        'demo-agent': {
          models: ['claude-sonnet-4-6'],
          tools: ['kb.search'],
        },
      },
    };
    state.registry = {
      agents: [{
        agentId: 'agent-01',
        role: 'demo-agent',
        publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'public-key' },
        status: 'active',
        governance: { projectId: 'agentzt' },
      }],
    };
    server = createServer(async (req, res) => {
      if (await routeManagementApi(req, res)) return;
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'not found' }));
    });
    await new Promise<void>((resolve) => {
      server.listen(0, () => {
        port = (server.address() as AddressInfo).port;
        resolve();
      });
    });
  });

  afterEach(() => {
    server.close();
    rmSync(root, { recursive: true, force: true });
  });

  it('requires authenticated users for management reads', async () => {
    const response = await request(port, 'GET', '/api/projects');

    expect(response.status).toBe(401);
    expect(response.body.error.type).toBe('authentication_error');
  });

  it('lists projects and agents for viewers without exposing public keys', async () => {
    const headers = { 'x-user-id': 'viewer-01', 'x-user-role': 'viewer' };

    const projects = await request(port, 'GET', '/api/projects', undefined, headers);
    const agents = await request(port, 'GET', '/api/agents', undefined, headers);

    expect(projects.status).toBe(200);
    expect(projects.body.projects).toEqual(['agentzt']);
    expect(agents.status).toBe(200);
    expect(agents.body.agents[0]).toMatchObject({ agentId: 'agent-01', role: 'demo-agent' });
    expect(JSON.stringify(agents.body)).not.toContain('public-key');
    expect(JSON.stringify(agents.body)).not.toContain('publicKeyJwk');
  });

  it('lets admins add projects, update agents, and upsert roles', async () => {
    const headers = { 'x-user-id': 'admin-01', 'x-user-role': 'admin' };

    const project = await request(port, 'POST', '/api/projects', { projectId: 'payments' }, headers);
    const agent = await request(port, 'PATCH', '/api/agents/agent-01', {
      status: 'disabled',
      description: 'paused by admin',
    }, headers);
    const role = await request(port, 'PUT', '/api/roles/payments-agent', {
      models: ['deepseek-chat'],
      tools: ['kb.search'],
      governance: { projectId: 'payments' },
    }, headers);

    expect(project.status).toBe(201);
    expect(state.policy.enterprise?.governance?.projectIds).toEqual(['agentzt', 'payments']);
    expect(agent.status).toBe(200);
    expect(state.registry.agents[0]?.status).toBe('disabled');
    expect(role.status).toBe(200);
    expect(state.policy.roles['payments-agent']?.models).toEqual(['deepseek-chat']);
  });

  it('denies viewer mutations and returns audit chain status', async () => {
    const viewerHeaders = { 'x-user-id': 'viewer-01', 'x-user-role': 'viewer' };
    const adminHeaders = { 'x-user-id': 'admin-01', 'x-user-role': 'admin' };

    const denied = await request(port, 'POST', '/api/projects', { projectId: 'blocked' }, viewerHeaders);
    const audit = await request(port, 'GET', '/api/audit?limit=10&verify=1', undefined, adminHeaders);

    expect(denied.status).toBe(403);
    expect(audit.status).toBe(200);
    expect(audit.body.events).toEqual([]);
    expect(audit.body.verify).toEqual({ ok: true, count: 0 });
  });
});

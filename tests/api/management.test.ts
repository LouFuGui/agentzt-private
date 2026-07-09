import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AgentRegistry, PolicyDoc } from '../../src/shared/types.ts';

const state = vi.hoisted(() => ({
  auditDir: '',
  sessionService: null as null | {
    verifyToken: (token: string) => { sub: string; role: 'owner' | 'admin' | 'viewer' };
  },
  sandboxRuns: [] as Array<{
    args: Record<string, unknown>;
    ctx: { agentId: string; role: string; requestId: string };
  }>,
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
  get AUDIT_DIR() {
    return state.auditDir;
  },
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

vi.mock('../../src/api/session.ts', () => ({
  getSessionTokenService: () => state.sessionService,
}));

vi.mock('../../src/gateway/tool-registry.ts', () => ({
  getTool: (name: string) => {
    if (name !== 'sandbox.execute') return undefined;
    return {
      name: 'sandbox.execute',
      description: 'test sandbox tool',
      validate: (args: Record<string, unknown>) => {
        const mode = args['mode'] ?? (args['command'] !== undefined ? 'command' : 'code');
        if (mode !== 'command' && mode !== 'code') return 'parameter "mode" must be "command" or "code"';
        if (mode === 'command') {
          if (typeof args['command'] !== 'string') return 'parameter "command" must be a string';
          if (args['code'] !== undefined) return 'command execution must not include "code"';
          return null;
        }
        if (typeof args['code'] !== 'string') return 'parameter "code" must be a string';
        if (args['language'] !== 'python' && args['language'] !== 'javascript' && args['language'] !== 'bash') {
          return 'parameter "language" must be one of: python, javascript, bash';
        }
        if (args['command'] !== undefined) return 'code execution must not include "command"';
        return null;
      },
      run: (args: Record<string, unknown>, ctx: { agentId: string; role: string; requestId: string }) => {
        state.sandboxRuns.push({ args, ctx });
        return { ok: true, output: { sandboxId: 'sbx-test', output: 'ok' } };
      },
    };
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
    state.sessionService = null;
    state.sandboxRuns = [];
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

  it('supports /api/v1 management routes', async () => {
    const headers = { 'x-user-id': 'viewer-01', 'x-user-role': 'viewer' };

    const response = await request(port, 'GET', '/api/v1/projects', undefined, headers);

    expect(response.status).toBe(200);
    expect(response.body.projects).toEqual(['agentzt']);
  });

  it('ignores test user headers when session auth is configured', async () => {
    state.sessionService = {
      verifyToken: (token: string) => {
        if (token !== 'valid-session') throw new Error('invalid token');
        return { sub: 'admin-01', role: 'admin' };
      },
    };

    const bypass = await request(port, 'POST', '/api/projects', { projectId: 'blocked' }, {
      'x-user-id': 'admin-01',
      'x-user-role': 'admin',
    });
    const authenticated = await request(port, 'POST', '/api/projects', { projectId: 'payments' }, {
      authorization: ['Bear', 'er valid-session'].join(''),
    });

    expect(bypass.status).toBe(401);
    expect(authenticated.status).toBe(201);
    expect(state.policy.enterprise?.governance?.projectIds).toEqual(['agentzt', 'payments']);
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

  it('lets admins create and delete agents without returning public keys', async () => {
    const headers = { 'x-user-id': 'admin-01', 'x-user-role': 'admin' };

    const created = await request(port, 'POST', '/api/agents', {
      agentId: 'agent-02',
      role: 'demo-agent',
      publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'second-public-key' },
      governance: { projectId: 'agentzt' },
      description: 'managed from API',
    }, headers);
    const duplicate = await request(port, 'POST', '/api/agents', {
      agentId: 'agent-02',
      role: 'demo-agent',
      publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'duplicate-public-key' },
    }, headers);
    const deleted = await request(port, 'DELETE', '/api/agents/agent-02', undefined, headers);

    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({
      agentId: 'agent-02',
      role: 'demo-agent',
      governance: { projectId: 'agentzt' },
    });
    expect(JSON.stringify(created.body)).not.toContain('second-public-key');
    expect(JSON.stringify(created.body)).not.toContain('publicKeyJwk');
    expect(duplicate.status).toBe(409);
    expect(deleted.status).toBe(200);
    expect(state.registry.agents.map((agent) => agent.agentId)).toEqual(['agent-01']);
  });

  it('filters audit events by agent, project, model, and decision', async () => {
    const headers = { 'x-user-id': 'viewer-01', 'x-user-role': 'viewer' };
    mkdirSync(state.auditDir, { recursive: true });
    writeFileSync(join(state.auditDir, 'gateway-audit.jsonl'), [
      JSON.stringify({
        ts: '2026-06-23T00:00:00.000Z',
        requestId: 'req-1',
        agentId: 'agent-01',
        role: 'demo-agent',
        governance: { projectId: 'agentzt' },
        action: 'model.call',
        resource: 'deepseek-chat',
        decision: 'allow',
        reason: 'ok',
      }),
      JSON.stringify({
        ts: '2026-06-23T00:00:01.000Z',
        requestId: 'req-2',
        agentId: 'agent-02',
        role: 'demo-agent',
        governance: { projectId: 'payments' },
        action: 'model.call',
        resource: 'claude-sonnet-4-6',
        decision: 'deny',
        reason: 'blocked',
      }),
    ].join('\n') + '\n');

    const response = await request(
      port,
      'GET',
      '/api/audit?agentId=agent-01&projectId=agentzt&model=deepseek-chat&decision=allow',
      undefined,
      headers,
    );

    expect(response.status).toBe(200);
    expect(response.body.events).toHaveLength(1);
    expect(response.body.events[0]).toMatchObject({
      requestId: 'req-1',
      agentId: 'agent-01',
      resource: 'deepseek-chat',
      decision: 'allow',
    });
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

  it('lets admins execute the sandbox debug endpoint', async () => {
    const adminHeaders = { 'x-user-id': 'admin-01', 'x-user-role': 'admin' };

    const response = await request(port, 'POST', '/api/v1/sandbox/execute', {
      command: 'echo debug',
    }, adminHeaders);

    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({ ok: true, output: { sandboxId: 'sbx-test' } });
    expect(state.sandboxRuns).toHaveLength(1);
    expect(state.sandboxRuns[0]).toMatchObject({
      args: { command: 'echo debug' },
      ctx: { agentId: 'management:admin-01', role: 'admin' },
    });
    const audit = readFileSync(join(state.auditDir, 'gateway-audit.jsonl'), 'utf8')
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({
      agentId: 'management:admin-01',
      role: 'admin',
      action: 'tool.call',
      resource: 'sandbox.execute',
      decision: 'allow',
      reason: 'management sandbox execute succeeded',
      userId: 'admin-01',
      meta: {
        ok: true,
        authVia: 'management',
      },
    });
  });
});

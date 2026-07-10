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
  gateway: {
    port: 0,
    issuer: 'agentzt-gateway',
    tokenTtlSeconds: 300,
    assertionMaxAgeSeconds: 60,
    upstream: {
      mode: 'mock' as const,
      anthropicBaseUrl: 'https://api.anthropic.com',
      apiKeyEnv: 'AGENTZT_UPSTREAM_ANTHROPIC_KEY',
    },
    sandbox: {
      enabled: true,
      runtime: 'http' as const,
      baseUrl: 'http://127.0.0.1:1',
      executePath: '/v1/sandbox/execute',
      healthPath: '/v1/sandbox/health',
      agentPath: '/v1/sandbox/agents',
      autoStart: false,
      networkAccess: false,
      filesystemAccess: [],
      runtimes: [{ name: 'local-http', type: 'http' as const, enabled: true, capacity: 1 }],
    },
  },
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
  loadGatewayConfig: () => state.gateway,
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
          if (args['command'].trim() === '') return 'parameter "command" must include an executable name';
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

function readBody(req: Parameters<Parameters<typeof createServer>[0]>[0]): Promise<string> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
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
    state.gateway = {
      port: 0,
      issuer: 'agentzt-gateway',
      tokenTtlSeconds: 300,
      assertionMaxAgeSeconds: 60,
      upstream: {
        mode: 'mock',
        anthropicBaseUrl: 'https://api.anthropic.com',
        apiKeyEnv: 'AGENTZT_UPSTREAM_ANTHROPIC_KEY',
      },
      sandbox: {
        enabled: true,
        runtime: 'http',
        baseUrl: 'http://127.0.0.1:1',
        executePath: '/v1/sandbox/execute',
        healthPath: '/v1/sandbox/health',
        agentPath: '/v1/sandbox/agents',
        autoStart: false,
        networkAccess: false,
        filesystemAccess: [],
        runtimes: [{ name: 'local-http', type: 'http', enabled: true, capacity: 1 }],
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

  it('rejects blank sandbox debug commands before execution', async () => {
    const adminHeaders = { 'x-user-id': 'admin-01', 'x-user-role': 'admin' };

    const response = await request(port, 'POST', '/api/v1/sandbox/execute', {
      command: '   ',
    }, adminHeaders);

    expect(response.status).toBe(400);
    expect(response.body.error.message).toBe('parameter "command" must include an executable name');
    expect(state.sandboxRuns).toHaveLength(0);
  });

  it('reports sandbox runtime registry health', async () => {
    const sandboxApi = createServer(async (req, res) => {
      if (req.method === 'GET' && req.url === '/v1/sandbox/health') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise<void>((resolve) => sandboxApi.listen(0, '127.0.0.1', () => resolve()));
    const address = sandboxApi.address() as AddressInfo;
    state.gateway.sandbox.baseUrl = `http://127.0.0.1:${address.port}`;
    try {
      const response = await request(port, 'GET', '/api/v1/sandbox/runtimes', undefined, {
        'x-user-id': 'viewer-01',
        'x-user-role': 'viewer',
      });

      expect(response.status).toBe(200);
      expect(response.body).toMatchObject({
        selected: 'http',
        health: { runtime: 'http', healthy: true },
        runtimes: [{ name: 'local-http', type: 'http', enabled: true }],
      });
    } finally {
      sandboxApi.close();
    }
  });

  it('filters sandbox runtime registry by project role resource and exposes capability declarations', async () => {
    const sandboxApi = createServer(async (req, res) => {
      if (req.method === 'GET' && req.url === '/v1/sandbox/health') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise<void>((resolve) => sandboxApi.listen(0, '127.0.0.1', () => resolve()));
    const address = sandboxApi.address() as AddressInfo;
    state.gateway.sandbox.baseUrl = `http://127.0.0.1:${address.port}`;
    state.gateway.sandbox.runtimes = [
      {
        name: 'default',
        type: 'http',
        enabled: true,
        baseUrl: state.gateway.sandbox.baseUrl,
        capacity: 100,
        priority: 1,
        allowedTenantIds: ['default'],
        allowedRoles: ['viewer'],
        allowedProjectIds: ['agentzt'],
        resources: ['sandbox.execute'],
        capabilities: ['sandbox.execute'],
      },
      {
        name: 'browser-jupyter',
        type: 'http',
        enabled: true,
        baseUrl: state.gateway.sandbox.baseUrl,
        capacity: 1,
        priority: 10,
        allowedTenantIds: ['enterprise'],
        allowedRoles: ['admin'],
        allowedProjectIds: ['agentzt'],
        resources: ['sandbox.browser'],
        capabilities: ['sandbox.browser', 'sandbox.jupyter.execute'],
        capabilityDeclarations: [
          { name: 'sandbox.browser', kind: 'browser', longTasks: true, sessionReuse: true, artifacts: true },
        ],
        orchestration: { longTasks: true, sessionReuse: true, artifacts: true, browser: true, jupyter: true, mcp: false },
      },
    ] as typeof state.gateway.sandbox.runtimes;
    state.gateway.sandbox.scheduling = { policy: 'priority' };
    try {
      const response = await request(
        port,
        'GET',
        '/api/v1/sandbox/runtimes?tenantId=enterprise&role=admin&projectId=agentzt&resource=sandbox.browser',
        undefined,
        { 'x-user-id': 'viewer-01', 'x-user-role': 'viewer' },
      );

      expect(response.status).toBe(200);
      expect(response.body).toMatchObject({
        selected: 'http',
        selectedRuntime: {
          name: 'browser-jupyter',
          capabilityDeclarations: [
            { name: 'sandbox.browser', kind: 'browser', longTasks: true, sessionReuse: true, artifacts: true },
          ],
          orchestration: { browser: true, jupyter: true },
        },
        scheduling: 'priority',
        selection: {
          tenantId: 'enterprise',
          role: 'admin',
          projectId: 'agentzt',
          resource: 'sandbox.browser',
          capability: 'sandbox.browser',
        },
        runtimes: [
          { name: 'default', eligible: false, selected: false, reason: 'tenant "enterprise" is not allowed' },
          { name: 'browser-jupyter', eligible: true, selected: true },
        ],
      });
    } finally {
      sandboxApi.close();
    }
  });

  it('manages agent process sandbox lifecycle through runtime adapter', async () => {
    const calls: string[] = [];
    const sandboxApi = createServer(async (req, res) => {
      const raw = await readBody(req);
      calls.push(`${req.method} ${req.url} ${raw}`);
      res.writeHead(200, { 'content-type': 'application/json' });
      if (req.method === 'POST' && req.url === '/v1/sandbox/agents') {
        res.statusCode = 201;
        res.end(JSON.stringify({ sandboxId: 'agent-sbx-1', runtime: 'http', status: 'created', image: 'alpine' }));
        return;
      }
      if (req.method === 'POST' && req.url === '/v1/sandbox/agents/agent-sbx-1/start') {
        res.end(JSON.stringify({ sandboxId: 'agent-sbx-1', runtime: 'http', status: 'started' }));
        return;
      }
      if (req.method === 'POST' && req.url === '/v1/sandbox/agents/agent-sbx-1/exec') {
        res.end(JSON.stringify({ sandboxId: 'agent-sbx-1', output: 'ran', exitCode: 0 }));
        return;
      }
      if (req.method === 'POST' && req.url === '/v1/sandbox/agents/agent-sbx-1/stop') {
        res.end(JSON.stringify({ sandboxId: 'agent-sbx-1', runtime: 'http', status: 'stopped' }));
        return;
      }
      if (req.method === 'POST' && req.url === '/v1/sandbox/agents/agent-sbx-1/destroy') {
        res.end(JSON.stringify({ sandboxId: 'agent-sbx-1', runtime: 'http', status: 'destroyed' }));
        return;
      }
      res.statusCode = 404;
      res.end(JSON.stringify({ error: 'not found' }));
    });
    await new Promise<void>((resolve) => sandboxApi.listen(0, '127.0.0.1', () => resolve()));
    const address = sandboxApi.address() as AddressInfo;
    state.gateway.sandbox.baseUrl = `http://127.0.0.1:${address.port}`;
    const headers = { 'x-user-id': 'admin-01', 'x-user-role': 'admin' };
    try {
      const created = await request(port, 'POST', '/api/v1/sandbox/agents', { image: 'alpine', projectId: 'agentzt' }, headers);
      const started = await request(port, 'POST', '/api/v1/sandbox/agents/agent-sbx-1/start', undefined, headers);
      const exec = await request(port, 'POST', '/api/v1/sandbox/agents/agent-sbx-1/exec', { command: 'echo inside' }, headers);
      const stopped = await request(port, 'POST', '/api/v1/sandbox/agents/agent-sbx-1/stop', undefined, headers);
      const destroyed = await request(port, 'POST', '/api/v1/sandbox/agents/agent-sbx-1/destroy', undefined, headers);

      expect(created.status).toBe(201);
      expect(started.body.status).toBe('started');
      expect(exec.body.output).toBe('ran');
      expect(stopped.body.status).toBe('stopped');
      expect(destroyed.body.status).toBe('destroyed');
      expect(calls.map((call) => call.split(' ').slice(0, 2).join(' '))).toEqual([
        'POST /v1/sandbox/agents',
        'POST /v1/sandbox/agents/agent-sbx-1/start',
        'POST /v1/sandbox/agents/agent-sbx-1/exec',
        'POST /v1/sandbox/agents/agent-sbx-1/stop',
        'POST /v1/sandbox/agents/agent-sbx-1/destroy',
      ]);
      const audit = readFileSync(join(state.auditDir, 'gateway-audit.jsonl'), 'utf8')
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line) as Record<string, unknown>);
      expect(audit.map((event) => event.action)).toEqual([
        'sandbox.create',
        'sandbox.start',
        'sandbox.exec',
        'sandbox.stop',
        'sandbox.destroy',
      ]);
    } finally {
      sandboxApi.close();
    }
  });
});

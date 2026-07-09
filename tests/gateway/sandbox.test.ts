import { execFileSync } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { FileSandbox } from '../../src/gateway/sandbox.ts';
import type { Server } from 'node:http';

const roots: string[] = [];

type DockerCreateBody = {
  Image: string;
  Cmd: string[];
  HostConfig: {
    NetworkMode: string;
    Memory: number;
  };
};
type HttpRequest = Parameters<Parameters<typeof createServer>[0]>[0];

type HttpSandboxRequest = {
  mode: 'command' | 'code';
  command?: string;
  language?: string;
  code?: string;
};

type SandboxToolResponse = {
  ok: boolean;
  output: {
    output: string;
    metrics: {
      networkAccess: boolean;
    };
  };
};

function makeRoot(): string {
  const root = join(tmpdir(), `agentzt-sandbox-${randomUUID()}`);
  roots.push(root);
  mkdirSync(root, { recursive: true });
  return root;
}

afterEach(() => {
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function writeJsonFile(path: string, value: unknown): void {
  writeFileSync(path, JSON.stringify(value, null, 2) + '\n');
}

function listen(server: Server, socketPath: string): Promise<void> {
  return new Promise((resolve) => server.listen(socketPath, () => resolve()));
}

function readBody(req: HttpRequest): Promise<string> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

async function makeDockerApi(): Promise<{
  socketPath: string;
  close: () => Promise<void>;
  requests: Array<{ method?: string; url?: string; body?: unknown }>;
}> {
  const root = makeRoot();
  const socketPath = join(root, 'docker.sock');
  const requests: Array<{ method?: string; url?: string; body?: unknown }> = [];
  let createRequest: DockerCreateBody | undefined;
  const server = createServer(async (req, res) => {
    const raw = await readBody(req);
    const body = raw ? JSON.parse(raw) : undefined;
    requests.push({ method: req.method, url: req.url, body });

    if (req.method === 'POST' && req.url === '/v1.41/containers/create') {
      createRequest = body as DockerCreateBody;
      res.writeHead(201, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ Id: 'container-1' }));
      return;
    }
    if (req.method === 'GET' && req.url === '/v1.41/_ping') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('OK');
      return;
    }
    if (req.method === 'POST' && req.url === '/v1.41/containers/container-1/start') {
      res.writeHead(204);
      res.end();
      return;
    }
    if (req.method === 'POST' && req.url === '/v1.41/containers/container-1/exec') {
      res.writeHead(201, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ Id: 'exec-1' }));
      return;
    }
    if (req.method === 'POST' && req.url === '/v1.41/exec/exec-1/start') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('exec-output');
      return;
    }
    if (req.method === 'GET' && req.url === '/v1.41/exec/exec-1/json') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ExitCode: 0 }));
      return;
    }
    if (req.method === 'POST' && req.url === '/v1.41/containers/container-1/stop') {
      res.writeHead(204);
      res.end();
      return;
    }
    if (req.method === 'POST' && req.url === '/v1.41/containers/container-1/wait?condition=not-running') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ StatusCode: 0 }));
      return;
    }
    if (req.method === 'GET' && req.url === '/v1.41/containers/container-1/logs?stdout=true&stderr=true') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end(`ran:${createRequest?.Cmd.join(' ') ?? ''}`);
      return;
    }
    if (req.method === 'DELETE' && req.url === '/v1.41/containers/container-1?force=true&v=true') {
      res.writeHead(204);
      res.end();
      return;
    }

    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end(`unexpected ${req.method} ${req.url}`);
  });
  await listen(server, socketPath);
  return {
    socketPath,
    requests,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

async function makeHttpSandboxApi(): Promise<{
  baseUrl: string;
  close: () => Promise<void>;
  requests: HttpSandboxRequest[];
}> {
  const requests: HttpSandboxRequest[] = [];
  const server = createServer(async (req, res) => {
    const raw = await readBody(req);
    if (!raw && req.method === 'POST') {
      res.writeHead(400, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'missing test request body' }));
      return;
    }
    const body = JSON.parse(raw) as HttpSandboxRequest;
    requests.push(body);
    if (req.method === 'POST' && req.url === '/v1/sandbox/execute') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        sandboxId: 'remote-1',
        output: body.mode === 'code' ? `code:${body.language}` : `command:${body.command}`,
        exitCode: 0,
        metrics: { executionTime: 7, memoryLimitMb: 64, networkAccess: false },
      }));
      return;
    }
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end(`unexpected ${req.method} ${req.url}`);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('http sandbox did not bind a TCP port');
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    requests,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

describe('sandbox runtime compatibility', () => {
  it('imports with Node native TypeScript stripping', () => {
    execFileSync(process.execPath, ['-e', "import('./src/gateway/sandbox.ts')"], {
      cwd: process.cwd(),
    });
  });
});

describe('FileSandbox', () => {
  it('allows files under configured roots and denies prefix escapes', async () => {
    const root = makeRoot();
    const allowed = join(root, 'allowed');
    const escaped = join(root, 'allowed-other');
    mkdirSync(allowed);
    mkdirSync(escaped);
    writeFileSync(join(allowed, 'ok.txt'), 'allowed');
    writeFileSync(join(escaped, 'secret.txt'), 'denied');

    const sandbox = new FileSandbox({
      timeout: 1000,
      memoryLimit: 128,
      networkAccess: false,
      filesystemAccess: [allowed],
      env: {},
    });

    const ok = await sandbox.execute('read', { path: join(allowed, 'ok.txt') });
    expect(ok).toMatchObject({ success: true, output: 'allowed' });

    const denied = await sandbox.execute('read', { path: join(escaped, 'secret.txt') });
    expect(denied).toMatchObject({ success: false });
    expect(denied.error).toContain('Access denied');
  });
});

describe('DockerSandboxRuntime', () => {
  it('creates a Docker sandbox, executes a command, reads logs, and removes it', async () => {
    const docker = await makeDockerApi();
    try {
      const { DockerSandboxRuntime } = await import('../../src/gateway/docker-sandbox.ts');
      const runtime = new DockerSandboxRuntime({
        socketPath: docker.socketPath,
        defaultImage: 'alpine:test',
        memoryMb: 128,
        maxMemoryMb: 256,
        networkAccess: false,
      });

      const result = await runtime.execute({ mode: 'command', command: 'echo ok', memoryMb: 256 });

      expect(result).toMatchObject({
        runtime: 'docker',
        mode: 'command',
        image: 'alpine:test',
        command: ['sh', '-c', 'echo ok'],
        exitCode: 0,
        timedOut: false,
      });
      expect(result.output).toContain('ran:sh -c echo ok');
      expect(docker.requests.map((r) => `${r.method} ${r.url}`)).toEqual([
        'POST /v1.41/containers/create',
        'POST /v1.41/containers/container-1/start',
        'POST /v1.41/containers/container-1/wait?condition=not-running',
        'GET /v1.41/containers/container-1/logs?stdout=true&stderr=true',
        'DELETE /v1.41/containers/container-1?force=true&v=true',
      ]);
      const create = docker.requests[0]?.body as DockerCreateBody;
      expect(create.HostConfig).toMatchObject({ NetworkMode: 'none', Memory: 256 * 1024 * 1024 });
    } finally {
      await docker.close();
    }
  });

  it('executes through the generic HTTP sandbox runtime adapter', async () => {
    const httpSandbox = await makeHttpSandboxApi();
    try {
      const { HttpSandboxRuntime } = await import('../../src/gateway/sandbox-runtime.ts');
      const runtime = new HttpSandboxRuntime({
        name: 'opensandbox',
        baseUrl: httpSandbox.baseUrl,
        timeoutMs: 1000,
      });


      const result = await runtime.execute({
        mode: 'code',
        language: 'python',
        code: 'print("ok")',
        memoryMb: 64,
      });

      expect(result).toMatchObject({
        sandboxId: 'remote-1',
        runtime: 'opensandbox',
        mode: 'code',
        language: 'python',
        exitCode: 0,
        output: 'code:python',
        metrics: { executionTime: 7, memoryLimitMb: 64, networkAccess: false },
      });
      expect(httpSandbox.requests).toEqual([{
        mode: 'code',
        language: 'python',
        code: 'print("ok")',
        memoryMb: 64,
      }]);
    } finally {
      await httpSandbox.close();
    }
  });

  it('adapts AIO Sandbox shell and Jupyter endpoints', async () => {
    const requests: Array<{ url?: string; body: unknown }> = [];
    const server = createServer(async (req, res) => {
      const raw = await readBody(req);
      requests.push({ url: req.url, body: raw ? JSON.parse(raw) : undefined });
      res.writeHead(200, { 'content-type': 'application/json' });
      if (req.url === '/v1/shell/exec') {
        res.end(JSON.stringify({ data: { output: 'shell-ok', exit_code: 0 } }));
        return;
      }
      if (req.url === '/v1/jupyter/execute') {
        res.end(JSON.stringify({ data: { output: 'py-ok' } }));
        return;
      }
      res.end(JSON.stringify({ output: 'unexpected' }));
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('aio sandbox did not bind a TCP port');
    try {
      const { AioSandboxRuntime } = await import('../../src/gateway/sandbox-runtime.ts');
      const runtime = new AioSandboxRuntime({
        name: 'aiosandbox',
        baseUrl: `http://127.0.0.1:${address.port}`,
        timeoutMs: 1000,
      });

      const shell = await runtime.execute({ mode: 'command', command: 'echo ok' });
      const python = await runtime.execute({ mode: 'code', language: 'python', code: 'print(1)' });

      expect(shell).toMatchObject({ runtime: 'aiosandbox', exitCode: 0, output: 'shell-ok' });
      expect(python).toMatchObject({ runtime: 'aiosandbox', exitCode: 0, output: 'py-ok' });
      expect(requests).toEqual([
        { url: '/v1/shell/exec', body: { command: 'echo ok' } },
        { url: '/v1/jupyter/execute', body: { code: 'print(1)' } },
      ]);
    } finally {
      server.close();
    }
  });

  it('uses OpenSandbox lifecycle API paths for agent process sandboxes', async () => {
    const calls: Array<{ method?: string; url?: string; body?: unknown }> = [];
    const server = createServer(async (req, res) => {
      const raw = await readBody(req);
      calls.push({ method: req.method, url: req.url, body: raw ? JSON.parse(raw) : undefined });
      res.writeHead(200, { 'content-type': 'application/json' });
      if (req.method === 'POST' && req.url === '/v1/sandboxes') {
        res.end(JSON.stringify({ id: 'osb-1', state: 'Pending', image: 'python:3.12' }));
        return;
      }
      res.end(JSON.stringify({ id: 'osb-1' }));
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('opensandbox did not bind a TCP port');
    try {
      const { OpenSandboxRuntime } = await import('../../src/gateway/sandbox-runtime.ts');
      const runtime = new OpenSandboxRuntime({
        name: 'opensandbox',
        baseUrl: `http://127.0.0.1:${address.port}`,
        timeoutMs: 1000,
      });

      const created = await runtime.createAgent({
        image: 'python:3.12',
        command: 'sleep infinity',
        projectId: 'agentzt',
        agentId: 'agent-01',
        memoryMb: 256,
        networkAccess: false,
      });
      const started = await runtime.startAgent(created.sandboxId);
      const stopped = await runtime.stopAgent(created.sandboxId);
      const destroyed = await runtime.destroyAgent(created.sandboxId);

      expect(created).toMatchObject({ sandboxId: 'osb-1', runtime: 'opensandbox', status: 'created' });
      expect(started.status).toBe('started');
      expect(stopped.status).toBe('stopped');
      expect(destroyed.status).toBe('destroyed');
      expect(calls.map((call) => `${call.method} ${call.url}`)).toEqual([
        'POST /v1/sandboxes',
        'POST /v1/sandboxes/osb-1/resume',
        'POST /v1/sandboxes/osb-1/pause',
        'DELETE /v1/sandboxes/osb-1',
      ]);
      expect(calls[0]?.body).toMatchObject({
        image: 'python:3.12',
        entrypoint: ['sh', '-c', 'sleep infinity'],
        resources: { memory: '256Mi' },
        metadata: { agentId: 'agent-01', projectId: 'agentzt', controlPlane: 'agentzt' },
      });
    } finally {
      server.close();
    }
  });

  it('selects an enabled runtime provider by project and capacity', async () => {
    const hits: string[] = [];
    const makeProvider = async (name: string) => {
      const server = createServer(async (req, res) => {
        await readBody(req);
        hits.push(name);
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ sandboxId: name, output: name, exitCode: 0 }));
      });
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
      const address = server.address();
      if (!address || typeof address === 'string') throw new Error(`${name} did not bind a TCP port`);
      return {
        baseUrl: `http://127.0.0.1:${address.port}`,
        close: () => server.close(),
      };
    };
    const low = await makeProvider('low');
    const high = await makeProvider('high');
    const { createSandboxRuntime } = await import('../../src/gateway/sandbox-runtime.ts');
    try {
      const runtime = createSandboxRuntime({
        enabled: true,
        runtime: 'http',
        baseUrl: low.baseUrl,
        autoStart: false,
        runtimes: [
          { name: 'low', type: 'http', enabled: true, baseUrl: low.baseUrl, capacity: 1, allowedProjectIds: ['agentzt'] },
          { name: 'high', type: 'http', enabled: true, baseUrl: high.baseUrl, capacity: 10, allowedProjectIds: ['agentzt'] },
          { name: 'other-project', type: 'http', enabled: true, baseUrl: low.baseUrl, capacity: 99, allowedProjectIds: ['payments'] },
        ],
      }, { projectId: 'agentzt', capability: 'sandbox.execute' });

      const result = await runtime.execute({ mode: 'command', command: 'echo selected' });

      expect(result.sandboxId).toBe('high');
      expect(hits).toEqual(['high']);
    } finally {
      low.close();
      high.close();
    }
  });

  it('supports Docker agent process sandbox lifecycle', async () => {
    const docker = await makeDockerApi();
    try {
      const { DockerSandboxRuntime } = await import('../../src/gateway/docker-sandbox.ts');
      const runtime = new DockerSandboxRuntime({
        socketPath: docker.socketPath,
        defaultImage: 'alpine:test',
        memoryMb: 64,
        networkAccess: false,
      });

      const health = await runtime.health();
      const created = await runtime.createAgent({ projectId: 'agentzt', agentId: 'agent-01' });
      const started = await runtime.startAgent(created.sandboxId);
      const exec = await runtime.execAgent(created.sandboxId, { mode: 'command', command: 'echo in-agent' });
      const stopped = await runtime.stopAgent(created.sandboxId);
      const destroyed = await runtime.destroyAgent(created.sandboxId);

      expect(health).toEqual({ runtime: 'docker', healthy: true });
      expect(created).toMatchObject({ runtime: 'docker', status: 'created', image: 'alpine:test' });
      expect(started).toMatchObject({ sandboxId: created.sandboxId, status: 'started' });
      expect(exec).toMatchObject({ sandboxId: created.sandboxId, exitCode: 0, output: 'exec-output' });
      expect(stopped.status).toBe('stopped');
      expect(destroyed.status).toBe('destroyed');
      expect(docker.requests.map((r) => `${r.method} ${r.url}`)).toEqual([
        'GET /v1.41/_ping',
        'POST /v1.41/containers/create',
        'POST /v1.41/containers/container-1/start',
        'POST /v1.41/containers/container-1/exec',
        'POST /v1.41/exec/exec-1/start',
        'GET /v1.41/exec/exec-1/json',
        'POST /v1.41/containers/container-1/stop',
        'DELETE /v1.41/containers/container-1?force=true&v=true',
      ]);
    } finally {
      await docker.close();
    }
  });
});

describe('sandbox.execute gateway tool', () => {
  it('authorizes execution through RBAC and records the audited result', async () => {
    const docker = await makeDockerApi();
    const root = makeRoot();
    mkdirSync(join(root, 'config'), { recursive: true });
    process.env.AGENTZT_ROOT = root;
    vi.resetModules();

    try {
      const { generateEd25519 } = await import('../../src/shared/crypto.ts');
      const { AgentIdentity } = await import('../../src/client/identity.ts');
      const { createGatewayServer } = await import('../../src/gateway/server.ts');
      const keys = generateEd25519();
      const agentId = 'sandbox-agent';
      const role = 'sandbox-role';

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
        sandbox: {
          enabled: true,
          runtime: 'docker',
          dockerSocketPath: docker.socketPath,
          defaultImage: 'alpine:test',
          timeoutMs: 1000,
          maxTimeoutMs: 1000,
          memoryMb: 64,
          maxMemoryMb: 128,
          networkAccess: false,
          filesystemAccess: [],
          policy: {
            allowedProjectIds: ['agentzt'],
            allowedCommands: ['echo'],
            allowedLanguages: ['python', 'javascript', 'bash'],
            maxTimeoutMs: 1000,
            maxMemoryMb: 128,
            allowNetworkAccess: false,
          },
        },
      });
      writeJsonFile(join(root, 'config', 'policy.json'), {
        version: 1,
        defaultDeny: true,
        roles: {
          [role]: {
            models: [],
            tools: ['sandbox.execute'],
            limits: { requestsPerMinute: 60 },
          },
        },
      });
      writeJsonFile(join(root, 'config', 'agents.json'), {
        agents: [{
          agentId,
          role,
          publicKeyJwk: keys.publicKeyJwk,
          status: 'active',
          governance: { projectId: 'agentzt' },
        }],
      });

      const identity = new AgentIdentity({
        agentId,
        role,
        publicKeyJwk: keys.publicKeyJwk,
        privateKeyJwk: keys.privateKeyJwk,
        createdAt: new Date().toISOString(),
      });
      const gateway = await createGatewayServer();
      await new Promise<void>((resolve) => gateway.server.listen(0, '127.0.0.1', () => resolve()));
      try {
        const address = gateway.server.address();
        if (!address || typeof address === 'string') throw new Error('gateway did not bind a TCP port');
        const baseUrl = `http://127.0.0.1:${address.port}`;
        const tokenResp = await fetch(`${baseUrl}/v1/token`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ assertion: identity.makeAssertion('agentzt-gateway/v1/token') }),
        });
        const tokenBody = await tokenResp.json() as { access_token: string };
        expect(tokenResp.status).toBe(200);

        const execResp = await fetch(`${baseUrl}/v1/tools/sandbox.execute`, {
          method: 'POST',
          headers: {
            authorization: 'Bearer ' + tokenBody.access_token,
            'content-type': 'application/json',
          },
          body: JSON.stringify({ arguments: { command: 'echo audited', memoryMb: 128 } }),
        });
        const execBody = await execResp.json() as SandboxToolResponse;

        expect(execResp.status).toBe(200);
        expect(execBody.ok).toBe(true);
        expect(execBody.output.output).toContain('echo audited');
        expect(execBody.output.metrics.networkAccess).toBe(false);

        const audit = readFileSync(join(root, '.agentzt', 'audit', 'gateway-audit.jsonl'), 'utf8')
          .trim()
          .split('\n')
          .map((line) => JSON.parse(line) as { action: string; resource: string; decision: string; meta?: Record<string, unknown> });
        const event = audit.find((e) => e.action === 'tool.call' && e.resource === 'sandbox.execute');
        expect(event).toMatchObject({ decision: 'allow' });
        expect(event?.meta).toMatchObject({
          ok: true,
          authVia: 'scope',
          sandbox: {
            runtime: 'docker',
            sandboxId: expect.any(String),
            policyDecision: 'allow',
            resourceLimits: { memoryMb: 128 },
            network: { access: false },
            filesystem: { access: [] },
          },
        });
      } finally {
        await new Promise<void>((resolve) => gateway.server.close(() => resolve()));
      }
    } finally {
      await docker.close();
    }
  });

  it('denies sandbox.execute when command policy rejects the workload', async () => {
    const docker = await makeDockerApi();
    const root = makeRoot();
    mkdirSync(join(root, 'config'), { recursive: true });
    process.env.AGENTZT_ROOT = root;
    vi.resetModules();

    try {
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
        sandbox: {
          enabled: true,
          runtime: 'docker',
          dockerSocketPath: docker.socketPath,
          defaultImage: 'alpine:test',
          policy: {
            allowedCommands: ['echo'],
            allowNetworkAccess: false,
          },
        },
      });
      const { getTool } = await import('../../src/gateway/tool-registry.ts');
      const tool = getTool('sandbox.execute');
      if (!tool) throw new Error('sandbox.execute not found');
      expect(tool.validate({ command: '   ' })).toBe('parameter "command" must include an executable name');

      const result = await tool.run(
        { command: 'rm -rf /workspace' },
        { agentId: 'agent-01', role: 'sandbox-role', requestId: 'req-01' },
      );

      expect(result).toMatchObject({
        ok: false,
        error: 'command "rm" is not allowed by sandbox policy',
        auditMeta: {
          sandbox: {
            policyDecision: 'deny',
            policy: { commandName: 'rm' },
          },
        },
      });
      expect(docker.requests).toHaveLength(0);
    } finally {
      await docker.close();
    }
  });

  it('routes sandbox.shell through the unified sandbox runtime', async () => {
    const docker = await makeDockerApi();
    const root = makeRoot();
    mkdirSync(join(root, 'config'), { recursive: true });
    process.env.AGENTZT_ROOT = root;
    vi.resetModules();

    try {
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
        sandbox: {
          enabled: true,
          runtime: 'docker',
          dockerSocketPath: docker.socketPath,
          defaultImage: 'alpine:test',
          policy: {
            allowedCommands: ['echo'],
            allowNetworkAccess: false,
          },
        },
      });
      const { getTool } = await import('../../src/gateway/tool-registry.ts');
      const tool = getTool('sandbox.shell');
      if (!tool) throw new Error('sandbox.shell not found');

      const result = await tool.run(
        { command: 'echo shell' },
        { agentId: 'agent-01', role: 'sandbox-role', requestId: 'req-shell' },
      );

      expect(result.ok).toBe(true);
      expect(result.output).toMatchObject({ runtime: 'docker', command: ['sh', '-c', 'echo shell'] });
      expect(result.auditMeta).toMatchObject({
        sandbox: {
          capability: 'sandbox.shell',
          runtime: 'docker',
          policyDecision: 'allow',
        },
      });
      expect(docker.requests.map((r) => `${r.method} ${r.url}`)).toContain('POST /v1.41/containers/create');
    } finally {
      await docker.close();
    }
  });

  it('runs sandbox validation before forwarding high-risk model input', async () => {
    const docker = await makeDockerApi();
    const root = makeRoot();
    mkdirSync(join(root, 'config'), { recursive: true });
    process.env.AGENTZT_ROOT = root;
    vi.resetModules();

    try {
      const { generateEd25519 } = await import('../../src/shared/crypto.ts');
      const { AgentIdentity } = await import('../../src/client/identity.ts');
      const { createGatewayServer } = await import('../../src/gateway/server.ts');
      const keys = generateEd25519();
      const agentId = 'model-sandbox-agent';
      const role = 'model-sandbox-role';

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
        sandbox: {
          enabled: true,
          runtime: 'docker',
          dockerSocketPath: docker.socketPath,
          defaultImage: 'alpine:test',
          timeoutMs: 1000,
          maxTimeoutMs: 1000,
          memoryMb: 64,
          maxMemoryMb: 128,
          networkAccess: false,
          modelValidation: {
            enabled: true,
            timeoutMs: 1000,
            memoryMb: 64,
            networkAccess: false,
          },
        },
      });
      writeJsonFile(join(root, 'config', 'policy.json'), {
        version: 1,
        defaultDeny: true,
        roles: {
          [role]: {
            models: ['claude-test'],
            tools: [],
            limits: { requestsPerMinute: 60 },
          },
        },
      });
      writeJsonFile(join(root, 'config', 'agents.json'), {
        agents: [{
          agentId,
          role,
          publicKeyJwk: keys.publicKeyJwk,
          status: 'active',
        }],
      });

      const identity = new AgentIdentity({
        agentId,
        role,
        publicKeyJwk: keys.publicKeyJwk,
        privateKeyJwk: keys.privateKeyJwk,
        createdAt: new Date().toISOString(),
      });
      const gateway = await createGatewayServer();
      await new Promise<void>((resolve) => gateway.server.listen(0, '127.0.0.1', () => resolve()));
      try {
        const address = gateway.server.address();
        if (!address || typeof address === 'string') throw new Error('gateway did not bind a TCP port');
        const baseUrl = `http://127.0.0.1:${address.port}`;
        const tokenResp = await fetch(`${baseUrl}/v1/token`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ assertion: identity.makeAssertion('agentzt-gateway/v1/token') }),
        });
        const tokenBody = await tokenResp.json() as { access_token: string };
        const modelResp = await fetch(`${baseUrl}/v1/messages`, {
          method: 'POST',
          headers: {
            authorization: 'Bearer ' + tokenBody.access_token,
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            model: 'claude-test',
            max_tokens: 32,
            messages: [{ role: 'user', content: 'validate this:\n```bash\necho ok\n```' }],
          }),
        });

        expect(modelResp.status).toBe(200);
        const validationCreate = docker.requests.find((r) =>
          r.method === 'POST'
          && r.url === '/v1.41/containers/create'
          && (r.body as DockerCreateBody).Cmd?.join('\n').includes('/tmp/agentzt-validate.sh'));
        expect(validationCreate).toBeDefined();
        const validationBody = validationCreate?.body as DockerCreateBody;
        expect(validationBody.Cmd.join('\n')).toContain('sh -n /tmp/agentzt-validate.sh');
        const audit = readFileSync(join(root, '.agentzt', 'audit', 'gateway-audit.jsonl'), 'utf8')
          .trim()
          .split('\n')
          .map((line) => JSON.parse(line) as { action: string; resource: string; meta?: Record<string, unknown> });
        const event = audit.find((e) => e.action === 'model.call' && e.resource === 'claude-test');
        expect(event?.meta?.inputSandboxValidation).toEqual([expect.objectContaining({ stage: 'input', kind: 'bash', exitCode: 0 })]);
      } finally {
        await new Promise<void>((resolve) => gateway.server.close(() => resolve()));
      }
    } finally {
      await docker.close();
    }
  });
});

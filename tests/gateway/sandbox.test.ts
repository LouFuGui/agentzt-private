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
  const server = createServer(async (req, res) => {
    const raw = await readBody(req);
    const body = raw ? JSON.parse(raw) : undefined;
    requests.push({ method: req.method, url: req.url, body });

    if (req.method === 'POST' && req.url === '/v1.41/containers/create') {
      res.writeHead(201, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ Id: 'container-1' }));
      return;
    }
    if (req.method === 'POST' && req.url === '/v1.41/containers/container-1/start') {
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
      const createBody = requests.find((r) => r.url === '/v1.41/containers/create')?.body as DockerCreateBody | undefined;
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end(`ran:${createBody?.Cmd.join(' ') ?? ''}`);
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
        mode: 'command',
        image: 'alpine:test',
        command: ['sh', '-lc', 'echo ok'],
        exitCode: 0,
        timedOut: false,
      });
      expect(result.output).toContain('ran:sh -lc echo ok');
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
        const execBody = await execResp.json() as { ok: boolean; output: { output: string; metrics: { networkAccess: boolean } } };

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
        expect(event?.meta).toMatchObject({ ok: true, authVia: 'scope' });
      } finally {
        await new Promise<void>((resolve) => gateway.server.close(() => resolve()));
      }
    } finally {
      await docker.close();
    }
  });
});

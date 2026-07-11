import { createServer } from 'node:http';
import { describe, expect, it } from 'vitest';
import { OpaClient, resolveOpaConfig, sanitizeForOpa } from '../../src/gateway/opa-client.ts';

function withOpa(handler: (body: any) => unknown) {
  return new Promise<{ url: string; seen: any[]; close: () => void }>((resolve) => {
    const seen: any[] = [];
    const server = createServer((req, res) => {
      let raw = '';
      req.on('data', (chunk) => (raw += chunk));
      req.on('end', () => {
        const body = JSON.parse(raw);
        seen.push({ path: req.url, body });
        const result = handler(body);
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ result }));
      });
    });
    server.listen(0, () => {
      const port = (server.address() as { port: number }).port;
      resolve({ url: `http://127.0.0.1:${port}`, seen, close: () => server.close() });
    });
  });
}

const input = {
  agentId: 'agent-1',
  role: 'demo-agent',
  action: 'tool.call' as const,
  resource: { kind: 'tool' as const, name: 'kb.search' },
  authVia: 'scope' as const,
  now: '2026-01-01T00:00:00.000Z',
};

describe('OPA client', () => {
  it('posts input to the configured data policy path and allows object decisions with reason', async () => {
    const opa = await withOpa(() => ({ allow: true, reason: 'rego allow' }));
    try {
      const client = new OpaClient({
        enabled: true,
        baseUrl: opa.url,
        policyPath: 'agentzt/authz/decision',
        timeoutMs: 1000,
        failOpen: false,
      });
      const decision = await client.decide(input);
      expect(decision).toEqual({ allow: true, reason: 'rego allow' });
      expect(opa.seen[0].path).toBe('/v1/data/agentzt/authz/decision');
      expect(opa.seen[0].body.input.resource.name).toBe('kb.search');
    } finally {
      opa.close();
    }
  });

  it('supports boolean deny results', async () => {
    const opa = await withOpa(() => false);
    try {
      const client = new OpaClient({
        enabled: true,
        baseUrl: opa.url,
        policyPath: 'agentzt/authz/allow',
        timeoutMs: 1000,
        failOpen: false,
      });
      await expect(client.decide(input)).resolves.toEqual({ allow: false, reason: 'OPA denied' });
      expect(opa.seen[0].path).toBe('/v1/data/agentzt/authz/allow');
    } finally {
      opa.close();
    }
  });

  it('fails closed on outage unless failOpen is enabled', async () => {
    const closed = new OpaClient({
      enabled: true,
      baseUrl: 'http://127.0.0.1:1',
      policyPath: 'agentzt/authz/decision',
      timeoutMs: 50,
      failOpen: false,
    });
    const open = new OpaClient({ ...closed.config, failOpen: true });

    expect((await closed.decide(input)).allow).toBe(false);
    const decision = await open.decide(input);
    expect(decision.allow).toBe(true);
    expect(decision.reason).toContain('fail-open');
  });

  it('resolves config only when explicitly enabled', () => {
    expect(resolveOpaConfig()).toBeNull();
    expect(resolveOpaConfig({
      enabled: true,
      baseUrl: 'http://opa:8181',
      policyPath: 'agentzt/authz/decision',
      timeoutMs: 500,
      failOpen: false,
    })?.baseUrl).toBe('http://opa:8181');
  });

  it('posts request.arguments when present in the input', async () => {
    const opa = await withOpa(() => ({ allow: true, reason: 'rego allow' }));
    try {
      const client = new OpaClient({
        enabled: true,
        baseUrl: opa.url,
        policyPath: 'agentzt/authz/decision',
        timeoutMs: 1000,
        failOpen: false,
      });
      const inputWithArgs = {
        ...input,
        request: { arguments: { query: 'zero trust telemetry' } },
      };
      await client.decide(inputWithArgs);
      expect(opa.seen[0].body.input.request.arguments.query).toBe('zero trust telemetry');
    } finally {
      opa.close();
    }
  });

  it('sanitizeForOpa redacts sensitive keys and preserves non-sensitive scalars', () => {
    const raw = {
      query: 'zero trust',
      password: 'hunter2',
      secret: 's3cr3t',
      token: 'tok-abc',
      apiKey: 'sk-123',
      api_key: 'sk-456',
      authorization: '******',
      credential: 'cred',
      key: 'private-key-value',
      nested: {
        host: 'example.com',
        secret: 'nested-secret',
      },
    };
    const sanitized = sanitizeForOpa(raw) as Record<string, unknown>;

    // Non-sensitive values are preserved.
    expect(sanitized['query']).toBe('zero trust');
    expect((sanitized['nested'] as Record<string, unknown>)['host']).toBe('example.com');

    // Sensitive keys at all depths are redacted.
    expect(sanitized['password']).toBe('[redacted]');
    expect(sanitized['secret']).toBe('[redacted]');
    expect(sanitized['token']).toBe('[redacted]');
    expect(sanitized['apiKey']).toBe('[redacted]');
    expect(sanitized['api_key']).toBe('[redacted]');
    expect(sanitized['authorization']).toBe('[redacted]');
    expect(sanitized['credential']).toBe('[redacted]');
    expect(sanitized['key']).toBe('[redacted]');
    expect((sanitized['nested'] as Record<string, unknown>)['secret']).toBe('[redacted]');
  });

  it('sanitizeForOpa truncates long strings', () => {
    const long = 'x'.repeat(300);
    const result = sanitizeForOpa(long) as string;
    expect(result.length).toBeLessThan(300);
    expect(result).toContain('…');
  });

  it('OpaClient can deny based on tool query argument via Rego-like policy', async () => {
    // Simulate a Rego policy that denies when query contains 'opa-block'.
    const opa = await withOpa((body: any) => {
      const query = body?.input?.request?.arguments?.query ?? '';
      if (typeof query === 'string' && query.includes('opa-block')) {
        return { allow: false, reason: 'query blocked by policy' };
      }
      return { allow: true, reason: 'rego allow' };
    });
    try {
      const client = new OpaClient({
        enabled: true,
        baseUrl: opa.url,
        policyPath: 'agentzt/authz/decision',
        timeoutMs: 1000,
        failOpen: false,
      });

      // Normal query is allowed.
      const allow = await client.decide({
        ...input,
        request: { arguments: { query: 'normal zero trust telemetry' } },
      });
      expect(allow.allow).toBe(true);

      // Blocked query is denied with the Rego reason.
      const deny = await client.decide({
        ...input,
        request: { arguments: { query: 'opa-block zero trust telemetry' } },
      });
      expect(deny.allow).toBe(false);
      expect(deny.reason).toBe('query blocked by policy');
    } finally {
      opa.close();
    }
  });
});

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
  const root = join(tmpdir(), `agentzt-direct-model-${randomUUID()}`);
  roots.push(root);
  mkdirSync(join(root, 'config'), { recursive: true });
  process.env.AGENTZT_ROOT = root;
  vi.resetModules();

  writeJsonFile(join(root, 'config', 'gateway.json'), {
    port: 0,
    issuer: 'agentzt-gateway',
    tokenTtlSeconds: 300,
    assertionMaxAgeSeconds: 60,
    upstream: {
      mode: 'passthrough',
      anthropicBaseUrl: 'https://anthropic.example',
      apiKeyEnv: 'ANTHROPIC_TEST_KEY',
      routes: [{ pattern: 'deepseek-*', provider: 'missing-provider', priority: 1 }],
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
    roles: {},
  });
  writeJsonFile(join(root, 'config', 'agents.json'), { agents: [] });

  const { createGatewayServer } = await import('../../src/gateway/server.ts');
  const { getAppStore, resetAppStore } = await import('../../src/api/app-store.ts');
  const gateway = await createGatewayServer();
  await new Promise<void>((resolve) => {
    gateway.server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = gateway.server.address();
  if (!address || typeof address === 'string') throw new Error('gateway did not bind a TCP port');
  const app = getAppStore().createApp('Direct Model Test', 'user_test', 'business');
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    modelApiKey: app.modelApiKey,
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

describe('direct model access', () => {
  it('propagates upstream provider misconfiguration errors', async () => {
    const { baseUrl, modelApiKey, close } = await makeHarness();
    try {
      const response = await fetch(`${baseUrl}/v1/chat/completions`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: ['Bearer', modelApiKey].join(' '),
        },
        body: JSON.stringify({
          model: 'deepseek-chat',
          messages: [{ role: 'user', content: 'hello' }],
        }),
      });
      const body = await response.json() as { error?: { type?: string; message?: string } };

      expect(response.status).toBe(502);
      expect(body.error).toMatchObject({
        type: 'upstream_misconfigured',
        message: 'upstream provider "missing-provider" is not configured',
      });
    } finally {
      close();
    }
  });
});

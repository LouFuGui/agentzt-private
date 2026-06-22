import { describe, expect, it } from 'vitest';
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { VaultClient } from '../../src/gateway/vault-client.ts';
import { resolveVaultConfig } from '../../src/gateway/vault-config.ts';

describe('VaultClient', () => {
  it('reads KV v2 model API keys using the configured token', async () => {
    const server = createServer((req: IncomingMessage, res: ServerResponse) => {
      expect(req.headers['x-vault-token']).toBe('vault-token-test');
      if (req.url === '/v1/secret/data/agentzt/upstream-anthropic-key') {
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ data: { data: { key: 'model-key-from-vault' } } }));
        return;
      }
      res.statusCode = 404;
      res.end(JSON.stringify({ errors: ['missing'] }));
    });
    await new Promise<void>((resolve) => server.listen(0, resolve));

    try {
      const address = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      const client = new VaultClient({
        enabled: true,
        server: { address },
        auth: { method: 'token', token: 'vault-token-test' },
        cache: { enabled: false },
      });
      await client.init();
      await expect(client.getModelApiKey()).resolves.toBe('model-key-from-vault');
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it('resolves token auth from environment overrides', () => {
    const prevAddr = process.env.VAULT_ADDR;
    const prevToken = process.env.VAULT_TOKEN;
    process.env.VAULT_ADDR = 'http://vault.example.test:8200';
    process.env.VAULT_TOKEN = 'vault-token-env';
    try {
      const config = resolveVaultConfig({ enabled: false });
      expect(config?.enabled).toBe(true);
      expect(config?.server.address).toBe('http://vault.example.test:8200');
      expect(config?.auth).toEqual({ method: 'token', token: 'vault-token-env' });
    } finally {
      if (prevAddr === undefined) delete process.env.VAULT_ADDR;
      else process.env.VAULT_ADDR = prevAddr;
      if (prevToken === undefined) delete process.env.VAULT_TOKEN;
      else process.env.VAULT_TOKEN = prevToken;
    }
  });
});

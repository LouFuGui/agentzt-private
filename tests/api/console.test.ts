import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { routeConsole } from '../../src/api/console.ts';

async function text(port: number, method: string, path: string) {
  const response = await fetch(`http://127.0.0.1:${port}${path}`, { method });
  return {
    status: response.status,
    type: response.headers.get('content-type'),
    body: await response.text(),
  };
}

describe('minimal web console', () => {
  let server: ReturnType<typeof createServer>;
  let port: number;

  beforeEach(async () => {
    server = createServer((req, res) => {
      if (routeConsole(req, res)) return;
      res.writeHead(404);
      res.end('not found');
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
  });

  it('serves the console entrypoint and assets', async () => {
    const html = await text(port, 'GET', '/console');
    const js = await text(port, 'GET', '/console/app.js');
    const css = await text(port, 'GET', '/console/styles.css');

    expect(html.status).toBe(200);
    expect(html.type).toContain('text/html');
    expect(html.body).toContain('AgentZT Console');
    expect(html.body).toContain('login-form');
    expect(html.body).toContain('export-audit');
    expect(html.body).toContain('sandbox-demo');
    expect(html.body).toContain('sandbox-demo-form');
    expect(js.status).toBe(200);
    expect(js.type).toContain('text/javascript');
    expect(js.body).toContain('/api/auth/login');
    expect(js.body).toContain('/api/v1/agents');
    expect(js.body).toContain('/api/v1/sandbox/runtimes');
    expect(js.body).toContain('/api/v1/sandbox/execute');
    expect(js.body).toContain('UNSANDBOXED IMPACT SIMULATION');
    expect(js.body).toContain('URL.createObjectURL');
    expect(css.status).toBe(200);
    expect(css.type).toContain('text/css');
    expect(css.body).toContain('demo-grid');
  });

  it('does not serve arbitrary paths', async () => {
    const response = await text(port, 'GET', '/console/../config/policy.json');

    expect(response.status).toBe(404);
    expect(response.body).toBe('not found');
  });
});

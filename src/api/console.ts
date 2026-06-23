import { readFileSync } from 'node:fs';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'console');
const ASSETS: Record<string, { file: string; type: string }> = {
  '/console': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/console/': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/console/index.html': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/console/styles.css': { file: 'styles.css', type: 'text/css; charset=utf-8' },
  '/console/app.js': { file: 'app.js', type: 'text/javascript; charset=utf-8' },
};

function sendText(res: ServerResponse, status: number, body: string, type: string): void {
  res.writeHead(status, {
    'content-type': type,
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  res.end(body);
}

export function routeConsole(req: IncomingMessage, res: ServerResponse): boolean {
  const method = req.method ?? 'GET';
  if (method !== 'GET' && method !== 'HEAD') return false;
  const path = new URL(req.url ?? '/', 'http://localhost').pathname;
  const asset = ASSETS[path];
  if (!asset) return false;
  const body = method === 'HEAD' ? '' : readFileSync(join(ROOT, asset.file), 'utf8');
  sendText(res, 200, body, asset.type);
  return true;
}

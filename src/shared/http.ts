import type { IncomingMessage, ServerResponse } from 'node:http';

export const REQUEST_ID_HEADER = 'x-agentzt-request-id';
export const AGENT_ID_HEADER = 'x-agentzt-agent-id';
// Agent declares intent to elevate (e.g. "tool:email.send"); the client proxy
// fulfils it via /v1/elevate and attaches the resulting grant on this header.
export const ELEVATE_HEADER = 'x-agentzt-elevate';
export const ELEVATION_HEADER = 'x-agentzt-elevation';

export async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

export async function readJson<T = unknown>(req: IncomingMessage): Promise<T> {
  const body = await readBody(req);
  if (body.length === 0) return {} as T;
  return JSON.parse(body.toString('utf8')) as T;
}

export function sendJson(
  res: ServerResponse,
  status: number,
  obj: unknown,
  headers: Record<string, string> = {},
): void {
  const payload = JSON.stringify(obj);
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(payload),
    ...headers,
  });
  res.end(payload);
}

/** Anthropic-style error envelope so SDK clients parse failures cleanly. */
export function sendError(
  res: ServerResponse,
  status: number,
  type: string,
  message: string,
): void {
  sendJson(res, status, { type: 'error', error: { type, message } });
}

export function bearerToken(req: IncomingMessage): string | null {
  const auth = req.headers['authorization'];
  if (!auth || Array.isArray(auth)) return null;
  const m = /^Bearer\s+(.+)$/i.exec(auth);
  return m ? (m[1] as string) : null;
}

export function headerValue(req: IncomingMessage, name: string): string | null {
  const v = req.headers[name.toLowerCase()];
  if (Array.isArray(v)) return v[0] ?? null;
  return v ?? null;
}

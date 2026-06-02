import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse, Server } from 'node:http';
import { resolve } from 'node:path';
import {
  readBody,
  sendJson,
  sendError,
  headerValue,
  REQUEST_ID_HEADER,
  AGENT_ID_HEADER,
  ELEVATE_HEADER,
  ELEVATION_HEADER,
} from '../shared/http.ts';
import { newId } from '../shared/crypto.ts';
import { makeLogger } from '../shared/log.ts';
import { AuditLogger } from '../shared/audit.ts';
import { AUDIT_DIR } from '../shared/paths.ts';
import type { AgentIdentity } from './identity.ts';
import type { TokenClient } from './token-client.ts';

const log = makeLogger('client');

export type ClientProxyOptions = {
  identity: AgentIdentity;
  tokens: TokenClient;
  gatewayUrl: string;
  listenPort: number;
};

/**
 * The agentzt-client local proxy. The agent points its model SDK at this proxy
 * (e.g. ANTHROPIC_BASE_URL=http://localhost:8787) and calls tools via it. The
 * proxy attaches the agent's identity (a fresh access token) to every request
 * and forwards to the gateway. The agent never holds the access token, the
 * enterprise API key, or the gateway's trust material.
 */
export function createClientProxy(opts: ClientProxyOptions): { server: Server; port: number } {
  const gatewayUrl = opts.gatewayUrl.replace(/\/$/, '');
  const audit = new AuditLogger(
    resolve(AUDIT_DIR, `client-${opts.identity.agentId}-audit.jsonl`),
  );

  // JIT elevation grants, cached per resource until shortly before expiry. The
  // agent only declares intent (x-agentzt-elevate: "tool:email.send"); the
  // client performs the /v1/elevate exchange and attaches the grant.
  const grants = new Map<string, { grant: string; expiresAt: number }>();

  async function getElevation(spec: string, rid: string): Promise<string | null> {
    const [kind, ...rest] = spec.split(':');
    const name = rest.join(':');
    if ((kind !== 'model' && kind !== 'tool') || !name) return null;
    const key = `${kind}:${name}`;
    const now = Math.floor(Date.now() / 1000);
    const cached = grants.get(key);
    if (cached && cached.expiresAt - 5 > now) return cached.grant;

    const token = await opts.tokens.getToken();
    const resp = await fetch(`${gatewayUrl}/v1/elevate`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${token}`,
        [REQUEST_ID_HEADER]: rid,
      },
      body: JSON.stringify({ kind, name, reason: 'agent-requested JIT elevation' }),
    });
    if (!resp.ok) {
      log.deny(`elevation request ${key} -> ${resp.status} rid=${rid}`);
      return null;
    }
    const data = (await resp.json()) as { elevation_grant: string; expires_in: number };
    grants.set(key, { grant: data.elevation_grant, expiresAt: now + data.expires_in });
    log.allow(`elevation granted ${key} (ttl=${data.expires_in}s) rid=${rid}`);
    return data.elevation_grant;
  }

  async function forward(
    req: IncomingMessage,
    res: ServerResponse,
    targetPath: string,
    action: 'model.call' | 'tool.call',
    resource: string,
  ) {
    const rid = headerValue(req, REQUEST_ID_HEADER) ?? newId('req');
    const started = Date.now();
    const body = await readBody(req);
    let token: string;
    try {
      token = await opts.tokens.getToken();
    } catch (err) {
      log.error(`could not obtain token: ${(err as Error).message}`);
      return sendError(res, 502, 'identity_error', (err as Error).message);
    }

    const headers: Record<string, string> = {
      'content-type': req.headers['content-type'] ?? 'application/json',
      authorization: `Bearer ${token}`,
      [REQUEST_ID_HEADER]: rid,
      [AGENT_ID_HEADER]: opts.identity.agentId,
    };

    // Fulfil a JIT elevation request declared by the agent.
    const elevateSpec = headerValue(req, ELEVATE_HEADER);
    if (elevateSpec) {
      const grant = await getElevation(elevateSpec, rid);
      if (grant) headers[ELEVATION_HEADER] = grant;
    }

    const resp = await fetch(`${gatewayUrl}${targetPath}`, { method: 'POST', headers, body });
    const respBody = Buffer.from(await resp.arrayBuffer());
    const latencyMs = Date.now() - started;

    audit.record({
      requestId: rid,
      agentId: opts.identity.agentId,
      role: opts.identity.role,
      action,
      resource,
      decision: resp.ok ? 'allow' : 'deny',
      reason: `gateway responded ${resp.status}`,
      latencyMs,
    });
    if (resp.ok) log.allow(`${action} ${resource} -> ${resp.status} (${latencyMs}ms) rid=${rid}`);
    else log.deny(`${action} ${resource} -> ${resp.status} (${latencyMs}ms) rid=${rid}`);

    res.writeHead(resp.status, {
      'content-type': resp.headers.get('content-type') ?? 'application/json',
      [REQUEST_ID_HEADER]: rid,
    });
    res.end(respBody);
  }

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const path = url.pathname;
    const method = req.method ?? 'GET';

    try {
      if (method === 'GET' && path === '/healthz') {
        return sendJson(res, 200, { status: 'ok', agentId: opts.identity.agentId });
      }
      if (method === 'GET' && path === '/agentzt/scope') {
        const scope = await opts.tokens.scope();
        return sendJson(res, 200, { agentId: opts.identity.agentId, role: opts.identity.role, scope });
      }
      if (method === 'POST' && path === '/v1/messages') {
        const peeked = await peekModel(req);
        return await forward(peeked.req, res, '/v1/messages', 'model.call', peeked.model);
      }
      if (method === 'POST' && path.startsWith('/v1/tools/')) {
        const name = decodeURIComponent(path.slice('/v1/tools/'.length));
        return await forward(req, res, `/v1/tools/${encodeURIComponent(name)}`, 'tool.call', name);
      }
      return sendError(res, 404, 'not_found', `no route for ${method} ${path}`);
    } catch (err) {
      log.error(`proxy error on ${method} ${path}: ${(err as Error).message}`);
      return sendError(res, 500, 'internal_error', 'client proxy error');
    }
  });

  return { server, port: opts.listenPort };
}

// Read the body once to learn the model name for logging, then hand a
// replayable request to forward().
async function peekModel(req: IncomingMessage): Promise<{ req: IncomingMessage; model: string }> {
  const body = await readBody(req);
  let model = 'unknown';
  try {
    const parsed = JSON.parse(body.toString('utf8')) as { model?: string };
    if (parsed.model) model = parsed.model;
  } catch {
    /* leave as unknown */
  }
  // Re-expose the already-consumed body as an async-iterable stream.
  const replay = Object.assign(req, {
    [Symbol.asyncIterator]: async function* () {
      yield body;
    },
  }) as unknown as IncomingMessage;
  return { req: replay, model };
}

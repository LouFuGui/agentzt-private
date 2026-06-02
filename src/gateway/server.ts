import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse, Server } from 'node:http';
import {
  readJson,
  sendJson,
  sendError,
  bearerToken,
  headerValue,
  REQUEST_ID_HEADER,
} from '../shared/http.ts';
import { newId } from '../shared/crypto.ts';
import { makeLogger } from '../shared/log.ts';
import { AuditLogger } from '../shared/audit.ts';
import { AUDIT_DIR } from '../shared/paths.ts';
import { resolve } from 'node:path';
import { loadGatewayConfig, loadPolicy } from '../shared/config.ts';
import { loadOrCreateGatewayKey } from './gateway-key.ts';
import { IdentityStore } from './identity-store.ts';
import { PolicyEngine } from './policy-engine.ts';
import { TokenService } from './token-service.ts';
import { RateLimiter } from './rate-limiter.ts';
import { callModel } from './upstream.ts';
import { getTool } from './tool-registry.ts';
import type { AccessTokenClaims } from '../shared/types.ts';

const log = makeLogger('gateway');

export function createGatewayServer(): { server: Server; port: number } {
  const cfg = loadGatewayConfig();
  const policy = new PolicyEngine(loadPolicy());
  const identities = new IdentityStore();
  const key = loadOrCreateGatewayKey();
  const tokens = new TokenService(cfg, identities, policy, key);
  const limiter = new RateLimiter(60_000);
  const audit = new AuditLogger(resolve(AUDIT_DIR, 'gateway-audit.jsonl'));

  log.info(`loaded ${identities.size()} registered agent identit(ies)`);
  log.info(`upstream model mode: ${cfg.upstream.mode}`);

  const tokenAudience = `${cfg.issuer}/v1/token`;

  function requestId(req: IncomingMessage): string {
    return headerValue(req, REQUEST_ID_HEADER) ?? newId('req');
  }

  // Verify bearer token; on failure write the response and return null.
  function authorize(
    req: IncomingMessage,
    res: ServerResponse,
  ): AccessTokenClaims | null {
    const token = bearerToken(req);
    if (!token) {
      sendError(res, 401, 'authentication_error', 'missing bearer token');
      return null;
    }
    try {
      return tokens.verifyAccessToken(token);
    } catch (err) {
      sendError(res, 401, 'authentication_error', (err as Error).message);
      return null;
    }
  }

  const server = createServer(async (req, res) => {
    const rid = requestId(req);
    res.setHeader(REQUEST_ID_HEADER, rid);
    const url = new URL(req.url ?? '/', 'http://localhost');
    const path = url.pathname;
    const method = req.method ?? 'GET';

    try {
      if (method === 'GET' && path === '/healthz') {
        return sendJson(res, 200, { status: 'ok', issuer: cfg.issuer });
      }

      if (method === 'GET' && path === '/.well-known/agentzt-jwks') {
        // Publish the gateway public key so resource servers can verify tokens.
        return sendJson(res, 200, {
          issuer: cfg.issuer,
          keys: [{ ...key.publicKeyJwk, use: 'sig', alg: 'EdDSA', kid: cfg.issuer }],
        });
      }

      if (method === 'POST' && path === '/v1/token') {
        return await handleToken(req, res, rid);
      }

      if (method === 'POST' && path === '/v1/messages') {
        return await handleMessages(req, res, rid);
      }

      if (method === 'POST' && path.startsWith('/v1/tools/')) {
        const name = decodeURIComponent(path.slice('/v1/tools/'.length));
        return await handleTool(req, res, rid, name);
      }

      return sendError(res, 404, 'not_found', `no route for ${method} ${path}`);
    } catch (err) {
      log.error(`unhandled error on ${method} ${path}: ${(err as Error).message}`);
      return sendError(res, 500, 'internal_error', 'internal error');
    }
  });

  async function handleToken(req: IncomingMessage, res: ServerResponse, rid: string) {
    const body = await readJson<{ assertion?: string }>(req);
    if (!body.assertion) {
      return sendError(res, 400, 'invalid_request', 'missing "assertion"');
    }
    const result = tokens.issue(body.assertion, tokenAudience);
    if (!result.ok) {
      audit.record({
        requestId: rid,
        agentId: result.agentId,
        role: null,
        action: 'token.reject',
        resource: tokenAudience,
        decision: 'deny',
        reason: result.reason,
      });
      log.deny(`token request from ${result.agentId ?? 'unknown'}: ${result.reason}`);
      return sendError(res, result.status, 'authentication_error', result.reason);
    }
    audit.record({
      requestId: rid,
      agentId: result.agentId,
      role: result.role,
      action: 'token.issue',
      resource: tokenAudience,
      decision: 'allow',
      reason: 'valid client assertion',
      meta: { exp: result.claims.exp, scope: result.claims.scope },
    });
    log.allow(`token issued to ${result.agentId} (role=${result.role}, ttl=${cfg.tokenTtlSeconds}s)`);
    return sendJson(res, 200, {
      access_token: result.token,
      token_type: 'Bearer',
      expires_in: cfg.tokenTtlSeconds,
      scope: result.claims.scope,
    });
  }

  async function handleMessages(req: IncomingMessage, res: ServerResponse, rid: string) {
    const claims = authorize(req, res);
    if (!claims) return;
    const started = Date.now();
    const body = await readJson<Record<string, unknown>>(req);
    const model = typeof body['model'] === 'string' ? (body['model'] as string) : '';
    if (!model) return sendError(res, 400, 'invalid_request', 'missing "model"');

    // 1) Scope check (the token's snapshot) then 2) live policy check.
    const inScope = claims.scope.models.includes('*') || claims.scope.models.includes(model);
    const decision = policy.decideModel(claims.role, model);
    if (!inScope || !decision.allow) {
      const reason = !inScope ? `model "${model}" not in token scope` : decision.reason;
      audit.record({
        requestId: rid, agentId: claims.sub, role: claims.role,
        action: 'model.call', resource: model, decision: 'deny', reason,
      });
      log.deny(`model.call ${claims.sub} -> ${model}: ${reason}`);
      return sendError(res, 403, 'permission_error', reason);
    }

    // Rate limit (resource-exhaustion containment).
    const limits = policy.limitsForRole(claims.role);
    const rl = limiter.check(`model:${claims.sub}`, limits.requestsPerMinute);
    if (!rl.allowed) {
      audit.record({
        requestId: rid, agentId: claims.sub, role: claims.role,
        action: 'model.call', resource: model, decision: 'deny',
        reason: `rate limit ${limits.requestsPerMinute}/min exceeded`,
      });
      return sendError(res, 429, 'rate_limit_error', 'requests per minute exceeded');
    }

    // Clamp max_tokens to the role cap (output control).
    if (limits.maxOutputTokens) {
      const requested = Number(body['max_tokens'] ?? limits.maxOutputTokens);
      body['max_tokens'] = Math.min(requested, limits.maxOutputTokens);
    }

    const result = await callModel(cfg, { model, body });
    const latencyMs = Date.now() - started;
    audit.record({
      requestId: rid, agentId: claims.sub, role: claims.role,
      action: 'model.call', resource: model, decision: 'allow',
      reason: decision.reason, latencyMs,
      meta: {
        upstreamStatus: result.status,
        usage: result.usage,
        maxTokens: body['max_tokens'],
      },
    });
    log.allow(`model.call ${claims.sub} -> ${model} (${latencyMs}ms, out=${result.usage?.output_tokens ?? '?'} tok)`);
    return sendJson(res, result.status, result.body, { [REQUEST_ID_HEADER]: rid });
  }

  async function handleTool(req: IncomingMessage, res: ServerResponse, rid: string, name: string) {
    const claims = authorize(req, res);
    if (!claims) return;
    const started = Date.now();

    const inScope = claims.scope.tools.includes('*') || claims.scope.tools.includes(name);
    const decision = policy.decideTool(claims.role, name);
    if (!inScope || !decision.allow) {
      const reason = !inScope ? `tool "${name}" not in token scope` : decision.reason;
      audit.record({
        requestId: rid, agentId: claims.sub, role: claims.role,
        action: 'tool.call', resource: name, decision: 'deny', reason,
      });
      log.deny(`tool.call ${claims.sub} -> ${name}: ${reason}`);
      return sendError(res, 403, 'permission_error', reason);
    }

    const tool = getTool(name);
    if (!tool) {
      // Policy allowed it but no implementation exists -> still deny-by-default.
      const reason = `tool "${name}" is not implemented`;
      audit.record({
        requestId: rid, agentId: claims.sub, role: claims.role,
        action: 'tool.call', resource: name, decision: 'deny', reason,
      });
      return sendError(res, 404, 'not_found', reason);
    }

    const limits = policy.limitsForRole(claims.role);
    const rl = limiter.check(`tool:${claims.sub}`, limits.requestsPerMinute);
    if (!rl.allowed) {
      audit.record({
        requestId: rid, agentId: claims.sub, role: claims.role,
        action: 'tool.call', resource: name, decision: 'deny',
        reason: `rate limit ${limits.requestsPerMinute}/min exceeded`,
      });
      return sendError(res, 429, 'rate_limit_error', 'requests per minute exceeded');
    }

    const body = await readJson<{ arguments?: Record<string, unknown> }>(req);
    const args = body.arguments ?? {};
    const validationError = tool.validate(args);
    if (validationError) {
      audit.record({
        requestId: rid, agentId: claims.sub, role: claims.role,
        action: 'tool.call', resource: name, decision: 'deny',
        reason: `parameter validation failed: ${validationError}`,
      });
      log.deny(`tool.call ${claims.sub} -> ${name}: ${validationError}`);
      return sendError(res, 400, 'invalid_request', validationError);
    }

    const result = await tool.run(args, { agentId: claims.sub, role: claims.role, requestId: rid });
    const latencyMs = Date.now() - started;
    audit.record({
      requestId: rid, agentId: claims.sub, role: claims.role,
      action: 'tool.call', resource: name, decision: 'allow',
      reason: decision.reason, latencyMs, meta: { ok: result.ok },
    });
    log.allow(`tool.call ${claims.sub} -> ${name} (${latencyMs}ms)`);
    return sendJson(res, result.ok ? 200 : 400, result, { [REQUEST_ID_HEADER]: rid });
  }

  return { server, port: cfg.port };
}

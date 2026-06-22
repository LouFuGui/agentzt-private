import { createServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { readFileSync } from 'node:fs';
import type { TLSSocket } from 'node:tls';
import type { IncomingMessage, ServerResponse, Server } from 'node:http';
import {
  readJson,
  sendJson,
  sendError,
  bearerToken,
  headerValue,
  REQUEST_ID_HEADER,
  ELEVATION_HEADER,
  APP_ID_HEADER,
  API_KEY_HEADER,
} from '../shared/http.ts';
import { newId } from '../shared/crypto.ts';
import { makeLogger } from '../shared/log.ts';
import { AuditLogger } from '../shared/audit.ts';
import { AUDIT_DIR, TLS_DIR } from '../shared/paths.ts';
import { resolve } from 'node:path';
import type {
  GatewayTlsConfig,
  GatewayConfig,
  OpaConfig,
  AccessTokenClaims,
  GuardrailConfig,
  AuthResult,
  App,
  GuardrailsCheckRequest,
  GuardrailsCheckResponse,
  ChatCompletionRequest,
  ChatCompletionResponse,
  SimpleMessage,
  RiskLevel,
} from '../shared/types.ts';
import { loadGatewayConfig, loadPolicy } from '../shared/config.ts';
import { loadOrCreateGatewayKey } from './gateway-key.ts';
import { IdentityStore } from './identity-store.ts';
import { PolicyEngine } from './policy-engine.ts';
import { TokenService } from './token-service.ts';
import { RateLimiter } from './rate-limiter.ts';
import { callModel } from './upstream.ts';
import { getTool } from './tool-registry.ts';
import { flattenMessages, redactSecretsDeep } from './guardrails.ts';
import { createGuardrailProvider } from './guardrail-providers.ts';
import { OpaClient, resolveOpaConfig } from './opa-client.ts';
import type { OpaDecisionInput } from './opa-client.ts';
import { getAppStore } from '../api/app-store.ts';
import { validateApiKeyAndGetApp } from '../api/apps.ts';
import { resolveSignozConfig, SigNozTelemetry } from '../shared/signoz.ts';
import type { AuditEvent } from '../shared/types.ts';

const DEFAULT_GUARDRAILS: GuardrailConfig = {
  provider: 'auto',
  input: { mode: 'block' },
  output: { redactSecrets: true, check: true },
  openguardrails: {
    baseUrl: 'https://api.openguardrails.com/v1',
    apiKeyEnv: 'OPENGUARDRAILS_API_KEY',
    model: 'OpenGuardrails-Text',
    timeoutMs: 5000,
    failOpen: false,
  },
};

const log = makeLogger('gateway');

function createOpaClient(config?: OpaConfig): OpaClient | null {
  const resolved = resolveOpaConfig(config);
  return resolved ? new OpaClient(resolved) : null;
}

// TLS is enabled by config (cfg.tls.enabled) or the AGENTZT_TLS=1 env override
// (used by the mTLS demo/tests with default .agentzt/tls/ paths).
function resolveTls(cfg: GatewayConfig): GatewayTlsConfig | null {
  if (process.env.AGENTZT_TLS === '1') {
    return {
      enabled: true,
      keyFile: resolve(TLS_DIR, 'server.key'),
      certFile: resolve(TLS_DIR, 'server.crt'),
      caFile: resolve(TLS_DIR, 'ca.crt'),
      channelBinding: process.env.AGENTZT_TLS_CHANNEL_BINDING !== '0',
    };
  }
  return cfg.tls?.enabled ? cfg.tls : null;
}

export function createGatewayServer(): { server: Server; port: number; tls: boolean; telemetry: SigNozTelemetry | null } {
  const cfg = loadGatewayConfig();
  const policy = new PolicyEngine(loadPolicy());
  const identities = new IdentityStore();
  const key = loadOrCreateGatewayKey();
  const tokens = new TokenService(cfg, identities, policy, key);
  const limiter = new RateLimiter(60_000);
  const audit = new AuditLogger(resolve(AUDIT_DIR, 'gateway-audit.jsonl'));
  const guardrails = cfg.guardrails ?? DEFAULT_GUARDRAILS;
  const guard = createGuardrailProvider(guardrails);
  const opaClient = createOpaClient(cfg.opa);
  const signozConfig = resolveSignozConfig(cfg.signoz);
  const telemetry = signozConfig ? new SigNozTelemetry(signozConfig, log) : null;
  const tls = resolveTls(cfg);

  log.info(`loaded ${identities.size()} registered agent identit(ies)`);
  log.info(`upstream model mode: ${cfg.upstream.mode}`);
  log.info(`guardrail provider: ${guard.name} (input=${guardrails.input.mode}, output.redact=${guardrails.output.redactSecrets})`);
  if (opaClient) log.info(`OPA policy: ON (path=${opaClient.config.policyPath}, failOpen=${opaClient.config.failOpen})`);
  if (signozConfig) log.info(`SigNoz telemetry: ON (endpoint=${signozConfig.endpoint}, service=${signozConfig.serviceName})`);
  if (tls) log.info(`mutual TLS: ON (client certs required${tls.channelBinding ? ', channel binding' : ''})`);

  const tokenAudience = `${cfg.issuer}/v1/token`;

  // Returns the client cert CN for an mTLS connection, or null.
  function peerCN(req: IncomingMessage): string | null {
    if (!tls) return null;
    const socket = req.socket as TLSSocket;
    if (typeof socket.getPeerCertificate !== 'function') return null;
    const cert = socket.getPeerCertificate();
    const cn = cert && cert.subject ? (cert.subject as { CN?: string }).CN : undefined;
    return cn ?? null;
  }

  function requestId(req: IncomingMessage): string {
    return headerValue(req, REQUEST_ID_HEADER) ?? newId('req');
  }

  function recordAudit(partial: Omit<AuditEvent, 'ts' | 'seq' | 'hash'>): AuditEvent {
    const event = audit.record(partial);
    telemetry?.recordAudit(event);
    return event;
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
    let claims: AccessTokenClaims;
    try {
      claims = tokens.verifyAccessToken(token);
    } catch (err) {
      sendError(res, 401, 'authentication_error', (err as Error).message);
      return null;
    }
    // Channel binding: the token may only be used over a TLS channel
    // authenticated as the same agent (cert CN == token subject).
    if (tls && tls.channelBinding) {
      const cn = peerCN(req);
      if (cn !== claims.sub) {
        sendError(res, 401, 'authentication_error',
          `channel binding failed: client cert CN "${cn}" != token subject "${claims.sub}"`);
        return null;
      }
    }
    return claims;
  }

  /**
   * Extended authorization supporting both Agent Token and API Key.
   * Returns AuthResult with the authentication type and associated context.
   */
  function authorizeExtended(
    req: IncomingMessage,
    res: ServerResponse,
  ): AuthResult | null {
    // Try Agent Token first (existing flow)
    const token = bearerToken(req);
    if (token) {
      // Check if it's an API Key format (sk-xxai-* or sk-xxai-model-*)
      if (token.startsWith('sk-xxai-')) {
        const app = validateApiKeyAndGetApp(token);
        if (!app) {
          sendError(res, 401, 'authentication_error', 'invalid API key');
          return null;
        }
        return {
          type: 'api_key',
          app,
          userId: app.ownerId,
        };
      }

      // Regular Agent Token
      try {
        const claims = tokens.verifyAccessToken(token);
        // Channel binding check
        if (tls && tls.channelBinding) {
          const cn = peerCN(req);
          if (cn !== claims.sub) {
            sendError(res, 401, 'authentication_error',
              `channel binding failed: client cert CN "${cn}" != token subject "${claims.sub}"`);
            return null;
          }
        }
        return {
          type: 'agent_token',
          agentId: claims.sub,
          role: claims.role,
          scope: claims.scope,
        };
      } catch (err) {
        sendError(res, 401, 'authentication_error', (err as Error).message);
        return null;
      }
    }

    // Check for API Key in header (alternative method)
    const apiKeyHeader = headerValue(req, API_KEY_HEADER);
    if (apiKeyHeader) {
      const app = validateApiKeyAndGetApp(apiKeyHeader);
      if (!app) {
        sendError(res, 401, 'authentication_error', 'invalid API key in header');
        return null;
      }
      return {
        type: 'api_key',
        app,
        userId: app.ownerId,
      };
    }

    // Check for App ID header (requires separate auth)
    const appIdHeader = headerValue(req, APP_ID_HEADER);
    if (appIdHeader) {
      // App ID header alone is not enough for auth - need token or API key
      sendError(res, 401, 'authentication_error', 'app ID header requires authentication');
      return null;
    }

    sendError(res, 401, 'authentication_error', 'missing bearer token or API key');
    return null;
  }

  /**
   * Check application quota limits.
   * Returns null if quota is OK, or error response if exceeded.
   */
  function checkQuota(
    app: App,
    res: ServerResponse,
    rid: string,
  ): { ok: boolean; reason?: string } {
    const { quota } = app;
    
    // Check checks limit
    if (quota.checksUsed >= quota.checksLimit) {
      recordAudit({
        requestId: rid,
        agentId: null,
        role: null,
        appId: app.appId,
        userId: app.ownerId,
        action: 'quota.exceeded',
        resource: 'checks',
        decision: 'deny',
        reason: `checks quota exceeded (${quota.checksUsed}/${quota.checksLimit})`,
      });
      sendError(res, 429, 'quota_exceeded', 
        `checks quota exceeded (${quota.checksUsed}/${quota.checksLimit})`);
      return { ok: false, reason: 'checks_quota' };
    }

    // Check tokens limit
    if (quota.tokensUsed >= quota.tokensLimit) {
      recordAudit({
        requestId: rid,
        agentId: null,
        role: null,
        appId: app.appId,
        userId: app.ownerId,
        action: 'quota.exceeded',
        resource: 'tokens',
        decision: 'deny',
        reason: `tokens quota exceeded (${quota.tokensUsed}/${quota.tokensLimit})`,
      });
      sendError(res, 402, 'payment_required',
        `tokens quota exceeded (${quota.tokensUsed}/${quota.tokensLimit})`);
      return { ok: false, reason: 'tokens_quota' };
    }

    return { ok: true };
  }

  /**
   * Increment quota usage after successful operation.
   */
  function incrementUsage(appId: string, checksDelta: number = 1, tokensDelta: number = 0): void {
    const store = getAppStore();
    store.incrementQuotaUsage(appId, checksDelta, tokensDelta);
  }

  /**
   * Load application-specific configuration for guardrails.
   * Merges app config with default guardrails config.
   */
  function loadAppGuardrailConfig(app: App): GuardrailConfig {
    const appConfig = app.config;
    
    // Build guardrail config from app settings
    // The app config controls which risk types are enabled
    const config: GuardrailConfig = {
      provider: guardrails.provider,
      input: { mode: guardrails.input.mode },
      output: { 
        redactSecrets: guardrails.output.redactSecrets,
        check: guardrails.output.check,
      },
      openguardrails: guardrails.openguardrails,
    };

    // Apply sensitivity threshold from app config
    // Higher sensitivity = stricter checking
    if (appConfig.sensitivity.level === 'high') {
      config.input.mode = 'block';
    } else if (appConfig.sensitivity.level === 'low') {
      config.input.mode = 'flag';
    }

    return config;
  }

  const handler = async (req: IncomingMessage, res: ServerResponse) => {
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

      if (method === 'POST' && path === '/v1/elevate') {
        return await handleElevate(req, res, rid);
      }

      if (method === 'POST' && path === '/v1/messages') {
        return await handleMessages(req, res, rid);
      }

      if (method === 'POST' && path.startsWith('/v1/tools/')) {
        const name = decodeURIComponent(path.slice('/v1/tools/'.length));
        return await handleTool(req, res, rid, name);
      }

      // === Security Gateway Mode: Transparent Proxy ===
      if (method === 'POST' && path.startsWith('/proxy/v1/')) {
        return await handleProxy(req, res, rid, path.slice('/proxy/v1/'.length));
      }

      // === API Call Mode: Active Detection ===
      if (method === 'POST' && path === '/v1/guardrails') {
        return await handleGuardrailsCheck(req, res, rid);
      }

      // === Direct Model Access: Privacy-Preserving ===
      if (method === 'POST' && path === '/v1/chat/completions') {
        return await handleDirectModelAccess(req, res, rid);
      }

      return sendError(res, 404, 'not_found', `no route for ${method} ${path}`);
    } catch (err) {
      log.error(`unhandled error on ${method} ${path}: ${(err as Error).message}`);
      return sendError(res, 500, 'internal_error', 'internal error');
    }
  };

  const server: Server = tls
    ? createHttpsServer(
        {
          key: readFileSync(tls.keyFile),
          cert: readFileSync(tls.certFile),
          ca: readFileSync(tls.caFile),
          requestCert: true,
          rejectUnauthorized: true,
          minVersion: 'TLSv1.2',
        },
        handler,
      )
    : createServer(handler);

  async function handleToken(req: IncomingMessage, res: ServerResponse, rid: string) {
    const body = await readJson<{ assertion?: string }>(req);
    if (!body.assertion) {
      return sendError(res, 400, 'invalid_request', 'missing "assertion"');
    }
    const result = tokens.issue(body.assertion, tokenAudience);
    if (!result.ok) {
      recordAudit({
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
    recordAudit({
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

  async function handleElevate(req: IncomingMessage, res: ServerResponse, rid: string) {
    const claims = authorize(req, res);
    if (!claims) return;
    const body = await readJson<{ kind?: string; name?: string; reason?: string; ttlSeconds?: number }>(req);
    const kind = body.kind === 'model' || body.kind === 'tool' ? body.kind : null;
    const name = typeof body.name === 'string' ? body.name : '';
    if (!kind || !name) {
      return sendError(res, 400, 'invalid_request', 'elevate requires "kind" (model|tool) and "name"');
    }
    const reason = (body.reason ?? '').slice(0, 500) || 'unspecified';

    const can = policy.canElevate(claims.role, kind, name);
    if (!can.allow) {
      recordAudit({
        requestId: rid, agentId: claims.sub, role: claims.role,
        action: 'elevation.reject', resource: `${kind}:${name}`, decision: 'deny', reason: can.reason,
        meta: { reason },
      });
      log.deny(`elevation.reject ${claims.sub} -> ${kind}:${name}: ${can.reason}`);
      return sendError(res, 403, 'permission_error', can.reason);
    }

    const maxTtl = policy.jitMaxTtl(claims.role);
    const ttl = Math.min(body.ttlSeconds && body.ttlSeconds > 0 ? body.ttlSeconds : maxTtl, maxTtl);
    const { grant, claims: gc } = tokens.issueElevation(claims.sub, claims.role, { kind, name }, reason, ttl);
    recordAudit({
      requestId: rid, agentId: claims.sub, role: claims.role,
      action: 'elevation.grant', resource: `${kind}:${name}`, decision: 'allow',
      reason: `JIT elevation (ttl=${ttl}s)`, meta: { reason, exp: gc.exp },
    });
    log.allow(`elevation.grant ${claims.sub} -> ${kind}:${name} (ttl=${ttl}s, reason="${reason}")`);
    return sendJson(res, 200, { elevation_grant: grant, expires_in: ttl, resource: { kind, name } });
  }

  // Authorize a resource: in standing scope, OR via a valid JIT elevation grant.
  function authorizeResource(
    req: IncomingMessage,
    claims: AccessTokenClaims,
    kind: 'model' | 'tool',
    name: string,
  ): { allow: boolean; reason: string; via: 'scope' | 'jit' } {
    const scopeList = kind === 'model' ? claims.scope.models : claims.scope.tools;
    const inScope = scopeList.includes('*') || scopeList.includes(name);
    const base = kind === 'model' ? policy.decideModel(claims.role, name) : policy.decideTool(claims.role, name);
    if (inScope && base.allow) return { allow: true, reason: base.reason, via: 'scope' };

    const grant = headerValue(req, ELEVATION_HEADER);
    if (grant) {
      try {
        const g = tokens.verifyElevation(grant, claims.sub, kind, name);
        return { allow: true, reason: `JIT elevation (exp in ${g.exp - Math.floor(Date.now() / 1000)}s)`, via: 'jit' };
      } catch (err) {
        return { allow: false, reason: `elevation invalid: ${(err as Error).message}`, via: 'jit' };
      }
    }
    return { allow: false, reason: !inScope ? `${kind} "${name}" not in scope (no JIT elevation)` : base.reason, via: 'scope' };
  }

  async function decideOpa(
    claims: AccessTokenClaims,
    action: 'model.call' | 'tool.call',
    kind: 'model' | 'tool',
    name: string,
    authVia: 'scope' | 'jit',
    riskLevel?: RiskLevel,
  ): Promise<{ allow: true; reason: string; input?: OpaDecisionInput } | { allow: false; reason: string; input?: OpaDecisionInput }> {
    if (!opaClient) return { allow: true, reason: 'OPA disabled' };
    const input: OpaDecisionInput = {
      agentId: claims.sub,
      role: claims.role,
      action,
      resource: { kind, name },
      authVia,
      riskLevel,
      now: new Date().toISOString(),
    };
    const decision = await opaClient.decide(input);
    return { ...decision, input };
  }

  async function handleMessages(req: IncomingMessage, res: ServerResponse, rid: string) {
    const claims = authorize(req, res);
    if (!claims) return;
    const started = Date.now();
    const body = await readJson<Record<string, unknown>>(req);
    const model = typeof body['model'] === 'string' ? (body['model'] as string) : '';
    if (!model) return sendError(res, 400, 'invalid_request', 'missing "model"');

    // Authorize: standing scope or JIT elevation.
    const authz = authorizeResource(req, claims, 'model', model);
    if (!authz.allow) {
      recordAudit({
        requestId: rid, agentId: claims.sub, role: claims.role,
        action: 'model.call', resource: model, decision: 'deny', reason: authz.reason,
      });
      log.deny(`model.call ${claims.sub} -> ${model}: ${authz.reason}`);
      return sendError(res, 403, 'permission_error', authz.reason);
    }
    const decision = { reason: authz.reason };

    // Rate limit (resource-exhaustion containment).
    const limits = policy.limitsForRole(claims.role);
    const rl = limiter.check(`model:${claims.sub}`, limits.requestsPerMinute);
    if (!rl.allowed) {
      recordAudit({
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

    // --- Input guardrail: prompt-injection / unsafe content (context-aware) ---
    const messages = flattenMessages(body);
    let inputVerdict = undefined;
    if (guardrails.input.mode !== 'off') {
      inputVerdict = await guard.checkInput(messages);
      if (inputVerdict.flagged && guardrails.input.mode === 'block') {
        const reason = `input guardrail (${inputVerdict.provider}) blocked: ${inputVerdict.riskLevel} [${inputVerdict.categories.join(', ')}]`;
        recordAudit({
          requestId: rid, agentId: claims.sub, role: claims.role,
          action: 'guardrail.block', resource: model, decision: 'deny', reason,
          meta: { stage: 'input', verdict: inputVerdict },
        });
        log.deny(`guardrail.block ${claims.sub} -> ${model}: ${reason}`);
        return sendError(res, 403, 'guardrail_blocked', reason);
      }
    }

    // --- ABAC: context-aware authorization (operating hours + risk-adaptive) --
    const riskLevelForAbac = inputVerdict?.riskLevel as RiskLevel | undefined;
    const abac = policy.decideAbac(claims.role, { now: new Date(), riskLevel: riskLevelForAbac });
    if (!abac.allow) {
      recordAudit({
        requestId: rid, agentId: claims.sub, role: claims.role,
        action: 'model.call', resource: model, decision: 'deny', reason: abac.reason,
        meta: { abac: true },
      });
      log.deny(`model.call ${claims.sub} -> ${model}: ${abac.reason}`);
      return sendError(res, 403, 'permission_error', abac.reason);
    }

    const opaDecision = await decideOpa(claims, 'model.call', 'model', model, authz.via, riskLevelForAbac);
    if (!opaDecision.allow) {
      recordAudit({
        requestId: rid, agentId: claims.sub, role: claims.role,
        action: 'model.call', resource: model, decision: 'deny', reason: opaDecision.reason,
        meta: { opa: true, opaInput: opaDecision.input },
      });
      log.deny(`model.call ${claims.sub} -> ${model}: ${opaDecision.reason}`);
      return sendError(res, 403, 'permission_error', opaDecision.reason);
    }

    const result = await callModel(cfg, { model, body });
    const latencyMs = Date.now() - started;

    // --- Output guardrails: context-aware review + secret redaction ---------
    let outputVerdict = undefined;
    let outRedactions = 0;
    if (result.status === 200) {
      const promptText = messages.map((m) => m.content).join('\n');
      const responseText = extractText(result.body);
      if (guardrails.output.check) {
        outputVerdict = await guard.checkOutput(promptText, responseText);
        if (outputVerdict.flagged && outputVerdict.action === 'replace' && outputVerdict.suggestAnswer) {
          replaceText(result.body, outputVerdict.suggestAnswer);
        } else if (outputVerdict.flagged && outputVerdict.action === 'reject') {
          replaceText(result.body, '[response withheld by output guardrail]');
        }
      }
      if (guardrails.output.redactSecrets) {
        const r = redactSecretsDeep(result.body);
        result.body = r.value;
        outRedactions = r.count;
      }
    }

    recordAudit({
      requestId: rid, agentId: claims.sub, role: claims.role,
      action: 'model.call', resource: model, decision: 'allow',
      reason: decision.reason, latencyMs,
      meta: {
        authVia: authz.via,
        upstreamStatus: result.status,
        usage: result.usage,
        maxTokens: body['max_tokens'],
        guardrailProvider: guard.name,
        inputVerdict,
        outputVerdict,
        outputRedactions: outRedactions,
        opa: opaClient ? { reason: opaDecision.reason } : undefined,
      },
    });
    const flags = [
      inputVerdict?.flagged ? `input:${inputVerdict.categories.join('|')}` : null,
      outputVerdict?.flagged ? `output:${outputVerdict.action}` : null,
      outRedactions ? `redacted:${outRedactions}` : null,
    ].filter(Boolean).join(' ');
    log.allow(`model.call ${claims.sub} -> ${model} (${latencyMs}ms, out=${result.usage?.output_tokens ?? '?'} tok)${flags ? ' ' + flags : ''}`);
    return sendJson(res, result.status, result.body, { [REQUEST_ID_HEADER]: rid });
  }

  async function handleTool(req: IncomingMessage, res: ServerResponse, rid: string, name: string) {
    const claims = authorize(req, res);
    if (!claims) return;
    const started = Date.now();

    // Authorize: standing scope or JIT elevation.
    const authz = authorizeResource(req, claims, 'tool', name);
    if (!authz.allow) {
      recordAudit({
        requestId: rid, agentId: claims.sub, role: claims.role,
        action: 'tool.call', resource: name, decision: 'deny', reason: authz.reason,
      });
      log.deny(`tool.call ${claims.sub} -> ${name}: ${authz.reason}`);
      return sendError(res, 403, 'permission_error', authz.reason);
    }
    const decision = { reason: authz.reason };

    // ABAC (operating hours; tool calls have no model risk signal).
    const abac = policy.decideAbac(claims.role, { now: new Date() });
    if (!abac.allow) {
      recordAudit({
        requestId: rid, agentId: claims.sub, role: claims.role,
        action: 'tool.call', resource: name, decision: 'deny', reason: abac.reason, meta: { abac: true },
      });
      log.deny(`tool.call ${claims.sub} -> ${name}: ${abac.reason}`);
      return sendError(res, 403, 'permission_error', abac.reason);
    }

    const opaDecision = await decideOpa(claims, 'tool.call', 'tool', name, authz.via);
    if (!opaDecision.allow) {
      recordAudit({
        requestId: rid, agentId: claims.sub, role: claims.role,
        action: 'tool.call', resource: name, decision: 'deny', reason: opaDecision.reason,
        meta: { opa: true, opaInput: opaDecision.input },
      });
      log.deny(`tool.call ${claims.sub} -> ${name}: ${opaDecision.reason}`);
      return sendError(res, 403, 'permission_error', opaDecision.reason);
    }

    const tool = getTool(name);
    if (!tool) {
      // Policy allowed it but no implementation exists -> still deny-by-default.
      const reason = `tool "${name}" is not implemented`;
      recordAudit({
        requestId: rid, agentId: claims.sub, role: claims.role,
        action: 'tool.call', resource: name, decision: 'deny', reason,
      });
      return sendError(res, 404, 'not_found', reason);
    }

    const limits = policy.limitsForRole(claims.role);
    const rl = limiter.check(`tool:${claims.sub}`, limits.requestsPerMinute);
    if (!rl.allowed) {
      recordAudit({
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
      recordAudit({
        requestId: rid, agentId: claims.sub, role: claims.role,
        action: 'tool.call', resource: name, decision: 'deny',
        reason: `parameter validation failed: ${validationError}`,
      });
      log.deny(`tool.call ${claims.sub} -> ${name}: ${validationError}`);
      return sendError(res, 400, 'invalid_request', validationError);
    }

    let result = await tool.run(args, { agentId: claims.sub, role: claims.role, requestId: rid });

    // Tool outputs are untrusted egress: redact credential-shaped strings before
    // they reach the agent (and could be fed back into a model prompt).
    let outRedactions = 0;
    if (guardrails.output.redactSecrets) {
      const r = redactSecretsDeep(result);
      result = r.value;
      outRedactions = r.count;
    }

    const latencyMs = Date.now() - started;
    recordAudit({
      requestId: rid, agentId: claims.sub, role: claims.role,
      action: 'tool.call', resource: name, decision: 'allow',
      reason: decision.reason, latencyMs,
      meta: { ok: result.ok, outputRedactions: outRedactions, authVia: authz.via, opa: opaClient ? { reason: opaDecision.reason } : undefined },
    });
    log.allow(`tool.call ${claims.sub} -> ${name} (${latencyMs}ms, via=${authz.via})${outRedactions ? ` redacted:${outRedactions}` : ''}`);
    return sendJson(res, result.ok ? 200 : 400, result, { [REQUEST_ID_HEADER]: rid });
  }

  // ============================================================================
  // Security Gateway Mode: Transparent Proxy (/proxy/v1/*)
  // ============================================================================

  /**
   * Security Gateway Mode: Transparent proxy with automatic guardrail detection.
   * - Reads messages from request body
   * - Automatically calls guardrail detection
   * - If passes, forwards to upstream Model API
   * - If fails, returns 403 with security response
   * - Preserves original request/response format
   */
  async function handleProxy(
    req: IncomingMessage,
    res: ServerResponse,
    rid: string,
    targetPath: string,
  ): Promise<void> {
    const auth = authorizeExtended(req, res);
    if (!auth) return;
    
    const started = Date.now();
    const body = await readJson<Record<string, unknown>>(req);
    const model = typeof body['model'] === 'string' ? (body['model'] as string) : 'default';

    // Get app context if API Key auth
    const app = auth.type === 'api_key' ? auth.app : null;
    
    // Check quota for API Key auth
    if (app) {
      const quotaCheck = checkQuota(app, res, rid);
      if (!quotaCheck.ok) return;
    }

    // Load app-specific guardrail config
    const guardConfig = app ? loadAppGuardrailConfig(app) : guardrails;
    const appGuard = createGuardrailProvider(guardConfig);

    // Extract messages for guardrail check
    const messages = flattenMessages(body);

    // --- Input guardrail check ---
    let inputVerdict = undefined;
    if (guardConfig.input.mode !== 'off') {
      inputVerdict = await appGuard.checkInput(messages);
      
      if (inputVerdict.flagged && guardConfig.input.mode === 'block') {
        const reason = `input guardrail blocked: ${inputVerdict.riskLevel} [${inputVerdict.categories.join(', ')}]`;
        
        recordAudit({
          requestId: rid,
          agentId: auth.type === 'agent_token' ? (auth.agentId ?? null) : null,
          role: auth.type === 'agent_token' ? (auth.role ?? null) : null,
          appId: app?.appId ?? null,
          userId: app?.ownerId ?? null,
          action: 'proxy.call',
          resource: model,
          decision: 'deny',
          reason,
          categories: inputVerdict.categories,
          score: inputVerdict.flagged ? 1 : 0,
          meta: { stage: 'input', verdict: inputVerdict, targetPath },
        });
        
        log.deny(`proxy.call blocked -> ${model}: ${reason}`);
        
        // Return security response
        const rejectTemplate = app?.config.responseTemplates.reject ?? 
          'Your request cannot be processed due to security policy.';
        return sendJson(res, 403, {
          type: 'error',
          error: {
            type: 'guardrail_blocked',
            message: reason,
            suggest_answer: inputVerdict.suggestAnswer ?? rejectTemplate,
            categories: inputVerdict.categories,
            risk_level: inputVerdict.riskLevel,
          },
        });
      }
    }

    // --- Forward to upstream Model API ---
    const result = await callModel(cfg, { model, body });
    const latencyMs = Date.now() - started;

    // --- Output guardrails ---
    let outputVerdict = undefined;
    let outRedactions = 0;
    if (result.status === 200) {
      const promptText = messages.map((m) => m.content).join('\n');
      const responseText = extractText(result.body);
      
      if (guardConfig.output.check) {
        outputVerdict = await appGuard.checkOutput(promptText, responseText);
        if (outputVerdict.flagged && outputVerdict.action === 'replace' && outputVerdict.suggestAnswer) {
          replaceText(result.body, outputVerdict.suggestAnswer);
        } else if (outputVerdict.flagged && outputVerdict.action === 'reject') {
          const replaceTemplate = app?.config.responseTemplates.replace ?? 
            'I apologize, but I cannot provide that information.';
          replaceText(result.body, replaceTemplate);
        }
      }
      
      if (guardConfig.output.redactSecrets) {
        const r = redactSecretsDeep(result.body);
        result.body = r.value;
        outRedactions = r.count;
      }
    }

    // Increment usage for API Key auth
    if (app) {
      const tokensUsed = (result.usage?.input_tokens ?? 0) + (result.usage?.output_tokens ?? 0);
      incrementUsage(app.appId, 1, tokensUsed);
    }

    recordAudit({
      requestId: rid,
      agentId: auth.type === 'agent_token' ? (auth.agentId ?? null) : null,
      role: auth.type === 'agent_token' ? (auth.role ?? null) : null,
      appId: app?.appId ?? null,
      userId: app?.ownerId ?? null,
      action: 'proxy.call',
      resource: model,
      decision: 'allow',
      reason: 'passed guardrails',
      latencyMs,
      categories: [...(inputVerdict?.categories ?? []), ...(outputVerdict?.categories ?? [])],
      score: (inputVerdict?.flagged ? 0.5 : 0) + (outputVerdict?.flagged ? 0.5 : 0),
      meta: {
        targetPath,
        upstreamStatus: result.status,
        usage: result.usage,
        guardrailProvider: appGuard.name,
        inputVerdict,
        outputVerdict,
        outputRedactions: outRedactions,
      },
    });

    log.allow(`proxy.call -> ${model} (${latencyMs}ms)${outRedactions ? ` redacted:${outRedactions}` : ''}`);
    return sendJson(res, result.status, result.body, { [REQUEST_ID_HEADER]: rid });
  }

  // ============================================================================
  // API Call Mode: Active Detection (/v1/guardrails)
  // ============================================================================

  /**
   * API Call Mode: Active guardrail detection without model call.
   * - Accepts messages and detection options
   * - Returns standard detection response format
   * - No model API call, just detection
   */
  async function handleGuardrailsCheck(
    req: IncomingMessage,
    res: ServerResponse,
    rid: string,
  ): Promise<void> {
    const auth = authorizeExtended(req, res);
    if (!auth) return;

    const started = Date.now();
    const body = await readJson<GuardrailsCheckRequest>(req);

    if (!body.messages || !Array.isArray(body.messages)) {
      return sendError(res, 400, 'invalid_request', 'missing or invalid "messages" field');
    }

    // Get app context if API Key auth
    const app = auth.type === 'api_key' ? auth.app : null;

    // Check quota for API Key auth
    if (app) {
      const quotaCheck = checkQuota(app, res, rid);
      if (!quotaCheck.ok) return;
    }

    // Load app-specific guardrail config
    const guardConfig = app ? loadAppGuardrailConfig(app) : guardrails;
    const appGuard = createGuardrailProvider(guardConfig);

    // Apply detection options from request
    const enableSecurity = body.enable_security ?? app?.config.riskTypes.security ?? true;
    const enableCompliance = body.enable_compliance ?? app?.config.riskTypes.compliance ?? true;
    const enableDataSecurity = body.enable_data_security ?? app?.config.riskTypes.dataSecurity ?? true;

    // Run guardrail check
    const verdict = await appGuard.checkInput(body.messages as SimpleMessage[]);
    const latencyMs = Date.now() - started;

    // Filter categories based on enabled risk types
    let filteredCategories = verdict.categories;
    if (!enableSecurity) {
      filteredCategories = filteredCategories.filter(c => !c.startsWith('S') || ['S5', 'S6', 'S18'].includes(c));
    }
    if (!enableCompliance) {
      filteredCategories = filteredCategories.filter(c => !['S4', 'S13', 'S14', 'S15'].includes(c));
    }
    if (!enableDataSecurity) {
      filteredCategories = filteredCategories.filter(c => !['S5', 'S6', 'S18'].includes(c));
    }

    // Build response
    const riskLevel = verdict.riskLevel as RiskLevel;
    const response: GuardrailsCheckResponse = {
      id: newId('gr'),
      action: verdict.action,
      risk_level: ['no_risk', 'low_risk', 'medium_risk', 'high_risk'].includes(riskLevel) 
        ? riskLevel as 'no_risk' | 'low_risk' | 'medium_risk' | 'high_risk'
        : 'no_risk',
      categories: filteredCategories,
      suggest_answer: verdict.suggestAnswer,
      hit_keywords: verdict.patterns,
      score: verdict.flagged ? 0.8 : 0.1,
      processed_content: verdict.flagged && verdict.action === 'replace' ? verdict.suggestAnswer : undefined,
      has_warning: verdict.flagged && verdict.action === 'pass',
      was_replaced: verdict.flagged && verdict.action === 'replace',
    };

    // Increment usage for API Key auth
    if (app) {
      incrementUsage(app.appId, 1, 0);
    }

    recordAudit({
      requestId: rid,
      agentId: auth.type === 'agent_token' ? (auth.agentId ?? null) : null,
      role: auth.type === 'agent_token' ? (auth.role ?? null) : null,
      appId: app?.appId ?? null,
      userId: app?.ownerId ?? null,
      action: 'guardrails.check',
      resource: body.model ?? 'guardrails',
      decision: verdict.flagged ? 'deny' : 'allow',
      reason: verdict.flagged ? `detected: ${filteredCategories.join(', ')}` : 'no risk detected',
      latencyMs,
      categories: filteredCategories,
      score: response.score,
      meta: {
        guardrailProvider: appGuard.name,
        verdict,
        enableSecurity,
        enableCompliance,
        enableDataSecurity,
      },
    });

    log.info(`guardrails.check -> ${response.action} (${latencyMs}ms, categories=${filteredCategories.join(',')})`);
    return sendJson(res, 200, response, { [REQUEST_ID_HEADER]: rid });
  }

  // ============================================================================
  // Direct Model Access: Privacy-Preserving (/v1/chat/completions)
  // ============================================================================

  /**
   * Direct Model Access: OpenAI-compatible endpoint with privacy guarantee.
   * - Validates Model API Key (sk-xxai-model-*)
   * - Directly calls detection model
   * - Privacy: No message content stored, only usage count tracked
   * - Returns OpenAI-compatible response
   */
  async function handleDirectModelAccess(
    req: IncomingMessage,
    res: ServerResponse,
    rid: string,
  ): Promise<void> {
    const token = bearerToken(req);
    if (!token) {
      return sendError(res, 401, 'authentication_error', 'missing bearer token');
    }

    // Must be Model API Key format
    if (!token.startsWith('sk-xxai-model-')) {
      return sendError(res, 401, 'authentication_error', 
        'Direct Model Access requires Model API Key (sk-xxai-model-*)');
    }

    // Validate Model API Key and get app
    const app = validateApiKeyAndGetApp(token);
    if (!app) {
      return sendError(res, 401, 'authentication_error', 'invalid Model API Key');
    }

    const started = Date.now();
    const body = await readJson<ChatCompletionRequest>(req);

    if (!body.model || typeof body.model !== 'string') {
      return sendError(res, 400, 'invalid_request', 'missing or invalid "model" field');
    }

    if (!body.messages || !Array.isArray(body.messages)) {
      return sendError(res, 400, 'invalid_request', 'missing or invalid "messages" field');
    }

    // Check quota
    const quotaCheck = checkQuota(app, res, rid);
    if (!quotaCheck.ok) return;

    // Load app-specific guardrail config
    const guardConfig = loadAppGuardrailConfig(app);
    const appGuard = createGuardrailProvider(guardConfig);

    // Run guardrail check (privacy: no content stored)
    const inputVerdict = await appGuard.checkInput(body.messages);

    if (inputVerdict.flagged && guardConfig.input.mode === 'block') {
      const reason = `input guardrail blocked: ${inputVerdict.riskLevel}`;
      
      recordAudit({
        requestId: rid,
        agentId: null,
        role: null,
        appId: app.appId,
        userId: app.ownerId,
        action: 'direct.call',
        resource: body.model,
        decision: 'deny',
        reason,
        categories: inputVerdict.categories,
        score: 1,
        meta: { stage: 'input', verdict: { ...inputVerdict, patterns: undefined } },
      });

      // Privacy: Don't log message content
      log.deny(`direct.call blocked -> ${body.model}: ${reason}`);

      return sendJson(res, 403, {
        id: newId('chat'),
        object: 'chat.completion',
        created: Math.floor(Date.now() / 1000),
        model: body.model,
        choices: [{
          index: 0,
          message: {
            role: 'assistant',
            content: app.config.responseTemplates.reject,
          },
          finish_reason: 'content_filter',
        }],
        usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
      });
    }

    // Call model (privacy: content not logged)
    const result = await callModel(cfg, { model: body.model, body: { ...body } });
    const latencyMs = Date.now() - started;

    // Process output
    let outputContent = extractText(result.body);
    let outputVerdict = undefined;
    
    if (result.status === 200 && guardConfig.output.check) {
      const promptText = body.messages.map(m => m.content).join('\n');
      outputVerdict = await appGuard.checkOutput(promptText, outputContent);
      
      if (outputVerdict.flagged) {
        if (outputVerdict.action === 'replace' && outputVerdict.suggestAnswer) {
          outputContent = outputVerdict.suggestAnswer;
        } else if (outputVerdict.action === 'reject') {
          outputContent = app.config.responseTemplates.replace;
        }
      }
    }

    // Estimate tokens (privacy: don't store actual content)
    const promptTokens = Math.ceil(body.messages.map(m => m.content).join('').length / 4);
    const completionTokens = Math.ceil(outputContent.length / 4);

    // Increment usage (privacy: only count, no content stored)
    incrementUsage(app.appId, 1, promptTokens + completionTokens);

    // Build OpenAI-compatible response
    const response: ChatCompletionResponse = {
      id: newId('chat'),
      object: 'chat.completion',
      created: Math.floor(Date.now() / 1000),
      model: body.model,
      choices: [{
        index: 0,
        message: {
          role: 'assistant',
          content: outputContent,
        },
        finish_reason: outputVerdict?.flagged ? 'content_filter' : 'stop',
      }],
      usage: {
        prompt_tokens: promptTokens,
        completion_tokens: completionTokens,
        total_tokens: promptTokens + completionTokens,
      },
    };

    recordAudit({
      requestId: rid,
      agentId: null,
      role: null,
      appId: app.appId,
      userId: app.ownerId,
      action: 'direct.call',
      resource: body.model,
      decision: 'allow',
      reason: 'privacy-preserving model access',
      latencyMs,
      categories: [...(inputVerdict?.categories ?? []), ...(outputVerdict?.categories ?? [])],
      score: (inputVerdict?.flagged ? 0.5 : 0) + (outputVerdict?.flagged ? 0.5 : 0),
      meta: {
        // Privacy: Only store counts, not content
        promptTokens,
        completionTokens,
        guardrailProvider: appGuard.name,
        inputFlagged: inputVerdict?.flagged,
        outputFlagged: outputVerdict?.flagged,
      },
    });

    // Privacy: Log only counts, not content
    log.allow(`direct.call -> ${body.model} (${latencyMs}ms, tokens=${promptTokens + completionTokens})`);
    return sendJson(res, 200, response, { [REQUEST_ID_HEADER]: rid });
  }

  return { server, port: cfg.port, tls: !!tls, telemetry };
}

// ---- Anthropic Messages response helpers -----------------------------------

function extractText(body: unknown): string {
  const content = (body as Record<string, unknown>)?.['content'];
  if (!Array.isArray(content)) return '';
  return content
    .map((b) => (b as Record<string, unknown>)['text'])
    .filter((t): t is string => typeof t === 'string')
    .join('\n');
}

function replaceText(body: unknown, text: string): void {
  if (body && typeof body === 'object') {
    (body as Record<string, unknown>)['content'] = [{ type: 'text', text }];
  }
}

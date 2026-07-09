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
import { decodeJwsPayload, newId } from '../shared/crypto.ts';
import { makeLogger } from '../shared/log.ts';
import { AuditLogger } from '../shared/audit.ts';
import { AUDIT_DIR, TLS_DIR } from '../shared/paths.ts';
import { resolve } from 'node:path';
import type {
  GatewayTlsConfig,
  GatewayConfig,
  OpaConfig,
  FalcoConfig,
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
import { loadGatewayKeyFromPrivateJwk, loadOrCreateGatewayKey } from './gateway-key.ts';
import { IdentityStore } from './identity-store.ts';
import { PolicyEngine } from './policy-engine.ts';
import { TokenService } from './token-service.ts';
import { RateLimiter } from './rate-limiter.ts';
import { callModel } from './upstream.ts';
import { getTool } from './tool-registry.ts';
import { createSandboxRuntime } from './sandbox-runtime.ts';
import type { SandboxRuntime } from './sandbox-runtime.ts';
import type { SandboxExecuteRequest } from './docker-sandbox.ts';
import { flattenMessages, redactSecretsDeep } from './guardrails.ts';
import { createGuardrailProvider } from './guardrail-providers.ts';
import { OpaClient, resolveOpaConfig } from './opa-client.ts';
import type { OpaDecisionInput } from './opa-client.ts';
import { FalcoRuntimeMonitor, resolveFalcoConfig } from './falco-client.ts';
import type { FalcoRuntimeDecision, FalcoWebhookPayload } from './falco-client.ts';
import { resolveVaultConfig } from './vault-config.ts';
import {
  getGatewaySigningKeyFromVault,
  getToolCredentialsFromVault,
  initializeVault,
  shutdownVault,
} from './vault-secrets.ts';
import { getAppStore } from '../api/app-store.ts';
import { validateApiKeyAndGetApp } from '../api/apps.ts';
import { routeAppsApi } from '../api/apps.ts';
import { routeConfigApi } from '../api/config.ts';
import { routeQuotaApi } from '../api/quota.ts';
import { routeStatsApi } from '../api/stats.ts';
import { routeTierApi } from '../api/tier.ts';
import { routeAlertsApi } from '../api/alerts.ts';
import { routeManagementApi } from '../api/management.ts';
import { routeConsole } from '../api/console.ts';
import { AuthApi, createAuthApi, SessionTokenService } from '../api/auth.ts';
import { setSessionTokenService } from '../api/session.ts';
import { recordAuditWithTelemetry, resolveSignozConfig, SigNozTelemetry } from '../shared/signoz.ts';
import type { AuditEvent } from '../shared/types.ts';

const RISK_LEVELS = ['no_risk', 'low_risk', 'medium_risk', 'high_risk', 'unknown'] as const;

function parseRiskLevel(value: unknown): RiskLevel | undefined {
  return typeof value === 'string' && (RISK_LEVELS as readonly string[]).includes(value)
    ? value as RiskLevel
    : undefined;
}

type SandboxValidationFinding = {
  stage: 'input' | 'output';
  kind: 'bash' | 'python' | 'javascript';
  exitCode: number;
  output: string;
};

function extractSandboxValidationRequests(text: string): Array<{ kind: 'bash' | 'python' | 'javascript'; code: string }> {
  const findings: Array<{ kind: 'bash' | 'python' | 'javascript'; code: string }> = [];
  const fence = /```(bash|sh|shell|python|py|javascript|js)\s*\n([\s\S]*?)```/gi;
  for (const match of text.matchAll(fence)) {
    const language = (match[1] ?? '').toLowerCase();
    const kind = language === 'python' || language === 'py'
      ? 'python'
      : language === 'javascript' || language === 'js'
        ? 'javascript'
        : 'bash';
    findings.push({ kind, code: match[2] ?? '' });
  }
  if (findings.length === 0 && /\b(rm\s+-rf|curl\s+|wget\s+|chmod\s+|ssh\s+|scp\s+)/i.test(text)) {
    findings.push({ kind: 'bash', code: text });
  }
  return findings.slice(0, 3);
}

function validationCommand(kind: 'bash' | 'python' | 'javascript', code: string): SandboxExecuteRequest {
  const marker = `AGENTZT_${newId('eof').replace(/[^A-Za-z0-9_]/g, '_')}`;
  const file = kind === 'python' ? '/tmp/agentzt-validate.py'
    : kind === 'javascript' ? '/tmp/agentzt-validate.js'
      : '/tmp/agentzt-validate.sh';
  const tool = kind === 'python' ? `python3 -m py_compile ${file}`
    : kind === 'javascript' ? `node --check ${file}`
      : `sh -n ${file}`;
  return {
    mode: 'command',
    command: `cat > ${file} <<'${marker}'\n${code}\n${marker}\n${tool}`,
  };
}

async function runSandboxValidation(
  runtime: SandboxRuntime | undefined,
  cfg: GatewayConfig,
  stage: 'input' | 'output',
  text: string,
): Promise<{ allow: boolean; findings: SandboxValidationFinding[]; reason?: string }> {
  if (!runtime || cfg.sandbox?.enabled === false || cfg.sandbox?.modelValidation?.enabled !== true) {
    return { allow: true, findings: [] };
  }
  const requests = extractSandboxValidationRequests(text);
  if (requests.length === 0) return { allow: true, findings: [] };
  const validation = cfg.sandbox.modelValidation;
  const findings: SandboxValidationFinding[] = [];
  for (const request of requests) {
    const result = await runtime.execute({
      ...validationCommand(request.kind, request.code),
      timeoutMs: validation.timeoutMs ?? 5000,
      memoryMb: validation.memoryMb ?? 64,
      networkAccess: validation.networkAccess ?? false,
    });
    findings.push({
      stage,
      kind: request.kind,
      exitCode: result.exitCode,
      output: result.output,
    });
    if (result.exitCode !== 0 || result.timedOut) {
      return {
        allow: false,
        findings,
        reason: `${stage} sandbox validation failed for ${request.kind}`,
      };
    }
  }
  return { allow: true, findings };
}

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

function createFalcoMonitor(config?: FalcoConfig): FalcoRuntimeMonitor | null {
  const resolved = resolveFalcoConfig(config);
  return resolved ? new FalcoRuntimeMonitor(resolved) : null;
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

export async function createGatewayServer(): Promise<{ server: Server; port: number; tls: boolean; telemetry: SigNozTelemetry | null }> {
  const cfg = loadGatewayConfig();
  const vault = resolveVaultConfig(cfg.vault);
  cfg.vault = vault ?? undefined;
  const policy = new PolicyEngine(loadPolicy());
  const identities = new IdentityStore();
  await initializeVault(vault);
  const key = await loadGatewaySigningKey(vault);
  const tokens = new TokenService(cfg, identities, policy, key);
  const limiter = new RateLimiter(60_000);
  const audit = new AuditLogger(resolve(AUDIT_DIR, 'gateway-audit.jsonl'));
  const guardrails = cfg.guardrails ?? DEFAULT_GUARDRAILS;
  const guard = createGuardrailProvider(guardrails);
  const opaClient = createOpaClient(cfg.opa);
  const signozConfig = resolveSignozConfig(cfg.signoz);
  const telemetry = signozConfig ? new SigNozTelemetry(signozConfig, log) : null;
  const falco = createFalcoMonitor(cfg.falco);
  const modelSandboxRuntime = cfg.sandbox?.enabled !== false && cfg.sandbox?.modelValidation?.enabled === true
    ? createSandboxRuntime(cfg.sandbox)
    : undefined;
  const tls = resolveTls(cfg);

  log.info(`loaded ${identities.size()} registered agent identit(ies)`);
  log.info(`upstream model mode: ${cfg.upstream.mode}`);
  log.info(`guardrail provider: ${guard.name} (input=${guardrails.input.mode}, output.redact=${guardrails.output.redactSecrets})`);
  if (opaClient) log.info(`OPA policy: ON (path=${opaClient.config.policyPath}, failOpen=${opaClient.config.failOpen})`);
  if (signozConfig) log.info(`SigNoz telemetry: ON (endpoint=${signozConfig.endpoint}, service=${signozConfig.serviceName})`);
  if (falco) log.info(`Falco runtime policy: ON (webhook=${falco.config.webhookPath}, minimum=${falco.config.minimumPriority})`);
  if (vault) log.info(`Vault secrets: ON (address=${vault.server.address}, failOpen=${vault.failOpen ?? false})`);
  if (modelSandboxRuntime) log.info(`model sandbox validation: ON (runtime=${modelSandboxRuntime.name})`);
  if (tls) log.info(`mutual TLS: ON (client certs required${tls.channelBinding ? ', channel binding' : ''})`);

  // User management API - reuses the gateway's own signing key for session tokens.
  const sessionService = new SessionTokenService(cfg.issuer, key.privateKey, key.publicKey);
  setSessionTokenService(sessionService);
  const authApi = createAuthApi(cfg.issuer, key.privateKey, key.publicKey);
  // Ensure the app store is initialised (singleton, safe to call multiple times).
  getAppStore();

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
    const entry = partial.agentId ? identities.get(partial.agentId)?.entry : undefined;
    const governance = partial.governance
      ?? (entry ? policy.governanceForAgent(entry) : undefined);
    return recordAuditWithTelemetry(audit, telemetry, { ...partial, governance });
  }

  function extractAuthErrorStatus(err: unknown): number {
    const status = (err as { status?: unknown }).status;
    return typeof status === 'number' ? status : 401;
  }

  function unverifiedAccessClaims(token: string): AccessTokenClaims | null {
    try {
      // Audit context only: this payload is intentionally unverified and must
      // never feed authorization or enforcement decisions.
      return decodeJwsPayload<AccessTokenClaims>(token);
    } catch {
      return null;
    }
  }

  // Verify bearer token; on failure write the response and return null.
  function authorize(
    req: IncomingMessage,
    res: ServerResponse,
    rid?: string,
    resource = 'access-token',
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
      const reason = (err as Error).message;
      const rejectedClaims = unverifiedAccessClaims(token);
      if (rid) {
        recordAudit({
          requestId: rid,
          agentId: rejectedClaims?.sub ?? null,
          role: rejectedClaims?.role ?? null,
          action: 'token.reject',
          resource,
          decision: 'deny',
          reason,
        });
      }
      sendError(res, extractAuthErrorStatus(err), 'authentication_error', reason);
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
    rid?: string,
    resource = 'access-token',
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
          governance: claims.governance,
          scope: claims.scope,
        };
      } catch (err) {
        const reason = (err as Error).message;
        const rejectedClaims = unverifiedAccessClaims(token);
        if (rid) {
          recordAudit({
            requestId: rid,
            agentId: rejectedClaims?.sub ?? null,
            role: rejectedClaims?.role ?? null,
            action: 'token.reject',
            resource,
            decision: 'deny',
            reason,
          });
        }
        sendError(res, extractAuthErrorStatus(err), 'authentication_error', reason);
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

      if (method === 'POST' && falco && path === falco.config.webhookPath) {
        return await handleFalcoEvent(req, res, rid);
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

      // === Minimal Web Console ===
      if (routeConsole(req, res)) return;

      // === Management API ===
      if (path.startsWith('/api/')) {
        // Auth routes (register/login/refresh/logout/me) - no prior auth required
        if (await authApi.route(req, res)) return;
        // Application management
        if (await routeAppsApi(req, res)) return;
        // Per-app configuration management
        if (await routeConfigApi(req, res)) return;
        // Quota management
        if (await routeQuotaApi(req, res)) return;
        // Statistics and analytics
        if (await routeStatsApi(req, res)) return;
        // Tier and subscription management
        if (await routeTierApi(req, res)) return;
        // Alert management
        if (await routeAlertsApi(req, res)) return;
        // Enterprise management (projects, agents, roles, policy, audit)
        if (await routeManagementApi(req, res)) return;
        return sendError(res, 404, 'not_found', `no route for ${method} ${path}`);
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
  server.on('close', () => {
    void shutdownVault();
  });

  async function handleFalcoEvent(req: IncomingMessage, res: ServerResponse, rid: string) {
    if (!falco) return sendError(res, 404, 'not_found', 'Falco integration is disabled');

    const secret = falco.verifySecret(
      headerValue(req, 'authorization'),
      headerValue(req, 'x-agentzt-falco-secret'),
    );
    if (!secret.allow) {
      recordAudit({
        requestId: rid,
        agentId: null,
        role: null,
        action: 'falco.event',
        resource: 'falco',
        decision: 'deny',
        reason: secret.reason,
      });
      return sendError(res, 401, 'authentication_error', secret.reason);
    }

    const body = await readJson<unknown>(req);
    if (!body || (typeof body !== 'object' && !Array.isArray(body))) {
      return sendError(res, 400, 'invalid_request', 'Falco event must be an object or array');
    }

    const alerts = falco.recordMany(body as FalcoWebhookPayload);
    for (const alert of alerts) {
      recordAudit({
        requestId: rid,
        agentId: alert.agentId,
        role: null,
        action: 'falco.event',
        resource: alert.rule,
        decision: 'allow',
        reason: alert.agentId
          ? `Falco ${alert.priority} event accepted`
          : 'Falco event accepted without agent binding',
        meta: {
          priority: alert.priority,
          output: alert.output,
          fields: alert.fields,
        },
      });
    }

    return sendJson(res, 202, { accepted: alerts.length });
  }

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
    const claims = authorize(req, res, rid, 'elevation');
    if (!claims) return;
    const body = await readJson<{ kind?: string; name?: string; reason?: string; ttlSeconds?: number; riskLevel?: string }>(req);
    const kind = body.kind === 'model' || body.kind === 'tool' ? body.kind : null;
    const name = typeof body.name === 'string' ? body.name : '';
    if (!kind || !name) {
      return sendError(res, 400, 'invalid_request', 'elevate requires "kind" (model|tool) and "name"');
    }
    const rawReason = typeof body.reason === 'string' ? body.reason.slice(0, 500).trim() : '';
    const reason = rawReason || 'unspecified';
    const riskLevel = parseRiskLevel(body.riskLevel);

    const resourceGovernance = policy.decideResourceGovernance(kind, name, claims.governance);
    if (!resourceGovernance.allow) {
      recordAudit({
        requestId: rid, agentId: claims.sub, role: claims.role,
        action: 'elevation.reject', resource: `${kind}:${name}`, decision: 'deny', reason: resourceGovernance.reason,
        meta: { reason },
      });
      log.deny(`elevation.reject ${claims.sub} -> ${kind}:${name}: ${resourceGovernance.reason}`);
      return sendError(res, 403, 'permission_error', resourceGovernance.reason);
    }

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

    const resourceClassJit = policy.decideResourceClassJit(kind, name, { reason: rawReason, riskLevel });
    if (!resourceClassJit.allow) {
      recordAudit({
        requestId: rid, agentId: claims.sub, role: claims.role,
        action: 'elevation.reject', resource: `${kind}:${name}`, decision: 'deny', reason: resourceClassJit.reason,
        meta: { reason, riskLevel },
      });
      log.deny(`elevation.reject ${claims.sub} -> ${kind}:${name}: ${resourceClassJit.reason}`);
      return sendError(res, 403, 'permission_error', resourceClassJit.reason);
    }

    const maxTtl = policy.jitMaxTtl(claims.role);
    const classMaxTtl = policy.resourceClassJitMaxTtl(kind, name);
    const ttlLimit = classMaxTtl ? Math.min(maxTtl, classMaxTtl) : maxTtl;
    const ttl = Math.min(body.ttlSeconds && body.ttlSeconds > 0 ? body.ttlSeconds : ttlLimit, ttlLimit);
    const { grant, claims: gc } = tokens.issueElevation(claims.sub, claims.role, { kind, name }, reason, ttl);
    recordAudit({
      requestId: rid, agentId: claims.sub, role: claims.role,
      action: 'elevation.grant', resource: `${kind}:${name}`, decision: 'allow',
      reason: `JIT elevation (ttl=${ttl}s)`, meta: { reason, riskLevel, exp: gc.exp },
    });
    log.allow(`elevation.grant ${claims.sub} -> ${kind}:${name} (ttl=${ttl}s, reason="${reason}")`);
    return sendJson(res, 200, { elevation_grant: grant, expires_in: ttl, resource: { kind, name } });
  }

  // Authorize a resource: in standing scope, OR via a valid JIT elevation grant.
  function approvalMeta(decision: { approvalRequired?: boolean; approvalType?: string }) {
    if (!decision.approvalRequired) return undefined;
    return { approvalRequired: true, approvalType: decision.approvalType };
  }

  function authorizeResource(
    req: IncomingMessage,
    claims: AccessTokenClaims,
    kind: 'model' | 'tool',
    name: string,
  ): { allow: boolean; reason: string; via: 'scope' | 'jit'; approvalRequired?: boolean; approvalType?: string } {
    const scopeList = kind === 'model' ? claims.scope.models : claims.scope.tools;
    const inScope = scopeList.includes('*') || scopeList.includes(name);
    const base = kind === 'model' ? policy.decideModel(claims.role, name) : policy.decideTool(claims.role, name);
    const resourceClass = policy.resourceClassFor(kind, name);
    const resourceGovernance = policy.decideResourceGovernance(kind, name, claims.governance);
    if (!resourceGovernance.allow) {
      return {
        allow: false,
        reason: resourceGovernance.reason,
        via: 'scope',
        approvalRequired: resourceGovernance.approvalRequired,
        approvalType: resourceGovernance.approvalType,
      };
    }
    const jitRequired = resourceClass?.jitRequired === true;
    if (inScope && base.allow && !jitRequired) return { allow: true, reason: base.reason, via: 'scope' };

    const grant = headerValue(req, ELEVATION_HEADER);
    if (grant) {
      try {
        const g = tokens.verifyElevation(grant, claims.sub, kind, name);
        return { allow: true, reason: `JIT elevation (exp in ${g.exp - Math.floor(Date.now() / 1000)}s)`, via: 'jit' };
      } catch (err) {
        return { allow: false, reason: `elevation invalid: ${(err as Error).message}`, via: 'jit' };
      }
    }
    if (jitRequired) {
      return { allow: false, reason: `${kind} "${name}" is in a JIT-required resource class`, via: 'jit' };
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

  function decideFalco(agentId: string): FalcoRuntimeDecision {
    if (!falco) return { allow: true, reason: 'Falco disabled' };
    return falco.decideAgent(agentId);
  }

  function blockFalcoIfNeeded(
    res: ServerResponse,
    rid: string,
    agentId: string | null | undefined,
    role: string | null | undefined,
    resource: string,
  ): boolean {
    if (!agentId) return false;
    const falcoDecision = decideFalco(agentId);
    if (falcoDecision.allow) return false;
    recordAudit({
      requestId: rid,
      agentId,
      role: role ?? null,
      action: 'falco.block',
      resource,
      decision: 'deny',
      reason: falcoDecision.reason,
      meta: { falco: falcoDecision.alert },
    });
    log.deny(`falco.block ${agentId} -> ${resource}: ${falcoDecision.reason}`);
    sendError(res, 403, 'permission_error', falcoDecision.reason);
    return true;
  }

  async function handleMessages(req: IncomingMessage, res: ServerResponse, rid: string) {
    const claims = authorize(req, res, rid, 'model');
    if (!claims) return;
    const started = Date.now();
    const body = await readJson<Record<string, unknown>>(req);
    const model = typeof body['model'] === 'string' ? (body['model'] as string) : '';
    if (!model) return sendError(res, 400, 'invalid_request', 'missing "model"');

    if (blockFalcoIfNeeded(res, rid, claims.sub, claims.role, model)) return;

    // Authorize: standing scope or JIT elevation.
    const authz = authorizeResource(req, claims, 'model', model);
    if (!authz.allow) {
      recordAudit({
        requestId: rid, agentId: claims.sub, role: claims.role,
        action: 'model.call', resource: model, decision: 'deny', reason: authz.reason,
        meta: approvalMeta(authz),
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
    const inputSandboxValidation = await runSandboxValidation(modelSandboxRuntime, cfg, 'input', messages.map((m) => m.content).join('\n'));
    if (!inputSandboxValidation.allow) {
      const reason = inputSandboxValidation.reason ?? 'input sandbox validation failed';
      recordAudit({
        requestId: rid, agentId: claims.sub, role: claims.role,
        action: 'sandbox.validate', resource: model, decision: 'deny', reason,
        meta: { stage: 'input', findings: inputSandboxValidation.findings },
      });
      log.deny(`sandbox.validate ${claims.sub} -> ${model}: ${reason}`);
      return sendError(res, 403, 'sandbox_validation_failed', reason);
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

    const result = await callModel(cfg, { model, body, protocol: 'anthropic-messages' });
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
    const outputSandboxValidation = result.status === 200
      ? await runSandboxValidation(modelSandboxRuntime, cfg, 'output', extractText(result.body))
      : { allow: true, findings: [] };
    if (!outputSandboxValidation.allow) {
      replaceText(result.body, '[response withheld by sandbox validation]');
    }

    recordAudit({
      requestId: rid, agentId: claims.sub, role: claims.role,
      action: 'model.call', resource: model, decision: 'allow',
      reason: decision.reason, latencyMs,
      meta: {
        authVia: authz.via,
        upstreamProvider: result.provider,
        upstreamStatus: result.status,
        usage: result.usage,
        maxTokens: body['max_tokens'],
        guardrailProvider: guard.name,
        inputVerdict,
        outputVerdict,
        inputSandboxValidation: inputSandboxValidation.findings,
        outputSandboxValidation: outputSandboxValidation.findings,
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
    const claims = authorize(req, res, rid, name);
    if (!claims) return;
    const started = Date.now();

    if (blockFalcoIfNeeded(res, rid, claims.sub, claims.role, name)) return;

    // Authorize: standing scope or JIT elevation.
    const authz = authorizeResource(req, claims, 'tool', name);
    if (!authz.allow) {
      recordAudit({
        requestId: rid, agentId: claims.sub, role: claims.role,
        action: 'tool.call', resource: name, decision: 'deny', reason: authz.reason,
        meta: approvalMeta(authz),
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

    let credentials: Record<string, string> | undefined;
    if (cfg.vault?.enabled) {
      try {
        credentials = await getToolCredentialsFromVault(cfg.vault, name);
      } catch (err) {
        log.warn(`Vault credentials unavailable for tool ${name}: ${(err as Error).message}`);
      }
    }

    let result = await tool.run(args, {
      agentId: claims.sub,
      role: claims.role,
      requestId: rid,
      governance: claims.governance,
      credentials,
    });

    // Tool outputs are untrusted egress: redact credential-shaped strings before
    // they reach the agent (and could be fed back into a model prompt).
    let outRedactions = 0;
    if (guardrails.output.redactSecrets) {
      const r = redactSecretsDeep(result);
      result = r.value;
      outRedactions = r.count;
    }
    const { auditMeta, ...wireResult } = result;

    const latencyMs = Date.now() - started;
    recordAudit({
      requestId: rid, agentId: claims.sub, role: claims.role,
      action: 'tool.call', resource: name, decision: 'allow',
      reason: decision.reason, latencyMs,
      meta: {
        ok: result.ok,
        outputRedactions: outRedactions,
        authVia: authz.via,
        opa: opaClient ? { reason: opaDecision.reason } : undefined,
        ...auditMeta,
      },
    });
    log.allow(`tool.call ${claims.sub} -> ${name} (${latencyMs}ms, via=${authz.via})${outRedactions ? ` redacted:${outRedactions}` : ''}`);
    return sendJson(res, wireResult.ok ? 200 : 400, wireResult, { [REQUEST_ID_HEADER]: rid });
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
    const auth = authorizeExtended(req, res, rid, targetPath);
    if (!auth) return;

    if (auth.type === 'agent_token' && blockFalcoIfNeeded(res, rid, auth.agentId, auth.role, targetPath)) return;
    
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
    const result = await callModel(cfg, {
      model,
      body,
      protocol: targetPath === 'chat/completions' ? 'openai-chat' : 'anthropic-messages',
    });
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
        upstreamProvider: result.provider,
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
    const auth = authorizeExtended(req, res, rid, 'guardrails');
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
    const result = await callModel(cfg, { model: body.model, body: { ...body }, protocol: 'openai-chat' });
    const latencyMs = Date.now() - started;
    if (result.status !== 200) {
      recordAudit({
        requestId: rid,
        agentId: null,
        role: null,
        appId: app.appId,
        userId: app.ownerId,
        action: 'direct.call',
        resource: body.model,
        decision: 'deny',
        reason: 'upstream model call failed',
        latencyMs,
        categories: inputVerdict.categories,
        score: inputVerdict.flagged ? 0.5 : 0,
        meta: {
          upstreamProvider: result.provider,
          upstreamStatus: result.status,
          guardrailProvider: appGuard.name,
          inputFlagged: inputVerdict.flagged,
        },
      });
      log.deny(`direct.call -> ${body.model}: upstream status ${result.status}`);
      return sendJson(res, result.status, result.body, { [REQUEST_ID_HEADER]: rid });
    }

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
        upstreamProvider: result.provider,
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

async function loadGatewaySigningKey(vault: ReturnType<typeof resolveVaultConfig>) {
  if (vault) {
    try {
      const privateKeyJwk = await getGatewaySigningKeyFromVault(vault);
      if (privateKeyJwk) {
        log.info('gateway signing key loaded from Vault');
        return loadGatewayKeyFromPrivateJwk(privateKeyJwk);
      }
    } catch (err) {
      log.warn(`Vault gateway signing key unavailable; using local key: ${(err as Error).message}`);
    }
  }
  return loadOrCreateGatewayKey();
}

// ---- Anthropic Messages response helpers -----------------------------------

function extractText(body: unknown): string {
  const data = body as Record<string, unknown> | null;
  if (!data || typeof data !== 'object') return '';

  // Anthropic Messages style:
  // { content: [{ type: "text", text: "..." }] }
  const content = data['content'];
  if (Array.isArray(content)) {
    return content
      .map((b) => (b as Record<string, unknown>)['text'])
      .filter((t): t is string => typeof t === 'string')
      .join('\n');
  }

  // OpenAI / DeepSeek chat completions style:
  // { choices: [{ message: { content: "..." } }] }
  const choices = data['choices'];
  if (Array.isArray(choices)) {
    const texts: string[] = [];
    for (const choice of choices) {
      const message = (choice as Record<string, unknown>)['message'] as Record<string, unknown> | undefined;
      const messageContent = message?.['content'];
      if (typeof messageContent === 'string') {
        texts.push(messageContent);
      } else if (Array.isArray(messageContent)) {
        for (const block of messageContent) {
          const text = (block as Record<string, unknown>)['text'];
          if (typeof text === 'string') texts.push(text);
        }
      }
    }
    return texts.join('\n');
  }

  return '';
}

function replaceText(body: unknown, text: string): void {
  if (body && typeof body === 'object') {
    (body as Record<string, unknown>)['content'] = [{ type: 'text', text }];
  }
}

import { existsSync, readFileSync } from 'node:fs';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { resolve } from 'node:path';
import { bearerToken, readJson, sendError, sendJson } from '../shared/http.ts';
import { AUDIT_DIR } from '../shared/paths.ts';
import { verifyChain } from '../shared/audit.ts';
import { loadPolicy, loadRegistry, savePolicy, saveRegistry } from '../shared/config.ts';
import type {
  AgentLifecycleStatus,
  AgentRegistryEntry,
  AuditEvent,
  GovernanceBoundary,
  PolicyDoc,
  RolePolicy,
  UserRole,
} from '../shared/types.ts';
import { getSessionTokenService } from './session.ts';

type AuthContext = {
  userId: string;
  role: UserRole;
};

type AuditFilters = {
  agentId?: string;
  role?: string;
  action?: string;
  resource?: string;
  decision?: string;
  projectId?: string;
};

const ROLE_RANK: Record<UserRole, number> = {
  owner: 3,
  admin: 2,
  viewer: 1,
};

const AGENT_STATUSES = ['active', 'disabled', 'revoked'] as const;

function roleAtLeast(actual: UserRole, required: UserRole): boolean {
  return ROLE_RANK[actual] >= ROLE_RANK[required];
}

function authenticate(req: IncomingMessage): AuthContext | null {
  const service = getSessionTokenService();
  const testUserId = req.headers['x-user-id'];
  const testRole = req.headers['x-user-role'];
  if (!service && typeof testUserId === 'string') {
    return {
      userId: testUserId,
      role: typeof testRole === 'string' && isUserRole(testRole) ? testRole : 'viewer',
    };
  }

  const token = bearerToken(req);
  if (!token || !service) return null;

  try {
    const claims = service.verifyToken(token);
    return { userId: claims.sub, role: claims.role };
  } catch {
    return null;
  }
}

function isUserRole(value: string): value is UserRole {
  return value === 'owner' || value === 'admin' || value === 'viewer';
}

function requireRole(req: IncomingMessage, res: ServerResponse, role: UserRole): AuthContext | null {
  const auth = authenticate(req);
  if (!auth) {
    sendError(res, 401, 'authentication_error', 'missing or invalid bearer token');
    return null;
  }
  if (!roleAtLeast(auth.role, role)) {
    sendError(res, 403, 'permission_error', `requires role ${role} or higher`);
    return null;
  }
  return auth;
}

function pathParts(req: IncomingMessage): string[] {
  const url = new URL(req.url ?? '/', 'http://localhost');
  return url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
}

function managementParts(req: IncomingMessage): string[] {
  const parts = pathParts(req);
  if (parts[0] === 'api' && parts[1] === 'v1') {
    return ['api', ...parts.slice(2)];
  }
  return parts;
}

function auditEvents(limit: number, filters: AuditFilters = {}): AuditEvent[] {
  const file = resolve(AUDIT_DIR, 'gateway-audit.jsonl');
  if (!existsSync(file)) return [];
  const lines = readFileSync(file, 'utf8').trim().split('\n').filter(Boolean);
  const events: AuditEvent[] = [];
  for (let i = lines.length - 1; i >= 0 && events.length < limit; i--) {
    const line = lines[i];
    if (!line) continue;
    const event = JSON.parse(line) as AuditEvent;
    if (matchesAuditFilters(event, filters)) events.push(event);
  }
  return events.reverse();
}

function projectIds(policy: PolicyDoc): string[] {
  return policy.enterprise?.governance?.projectIds ?? [];
}

function saveProjectIds(policy: PolicyDoc, projects: string[]): void {
  policy.enterprise ??= {
    version: 1,
    agentLifecycle: { denyStatuses: ['disabled', 'revoked'] },
    decisionOrder: [],
  };
  policy.enterprise.governance ??= {};
  policy.enterprise.governance.projectIds = [...new Set(projects)].sort();
  savePolicy(policy);
}

function publicAgent(entry: AgentRegistryEntry): Omit<AgentRegistryEntry, 'publicKeyJwk'> {
  const { publicKeyJwk: _publicKeyJwk, ...rest } = entry;
  return rest;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function isPublicJwk(value: unknown): value is JsonWebKey {
  if (!isObject(value)) return false;
  return value['kty'] === 'OKP'
    && value['crv'] === 'Ed25519'
    && typeof value['x'] === 'string'
    && value['d'] === undefined;
}

function isAgentStatus(value: unknown): value is AgentLifecycleStatus {
  return typeof value === 'string' && (AGENT_STATUSES as readonly string[]).includes(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function isGovernance(value: unknown): value is GovernanceBoundary {
  if (value === undefined) return true;
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const obj = value as Record<string, unknown>;
  return ['organizationId', 'projectId', 'environment'].every((key) =>
    obj[key] === undefined || typeof obj[key] === 'string');
}

function isRolePolicy(value: unknown): value is RolePolicy {
  if (!isObject(value)) return false;
  const obj = value;
  return isStringArray(obj['models'])
    && isStringArray(obj['tools'])
    && isGovernance(obj['governance']);
}

function matchesAuditFilters(event: AuditEvent, filters: AuditFilters): boolean {
  if (filters.agentId !== undefined && event.agentId !== filters.agentId) return false;
  if (filters.role !== undefined && event.role !== filters.role) return false;
  if (filters.action !== undefined && event.action !== filters.action) return false;
  if (filters.resource !== undefined && event.resource !== filters.resource) return false;
  if (filters.decision !== undefined && event.decision !== filters.decision) return false;
  if (filters.projectId !== undefined && event.governance?.projectId !== filters.projectId) return false;
  return true;
}

async function handleProjects(req: IncomingMessage, res: ServerResponse, method: string, parts: string[]): Promise<boolean> {
  if (parts[1] !== 'projects') return false;
  if (method === 'GET' && parts.length === 2) {
    if (!requireRole(req, res, 'viewer')) return true;
    const policy = loadPolicy();
    sendJson(res, 200, { projects: projectIds(policy) });
    return true;
  }
  if (method === 'POST' && parts.length === 2) {
    if (!requireRole(req, res, 'admin')) return true;
    const body = await readJson<{ projectId?: unknown }>(req);
    if (typeof body.projectId !== 'string' || body.projectId.trim() === '') {
      sendError(res, 400, 'invalid_request', 'projectId is required');
      return true;
    }
    const policy = loadPolicy();
    saveProjectIds(policy, [...projectIds(policy), body.projectId.trim()]);
    sendJson(res, 201, { projectId: body.projectId.trim() });
    return true;
  }
  if (method === 'DELETE' && parts.length === 3) {
    if (!requireRole(req, res, 'admin')) return true;
    const policy = loadPolicy();
    saveProjectIds(policy, projectIds(policy).filter((id) => id !== parts[2]));
    sendJson(res, 200, { deleted: parts[2] });
    return true;
  }
  return false;
}

async function handleAgents(req: IncomingMessage, res: ServerResponse, method: string, parts: string[]): Promise<boolean> {
  if (parts[1] !== 'agents') return false;
  const registry = loadRegistry();
  if (method === 'POST' && parts.length === 2) {
    if (!requireRole(req, res, 'admin')) return true;
    const body = await readJson<{
      agentId?: unknown;
      role?: unknown;
      publicKeyJwk?: unknown;
      description?: unknown;
      governance?: unknown;
      status?: unknown;
    }>(req);
    if (typeof body.agentId !== 'string' || body.agentId.trim() === '') {
      sendError(res, 400, 'invalid_request', 'agentId is required');
      return true;
    }
    if (typeof body.role !== 'string' || body.role.trim() === '') {
      sendError(res, 400, 'invalid_request', 'role is required');
      return true;
    }
    if (!isPublicJwk(body.publicKeyJwk)) {
      sendError(res, 400, 'invalid_request', 'publicKeyJwk is required');
      return true;
    }
    if (body.description !== undefined && typeof body.description !== 'string') {
      sendError(res, 400, 'invalid_request', 'description must be a string');
      return true;
    }
    if (!isGovernance(body.governance)) {
      sendError(res, 400, 'invalid_request', 'governance must contain string organizationId, projectId, or environment');
      return true;
    }
    if (body.status !== undefined && !isAgentStatus(body.status)) {
      sendError(res, 400, 'invalid_request', 'status must be active, disabled, or revoked');
      return true;
    }
    const agentId = body.agentId.trim();
    const role = body.role.trim();
    if (registry.agents.some((agent) => agent.agentId === agentId)) {
      sendError(res, 409, 'conflict', `agent "${agentId}" already exists`);
      return true;
    }
    const policy = loadPolicy();
    if (!policy.roles[role]) {
      sendError(res, 400, 'invalid_request', `role "${role}" not found`);
      return true;
    }
    const entry: AgentRegistryEntry = {
      agentId,
      role,
      publicKeyJwk: body.publicKeyJwk,
      createdAt: new Date().toISOString(),
    };
    if (body.status !== undefined) entry.status = body.status;
    if (body.description !== undefined) entry.description = body.description;
    if (body.governance !== undefined) entry.governance = body.governance;
    if (entry.status === 'revoked') entry.revokedAt = new Date().toISOString();
    registry.agents.push(entry);
    saveRegistry(registry);
    sendJson(res, 201, publicAgent(entry));
    return true;
  }
  if (method === 'GET' && parts.length === 2) {
    if (!requireRole(req, res, 'viewer')) return true;
    sendJson(res, 200, {
      agents: registry.agents.map(publicAgent),
      total: registry.agents.length,
    });
    return true;
  }
  if (method === 'GET' && parts.length === 3) {
    if (!requireRole(req, res, 'viewer')) return true;
    const entry = registry.agents.find((agent) => agent.agentId === parts[2]);
    if (!entry) {
      sendError(res, 404, 'not_found', `agent "${parts[2]}" not found`);
      return true;
    }
    sendJson(res, 200, publicAgent(entry));
    return true;
  }
  if (method === 'PATCH' && parts.length === 3) {
    if (!requireRole(req, res, 'admin')) return true;
    const entry = registry.agents.find((agent) => agent.agentId === parts[2]);
    if (!entry) {
      sendError(res, 404, 'not_found', `agent "${parts[2]}" not found`);
      return true;
    }
    const body = await readJson<{
      role?: unknown;
      status?: unknown;
      description?: unknown;
      governance?: unknown;
      revokedReason?: unknown;
    }>(req);
    if (body.role !== undefined && typeof body.role !== 'string') {
      sendError(res, 400, 'invalid_request', 'role must be a string');
      return true;
    }
    if (body.status !== undefined && !isAgentStatus(body.status)) {
      sendError(res, 400, 'invalid_request', 'status must be active, disabled, or revoked');
      return true;
    }
    if (body.description !== undefined && typeof body.description !== 'string') {
      sendError(res, 400, 'invalid_request', 'description must be a string');
      return true;
    }
    if (!isGovernance(body.governance)) {
      sendError(res, 400, 'invalid_request', 'governance must contain string organizationId, projectId, or environment');
      return true;
    }
    if (body.role !== undefined) entry.role = body.role;
    if (body.status !== undefined) {
      entry.status = body.status;
      if (body.status === 'revoked') entry.revokedAt ??= new Date().toISOString();
      if (body.status !== 'revoked') {
        delete entry.revokedAt;
        delete entry.revokedReason;
      }
    }
    if (body.description !== undefined) entry.description = body.description;
    if (body.governance !== undefined) entry.governance = body.governance;
    if (typeof body.revokedReason === 'string') entry.revokedReason = body.revokedReason;
    saveRegistry(registry);
    sendJson(res, 200, publicAgent(entry));
    return true;
  }
  if (method === 'DELETE' && parts.length === 3) {
    if (!requireRole(req, res, 'admin')) return true;
    const before = registry.agents.length;
    registry.agents = registry.agents.filter((agent) => agent.agentId !== parts[2]);
    if (registry.agents.length === before) {
      sendError(res, 404, 'not_found', `agent "${parts[2]}" not found`);
      return true;
    }
    saveRegistry(registry);
    sendJson(res, 200, { deleted: parts[2] });
    return true;
  }
  return false;
}

async function handleRoles(req: IncomingMessage, res: ServerResponse, method: string, parts: string[]): Promise<boolean> {
  if (parts[1] !== 'roles') return false;
  const policy = loadPolicy();
  if (method === 'GET' && parts.length === 2) {
    if (!requireRole(req, res, 'viewer')) return true;
    sendJson(res, 200, { roles: policy.roles });
    return true;
  }
  if (method === 'GET' && parts.length === 3) {
    if (!requireRole(req, res, 'viewer')) return true;
    const roleName = parts[2] ?? '';
    const role = policy.roles[roleName];
    if (!role) {
      sendError(res, 404, 'not_found', `role "${roleName}" not found`);
      return true;
    }
    sendJson(res, 200, role);
    return true;
  }
  if (method === 'PUT' && parts.length === 3) {
    if (!requireRole(req, res, 'admin')) return true;
    const roleName = parts[2] ?? '';
    const body = await readJson<unknown>(req);
    if (!isRolePolicy(body)) {
      sendError(res, 400, 'invalid_request', 'role policy requires models and tools string arrays');
      return true;
    }
    policy.roles[roleName] = body;
    savePolicy(policy);
    sendJson(res, 200, { name: roleName, role: body });
    return true;
  }
  if (method === 'DELETE' && parts.length === 3) {
    if (!requireRole(req, res, 'admin')) return true;
    const roleName = parts[2] ?? '';
    delete policy.roles[roleName];
    savePolicy(policy);
    sendJson(res, 200, { deleted: roleName });
    return true;
  }
  return false;
}

async function handlePolicy(req: IncomingMessage, res: ServerResponse, method: string, parts: string[]): Promise<boolean> {
  if (parts[1] !== 'policy') return false;
  if (method === 'GET' && parts.length === 2) {
    if (!requireRole(req, res, 'viewer')) return true;
    sendJson(res, 200, loadPolicy());
    return true;
  }
  if (method === 'PUT' && parts.length === 2) {
    if (!requireRole(req, res, 'admin')) return true;
    const policy = await readJson<PolicyDoc>(req);
    if (!policy || typeof policy.version !== 'number' || typeof policy.defaultDeny !== 'boolean' || !policy.roles) {
      sendError(res, 400, 'invalid_request', 'policy requires version, defaultDeny, and roles');
      return true;
    }
    savePolicy(policy);
    sendJson(res, 200, policy);
    return true;
  }
  return false;
}

async function handleAudit(req: IncomingMessage, res: ServerResponse, method: string, parts: string[]): Promise<boolean> {
  if (parts[1] !== 'audit') return false;
  if (method !== 'GET' || parts.length !== 2) return false;
  if (!requireRole(req, res, 'viewer')) return true;
  const url = new URL(req.url ?? '/', 'http://localhost');
  const limit = Math.min(Math.max(Number(url.searchParams.get('limit') ?? 100), 1), 1000);
  const file = resolve(AUDIT_DIR, 'gateway-audit.jsonl');
  const verify = url.searchParams.get('verify') === '1' ? verifyChain(file) : undefined;
  const resource = url.searchParams.get('resource') ?? url.searchParams.get('model') ?? undefined;
  const filters: AuditFilters = {
    agentId: url.searchParams.get('agentId') ?? undefined,
    role: url.searchParams.get('role') ?? undefined,
    action: url.searchParams.get('action') ?? undefined,
    resource,
    decision: url.searchParams.get('decision') ?? undefined,
    projectId: url.searchParams.get('projectId') ?? undefined,
  };
  sendJson(res, 200, {
    events: auditEvents(limit, filters),
    verify,
  });
  return true;
}

async function handleSandbox(req: IncomingMessage, res: ServerResponse, method: string, parts: string[]): Promise<boolean> {
  if (parts[1] !== 'sandbox') return false;
  if (method !== 'POST' || parts.length !== 3 || parts[2] !== 'execute') return false;
  const auth = requireRole(req, res, 'admin');
  if (!auth) return true;

  const body = await readJson<Record<string, unknown>>(req);
  const args = isObject(body['arguments']) ? body['arguments'] as Record<string, unknown> : body;
  const { getTool } = await import('../gateway/tool-registry.ts');
  const tool = getTool('sandbox.execute');
  if (!tool) {
    sendError(res, 404, 'not_found', 'sandbox.execute is not implemented');
    return true;
  }
  const validationError = tool.validate(args);
  if (validationError) {
    sendError(res, 400, 'invalid_request', validationError);
    return true;
  }
  const result = await tool.run(args, {
    agentId: `management:${auth.userId}`,
    role: auth.role,
    requestId: `management-sandbox-${Date.now()}`,
    governance: typeof body['projectId'] === 'string' ? { projectId: body['projectId'] } : undefined,
  });
  const { auditMeta: _auditMeta, ...wireResult } = result;
  sendJson(res, wireResult.ok ? 200 : 400, wireResult);
  return true;
}

export async function routeManagementApi(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
  const parts = managementParts(req);
  if (parts[0] !== 'api') return false;
  const method = req.method ?? 'GET';
  return await handleProjects(req, res, method, parts)
    || await handleAgents(req, res, method, parts)
    || await handleRoles(req, res, method, parts)
    || await handlePolicy(req, res, method, parts)
    || await handleAudit(req, res, method, parts)
    || await handleSandbox(req, res, method, parts);
}

import { writeFileSync, mkdirSync, existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { IDENTITIES_DIR, AUDIT_DIR } from '../shared/paths.ts';
import { generateEd25519, newId } from '../shared/crypto.ts';
import { loadRegistry, saveRegistry, loadPolicy, savePolicy } from '../shared/config.ts';
import { verifyChain } from '../shared/audit.ts';
import { AuditLogger } from '../shared/audit.ts';
import { caInit, issueClientCert } from './tls.ts';
import { exportPolicyState } from '../gateway/policy-export.ts';
import { defaultEnterprisePolicy } from '../gateway/policy-engine.ts';
import type {
  AgentIdentityFile,
  AgentLifecycleStatus,
  AgentRegistryEntry,
  AuditAction,
  EnterpriseResourceClass,
  PolicyDoc,
} from '../shared/types.ts';

function flag(args: string[], name: string): string | undefined {
  const idx = args.indexOf(name);
  return idx >= 0 ? args[idx + 1] : undefined;
}

function usage(): never {
  console.log(`agentzt — Zero Trust for AI Agents

Usage:
  npm run enroll -- --agent <id> --role <role> [--description <text>] [--mtls]
  node src/cli/index.ts agents [disable|revoke --agent <id> [--reason <text>] | role --agent <id> --role <role> [--reason <text>] | rotate-key --agent <id> [--reason <text>] [--mtls]]
  node src/cli/index.ts audit [--limit N | --verify]
  node src/cli/index.ts policy export
  node src/cli/index.ts policy role grant --role <role> [--models a,b] [--tools x,y] [--reason <text>]
  node src/cli/index.ts policy resource-class set --name <name> --kind model|tool --resources a,b [--jit-required true|false] [--description <text>] [--reason <text>]
  node src/cli/index.ts policy lifecycle deny-statuses --statuses active,disabled,revoked [--reason <text>]
  node src/cli/index.ts policy jit set --role <role> [--models a,b] [--tools x,y] [--ttl seconds] [--reason <text>]
  node src/cli/index.ts roles
  node src/cli/index.ts tls init [--force]
  node src/cli/index.ts tls issue --agent <id>

Commands:
  enroll   Generate a cryptographic identity for an agent, write the private
           key to .agentzt/identities/<id>.json, and register the public key
           in config/agents.json. With --mtls, also issue an mTLS client cert.
  agents   List registered agent identities, or disable/revoke/change role/rotate key with audit.
  roles    List roles defined in config/policy.json.
  audit    Print recent gateway audit events, or --verify the hash chain.
  policy   Export or mutate policy state with tamper-evident audit events.
  tls      Manage mutual-TLS PKI: 'init' creates the CA + gateway server cert,
           'issue --agent <id>' issues a client cert (requires openssl).
`);
  process.exit(1);
}

function agentStatus(entry: AgentRegistryEntry): AgentLifecycleStatus {
  if (entry.revokedAt || entry.status === 'revoked') return 'revoked';
  if (entry.disabled || entry.status === 'disabled') return 'disabled';
  return 'active';
}

function recordLifecycleAudit(action: AuditAction, entry: AgentRegistryEntry, reason: string): void {
  const audit = new AuditLogger(resolve(AUDIT_DIR, 'gateway-audit.jsonl'));
  audit.record({
    requestId: newId('cli'),
    agentId: entry.agentId,
    role: entry.role,
    governance: entry.governance,
    action,
    resource: `agent:${entry.agentId}`,
    decision: 'allow',
    reason,
    meta: {
      status: agentStatus(entry),
    },
  });
}

function recordPolicyAudit(action: AuditAction, resource: string, reason: string, meta: Record<string, unknown>): void {
  const audit = new AuditLogger(resolve(AUDIT_DIR, 'gateway-audit.jsonl'));
  audit.record({
    requestId: newId('cli'),
    agentId: null,
    role: null,
    action,
    resource,
    decision: 'allow',
    reason,
    meta,
  });
}

function csv(value: string | undefined): string[] | undefined {
  if (value === undefined) return undefined;
  return value.split(',').map((part) => part.trim()).filter(Boolean);
}

function mergeUnique(existing: string[], additions: string[] | undefined): string[] {
  if (!additions) return existing;
  return [...new Set([...existing, ...additions])].sort();
}

function parseBoolean(value: string | undefined, name: string): boolean | undefined {
  if (value === undefined) return undefined;
  if (value === 'true') return true;
  if (value === 'false') return false;
  console.error(`error: ${name} must be true or false`);
  process.exit(1);
}

function parsePositiveInt(value: string | undefined, name: string): number | undefined {
  if (value === undefined) return undefined;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    console.error(`error: ${name} must be a positive integer`);
    process.exit(1);
  }
  return parsed;
}

function ensureEnterprise(policy: PolicyDoc): NonNullable<PolicyDoc['enterprise']> {
  policy.enterprise ??= defaultEnterprisePolicy();
  policy.enterprise.agentLifecycle ??= { denyStatuses: ['disabled', 'revoked'] };
  policy.enterprise.resourceClasses ??= {};
  return policy.enterprise;
}

function identityPath(agentId: string): string {
  return resolve(IDENTITIES_DIR, `${agentId}.json`);
}

function cmdEnroll(args: string[]): void {
  const agentId = flag(args, '--agent');
  const role = flag(args, '--role');
  const description = flag(args, '--description');
  const force = args.includes('--force');
  if (!agentId || !role) usage();

  const policy = loadPolicy();
  if (!policy.roles[role]) {
    console.error(`error: role "${role}" is not defined in config/policy.json`);
    console.error(`available roles: ${Object.keys(policy.roles).join(', ')}`);
    process.exit(1);
  }

  const reg = loadRegistry();
  if (reg.agents.some((a) => a.agentId === agentId)) {
    if (!force) {
      console.error(`error: agent "${agentId}" is already registered (use --force to re-enroll)`);
      process.exit(1);
    }
    reg.agents = reg.agents.filter((a) => a.agentId !== agentId);
  }

  const mtls = args.includes('--mtls');
  const { publicKeyJwk, privateKeyJwk } = generateEd25519();
  const createdAt = new Date().toISOString();

  mkdirSync(IDENTITIES_DIR, { recursive: true });
  const identityFile: AgentIdentityFile = {
    agentId,
    role,
    publicKeyJwk,
    privateKeyJwk,
    createdAt,
  };
  const idPath = identityPath(agentId);
  if (existsSync(idPath) && !force) {
    console.error(`error: identity file already exists: ${idPath} (use --force to overwrite)`);
    process.exit(1);
  }
  writeFileSync(idPath, JSON.stringify(identityFile, null, 2));

  const entry: AgentRegistryEntry = {
    agentId,
    role,
    publicKeyJwk,
    createdAt,
  };
  if (description) entry.description = description;
  reg.agents.push(entry);
  saveRegistry(reg);
  recordLifecycleAudit('lifecycle.create', entry, `agent "${agentId}" enrolled`);

  if (mtls) issueClientCert(agentId);

  console.log(`enrolled agent "${agentId}" (role=${role})`);
  console.log(`  private identity: ${idPath}  (keep secret; gitignored)`);
  console.log(`  public key registered in config/agents.json`);
  console.log(`\nrun its client proxy with:`);
  console.log(`  AGENTZT_AGENT_ID=${agentId} npm run client`);
}

function cmdAgentLifecycle(args: string[], target: 'disabled' | 'revoked'): void {
  const agentId = flag(args, '--agent');
  const reason = flag(args, '--reason');
  if (!agentId) {
    console.error(`error: agents ${target === 'disabled' ? 'disable' : 'revoke'} requires --agent <id>`);
    process.exit(1);
  }

  const reg = loadRegistry();
  const entry = reg.agents.find((a) => a.agentId === agentId);
  if (!entry) {
    console.error(`error: agent "${agentId}" is not registered`);
    process.exit(1);
  }

  const current = agentStatus(entry);
  if (current === target) {
    console.log(`agent "${agentId}" is already ${target}`);
    return;
  }
  if (current === 'revoked') {
    console.error(`error: agent "${agentId}" is revoked and cannot be changed`);
    process.exit(1);
  }

  if (target === 'disabled') {
    entry.status = 'disabled';
    entry.disabled = true;
  } else {
    entry.status = 'revoked';
    entry.disabled = undefined;
    entry.revokedAt = new Date().toISOString();
    if (reason) entry.revokedReason = reason;
  }

  saveRegistry(reg);
  const action = target === 'disabled' ? 'lifecycle.disable' : 'lifecycle.revoke';
  recordLifecycleAudit(action, entry, reason ?? `agent "${agentId}" ${target}`);
  console.log(`${target} agent "${agentId}"`);
}

function cmdAgentRoleChange(args: string[]): void {
  const agentId = flag(args, '--agent');
  const role = flag(args, '--role');
  const reason = flag(args, '--reason');
  if (!agentId || !role) {
    console.error('error: agents role requires --agent <id> --role <role>');
    process.exit(1);
  }

  const policy = loadPolicy();
  if (!policy.roles[role]) {
    console.error(`error: role "${role}" is not defined in config/policy.json`);
    console.error(`available roles: ${Object.keys(policy.roles).join(', ')}`);
    process.exit(1);
  }

  const reg = loadRegistry();
  const entry = reg.agents.find((a) => a.agentId === agentId);
  if (!entry) {
    console.error(`error: agent "${agentId}" is not registered`);
    process.exit(1);
  }
  if (agentStatus(entry) === 'revoked') {
    console.error(`error: agent "${agentId}" is revoked and cannot be changed`);
    process.exit(1);
  }
  if (entry.role === role) {
    console.log(`agent "${agentId}" already has role "${role}"`);
    return;
  }

  const previousRole = entry.role;
  entry.role = role;
  saveRegistry(reg);

  const idPath = identityPath(agentId);
  if (existsSync(idPath)) {
    const identity = JSON.parse(readFileSync(idPath, 'utf8')) as AgentIdentityFile;
    identity.role = role;
    writeFileSync(idPath, JSON.stringify(identity, null, 2) + '\n');
  }

  const auditReason = reason ?? `agent "${agentId}" role changed from "${previousRole}" to "${role}"`;
  const audit = new AuditLogger(resolve(AUDIT_DIR, 'gateway-audit.jsonl'));
  audit.record({
    requestId: newId('cli'),
    agentId: entry.agentId,
    role: entry.role,
    governance: entry.governance,
    action: 'lifecycle.role_change',
    resource: `agent:${entry.agentId}`,
    decision: 'allow',
    reason: auditReason,
    meta: {
      previousRole,
      newRole: role,
      status: agentStatus(entry),
    },
  });
  console.log(`changed agent "${agentId}" role from "${previousRole}" to "${role}"`);
}

function cmdAgentKeyRotation(args: string[]): void {
  const agentId = flag(args, '--agent');
  const reason = flag(args, '--reason');
  if (!agentId) {
    console.error('error: agents rotate-key requires --agent <id>');
    process.exit(1);
  }

  const reg = loadRegistry();
  const entry = reg.agents.find((a) => a.agentId === agentId);
  if (!entry) {
    console.error(`error: agent "${agentId}" is not registered`);
    process.exit(1);
  }
  if (agentStatus(entry) === 'revoked') {
    console.error(`error: agent "${agentId}" is revoked and cannot rotate keys`);
    process.exit(1);
  }

  const { publicKeyJwk, privateKeyJwk } = generateEd25519();
  entry.publicKeyJwk = publicKeyJwk;
  saveRegistry(reg);

  mkdirSync(IDENTITIES_DIR, { recursive: true });
  const idPath = identityPath(agentId);
  const existing = existsSync(idPath)
    ? JSON.parse(readFileSync(idPath, 'utf8')) as Partial<AgentIdentityFile>
    : {};
  const identityFile: AgentIdentityFile = {
    agentId,
    role: entry.role,
    publicKeyJwk,
    privateKeyJwk,
    createdAt: existing.createdAt ?? entry.createdAt ?? new Date().toISOString(),
  };
  writeFileSync(idPath, JSON.stringify(identityFile, null, 2) + '\n');

  if (args.includes('--mtls')) issueClientCert(agentId);

  recordLifecycleAudit('lifecycle.key_rotation', entry, reason ?? `agent "${agentId}" key rotated`);
  console.log(`rotated key for agent "${agentId}"`);
  console.log(`  private identity: ${idPath}  (keep secret; gitignored)`);
}

function cmdAgents(args: string[]): void {
  const sub = args[0];
  if (sub === 'disable') {
    cmdAgentLifecycle(args.slice(1), 'disabled');
    return;
  }
  if (sub === 'revoke') {
    cmdAgentLifecycle(args.slice(1), 'revoked');
    return;
  }
  if (sub === 'role') {
    cmdAgentRoleChange(args.slice(1));
    return;
  }
  if (sub === 'rotate-key') {
    cmdAgentKeyRotation(args.slice(1));
    return;
  }
  if (sub) {
    console.error('usage: node src/cli/index.ts agents [disable|revoke --agent <id> [--reason <text>] | role --agent <id> --role <role> [--reason <text>] | rotate-key --agent <id> [--reason <text>] [--mtls]]');
    process.exit(1);
  }

  const reg = loadRegistry();
  if (reg.agents.length === 0) {
    console.log('no agents registered. Enroll one: npm run enroll -- --agent <id> --role <role>');
    return;
  }
  for (const a of reg.agents) {
    const status = agentStatus(a);
    console.log(`${a.agentId}\trole=${a.role}\t${status}\t${a.description ?? ''}`);
  }
}

function cmdRoles(): void {
  const policy = loadPolicy();
  for (const [name, r] of Object.entries(policy.roles)) {
    console.log(`${name}`);
    console.log(`  models: ${r.models.join(', ')}`);
    console.log(`  tools:  ${r.tools.join(', ')}`);
    if (r.description) console.log(`  ${r.description}`);
  }
}

function cmdPolicy(args: string[]): void {
  const sub = args[0];
  if (sub === 'export') {
    console.log(JSON.stringify(exportPolicyState(loadPolicy(), loadRegistry()), null, 2));
    return;
  }
  if (sub === 'role' && args[1] === 'grant') {
    cmdPolicyRoleGrant(args.slice(2));
    return;
  }
  if (sub === 'resource-class' && args[1] === 'set') {
    cmdPolicyResourceClassSet(args.slice(2));
    return;
  }
  if (sub === 'lifecycle' && args[1] === 'deny-statuses') {
    cmdPolicyLifecycleDenyStatuses(args.slice(2));
    return;
  }
  if (sub === 'jit' && args[1] === 'set') {
    cmdPolicyJitSet(args.slice(2));
    return;
  }
  console.error('usage: node src/cli/index.ts policy export | role grant | resource-class set | lifecycle deny-statuses | jit set');
  process.exit(1);
}

function cmdPolicyRoleGrant(args: string[]): void {
  const roleName = flag(args, '--role');
  const models = csv(flag(args, '--models'));
  const tools = csv(flag(args, '--tools'));
  const reason = flag(args, '--reason');
  if (!roleName || (!models && !tools)) {
    console.error('error: policy role grant requires --role <role> and at least one of --models or --tools');
    process.exit(1);
  }

  const policy = loadPolicy();
  const role = policy.roles[roleName];
  if (!role) {
    console.error(`error: role "${roleName}" is not defined in config/policy.json`);
    process.exit(1);
  }
  const before = { models: [...role.models], tools: [...role.tools] };
  role.models = mergeUnique(role.models, models);
  role.tools = mergeUnique(role.tools, tools);
  savePolicy(policy);

  recordPolicyAudit(
    'policy.role_grant.change',
    `role:${roleName}`,
    reason ?? `role "${roleName}" grants changed`,
    { before, after: { models: role.models, tools: role.tools }, addedModels: models ?? [], addedTools: tools ?? [] },
  );
  console.log(`updated grants for role "${roleName}"`);
}

function cmdPolicyResourceClassSet(args: string[]): void {
  const name = flag(args, '--name');
  const kind = flag(args, '--kind');
  const resources = csv(flag(args, '--resources'));
  const jitRequired = parseBoolean(flag(args, '--jit-required'), '--jit-required');
  const description = flag(args, '--description');
  const reason = flag(args, '--reason');
  if (!name || (kind !== 'model' && kind !== 'tool') || !resources?.length) {
    console.error('error: policy resource-class set requires --name <name> --kind model|tool --resources a,b');
    process.exit(1);
  }

  const policy = loadPolicy();
  const enterprise = ensureEnterprise(policy);
  const before = enterprise.resourceClasses?.[name] ?? null;
  const next: EnterpriseResourceClass = {
    ...(before ?? {}),
    kind,
    resources,
  };
  if (description !== undefined) next.description = description;
  if (jitRequired !== undefined) next.jitRequired = jitRequired;
  enterprise.resourceClasses![name] = next;
  savePolicy(policy);

  recordPolicyAudit(
    'policy.resource_class.change',
    `resource-class:${name}`,
    reason ?? `resource class "${name}" changed`,
    { before, after: next },
  );
  console.log(`set resource class "${name}"`);
}

function cmdPolicyLifecycleDenyStatuses(args: string[]): void {
  const statuses = csv(flag(args, '--statuses')) as AgentLifecycleStatus[] | undefined;
  const reason = flag(args, '--reason');
  const valid = new Set(['active', 'disabled', 'revoked']);
  if (!statuses?.length || statuses.some((status) => !valid.has(status))) {
    console.error('error: policy lifecycle deny-statuses requires --statuses active,disabled,revoked');
    process.exit(1);
  }

  const policy = loadPolicy();
  const enterprise = ensureEnterprise(policy);
  const before = [...enterprise.agentLifecycle.denyStatuses];
  enterprise.agentLifecycle.denyStatuses = [...new Set(statuses)].sort();
  savePolicy(policy);

  recordPolicyAudit(
    'policy.lifecycle_rule.change',
    'policy:agent-lifecycle',
    reason ?? 'agent lifecycle deny statuses changed',
    { before: { denyStatuses: before }, after: { denyStatuses: enterprise.agentLifecycle.denyStatuses } },
  );
  console.log(`set lifecycle deny statuses: ${enterprise.agentLifecycle.denyStatuses.join(', ')}`);
}

function cmdPolicyJitSet(args: string[]): void {
  const roleName = flag(args, '--role');
  const models = csv(flag(args, '--models'));
  const tools = csv(flag(args, '--tools'));
  const ttl = parsePositiveInt(flag(args, '--ttl'), '--ttl');
  const reason = flag(args, '--reason');
  if (!roleName || (!models && !tools && ttl === undefined)) {
    console.error('error: policy jit set requires --role <role> and at least one of --models, --tools, or --ttl');
    process.exit(1);
  }

  const policy = loadPolicy();
  const role = policy.roles[roleName];
  if (!role) {
    console.error(`error: role "${roleName}" is not defined in config/policy.json`);
    process.exit(1);
  }
  const before = role.jit ? { ...role.jit } : null;
  role.jit = {
    elevatableModels: models ?? role.jit?.elevatableModels,
    elevatableTools: tools ?? role.jit?.elevatableTools,
    maxTtlSeconds: ttl ?? role.jit?.maxTtlSeconds ?? 300,
  };
  if (!role.jit.elevatableModels?.length) delete role.jit.elevatableModels;
  if (!role.jit.elevatableTools?.length) delete role.jit.elevatableTools;
  savePolicy(policy);

  recordPolicyAudit(
    'policy.jit_config.change',
    `role:${roleName}:jit`,
    reason ?? `role "${roleName}" JIT config changed`,
    { before, after: role.jit },
  );
  console.log(`set JIT config for role "${roleName}"`);
}

function cmdAudit(args: string[]): void {
  const file = resolve(AUDIT_DIR, 'gateway-audit.jsonl');
  if (!existsSync(file)) {
    console.log('no audit log yet (start the gateway and make some requests).');
    return;
  }

  if (args.includes('--verify')) {
    const v = verifyChain(file);
    if (v.ok) {
      console.log(`audit chain OK — ${v.count} event(s), hash chain intact (tamper-evident).`);
    } else {
      console.error(`audit chain BROKEN at seq ${v.brokenAtSeq}: ${v.reason}`);
      console.error(`  ${v.count} event(s) verified before the break.`);
      process.exit(2);
    }
    return;
  }

  const limit = Number(flag(args, '--limit') ?? '20');
  const lines = readFileSync(file, 'utf8').trim().split('\n').filter(Boolean);
  for (const line of lines.slice(-limit)) {
    const ev = JSON.parse(line);
    const mark = ev.decision === 'allow' ? 'ALLOW' : 'DENY ';
    console.log(`#${ev.seq} ${ev.ts} ${mark} ${ev.action} ${ev.agentId ?? '-'} -> ${ev.resource}  (${ev.reason}) rid=${ev.requestId}`);
  }
}

function cmdTls(args: string[]): void {
  const sub = args[0];
  if (sub === 'init') {
    caInit(args.includes('--force'));
  } else if (sub === 'issue') {
    const agentId = flag(args, '--agent');
    if (!agentId) {
      console.error('error: tls issue requires --agent <id>');
      process.exit(1);
    }
    issueClientCert(agentId);
  } else {
    console.error('usage: tls init [--force] | tls issue --agent <id>');
    process.exit(1);
  }
}

const [cmd, ...rest] = process.argv.slice(2);
switch (cmd) {
  case 'enroll': cmdEnroll(rest); break;
  case 'agents': cmdAgents(rest); break;
  case 'roles': cmdRoles(); break;
  case 'audit': cmdAudit(rest); break;
  case 'policy': cmdPolicy(rest); break;
  case 'tls': cmdTls(rest); break;
  default: usage();
}

import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { verifyChain } from '../../src/shared/audit.ts';

const roots: string[] = [];

function writeJsonFile(path: string, value: unknown): void {
  writeFileSync(path, JSON.stringify(value, null, 2) + '\n');
}

function makeRoot(): string {
  const root = join(tmpdir(), `agentzt-policy-change-${randomUUID()}`);
  roots.push(root);
  mkdirSync(join(root, 'config'), { recursive: true });
  writeJsonFile(join(root, 'config', 'agents.json'), { agents: [] });
  writeJsonFile(join(root, 'config', 'policy.json'), {
    version: 1,
    defaultDeny: true,
    enterprise: {
      version: 1,
      agentLifecycle: { denyStatuses: ['disabled', 'revoked'] },
      decisionOrder: ['token', 'agent_lifecycle', 'rbac_or_jit'],
      resourceClasses: {},
    },
    roles: {
      'demo-agent': {
        models: ['claude-haiku-4-5'],
        tools: ['kb.search'],
      },
    },
  });
  return root;
}

afterEach(() => {
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe('policy change audit events', () => {
  it('records role grant, resource class, lifecycle rule, and JIT changes', () => {
    const root = makeRoot();
    const cli = resolve(process.cwd(), 'src/cli/index.ts');
    const env = { ...process.env, AGENTZT_ROOT: root };

    execFileSync(process.execPath, [
      cli,
      'policy',
      'role',
      'grant',
      '--role',
      'demo-agent',
      '--models',
      'claude-sonnet-4-6',
      '--tools',
      'web.fetch',
      '--reason',
      'approve read-only research',
    ], { env });
    execFileSync(process.execPath, [
      cli,
      'policy',
      'resource-class',
      'set',
      '--name',
      'high-blast',
      '--kind',
      'tool',
      '--resources',
      'email.send,temporal.workflow.start',
      '--jit-required',
      'true',
      '--reason',
      'classify high-risk tools',
    ], { env });
    execFileSync(process.execPath, [
      cli,
      'policy',
      'lifecycle',
      'deny-statuses',
      '--statuses',
      'disabled,revoked',
      '--reason',
      'deny inactive agents',
    ], { env });
    execFileSync(process.execPath, [
      cli,
      'policy',
      'jit',
      'set',
      '--role',
      'demo-agent',
      '--tools',
      'email.send',
      '--ttl',
      '120',
      '--reason',
      'temporary send approval only',
    ], { env });

    const policy = JSON.parse(readFileSync(join(root, 'config', 'policy.json'), 'utf8'));
    expect(policy.roles['demo-agent'].models).toEqual(['claude-haiku-4-5', 'claude-sonnet-4-6']);
    expect(policy.roles['demo-agent'].tools).toEqual(['kb.search', 'web.fetch']);
    expect(policy.enterprise.resourceClasses['high-blast']).toMatchObject({
      kind: 'tool',
      resources: ['email.send', 'temporal.workflow.start'],
      jitRequired: true,
    });
    expect(policy.enterprise.agentLifecycle.denyStatuses).toEqual(['disabled', 'revoked']);
    expect(policy.roles['demo-agent'].jit).toEqual({
      elevatableTools: ['email.send'],
      maxTtlSeconds: 120,
    });

    const auditFile = join(root, '.agentzt', 'audit', 'gateway-audit.jsonl');
    const auditLines = readFileSync(auditFile, 'utf8')
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line));

    expect(auditLines.map((event) => event.action)).toEqual([
      'policy.role_grant.change',
      'policy.resource_class.change',
      'policy.lifecycle_rule.change',
      'policy.jit_config.change',
    ]);
    expect(auditLines.map((event) => event.agentId)).toEqual([null, null, null, null]);
    expect(auditLines.map((event) => event.decision)).toEqual(['allow', 'allow', 'allow', 'allow']);
    expect(auditLines[0].meta.addedModels).toEqual(['claude-sonnet-4-6']);
    expect(auditLines[1].resource).toBe('resource-class:high-blast');
    expect(auditLines[2].meta.after).toEqual({ denyStatuses: ['disabled', 'revoked'] });
    expect(auditLines[3].meta.after.maxTtlSeconds).toBe(120);
    expect(verifyChain(auditFile)).toMatchObject({ ok: true, count: 4 });
  });
});

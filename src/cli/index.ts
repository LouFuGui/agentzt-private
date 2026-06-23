import { writeFileSync, mkdirSync, existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { IDENTITIES_DIR, AUDIT_DIR } from '../shared/paths.ts';
import { generateEd25519 } from '../shared/crypto.ts';
import { loadRegistry, saveRegistry, loadPolicy } from '../shared/config.ts';
import { verifyChain } from '../shared/audit.ts';
import { caInit, issueClientCert } from './tls.ts';
import { exportPolicyState } from '../gateway/policy-export.ts';
import type { AgentIdentityFile, AgentRegistryEntry } from '../shared/types.ts';

function flag(args: string[], name: string): string | undefined {
  const idx = args.indexOf(name);
  return idx >= 0 ? args[idx + 1] : undefined;
}

function usage(): never {
  console.log(`agentzt — Zero Trust for AI Agents

Usage:
  npm run enroll -- --agent <id> --role <role> [--description <text>] [--mtls]
  node src/cli/index.ts agents
  node src/cli/index.ts audit [--limit N | --verify]
  node src/cli/index.ts policy export
  node src/cli/index.ts roles
  node src/cli/index.ts tls init [--force]
  node src/cli/index.ts tls issue --agent <id>

Commands:
  enroll   Generate a cryptographic identity for an agent, write the private
           key to .agentzt/identities/<id>.json, and register the public key
           in config/agents.json. With --mtls, also issue an mTLS client cert.
  agents   List registered agent identities.
  roles    List roles defined in config/policy.json.
  audit    Print recent gateway audit events, or --verify the hash chain.
  policy   Export policy state for GRC/SIEM/SOAR ingestion.
  tls      Manage mutual-TLS PKI: 'init' creates the CA + gateway server cert,
           'issue --agent <id>' issues a client cert (requires openssl).
`);
  process.exit(1);
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
  const idPath = resolve(IDENTITIES_DIR, `${agentId}.json`);
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

  if (mtls) issueClientCert(agentId);

  console.log(`enrolled agent "${agentId}" (role=${role})`);
  console.log(`  private identity: ${idPath}  (keep secret; gitignored)`);
  console.log(`  public key registered in config/agents.json`);
  console.log(`\nrun its client proxy with:`);
  console.log(`  AGENTZT_AGENT_ID=${agentId} npm run client`);
}

function cmdAgents(): void {
  const reg = loadRegistry();
  if (reg.agents.length === 0) {
    console.log('no agents registered. Enroll one: npm run enroll -- --agent <id> --role <role>');
    return;
  }
  for (const a of reg.agents) {
    const status = a.disabled ? 'DISABLED' : 'active';
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

  function cmdPolicy(args: string[]): void {
    const sub = args[0];
    if (sub !== 'export') {
      console.error('usage: node src/cli/index.ts policy export');
      process.exit(1);
    }
    console.log(JSON.stringify(exportPolicyState(loadPolicy(), loadRegistry()), null, 2));
  }
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
  case 'agents': cmdAgents(); break;
  case 'roles': cmdRoles(); break;
  case 'audit': cmdAudit(rest); break;
  case 'policy': cmdPolicy(rest); break;
  case 'tls': cmdTls(rest); break;
  default: usage();
}

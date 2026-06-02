import { resolve } from 'node:path';
import { existsSync, readFileSync } from 'node:fs';
import { makeLogger } from '../shared/log.ts';
import { IDENTITIES_DIR, TLS_DIR, TLS_CLIENTS_DIR } from '../shared/paths.ts';
import { AgentIdentity } from './identity.ts';
import { TokenClient } from './token-client.ts';
import { createClientProxy } from './proxy.ts';
import type { ClientTls } from './transport.ts';

const log = makeLogger('client');

// Resolve the agent identity file: --identity <path>, $AGENTZT_IDENTITY, or
// .agentzt/identities/<AGENTZT_AGENT_ID>.json
function resolveIdentityPath(): string {
  const args = process.argv.slice(2);
  const idx = args.indexOf('--identity');
  if (idx >= 0 && args[idx + 1]) return resolve(args[idx + 1] as string);
  if (process.env.AGENTZT_IDENTITY) return resolve(process.env.AGENTZT_IDENTITY);
  if (process.env.AGENTZT_AGENT_ID) {
    return resolve(IDENTITIES_DIR, `${process.env.AGENTZT_AGENT_ID}.json`);
  }
  throw new Error(
    'no agent identity. Use --identity <file>, or set AGENTZT_IDENTITY / AGENTZT_AGENT_ID. ' +
      'Create one with: npm run enroll -- --agent <id> --role <role>',
  );
}

function intArg(name: string, envName: string, fallback: number): number {
  const args = process.argv.slice(2);
  const idx = args.indexOf(name);
  if (idx >= 0 && args[idx + 1]) return Number(args[idx + 1]);
  if (process.env[envName]) return Number(process.env[envName]);
  return fallback;
}

function strArg(name: string, envName: string, fallback: string): string {
  const args = process.argv.slice(2);
  const idx = args.indexOf(name);
  if (idx >= 0 && args[idx + 1]) return args[idx + 1] as string;
  return process.env[envName] ?? fallback;
}

const identityPath = resolveIdentityPath();
if (!existsSync(identityPath)) {
  log.error(`identity file not found: ${identityPath}`);
  process.exit(1);
}

const identity = AgentIdentity.fromFile(identityPath);
const listenPort = intArg('--port', 'AGENTZT_CLIENT_PORT', 8787);

// mTLS: opt-in via --mtls or AGENTZT_TLS=1. Loads the agentzt CA (sole trust
// anchor) plus this agent's client cert/key issued by `agentzt tls issue`.
const mtls = process.argv.slice(2).includes('--mtls') || process.env.AGENTZT_TLS === '1';
let tls: ClientTls | null = null;
let defaultGateway = 'http://localhost:8700';
if (mtls) {
  const caFile = resolve(TLS_DIR, 'ca.crt');
  const certFile = resolve(TLS_CLIENTS_DIR, `${identity.agentId}.crt`);
  const keyFile = resolve(TLS_CLIENTS_DIR, `${identity.agentId}.key`);
  for (const f of [caFile, certFile, keyFile]) {
    if (!existsSync(f)) {
      log.error(`mTLS enabled but missing ${f}. Run: node src/cli/index.ts tls init && node src/cli/index.ts tls issue --agent ${identity.agentId}`);
      process.exit(1);
    }
  }
  tls = {
    ca: readFileSync(caFile),
    cert: readFileSync(certFile),
    key: readFileSync(keyFile),
    pinSha256: process.env.AGENTZT_TLS_PIN,
  };
  defaultGateway = 'https://localhost:8700';
}

const gatewayUrl = strArg('--gateway', 'AGENTZT_GATEWAY_URL', defaultGateway);
const tokens = new TokenClient(identity, gatewayUrl, tls);
const { server, port } = createClientProxy({ identity, tokens, gatewayUrl, listenPort, tls });

server.listen(port, () => {
  log.info(`agentzt-client proxy for "${identity.agentId}" (role=${identity.role})`);
  log.info(`  listening   http://localhost:${port}`);
  log.info(`  gateway     ${gatewayUrl}${tls ? '  (mutual TLS)' : ''}`);
  log.info(`  point your agent at it:`);
  log.info(`    export ANTHROPIC_BASE_URL=http://localhost:${port}`);
  log.info(`    export ANTHROPIC_API_KEY=agentzt-managed   # value ignored; identity is cryptographic`);
});

function shutdown(sig: string) {
  log.info(`received ${sig}, shutting down`);
  server.close(() => process.exit(0));
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import {
  POLICY_FILE,
  GATEWAY_CONFIG_FILE,
  AGENTS_FILE,
} from './paths.ts';
import { JsonPolicyStore } from './policy-store.ts';
import type {
  PolicyDoc,
  GatewayConfig,
  AgentRegistry,
} from './types.ts';

function readJsonFile<T>(file: string): T {
  return JSON.parse(readFileSync(file, 'utf8')) as T;
}

const policyStore = new JsonPolicyStore(POLICY_FILE);

export function loadPolicy(): PolicyDoc {
  return policyStore.load();
}

export function savePolicy(policy: PolicyDoc): void {
  policyStore.save(policy);
}

export function loadGatewayConfig(): GatewayConfig {
  return readJsonFile<GatewayConfig>(GATEWAY_CONFIG_FILE);
}

export function loadRegistry(): AgentRegistry {
  if (!existsSync(AGENTS_FILE)) return { agents: [] };
  const doc = readJsonFile<AgentRegistry>(AGENTS_FILE);
  return { agents: doc.agents ?? [] };
}

export function saveRegistry(reg: AgentRegistry): void {
  const out = {
    _comment:
      "Agent identity registry (the gateway's view). Each entry binds a cryptographic public key to an agentId and a role. Populated by `npm run enroll`. Private keys never live here — they stay in .agentzt/identities/ on the agent host.",
    agents: reg.agents,
  };
  writeFileSync(AGENTS_FILE, JSON.stringify(out, null, 2) + '\n');
}

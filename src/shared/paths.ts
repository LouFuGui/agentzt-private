import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

// src/shared/paths.ts -> repo root is two levels up.
const here = dirname(fileURLToPath(import.meta.url));

export const ROOT = process.env.AGENTZT_ROOT
  ? resolve(process.env.AGENTZT_ROOT)
  : resolve(here, '..', '..');

export const CONFIG_DIR = resolve(ROOT, 'config');
export const STATE_DIR = resolve(ROOT, '.agentzt');
export const IDENTITIES_DIR = resolve(STATE_DIR, 'identities');
export const AUDIT_DIR = resolve(STATE_DIR, 'audit');
export const TLS_DIR = resolve(STATE_DIR, 'tls');
export const TLS_CLIENTS_DIR = resolve(TLS_DIR, 'clients');

export const POLICY_FILE = resolve(CONFIG_DIR, 'policy.json');
export const GATEWAY_CONFIG_FILE = resolve(CONFIG_DIR, 'gateway.json');
export const AGENTS_FILE = resolve(CONFIG_DIR, 'agents.json');
export const GATEWAY_KEY_FILE = resolve(STATE_DIR, 'gateway-key.json');
export const APPS_DB_FILE = resolve(STATE_DIR, 'apps.db');

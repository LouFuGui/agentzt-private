import type { KeyObject } from 'node:crypto';
import { loadRegistry } from '../shared/config.ts';
import { publicKeyFromJwk } from '../shared/crypto.ts';
import type { AgentLifecycleStatus, AgentRegistryEntry, Decision } from '../shared/types.ts';

export type ResolvedIdentity = {
  entry: AgentRegistryEntry;
  publicKey: KeyObject;
};

export function agentLifecycleStatus(entry: AgentRegistryEntry): AgentLifecycleStatus {
  if (entry.revokedAt || entry.status === 'revoked') return 'revoked';
  if (entry.disabled || entry.status === 'disabled') return 'disabled';
  return 'active';
}

/**
 * In-memory view of the agent registry. Maps agentId -> public key + role.
 * "Never trust, always verify": every token request is checked against a
 * registered cryptographic identity. Unknown, disabled, or revoked agents are
 * rejected at token issuance and when existing tokens are presented.
 */
export class IdentityStore {
  private byId = new Map<string, ResolvedIdentity>();

  constructor() {
    this.reload();
  }

  reload(): number {
    this.byId.clear();
    const reg = loadRegistry();
    for (const entry of reg.agents) {
      this.byId.set(entry.agentId, {
        entry,
        publicKey: publicKeyFromJwk(entry.publicKeyJwk),
      });
    }
    return this.byId.size;
  }

  get(agentId: string): ResolvedIdentity | undefined {
    return this.byId.get(agentId);
  }

  decideAgent(agentId: string): Decision {
    const identity = this.byId.get(agentId);
    if (!identity) return { allow: false, reason: `unknown agent "${agentId}"` };
    const status = agentLifecycleStatus(identity.entry);
    if (status !== 'active') {
      return { allow: false, reason: `agent "${agentId}" is ${status}` };
    }
    return { allow: true, reason: `agent "${agentId}" is active` };
  }

  size(): number {
    return this.byId.size;
  }
}

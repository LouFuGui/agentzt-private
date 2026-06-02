import type { KeyObject } from 'node:crypto';
import { loadRegistry } from '../shared/config.ts';
import { publicKeyFromJwk } from '../shared/crypto.ts';
import type { AgentRegistryEntry } from '../shared/types.ts';

export type ResolvedIdentity = {
  entry: AgentRegistryEntry;
  publicKey: KeyObject;
};

/**
 * In-memory view of the agent registry. Maps agentId -> public key + role.
 * "Never trust, always verify": every token request is checked against a
 * registered cryptographic identity. Unknown or disabled agents are rejected.
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
      if (entry.disabled) continue;
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

  size(): number {
    return this.byId.size;
  }
}

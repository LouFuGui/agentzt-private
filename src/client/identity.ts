import { readFileSync } from 'node:fs';
import type { KeyObject } from 'node:crypto';
import { privateKeyFromJwk, signJws, newId } from '../shared/crypto.ts';
import type { AgentIdentityFile, ClientAssertionClaims } from '../shared/types.ts';

/**
 * The agent's local identity. Wraps the private key and produces short-lived
 * signed assertions used to obtain access tokens. The private key never leaves
 * this process.
 */
export class AgentIdentity {
  readonly agentId: string;
  readonly role: string;
  private privateKey: KeyObject;

  constructor(file: AgentIdentityFile) {
    this.agentId = file.agentId;
    this.role = file.role;
    this.privateKey = privateKeyFromJwk(file.privateKeyJwk);
  }

  static fromFile(path: string): AgentIdentity {
    const file = JSON.parse(readFileSync(path, 'utf8')) as AgentIdentityFile;
    return new AgentIdentity(file);
  }

  /** Build a signed client assertion for the gateway token endpoint. */
  makeAssertion(audience: string, ttlSeconds = 60): string {
    const now = Math.floor(Date.now() / 1000);
    const claims: ClientAssertionClaims = {
      iss: this.agentId,
      sub: this.agentId,
      aud: audience,
      iat: now,
      exp: now + ttlSeconds,
      jti: newId('asrt'),
    };
    return signJws(claims, this.privateKey, {
      typ: 'agentzt-client-assertion',
      kid: this.agentId,
    });
  }
}

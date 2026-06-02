import type { KeyObject } from 'node:crypto';
import {
  signJws,
  verifyJws,
  decodeJwsHeader,
  newId,
} from '../shared/crypto.ts';
import type {
  AccessTokenClaims,
  ClientAssertionClaims,
  GatewayConfig,
} from '../shared/types.ts';
import type { IdentityStore } from './identity-store.ts';
import type { PolicyEngine } from './policy-engine.ts';
import type { GatewaySigningKey } from './gateway-key.ts';

export type TokenResult =
  | { ok: true; token: string; claims: AccessTokenClaims; agentId: string; role: string }
  | { ok: false; status: number; reason: string; agentId: string | null };

/**
 * OAuth2-style private_key_jwt flow:
 *  - the client signs a short-lived assertion with its agent private key,
 *  - the gateway verifies it against the registered public key,
 *  - on success the gateway mints a short-lived access token (minutes) scoped
 *    to exactly the models/tools the agent's role permits.
 *
 * No long-lived shared secrets ever cross the wire (Foundation baseline:
 * "short-lived tokens issued by an identity provider").
 */
export class TokenService {
  private cfg: GatewayConfig;
  private identities: IdentityStore;
  private policy: PolicyEngine;
  private key: GatewaySigningKey;
  // Anti-replay: remember consumed assertion IDs until they expire.
  private seenJti = new Map<string, number>();

  constructor(
    cfg: GatewayConfig,
    identities: IdentityStore,
    policy: PolicyEngine,
    key: GatewaySigningKey,
  ) {
    this.cfg = cfg;
    this.identities = identities;
    this.policy = policy;
    this.key = key;
  }

  private sweepReplayCache(now: number): void {
    for (const [jti, exp] of this.seenJti) {
      if (exp < now) this.seenJti.delete(jti);
    }
  }

  /** Verify a client assertion and issue an access token. */
  issue(assertion: string, audience: string): TokenResult {
    let agentId: string | null = null;
    try {
      const header = decodeJwsHeader(assertion);
      if (header.alg !== 'EdDSA' || header.typ !== 'agentzt-client-assertion') {
        return { ok: false, status: 400, reason: 'unexpected assertion header', agentId };
      }
      agentId = header.kid ?? null;
      if (!agentId) {
        return { ok: false, status: 400, reason: 'assertion missing kid (agentId)', agentId };
      }

      const identity = this.identities.get(agentId);
      if (!identity) {
        return { ok: false, status: 401, reason: `unknown or disabled agent "${agentId}"`, agentId };
      }

      // Signature check against the REGISTERED public key (never trust kid alone).
      const claims = verifyJws<ClientAssertionClaims>(assertion, identity.publicKey);

      const now = Math.floor(Date.now() / 1000);
      this.sweepReplayCache(now);

      if (claims.sub !== agentId || claims.iss !== agentId) {
        return { ok: false, status: 401, reason: 'assertion subject mismatch', agentId };
      }
      if (claims.aud !== audience) {
        return { ok: false, status: 401, reason: 'assertion audience mismatch', agentId };
      }
      if (claims.exp <= now) {
        return { ok: false, status: 401, reason: 'assertion expired', agentId };
      }
      if (claims.iat > now + 30) {
        return { ok: false, status: 401, reason: 'assertion issued in the future', agentId };
      }
      if (now - claims.iat > this.cfg.assertionMaxAgeSeconds) {
        return { ok: false, status: 401, reason: 'assertion too old', agentId };
      }
      if (this.seenJti.has(claims.jti)) {
        return { ok: false, status: 401, reason: 'assertion replay detected', agentId };
      }
      this.seenJti.set(claims.jti, claims.exp);

      const role = identity.entry.role;
      if (!this.policy.getRole(role)) {
        return { ok: false, status: 403, reason: `role "${role}" has no policy`, agentId };
      }

      const scope = this.policy.scopeForRole(role);
      const accessClaims: AccessTokenClaims = {
        iss: this.cfg.issuer,
        sub: agentId,
        role,
        scope,
        iat: now,
        exp: now + this.cfg.tokenTtlSeconds,
        jti: newId('at'),
      };
      const token = signJws(accessClaims, this.key.privateKey, {
        typ: 'agentzt-access-token',
        kid: this.cfg.issuer,
      });
      return { ok: true, token, claims: accessClaims, agentId, role };
    } catch (err) {
      return {
        ok: false,
        status: 401,
        reason: `assertion verification failed: ${(err as Error).message}`,
        agentId,
      };
    }
  }

  /** Verify an access token presented on a resource call. */
  verifyAccessToken(token: string): AccessTokenClaims {
    const header = decodeJwsHeader(token);
    if (header.typ !== 'agentzt-access-token') {
      throw new Error('not an access token');
    }
    const claims = verifyJws<AccessTokenClaims>(token, this.key.publicKey);
    const now = Math.floor(Date.now() / 1000);
    if (claims.iss !== this.cfg.issuer) throw new Error('issuer mismatch');
    if (claims.exp <= now) throw new Error('access token expired');
    return claims;
  }
}

// Used by clients/tests to verify the gateway-issued token with the public key.
export function verifyAccessTokenWith(
  token: string,
  publicKey: KeyObject,
): AccessTokenClaims {
  return verifyJws<AccessTokenClaims>(token, publicKey);
}

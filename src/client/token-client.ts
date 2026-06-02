import type { AgentIdentity } from './identity.ts';
import { decodeJwsPayload } from '../shared/crypto.ts';
import type { AccessTokenClaims } from '../shared/types.ts';

type CachedToken = {
  token: string;
  expiresAt: number; // epoch seconds
  scope: { models: string[]; tools: string[] };
};

/**
 * Obtains and caches short-lived access tokens, refreshing automatically
 * before expiry. This is the "automatic token refresh without human
 * intervention" the Foundation tier calls for — no long-lived secret is ever
 * stored or reused.
 */
export class TokenClient {
  private identity: AgentIdentity;
  private gatewayUrl: string;
  private cached: CachedToken | null = null;
  private refreshSkewSeconds = 30;
  private inflight: Promise<CachedToken> | null = null;

  constructor(identity: AgentIdentity, gatewayUrl: string) {
    this.identity = identity;
    this.gatewayUrl = gatewayUrl.replace(/\/$/, '');
  }

  private fresh(): boolean {
    if (!this.cached) return false;
    const now = Math.floor(Date.now() / 1000);
    return this.cached.expiresAt - this.refreshSkewSeconds > now;
  }

  async getToken(): Promise<string> {
    if (this.fresh()) return this.cached!.token;
    if (!this.inflight) {
      this.inflight = this.fetchToken().finally(() => {
        this.inflight = null;
      });
    }
    const c = await this.inflight;
    return c.token;
  }

  async scope(): Promise<{ models: string[]; tools: string[] }> {
    await this.getToken();
    return this.cached!.scope;
  }

  private async fetchToken(): Promise<CachedToken> {
    const audience = `agentzt-gateway/v1/token`;
    const assertion = this.identity.makeAssertion(audience);
    const resp = await fetch(`${this.gatewayUrl}/v1/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ assertion }),
    });
    if (!resp.ok) {
      const err = await resp.text();
      throw new Error(`token request failed (${resp.status}): ${err}`);
    }
    const data = (await resp.json()) as { access_token: string };
    const claims = decodeJwsPayload<AccessTokenClaims>(data.access_token);
    this.cached = {
      token: data.access_token,
      expiresAt: claims.exp,
      scope: claims.scope,
    };
    return this.cached;
  }
}

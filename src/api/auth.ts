/**
 * Authentication module for user accounts.
 * Provides registration, login, and session token management.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import type { KeyObject } from 'node:crypto';
import { signJws, verifyJws, decodeJwsHeader, newId } from '../shared/crypto.ts';
import { readJson, sendJson, sendError, bearerToken } from '../shared/http.ts';
import type { User, UserRole, UserTier, SessionTokenClaims } from '../shared/types.ts';
import { UserStore, getUserStore } from './user-store.ts';

// Default session token TTL: 24 hours in seconds
export const DEFAULT_SESSION_TTL_SECONDS = 24 * 60 * 60;

// Refresh token TTL: 7 days in seconds
export const REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60;

/**
 * Session token service for managing user authentication tokens.
 */
export class SessionTokenService {
  private issuer: string;
  private privateKey: KeyObject;
  private publicKey: KeyObject;
  private ttlSeconds: number;
  private refreshTtlSeconds: number;
  // Token revocation list (jti -> expiration time)
  private revokedTokens: Map<string, number> = new Map();

  constructor(
    issuer: string,
    privateKey: KeyObject,
    publicKey: KeyObject,
    ttlSeconds: number = DEFAULT_SESSION_TTL_SECONDS,
    refreshTtlSeconds: number = REFRESH_TOKEN_TTL_SECONDS,
  ) {
    this.issuer = issuer;
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.ttlSeconds = ttlSeconds;
    this.refreshTtlSeconds = refreshTtlSeconds;
  }

  /**
   * Issue a session token for a user.
   */
  issueToken(user: User): { token: string; claims: SessionTokenClaims; expiresIn: number } {
    const now = Math.floor(Date.now() / 1000);
    const claims: SessionTokenClaims = {
      iss: this.issuer,
      sub: user.userId,
      email: user.email,
      role: user.role,
      tier: user.tier,
      iat: now,
      exp: now + this.ttlSeconds,
      jti: newId('sess'),
    };
    const token = signJws(claims, this.privateKey, {
      typ: 'agentzt-session-token',
      kid: this.issuer,
    });
    return { token, claims, expiresIn: this.ttlSeconds };
  }

  /**
   * Issue a refresh token for a user.
   */
  issueRefreshToken(user: User): { token: string; jti: string; expiresIn: number } {
    const now = Math.floor(Date.now() / 1000);
    const jti = newId('refresh');
    const claims = {
      iss: this.issuer,
      sub: user.userId,
      type: 'refresh',
      iat: now,
      exp: now + this.refreshTtlSeconds,
      jti,
    };
    const token = signJws(claims, this.privateKey, {
      typ: 'agentzt-refresh-token',
      kid: this.issuer,
    });
    return { token, jti, expiresIn: this.refreshTtlSeconds };
  }

  /**
   * Verify a session token.
   * Returns the claims if valid, throws otherwise.
   */
  verifyToken(token: string): SessionTokenClaims {
    const header = decodeJwsHeader(token);
    if (header.typ !== 'agentzt-session-token') {
      throw new Error('not a session token');
    }
    const claims = verifyJws<SessionTokenClaims>(token, this.publicKey);
    const now = Math.floor(Date.now() / 1000);
    
    if (claims.iss !== this.issuer) {
      throw new Error('issuer mismatch');
    }
    if (claims.exp <= now) {
      throw new Error('token expired');
    }
    if (this.isRevoked(claims.jti)) {
      throw new Error('token revoked');
    }
    return claims;
  }

  /**
   * Verify a refresh token.
   */
  verifyRefreshToken(token: string): { userId: string; jti: string } {
    const header = decodeJwsHeader(token);
    if (header.typ !== 'agentzt-refresh-token') {
      throw new Error('not a refresh token');
    }
    const claims = verifyJws<{ iss: string; sub: string; type: string; jti: string; exp: number }>(
      token,
      this.publicKey,
    );
    const now = Math.floor(Date.now() / 1000);
    
    if (claims.iss !== this.issuer) {
      throw new Error('issuer mismatch');
    }
    if (claims.type !== 'refresh') {
      throw new Error('not a refresh token');
    }
    if (claims.exp <= now) {
      throw new Error('refresh token expired');
    }
    if (this.isRevoked(claims.jti)) {
      throw new Error('refresh token revoked');
    }
    return { userId: claims.sub, jti: claims.jti };
  }

  /**
   * Revoke a token by its jti.
   */
  revoke(jti: string, exp: number): void {
    this.revokedTokens.set(jti, exp);
    this.sweepRevokedTokens();
  }

  /**
   * Check if a token is revoked.
   */
  isRevoked(jti: string): boolean {
    return this.revokedTokens.has(jti);
  }

  /**
   * Clean up expired revoked tokens.
   */
  private sweepRevokedTokens(): void {
    const now = Math.floor(Date.now() / 1000);
    for (const [jti, exp] of this.revokedTokens) {
      if (exp < now) {
        this.revokedTokens.delete(jti);
      }
    }
  }
}

/**
 * Authentication API handler.
 */
export class AuthApi {
  private userStore: UserStore;
  private tokenService: SessionTokenService;

  constructor(userStore: UserStore, tokenService: SessionTokenService) {
    this.userStore = userStore;
    this.tokenService = tokenService;
  }

  /**
   * Handle POST /api/auth/register
   */
  async handleRegister(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      const body = await readJson<{
        email?: string;
        password?: string;
        role?: UserRole;
        tier?: UserTier;
      }>(req);

      if (!body.email || !body.password) {
        return sendError(res, 400, 'invalid_request', 'email and password are required');
      }

      const result = await this.userStore.create({
        email: body.email,
        password: body.password,
        role: body.role,
        tier: body.tier,
      });

      if (!result.ok) {
        return sendError(res, 400, 'registration_error', result.error);
      }

      // Issue session token for the new user
      const { token, claims, expiresIn } = this.tokenService.issueToken(result.user);
      const { token: refreshToken, expiresIn: refreshExpiresIn } = this.tokenService.issueRefreshToken(result.user);

      return sendJson(res, 201, {
        user: {
          userId: result.user.userId,
          email: result.user.email,
          role: result.user.role,
          tier: result.user.tier,
          createdAt: result.user.createdAt,
        },
        session: {
          token,
          tokenType: 'Bearer',
          expiresIn,
        },
        refreshToken: {
          token: refreshToken,
          expiresIn: refreshExpiresIn,
        },
      });
    } catch (err) {
      return sendError(res, 500, 'internal_error', (err as Error).message);
    }
  }

  /**
   * Handle POST /api/auth/login
   */
  async handleLogin(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      const body = await readJson<{ email?: string; password?: string }>(req);

      if (!body.email || !body.password) {
        return sendError(res, 400, 'invalid_request', 'email and password are required');
      }

      const result = await this.userStore.verifyCredentials(body.email, body.password);

      if (!result.ok) {
        return sendError(res, 401, 'authentication_error', result.error);
      }

      // Issue session token
      const { token, claims, expiresIn } = this.tokenService.issueToken(result.user);
      const { token: refreshToken, expiresIn: refreshExpiresIn } = this.tokenService.issueRefreshToken(result.user);

      return sendJson(res, 200, {
        user: {
          userId: result.user.userId,
          email: result.user.email,
          role: result.user.role,
          tier: result.user.tier,
          createdAt: result.user.createdAt,
        },
        session: {
          token,
          tokenType: 'Bearer',
          expiresIn,
        },
        refreshToken: {
          token: refreshToken,
          expiresIn: refreshExpiresIn,
        },
      });
    } catch (err) {
      return sendError(res, 500, 'internal_error', (err as Error).message);
    }
  }

  /**
   * Handle POST /api/auth/refresh
   */
  async handleRefresh(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      const body = await readJson<{ refreshToken?: string }>(req);

      if (!body.refreshToken) {
        return sendError(res, 400, 'invalid_request', 'refreshToken is required');
      }

      let userId: string;
      let jti: string;
      try {
        const result = this.tokenService.verifyRefreshToken(body.refreshToken);
        userId = result.userId;
        jti = result.jti;
      } catch (err) {
        return sendError(res, 401, 'authentication_error', (err as Error).message);
      }

      // Revoke the old refresh token
      const now = Math.floor(Date.now() / 1000);
      this.tokenService.revoke(jti, now + REFRESH_TOKEN_TTL_SECONDS);

      // Get user and issue new tokens
      const user = this.userStore.getById(userId);
      if (!user) {
        return sendError(res, 401, 'authentication_error', 'user not found');
      }

      const { token, expiresIn } = this.tokenService.issueToken(user);
      const { token: newRefreshToken, expiresIn: refreshExpiresIn } = this.tokenService.issueRefreshToken(user);

      return sendJson(res, 200, {
        session: {
          token,
          tokenType: 'Bearer',
          expiresIn,
        },
        refreshToken: {
          token: newRefreshToken,
          expiresIn: refreshExpiresIn,
        },
      });
    } catch (err) {
      return sendError(res, 500, 'internal_error', (err as Error).message);
    }
  }

  /**
   * Handle POST /api/auth/logout
   */
  async handleLogout(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      const token = bearerToken(req);
      if (!token) {
        return sendError(res, 401, 'authentication_error', 'missing bearer token');
      }

      try {
        const claims = this.tokenService.verifyToken(token);
        // Revoke the session token
        this.tokenService.revoke(claims.jti, claims.exp);
      } catch {
        // Token already invalid, consider logout successful
      }

      return sendJson(res, 200, { message: 'Logged out successfully' });
    } catch (err) {
      return sendError(res, 500, 'internal_error', (err as Error).message);
    }
  }

  /**
   * Handle GET /api/auth/me - Get current user info
   */
  async handleMe(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      const token = bearerToken(req);
      if (!token) {
        return sendError(res, 401, 'authentication_error', 'missing bearer token');
      }

      let claims: SessionTokenClaims;
      try {
        claims = this.tokenService.verifyToken(token);
      } catch (err) {
        return sendError(res, 401, 'authentication_error', (err as Error).message);
      }

      const user = this.userStore.getById(claims.sub);
      if (!user) {
        return sendError(res, 404, 'not_found', 'user not found');
      }

      return sendJson(res, 200, {
        userId: user.userId,
        email: user.email,
        role: user.role,
        tier: user.tier,
        createdAt: user.createdAt,
      });
    } catch (err) {
      return sendError(res, 500, 'internal_error', (err as Error).message);
    }
  }

  /**
   * Route auth requests to appropriate handler.
   */
  async handle(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const path = url.pathname;
    const method = req.method ?? 'GET';

    if (method === 'POST' && path === '/api/auth/register') {
      await this.handleRegister(req, res);
      return true;
    }
    if (method === 'POST' && path === '/api/auth/login') {
      await this.handleLogin(req, res);
      return true;
    }
    if (method === 'POST' && path === '/api/auth/refresh') {
      await this.handleRefresh(req, res);
      return true;
    }
    if (method === 'POST' && path === '/api/auth/logout') {
      await this.handleLogout(req, res);
      return true;
    }
    if (method === 'GET' && path === '/api/auth/me') {
      await this.handleMe(req, res);
      return true;
    }

    return false;
  }
}

/**
 * Create an AuthApi instance with default configuration.
 */
export function createAuthApi(
  issuer: string,
  privateKey: KeyObject,
  publicKey: KeyObject,
  sessionTtlSeconds?: number,
): AuthApi {
  const userStore = getUserStore();
  const tokenService = new SessionTokenService(issuer, privateKey, publicKey, sessionTtlSeconds);
  return new AuthApi(userStore, tokenService);
}

// Export for convenience
export { getUserStore, UserStore };
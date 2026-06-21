/**
 * Authentication middleware for protecting API routes.
 * Provides requireAuth and requireRole middleware functions.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { bearerToken, sendError } from '../shared/http.ts';
import type { SessionTokenClaims, UserRole } from '../shared/types.ts';
import { SessionTokenService } from './auth.ts';

/**
 * Middleware context containing authenticated user information.
 */
export type AuthContext = {
  claims: SessionTokenClaims;
  userId: string;
  email: string;
  role: UserRole;
  tier: string;
};

/**
 * Middleware function type.
 */
export type Middleware = (
  req: IncomingMessage,
  res: ServerResponse,
  next: () => Promise<void>,
) => Promise<void>;

/**
 * Request handler with auth context.
 */
export type AuthenticatedHandler = (
  req: IncomingMessage,
  res: ServerResponse,
  auth: AuthContext,
) => Promise<void>;

/**
 * Role hierarchy for permission checking.
 * owner > admin > viewer
 */
const ROLE_HIERARCHY: Record<UserRole, number> = {
  owner: 3,
  admin: 2,
  viewer: 1,
};

/**
 * Check if a role has sufficient permissions.
 */
export function hasRole(userRole: UserRole, requiredRole: UserRole): boolean {
  return ROLE_HIERARCHY[userRole] >= ROLE_HIERARCHY[requiredRole];
}

/**
 * Create authentication middleware with a token service.
 */
export function createAuthMiddleware(tokenService: SessionTokenService): {
  requireAuth: Middleware;
  requireRole: (role: UserRole) => Middleware;
  authenticate: (req: IncomingMessage) => AuthContext | null;
  wrapHandler: (handler: AuthenticatedHandler) => Middleware;
} {
  /**
   * Extract and verify authentication from request.
   * Returns auth context if valid, null otherwise.
   */
  function authenticate(req: IncomingMessage): AuthContext | null {
    const token = bearerToken(req);
    if (!token) return null;

    try {
      const claims = tokenService.verifyToken(token);
      return {
        claims,
        userId: claims.sub,
        email: claims.email,
        role: claims.role,
        tier: claims.tier,
      };
    } catch {
      return null;
    }
  }

  /**
   * Middleware that requires authentication.
   * Passes auth context to next handler via custom header.
   */
  const requireAuth: Middleware = async (req, res, next) => {
    const auth = authenticate(req);
    if (!auth) {
      return sendError(res, 401, 'authentication_error', 'missing or invalid bearer token');
    }
    // Store auth context in request headers for downstream handlers
    (req as IncomingMessage & { auth?: AuthContext }).auth = auth;
    await next();
  };

  /**
   * Middleware that requires a specific role or higher.
   */
  const requireRole = (requiredRole: UserRole): Middleware => {
    return async (req, res, next) => {
      const auth = authenticate(req);
      if (!auth) {
        return sendError(res, 401, 'authentication_error', 'missing or invalid bearer token');
      }
      if (!hasRole(auth.role, requiredRole)) {
        return sendError(res, 403, 'permission_error', `requires role ${requiredRole} or higher`);
      }
      (req as IncomingMessage & { auth?: AuthContext }).auth = auth;
      await next();
    };
  };

  /**
   * Wrap an authenticated handler to receive auth context.
   */
  const wrapHandler = (handler: AuthenticatedHandler): Middleware => {
    return async (req, res, next) => {
      const auth = authenticate(req);
      if (!auth) {
        return sendError(res, 401, 'authentication_error', 'missing or invalid bearer token');
      }
      await handler(req, res, auth);
    };
  };

  return {
    requireAuth,
    requireRole,
    authenticate,
    wrapHandler,
  };
}

/**
 * Convenience function to get auth context from a request.
 * Must be used after requireAuth or requireRole middleware.
 */
export function getAuthContext(req: IncomingMessage): AuthContext | undefined {
  return (req as IncomingMessage & { auth?: AuthContext }).auth;
}

/**
 * Create a middleware chain that applies multiple middleware in sequence.
 */
export function createMiddlewareChain(middlewares: Middleware[]): Middleware {
  return async (req, res, next) => {
    let index = 0;
    const runNext = async (): Promise<void> => {
      if (index < middlewares.length) {
        const middleware = middlewares[index]!;
        index++;
        await middleware(req, res, runNext);
      } else {
        await next();
      }
    };
    await runNext();
  };
}

/**
 * Common middleware combinations.
 */
export function createOwnerOnlyMiddleware(tokenService: SessionTokenService): Middleware {
  const { requireRole } = createAuthMiddleware(tokenService);
  return requireRole('owner');
}

export function createAdminOnlyMiddleware(tokenService: SessionTokenService): Middleware {
  const { requireRole } = createAuthMiddleware(tokenService);
  return requireRole('admin');
}

export function createViewerOrHigherMiddleware(tokenService: SessionTokenService): Middleware {
  const { requireRole } = createAuthMiddleware(tokenService);
  return requireRole('viewer');
}
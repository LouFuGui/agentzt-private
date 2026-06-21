/**
 * User Authentication Tests
 * Tests for registration, login, session token management, and permissions
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { generateKeyPair } from 'node:crypto';
import { promisify } from 'node:util';

// Import modules to test
import { SessionTokenService, AuthApi, createAuthApi } from '../../src/api/auth.ts';
import { UserStore, getUserStore, hashPassword, verifyPassword, isValidEmail, isValidPassword } from '../../src/api/user-store.ts';
import type { User, UserRole, UserTier } from '../../src/shared/types.ts';

const generateKeyPairAsync = promisify(generateKeyPair);

// Helper to create HTTP request
async function makeRequest(
  port: number,
  method: string,
  path: string,
  body?: unknown,
  headers?: Record<string, string>,
): Promise<{ status: number; body: unknown }> {
  const response = await fetch(`http://localhost:${port}${path}`, {
    method,
    headers: {
      'content-type': 'application/json',
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const responseBody = await response.json();
  return { status: response.status, body: responseBody };
}

describe('User System Tests', () => {
  describe('Password Utilities', () => {
    it('should hash password correctly', async () => {
      const password = 'testPassword123';
      const hash = await hashPassword(password);
      
      expect(hash).toBeDefined();
      expect(hash).toContain(':');
      expect(hash.split(':').length).toBe(2);
    });

    it('should verify correct password', async () => {
      const password = 'testPassword123';
      const hash = await hashPassword(password);
      
      const isValid = await verifyPassword(password, hash);
      expect(isValid).toBe(true);
    });

    it('should reject incorrect password', async () => {
      const password = 'testPassword123';
      const hash = await hashPassword(password);
      
      const isValid = await verifyPassword('wrongPassword', hash);
      expect(isValid).toBe(false);
    });

    it('should validate email format', () => {
      expect(isValidEmail('test@example.com')).toBe(true);
      expect(isValidEmail('invalid-email')).toBe(false);
      expect(isValidEmail('test@')).toBe(false);
      expect(isValidEmail('@example.com')).toBe(false);
    });

    it('should validate password strength', () => {
      expect(isValidPassword('short').valid).toBe(false);
      expect(isValidPassword('short').message).toContain('8 characters');
      expect(isValidPassword('validPassword123').valid).toBe(true);
    });
  });

  describe('UserStore', () => {
    let userStore: UserStore;

    beforeEach(() => {
      // Use a temporary test database with unique name
      const timestamp = Date.now();
      userStore = new UserStore(`./test-users-${timestamp}.json`);
    });

    afterEach(() => {
      // Clean up test database
      const users = userStore.list();
      for (const user of users) {
        userStore.delete(user.userId);
      }
    });

    it('should create a new user', async () => {
      const result = await userStore.create({
        email: 'test@example.com',
        password: 'testPassword123',
        role: 'viewer',
        tier: 'personal',
      });

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.user.email).toBe('test@example.com');
        expect(result.user.role).toBe('viewer');
        expect(result.user.tier).toBe('personal');
        expect(result.user.userId).toBeDefined();
        expect(result.user.createdAt).toBeDefined();
        expect(result.user.passwordHash).toBeDefined();
      }
    });

    it('should reject invalid email', async () => {
      const result = await userStore.create({
        email: 'invalid-email',
        password: 'testPassword123',
      });

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toContain('Invalid email');
      }
    });

    it('should reject weak password', async () => {
      const result = await userStore.create({
        email: 'test@example.com',
        password: 'short',
      });

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toContain('8 characters');
      }
    });

    it('should reject duplicate email', async () => {
      // Create first user
      await userStore.create({
        email: 'duplicate@example.com',
        password: 'testPassword123',
      });

      // Try to create duplicate
      const result = await userStore.create({
        email: 'duplicate@example.com',
        password: 'testPassword123',
      });

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toContain('already registered');
      }
    });

    it('should get user by ID', async () => {
      const createResult = await userStore.create({
        email: 'test@example.com',
        password: 'testPassword123',
      });

      if (createResult.ok) {
        const user = userStore.getById(createResult.user.userId);
        expect(user).toBeDefined();
        expect(user?.email).toBe('test@example.com');
      }
    });

    it('should get user by email', async () => {
      const createResult = await userStore.create({
        email: 'test@example.com',
        password: 'testPassword123',
      });

      if (createResult.ok) {
        const user = userStore.getByEmail('test@example.com');
        expect(user).toBeDefined();
        expect(user?.userId).toBe(createResult.user.userId);
      }
    });

    it('should verify credentials', async () => {
      await userStore.create({
        email: 'test@example.com',
        password: 'testPassword123',
      });

      const result = await userStore.verifyCredentials('test@example.com', 'testPassword123');
      expect(result.ok).toBe(true);
    });

    it('should reject invalid credentials', async () => {
      await userStore.create({
        email: 'test@example.com',
        password: 'testPassword123',
      });

      const result = await userStore.verifyCredentials('test@example.com', 'wrongPassword');
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toContain('Invalid');
      }
    });

    it('should update user', async () => {
      const createResult = await userStore.create({
        email: 'test@example.com',
        password: 'testPassword123',
        role: 'viewer',
      });

      if (createResult.ok) {
        const updateResult = await userStore.update(createResult.user.userId, {
          role: 'admin',
        });

        expect(updateResult.ok).toBe(true);
        if (updateResult.ok) {
          expect(updateResult.user.role).toBe('admin');
        }
      }
    });

    it('should delete user', async () => {
      const createResult = await userStore.create({
        email: 'delete@example.com',
        password: 'testPassword123',
      });

      if (createResult.ok) {
        const deleted = userStore.delete(createResult.user.userId);
        expect(deleted).toBe(true);

        const user = userStore.getById(createResult.user.userId);
        expect(user).toBeUndefined();
      }
    });
  });

  describe('SessionTokenService', () => {
    let tokenService: SessionTokenService;
    let privateKey: Awaited<ReturnType<typeof generateKeyPairAsync>>['privateKey'];
    let publicKey: Awaited<ReturnType<typeof generateKeyPairAsync>>['publicKey'];
    let testUser: User;

    beforeEach(async () => {
      const keys = await generateKeyPairAsync('ed25519');
      privateKey = keys.privateKey;
      publicKey = keys.publicKey;

      tokenService = new SessionTokenService(
        'test-issuer',
        privateKey,
        publicKey,
        3600, // 1 hour
        86400, // 1 day
      );

      testUser = {
        userId: 'user_test123',
        email: 'test@example.com',
        passwordHash: 'test-hash',
        role: 'admin',
        createdAt: new Date().toISOString(),
        tier: 'business',
      };
    });

    it('should issue session token', () => {
      const result = tokenService.issueToken(testUser);
      
      expect(result.token).toBeDefined();
      expect(result.claims.sub).toBe(testUser.userId);
      expect(result.claims.email).toBe(testUser.email);
      expect(result.claims.role).toBe(testUser.role);
      expect(result.claims.tier).toBe(testUser.tier);
      expect(result.claims.iss).toBe('test-issuer');
      expect(result.expiresIn).toBe(3600);
    });

    it('should issue refresh token', () => {
      const result = tokenService.issueRefreshToken(testUser);
      
      expect(result.token).toBeDefined();
      expect(result.jti).toBeDefined();
      expect(result.expiresIn).toBe(86400);
    });

    it('should verify valid session token', () => {
      const { token } = tokenService.issueToken(testUser);
      const claims = tokenService.verifyToken(token);
      
      expect(claims.sub).toBe(testUser.userId);
      expect(claims.email).toBe(testUser.email);
    });

    it('should reject invalid token type', async () => {
      const { token } = tokenService.issueRefreshToken(testUser);
      
      expect(() => tokenService.verifyToken(token)).toThrow('not a session token');
    });

    it('should reject expired token', () => {
      // Create a service with very short TTL
      const shortTtlService = new SessionTokenService(
        'test-issuer',
        privateKey,
        publicKey,
        -1, // Already expired
        86400,
      );

      const { token } = shortTtlService.issueToken(testUser);
      
      expect(() => shortTtlService.verifyToken(token)).toThrow('expired');
    });

    it('should revoke token', () => {
      const { token, claims } = tokenService.issueToken(testUser);
      
      tokenService.revoke(claims.jti, claims.exp);
      
      expect(() => tokenService.verifyToken(token)).toThrow('revoked');
    });

    it('should verify refresh token', () => {
      const { token } = tokenService.issueRefreshToken(testUser);
      const result = tokenService.verifyRefreshToken(token);
      
      expect(result.userId).toBe(testUser.userId);
      expect(result.jti).toBeDefined();
    });

    it('should reject revoked refresh token', () => {
      const { token, jti } = tokenService.issueRefreshToken(testUser);
      
      tokenService.revoke(jti, Date.now() / 1000 + 86400);
      
      expect(() => tokenService.verifyRefreshToken(token)).toThrow('revoked');
    });
  });

  describe('AuthApi Integration', () => {
    let server: ReturnType<typeof createServer>;
    let port: number;
    let authApi: AuthApi;
    let userStore: UserStore;
    let tokenService: SessionTokenService;
    let privateKey: Awaited<ReturnType<typeof generateKeyPairAsync>>['privateKey'];
    let publicKey: Awaited<ReturnType<typeof generateKeyPairAsync>>['publicKey'];

    beforeEach(async () => {
      const keys = await generateKeyPairAsync('ed25519');
      privateKey = keys.privateKey;
      publicKey = keys.publicKey;

      userStore = new UserStore('./test-users-integration.json');
      tokenService = new SessionTokenService('test-issuer', privateKey, publicKey);
      authApi = new AuthApi(userStore, tokenService);

      server = createServer(async (req, res) => {
        await authApi.handle(req, res);
      });

      await new Promise<void>((resolve) => {
        server.listen(0, () => {
          port = (server.address() as AddressInfo).port;
          resolve();
        });
      });
    });

    afterEach(() => {
      server.close();
      userStore.list().forEach(user => userStore.delete(user.userId));
    });

    it('should register new user', async () => {
      const response = await makeRequest(port, 'POST', '/api/auth/register', {
        email: 'newuser@example.com',
        password: 'testPassword123',
      });

      expect(response.status).toBe(201);
      expect(response.body.user).toBeDefined();
      expect(response.body.session).toBeDefined();
      expect(response.body.refreshToken).toBeDefined();
    });

    it('should reject registration with missing fields', async () => {
      const response = await makeRequest(port, 'POST', '/api/auth/register', {
        email: 'test@example.com',
      });

      expect(response.status).toBe(400);
      // Check for error message in response
      const errorStr = typeof response.body.error === 'string' 
        ? response.body.error 
        : typeof response.body.message === 'string' 
          ? response.body.message 
          : JSON.stringify(response.body);
      expect(errorStr.toLowerCase()).toContain('password');
    });

    it('should login with valid credentials', async () => {
      // First register
      await makeRequest(port, 'POST', '/api/auth/register', {
        email: 'login@example.com',
        password: 'testPassword123',
      });

      // Then login
      const response = await makeRequest(port, 'POST', '/api/auth/login', {
        email: 'login@example.com',
        password: 'testPassword123',
      });

      expect(response.status).toBe(200);
      expect(response.body.user).toBeDefined();
      expect(response.body.session).toBeDefined();
      expect(response.body.refreshToken).toBeDefined();
    });

    it('should reject login with invalid credentials', async () => {
      const response = await makeRequest(port, 'POST', '/api/auth/login', {
        email: 'nonexistent@example.com',
        password: 'wrongPassword',
      });

      expect(response.status).toBe(401);
    });

    it('should refresh token', async () => {
      // Register
      const regResponse = await makeRequest(port, 'POST', '/api/auth/register', {
        email: 'refresh@example.com',
        password: 'testPassword123',
      });

      const refreshToken = regResponse.body.refreshToken.token;

      // Refresh
      const refreshResponse = await makeRequest(port, 'POST', '/api/auth/refresh', {
        refreshToken,
      });

      expect(refreshResponse.status).toBe(200);
      expect(refreshResponse.body.session).toBeDefined();
      expect(refreshResponse.body.refreshToken).toBeDefined();
    });

    it('should reject invalid refresh token', async () => {
      const response = await makeRequest(port, 'POST', '/api/auth/refresh', {
        refreshToken: 'invalid-token',
      });

      expect(response.status).toBe(401);
    });

    it('should logout successfully', async () => {
      // Register
      const regResponse = await makeRequest(port, 'POST', '/api/auth/register', {
        email: 'logout@example.com',
        password: 'testPassword123',
      });

      const token = regResponse.body.session.token;

      // Logout
      const logoutResponse = await makeRequest(port, 'POST', '/api/auth/logout', undefined, {
        authorization: `Bearer ${token}`,
      });

      expect(logoutResponse.status).toBe(200);
      expect(logoutResponse.body.message).toContain('success');
    });

    it('should get current user info', async () => {
      // Register
      const regResponse = await makeRequest(port, 'POST', '/api/auth/register', {
        email: 'me@example.com',
        password: 'testPassword123',
      });

      const token = regResponse.body.session.token;

      // Get me
      const meResponse = await makeRequest(port, 'GET', '/api/auth/me', undefined, {
        authorization: `Bearer ${token}`,
      });

      expect(meResponse.status).toBe(200);
      expect(meResponse.body.email).toBe('me@example.com');
    });

    it('should reject me request without token', async () => {
      const response = await makeRequest(port, 'GET', '/api/auth/me');

      expect(response.status).toBe(401);
    });
  });

  describe('Permission Tests', () => {
    it('should assign correct roles', async () => {
      const userStore = new UserStore('./test-users-perms.json');
      
      const roles: UserRole[] = ['owner', 'admin', 'viewer'];
      
      for (const role of roles) {
        const result = await userStore.create({
          email: `${role}@example.com`,
          password: 'testPassword123',
          role,
        });

        if (result.ok) {
          expect(result.user.role).toBe(role);
        }
      }

      userStore.list().forEach(user => userStore.delete(user.userId));
    });

    it('should assign correct tiers', async () => {
      const userStore = new UserStore('./test-users-tiers.json');
      
      const tiers: UserTier[] = ['personal', 'business', 'enterprise'];
      
      for (const tier of tiers) {
        const result = await userStore.create({
          email: `${tier}@example.com`,
          password: 'testPassword123',
          tier,
        });

        if (result.ok) {
          expect(result.user.tier).toBe(tier);
        }
      }

      userStore.list().forEach(user => userStore.delete(user.userId));
    });
  });
});
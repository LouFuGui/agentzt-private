/**
 * User store module for managing user accounts.
 * Uses file-based JSON storage (compatible with existing project patterns).
 * Password hashing uses Node.js built-in scrypt (PBKDF2-like security).
 */

import { scrypt, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { User, UserRole, UserTier } from '../shared/types.ts';
import { newId } from '../shared/crypto.ts';

const here = dirname(fileURLToPath(import.meta.url));

// Default path for user database
const DEFAULT_USER_DB_PATH = resolve(here, '..', '..', '.agentzt', 'users.json');

// Password hashing configuration
const HASH_SALT_LENGTH = 32;
const HASH_KEY_LENGTH = 64;
const HASH_COST = 16384; // N parameter for scrypt

export type UserRecord = User;

export type CreateUserInput = {
  email: string;
  password: string;
  role?: UserRole;
  tier?: UserTier;
};

export type UpdateUserInput = {
  email?: string;
  password?: string;
  role?: UserRole;
  tier?: UserTier;
};

/**
 * Hash a password using scrypt.
 * Returns a string in format: "salt:hash" (both hex-encoded).
 */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(HASH_SALT_LENGTH);
  return new Promise((resolve, reject) => {
    scrypt(password, salt, HASH_KEY_LENGTH, { cost: HASH_COST }, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(`${salt.toString('hex')}:${derivedKey.toString('hex')}`);
    });
  });
}

/**
 * Verify a password against a stored hash.
 * Uses timing-safe comparison to prevent timing attacks.
 */
export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  const [saltHex, hashHex] = storedHash.split(':');
  if (!saltHex || !hashHex) return false;
  
  const salt = Buffer.from(saltHex, 'hex');
  const storedKey = Buffer.from(hashHex, 'hex');
  
  return new Promise((resolve, reject) => {
    scrypt(password, salt, HASH_KEY_LENGTH, { cost: HASH_COST }, (err, derivedKey) => {
      if (err) return reject(err);
      if (derivedKey.length !== storedKey.length) {
        return resolve(false);
      }
      resolve(timingSafeEqual(derivedKey, storedKey));
    });
  });
}

/**
 * Validate email format.
 */
export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Validate password strength.
 * Requires at least 8 characters.
 */
export function isValidPassword(password: string): { valid: boolean; message?: string } {
  if (password.length < 8) {
    return { valid: false, message: 'Password must be at least 8 characters' };
  }
  return { valid: true };
}

/**
 * User store class for managing user accounts.
 * Uses file-based JSON storage for persistence.
 */
export class UserStore {
  private dbPath: string;
  private users: Map<string, UserRecord> = new Map();
  private emailIndex: Map<string, string> = new Map(); // email -> userId
  private loaded: boolean = false;

  constructor(dbPath: string = DEFAULT_USER_DB_PATH) {
    this.dbPath = dbPath;
  }

  /**
   * Load users from the database file.
   */
  private load(): void {
    if (this.loaded) return;
    
    if (existsSync(this.dbPath)) {
      try {
        const data = readFileSync(this.dbPath, 'utf8');
        const users = JSON.parse(data) as UserRecord[];
        for (const user of users) {
          this.users.set(user.userId, user);
          this.emailIndex.set(user.email.toLowerCase(), user.userId);
        }
      } catch {
        // If file is corrupted or empty, start fresh
        this.users.clear();
        this.emailIndex.clear();
      }
    }
    this.loaded = true;
  }

  /**
   * Save users to the database file.
   */
  private save(): void {
    const dir = dirname(this.dbPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    const users = Array.from(this.users.values());
    writeFileSync(this.dbPath, JSON.stringify(users, null, 2), 'utf8');
  }

  /**
   * Create a new user.
   * Returns the created user or an error message.
   */
  async create(input: CreateUserInput): Promise<{ ok: true; user: UserRecord } | { ok: false; error: string }> {
    this.load();
    
    // Validate email
    if (!isValidEmail(input.email)) {
      return { ok: false, error: 'Invalid email format' };
    }
    
    // Validate password
    const passwordValidation = isValidPassword(input.password);
    if (!passwordValidation.valid) {
      return { ok: false, error: passwordValidation.message! };
    }
    
    // Check if email already exists
    const normalizedEmail = input.email.toLowerCase();
    if (this.emailIndex.has(normalizedEmail)) {
      return { ok: false, error: 'Email already registered' };
    }
    
    // Hash password
    const passwordHash = await hashPassword(input.password);
    
    // Create user
    const userId = newId('user');
    const now = new Date().toISOString();
    const user: UserRecord = {
      userId,
      email: input.email,
      passwordHash,
      role: input.role ?? 'viewer',
      createdAt: now,
      tier: input.tier ?? 'personal',
    };
    
    this.users.set(userId, user);
    this.emailIndex.set(normalizedEmail, userId);
    this.save();
    
    return { ok: true, user };
  }

  /**
   * Get a user by ID.
   */
  getById(userId: string): UserRecord | undefined {
    this.load();
    return this.users.get(userId);
  }

  /**
   * Get a user by email.
   */
  getByEmail(email: string): UserRecord | undefined {
    this.load();
    const userId = this.emailIndex.get(email.toLowerCase());
    return userId ? this.users.get(userId) : undefined;
  }

  /**
   * Update a user.
   */
  async update(userId: string, input: UpdateUserInput): Promise<{ ok: true; user: UserRecord } | { ok: false; error: string }> {
    this.load();
    
    const user = this.users.get(userId);
    if (!user) {
      return { ok: false, error: 'User not found' };
    }
    
    // Update email if provided
    if (input.email !== undefined) {
      if (!isValidEmail(input.email)) {
        return { ok: false, error: 'Invalid email format' };
      }
      const normalizedEmail = input.email.toLowerCase();
      const existingUserId = this.emailIndex.get(normalizedEmail);
      if (existingUserId && existingUserId !== userId) {
        return { ok: false, error: 'Email already in use' };
      }
      // Remove old email index
      this.emailIndex.delete(user.email.toLowerCase());
      user.email = input.email;
      this.emailIndex.set(normalizedEmail, userId);
    }
    
    // Update password if provided
    if (input.password !== undefined) {
      const passwordValidation = isValidPassword(input.password);
      if (!passwordValidation.valid) {
        return { ok: false, error: passwordValidation.message! };
      }
      user.passwordHash = await hashPassword(input.password);
    }
    
    // Update role if provided
    if (input.role !== undefined) {
      user.role = input.role;
    }
    
    // Update tier if provided
    if (input.tier !== undefined) {
      user.tier = input.tier;
    }
    
    this.users.set(userId, user);
    this.save();
    
    return { ok: true, user };
  }

  /**
   * Delete a user.
   */
  delete(userId: string): boolean {
    this.load();
    
    const user = this.users.get(userId);
    if (!user) return false;
    
    this.emailIndex.delete(user.email.toLowerCase());
    this.users.delete(userId);
    this.save();
    
    return true;
  }

  /**
   * List all users.
   */
  list(): UserRecord[] {
    this.load();
    return Array.from(this.users.values());
  }

  /**
   * Verify user credentials.
   */
  async verifyCredentials(email: string, password: string): Promise<{ ok: true; user: UserRecord } | { ok: false; error: string }> {
    this.load();
    
    const user = this.getByEmail(email);
    if (!user) {
      return { ok: false, error: 'Invalid email or password' };
    }
    
    const valid = await verifyPassword(password, user.passwordHash);
    if (!valid) {
      return { ok: false, error: 'Invalid email or password' };
    }
    
    return { ok: true, user };
  }

  /**
   * Get the number of users.
   */
  size(): number {
    this.load();
    return this.users.size;
  }
}

// Singleton instance for convenience
let defaultStore: UserStore | null = null;

export function getUserStore(): UserStore {
  if (!defaultStore) {
    defaultStore = new UserStore();
  }
  return defaultStore;
}
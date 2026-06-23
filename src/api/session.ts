/**
 * Singleton session token service.
 * Initialized by the gateway server on startup so that all API modules
 * can verify user session tokens without circular imports.
 */

import type { SessionTokenService } from './auth.ts';

let _service: SessionTokenService | null = null;

/**
 * Set the singleton session token service (called once at server startup).
 */
export function setSessionTokenService(svc: SessionTokenService): void {
  _service = svc;
}

/**
 * Get the session token service, or null before the server initializes it.
 */
export function getSessionTokenService(): SessionTokenService | null {
  return _service;
}

/**
 * Reset the singleton (for tests).
 */
export function resetSessionTokenService(): void {
  _service = null;
}

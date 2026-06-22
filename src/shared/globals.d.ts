import type { JsonWebKey as NodeJsonWebKey } from 'node:crypto';

declare global {
  type JsonWebKey = NodeJsonWebKey;
}

export {};

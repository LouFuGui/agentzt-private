import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { createPublicKey } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import {
  generateEd25519,
  privateKeyFromJwk,
  publicKeyFromJwk,
} from '../shared/crypto.ts';
import type { Ed25519KeyPair } from '../shared/crypto.ts';
import { GATEWAY_KEY_FILE } from '../shared/paths.ts';

export type GatewaySigningKey = {
  privateKey: KeyObject;
  publicKey: KeyObject;
  publicKeyJwk: JsonWebKey;
};

/**
 * Load the gateway's own signing key, generating one on first run. The gateway
 * signs every access token with this key; clients/resource servers verify
 * tokens against the public half. The private key is the gateway's root of
 * trust — in production it belongs in an HSM/KMS (Advanced tier).
 */
export function loadOrCreateGatewayKey(): GatewaySigningKey {
  let pair: Ed25519KeyPair;
  if (existsSync(GATEWAY_KEY_FILE)) {
    pair = JSON.parse(readFileSync(GATEWAY_KEY_FILE, 'utf8')) as Ed25519KeyPair;
  } else {
    pair = generateEd25519();
    mkdirSync(dirname(GATEWAY_KEY_FILE), { recursive: true });
    writeFileSync(GATEWAY_KEY_FILE, JSON.stringify(pair, null, 2));
  }

  return {
    privateKey: privateKeyFromJwk(pair.privateKeyJwk),
    publicKey: publicKeyFromJwk(pair.publicKeyJwk),
    publicKeyJwk: pair.publicKeyJwk,
  };
}

export function loadGatewayKeyFromPrivateJwk(privateKeyJwk: JsonWebKey): GatewaySigningKey {
  const privateKey = privateKeyFromJwk(privateKeyJwk);
  const publicKey = createPublicKey(privateKey);
  return {
    privateKey,
    publicKey,
    publicKeyJwk: publicKey.export({ format: 'jwk' }) as JsonWebKey,
  };
}

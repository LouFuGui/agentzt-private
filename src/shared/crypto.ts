import {
  generateKeyPairSync,
  createPublicKey,
  createPrivateKey,
  sign as nodeSign,
  verify as nodeVerify,
  randomUUID,
  randomBytes,
} from 'node:crypto';
import type { KeyObject } from 'node:crypto';

export type Ed25519KeyPair = {
  publicKeyJwk: JsonWebKey;
  privateKeyJwk: JsonWebKey;
};

export function generateEd25519(): Ed25519KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKeyJwk: publicKey.export({ format: 'jwk' }) as JsonWebKey,
    privateKeyJwk: privateKey.export({ format: 'jwk' }) as JsonWebKey,
  };
}

export function publicKeyFromJwk(jwk: JsonWebKey): KeyObject {
  return createPublicKey({ key: jwk as object, format: 'jwk' });
}

export function privateKeyFromJwk(jwk: JsonWebKey): KeyObject {
  return createPrivateKey({ key: jwk as object, format: 'jwk' });
}

// ---- Compact JWS (EdDSA / Ed25519) ----------------------------------------

function b64url(buf: Buffer | string): string {
  return Buffer.from(buf).toString('base64url');
}

function fromB64url(s: string): Buffer {
  return Buffer.from(s, 'base64url');
}

export type JwsHeader = {
  alg: 'EdDSA';
  typ: string;
  kid?: string;
};

export function signJws(
  payload: object,
  privateKey: KeyObject,
  header: { typ: string; kid?: string },
): string {
  const fullHeader: JwsHeader = { alg: 'EdDSA', typ: header.typ };
  if (header.kid) fullHeader.kid = header.kid;
  const signingInput =
    b64url(JSON.stringify(fullHeader)) + '.' + b64url(JSON.stringify(payload));
  const signature = nodeSign(null, Buffer.from(signingInput), privateKey);
  return signingInput + '.' + b64url(signature);
}

export function decodeJwsHeader(token: string): JwsHeader {
  const part = token.split('.')[0];
  if (!part) throw new Error('malformed token: missing header');
  return JSON.parse(fromB64url(part).toString('utf8')) as JwsHeader;
}

export function decodeJwsPayload<T>(token: string): T {
  const part = token.split('.')[1];
  if (!part) throw new Error('malformed token: missing payload');
  return JSON.parse(fromB64url(part).toString('utf8')) as T;
}

/** Verify signature and return the decoded payload. Throws on any failure. */
export function verifyJws<T>(token: string, publicKey: KeyObject): T {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('malformed token');
  const [h, p, s] = parts as [string, string, string];
  const signingInput = h + '.' + p;
  const ok = nodeVerify(null, Buffer.from(signingInput), publicKey, fromB64url(s));
  if (!ok) throw new Error('invalid signature');
  return JSON.parse(fromB64url(p).toString('utf8')) as T;
}

export function newId(prefix: string): string {
  return `${prefix}_${randomUUID()}`;
}

export function newNonce(): string {
  return randomBytes(16).toString('hex');
}

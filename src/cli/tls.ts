// Minimal PKI for agentzt mutual TLS, built on the system `openssl`. PKI
// provisioning is a setup-time concern (real deployments use openssl / step-ca /
// Vault); the runtime uses only Node's built-in TLS. mTLS is opt-in, so this is
// the only part of agentzt that shells out, and only when you run `agentzt tls`.

import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdirSync, existsSync, rmSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { TLS_DIR, TLS_CLIENTS_DIR } from '../shared/paths.ts';

function openssl(args: string[]): void {
  execFileSync('openssl', args, { stdio: ['ignore', 'ignore', 'pipe'] });
}

function ensureOpenssl(): void {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
  } catch {
    throw new Error('openssl not found on PATH — required for `agentzt tls` (mTLS setup)');
  }
}

const CA_KEY = () => resolve(TLS_DIR, 'ca.key');
const CA_CRT = () => resolve(TLS_DIR, 'ca.crt');
const SRV_KEY = () => resolve(TLS_DIR, 'server.key');
const SRV_CRT = () => resolve(TLS_DIR, 'server.crt');
const clientKey = (id: string) => resolve(TLS_CLIENTS_DIR, `${id}.key`);
const clientCrt = (id: string) => resolve(TLS_CLIENTS_DIR, `${id}.crt`);

function genEcKey(out: string): void {
  openssl(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', out]);
}

// Sign a CSR (subject CN) with the CA, applying the given x509 extensions.
function signCert(csrSubject: string, keyOut: string, crtOut: string, days: number, ext: string): void {
  const tmp = resolve(tmpdir(), `agentzt-${randomUUID()}`);
  const csr = `${tmp}.csr`;
  const extf = `${tmp}.ext`;
  try {
    genEcKey(keyOut);
    openssl(['req', '-new', '-key', keyOut, '-out', csr, '-subj', csrSubject]);
    writeFileSync(extf, ext);
    openssl([
      'x509', '-req', '-in', csr, '-CA', CA_CRT(), '-CAkey', CA_KEY(),
      '-CAcreateserial', '-out', crtOut, '-days', String(days), '-sha256', '-extfile', extf,
    ]);
  } finally {
    for (const f of [csr, extf]) if (existsSync(f)) rmSync(f);
  }
}

/** Create the CA and the gateway server certificate (idempotent unless --force). */
export function caInit(force = false): void {
  ensureOpenssl();
  mkdirSync(TLS_DIR, { recursive: true });
  mkdirSync(TLS_CLIENTS_DIR, { recursive: true });

  if (existsSync(CA_CRT()) && !force) {
    console.log(`CA already exists at ${CA_CRT()} (use --force to recreate)`);
  } else {
    genEcKey(CA_KEY());
    openssl([
      'req', '-x509', '-new', '-key', CA_KEY(), '-sha256', '-days', '3650',
      '-out', CA_CRT(), '-subj', '/CN=agentzt-ca',
      '-addext', 'basicConstraints=critical,CA:TRUE',
      '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
    ]);
    console.log(`created CA: ${CA_CRT()}`);
  }

  signCert(
    '/CN=localhost',
    SRV_KEY(),
    SRV_CRT(),
    825,
    'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n',
  );
  console.log(`issued gateway server cert: ${SRV_CRT()} (CN=localhost)`);
}

/** Issue a client certificate for an agent (CN=agentId). */
export function issueClientCert(agentId: string): void {
  ensureOpenssl();
  if (!existsSync(CA_CRT())) throw new Error('no CA — run `agentzt tls init` first');
  mkdirSync(TLS_CLIENTS_DIR, { recursive: true });
  signCert(
    `/CN=${agentId}`,
    clientKey(agentId),
    clientCrt(agentId),
    365,
    'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n',
  );
  console.log(`issued client cert for "${agentId}": ${clientCrt(agentId)} (CN=${agentId})`);
}

export const tlsPaths = {
  caCrt: CA_CRT,
  serverKey: SRV_KEY,
  serverCrt: SRV_CRT,
  clientKey,
  clientCrt,
};

export function readPem(file: string): string {
  return readFileSync(file, 'utf8');
}

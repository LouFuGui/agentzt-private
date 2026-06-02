import { request as httpsRequest } from 'node:https';
import { checkServerIdentity } from 'node:tls';
import type { PeerCertificate } from 'node:tls';

/** Client mTLS material. `ca` is the SOLE trust anchor (CA pinning): the client
 *  trusts only the agentzt CA, not system roots. `pinSha256` optionally pins the
 *  exact server leaf certificate. */
export type ClientTls = {
  key: Buffer;
  cert: Buffer;
  ca: Buffer;
  pinSha256?: string;
};

export type TransportResponse = {
  status: number;
  contentType: string;
  body: Buffer;
};

export type TransportRequest = {
  method: string;
  headers: Record<string, string>;
  body?: Buffer;
  tls: ClientTls | null;
};

/** Unified outbound request: HTTPS + client cert when `tls` is set, else fetch. */
export async function request(url: string, opts: TransportRequest): Promise<TransportResponse> {
  if (!opts.tls) {
    const resp = await fetch(url, { method: opts.method, headers: opts.headers, body: opts.body });
    return {
      status: resp.status,
      contentType: resp.headers.get('content-type') ?? 'application/json',
      body: Buffer.from(await resp.arrayBuffer()),
    };
  }
  return requestTls(url, opts, opts.tls);
}

function requestTls(urlStr: string, opts: TransportRequest, tls: ClientTls): Promise<TransportResponse> {
  const u = new URL(urlStr);
  return new Promise((resolve, reject) => {
    const req = httpsRequest(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname + u.search,
        method: opts.method,
        headers: opts.headers,
        key: tls.key,
        cert: tls.cert,
        ca: tls.ca, // trust ONLY the agentzt CA
        rejectUnauthorized: true,
        servername: u.hostname,
        checkServerIdentity: (host: string, cert: PeerCertificate) => {
          const err = checkServerIdentity(host, cert);
          if (err) return err;
          if (tls.pinSha256) {
            const fp = (cert.fingerprint256 ?? '').replace(/:/g, '').toLowerCase();
            if (fp !== tls.pinSha256.replace(/:/g, '').toLowerCase()) {
              return new Error('server certificate pin mismatch');
            }
          }
          return undefined;
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c as Buffer));
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 0,
            contentType: (res.headers['content-type'] as string) ?? 'application/json',
            body: Buffer.concat(chunks),
          }),
        );
      },
    );
    req.on('error', reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

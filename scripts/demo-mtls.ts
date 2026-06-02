/**
 * Mutual-TLS end-to-end demo:
 *   1. agentzt tls init           — create CA + gateway server cert
 *   2. enroll demo agent --mtls   — identity key + client cert (CN=agentId)
 *   3. start gateway with AGENTZT_TLS=1  (HTTPS, requestCert + rejectUnauthorized)
 *   4. start client with --mtls          (presents client cert, pins agentzt CA)
 *   5. run the demo agent through the mTLS channel
 *   6. print the audit trail
 *
 * Run: npm run demo:mtls   (requires openssl on PATH)
 */
import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { ROOT } from '../src/shared/paths.ts';

const AGENT_ID = 'demo-agent-01';
const ROLE = 'demo-agent';
const GATEWAY_PORT = 8700;
const CLIENT_PORT = 8787;

function run(cmd: string, args: string[], extraEnv: Record<string, string> = {}): ChildProcess {
  return spawn(cmd, args, { cwd: ROOT, stdio: 'inherit', env: { ...process.env, ...extraEnv } });
}
function runToCompletion(cmd: string, args: string[], extraEnv: Record<string, string> = {}): Promise<number> {
  return new Promise((res) => run(cmd, args, extraEnv).on('exit', (c) => res(c ?? 0)));
}
async function waitForHealthHttps(url: string, timeoutMs = 8000): Promise<void> {
  // The gateway requires a client cert, so /healthz over TLS will 401/handshake-fail
  // from a plain client; instead we poll the TCP port via the client proxy's health.
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(url);
      if (r.ok) return;
    } catch {
      /* not up */
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error(`timed out waiting for ${url}`);
}
async function waitTcp(port: number, timeoutMs = 8000): Promise<void> {
  const { connect } = await import('node:net');
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const ok = await new Promise<boolean>((res) => {
      const s = connect(port, '127.0.0.1');
      s.on('connect', () => { s.destroy(); res(true); });
      s.on('error', () => res(false));
    });
    if (ok) return;
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error(`timed out waiting for tcp :${port}`);
}

const procs: ChildProcess[] = [];
const cleanup = () => procs.forEach((p) => !p.killed && p.kill('SIGTERM'));
process.on('SIGINT', () => { cleanup(); process.exit(1); });

async function main() {
  console.log('\n>>> [1/5] initialize PKI (CA + gateway server cert)');
  if ((await runToCompletion('node', ['src/cli/index.ts', 'tls', 'init', '--force'])) !== 0) {
    throw new Error('tls init failed (is openssl installed?)');
  }

  console.log(`\n>>> [2/5] enroll "${AGENT_ID}" with an mTLS client cert`);
  await runToCompletion('node', [
    'src/cli/index.ts', 'enroll', '--agent', AGENT_ID, '--role', ROLE, '--force', '--mtls',
    '--description', 'mTLS demo agent',
  ]);

  console.log('\n>>> [3/5] start gateway with mutual TLS (AGENTZT_TLS=1)');
  procs.push(run('node', ['src/gateway/index.ts'], { AGENTZT_TLS: '1' }));
  await waitTcp(GATEWAY_PORT);

  console.log('\n>>> [4/5] start client proxy with --mtls (client cert + CA pinning)');
  procs.push(run('node', ['src/client/index.ts', '--mtls'], { AGENTZT_AGENT_ID: AGENT_ID }));
  await waitForHealthHttps(`http://localhost:${CLIENT_PORT}/healthz`);

  console.log('\n>>> [5/5] run demo agent over the mutually-authenticated channel');
  await runToCompletion('node', ['examples/demo-agent/agent.ts'], {
    ANTHROPIC_BASE_URL: `http://localhost:${CLIENT_PORT}`,
  });

  console.log('\n>>> gateway audit trail');
  await runToCompletion('node', ['src/cli/index.ts', 'audit', '--limit', '12']);

  cleanup();
  await new Promise((r) => setTimeout(r, 200));
  console.log('\n>>> mTLS demo complete');
  process.exit(0);
}

main().catch((err) => { console.error('mTLS demo failed:', err.message); cleanup(); process.exit(1); });

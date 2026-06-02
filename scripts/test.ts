/**
 * Lightweight zero-dependency test suite. Boots a real gateway, enrolls a test
 * agent, and asserts the core Zero Trust properties hold.
 *
 * Run: npm test
 */
import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { ROOT } from '../src/shared/paths.ts';
import { AgentIdentity } from '../src/client/identity.ts';
import { resolve } from 'node:path';
import { IDENTITIES_DIR } from '../src/shared/paths.ts';

const GW = 'http://localhost:8700';
const AUD = 'agentzt-gateway/v1/token';
const AGENT = 'test-agent-01';

let pass = 0;
let fail = 0;
function check(cond: boolean, msg: string) {
  if (cond) { pass++; console.log(`PASS ${msg}`); }
  else { fail++; console.log(`FAIL ${msg}`); }
}

function sh(cmd: string, args: string[], env: Record<string, string> = {}): Promise<number> {
  return new Promise((res) => {
    const c = spawn(cmd, args, { cwd: ROOT, stdio: 'ignore', env: { ...process.env, ...env } });
    c.on('exit', (code) => res(code ?? 0));
  });
}

async function waitHealth(url: string, timeoutMs = 8000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    try { if ((await fetch(url)).ok) return; } catch { /* retry */ }
    await new Promise((r) => setTimeout(r, 120));
  }
  throw new Error(`timeout waiting for ${url}`);
}

async function getToken(assertion: string) {
  const r = await fetch(`${GW}/v1/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ assertion }),
  });
  return { status: r.status, body: (await r.json().catch(() => null)) as any };
}

let gateway: ChildProcess | null = null;
async function main() {
  await sh('node', ['src/cli/index.ts', 'enroll', '--agent', AGENT, '--role', 'demo-agent', '--force']);

  gateway = spawn('node', ['src/gateway/index.ts'], { cwd: ROOT, stdio: 'ignore', env: process.env });
  await waitHealth(`${GW}/healthz`);

  const identity = AgentIdentity.fromFile(resolve(IDENTITIES_DIR, `${AGENT}.json`));

  // 1. Valid assertion -> token issued, scoped to the role.
  const a1 = identity.makeAssertion(AUD);
  const t1 = await getToken(a1);
  check(t1.status === 200 && typeof t1.body?.access_token === 'string', 'valid assertion issues a token');
  check(
    Array.isArray(t1.body?.scope?.models) && t1.body.scope.models.includes('claude-sonnet-4-6'),
    'token scope reflects role policy',
  );
  const token = t1.body.access_token as string;

  // 2. Replay of the same assertion is rejected.
  const t2 = await getToken(a1);
  check(t2.status === 401, 'replayed assertion is rejected (anti-replay)');

  // 3. Allowed model call succeeds.
  const mOk = await fetch(`${GW}/v1/messages`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 16, messages: [{ role: 'user', content: 'hi' }] }),
  });
  check(mOk.status === 200, 'in-scope model call is allowed');

  // 4. Out-of-scope model call is denied.
  const mDeny = await fetch(`${GW}/v1/messages`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ model: 'claude-opus-4-8', max_tokens: 16, messages: [] }),
  });
  check(mDeny.status === 403, 'out-of-scope model call is denied (deny-by-default)');

  // 5. Out-of-scope tool (least agency) denied.
  const tDeny = await fetch(`${GW}/v1/tools/email.send`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ arguments: { to: 'x@y.z', body: 'hi' } }),
  });
  check(tDeny.status === 403, 'out-of-scope tool call is denied (least agency)');

  // 6. Parameter validation rejects a write via the read-only db tool.
  const pv = await fetch(`${GW}/v1/tools/db.query`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ arguments: { sql: 'DELETE FROM t' } }),
  });
  check(pv.status === 400, 'tool parameter validation rejects write statements');

  // 7. Forged bearer token is rejected.
  const forged = await fetch(`${GW}/v1/messages`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer a.b.c' },
    body: JSON.stringify({ model: 'claude-sonnet-4-6', messages: [] }),
  });
  check(forged.status === 401, 'forged bearer token is rejected');

  console.log(`\n${pass} passed, ${fail} failed`);
}

main()
  .then(() => { gateway?.kill('SIGTERM'); process.exit(fail ? 1 : 0); })
  .catch((err) => { console.error('test error:', err.message); gateway?.kill('SIGTERM'); process.exit(1); });

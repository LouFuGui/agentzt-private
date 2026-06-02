/**
 * One-command end-to-end demo:
 *   1. enroll a demo agent (if not already enrolled)
 *   2. start the gateway
 *   3. start the client proxy for the demo agent
 *   4. run the demo agent through the proxy
 *   5. print the gateway audit trail
 *   6. tear everything down
 *
 * Run: npm run demo
 */
import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { ROOT } from '../src/shared/paths.ts';

const AGENT_ID = 'demo-agent-01';
const ROLE = 'demo-agent';
const GATEWAY_PORT = 8700;
const CLIENT_PORT = 8787;

function run(cmd: string, args: string[], extraEnv: Record<string, string> = {}): ChildProcess {
  return spawn(cmd, args, {
    cwd: ROOT,
    stdio: 'inherit',
    env: { ...process.env, ...extraEnv },
  });
}

function runToCompletion(cmd: string, args: string[], extraEnv: Record<string, string> = {}): Promise<number> {
  return new Promise((res) => {
    const child = run(cmd, args, extraEnv);
    child.on('exit', (code) => res(code ?? 0));
  });
}

async function waitForHealth(url: string, timeoutMs = 8000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(url);
      if (r.ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error(`timed out waiting for ${url}`);
}

const procs: ChildProcess[] = [];
function cleanup() {
  for (const p of procs) {
    if (!p.killed) p.kill('SIGTERM');
  }
}
process.on('SIGINT', () => { cleanup(); process.exit(1); });

async function main() {
  // 1. (Re-)enroll the demo agent so identity file + registry stay in sync.
  console.log(`\n>>> enrolling demo agent "${AGENT_ID}" (role=${ROLE})`);
  const code = await runToCompletion('node', [
    'src/cli/index.ts', 'enroll', '--agent', AGENT_ID, '--role', ROLE,
    '--force', '--description', 'bundled end-to-end demo agent',
  ]);
  if (code !== 0) throw new Error('enrollment failed');

  // 2. Gateway.
  console.log('\n>>> starting agentzt-gateway');
  const gateway = run('node', ['src/gateway/index.ts']);
  procs.push(gateway);
  await waitForHealth(`http://localhost:${GATEWAY_PORT}/healthz`);

  // 3. Client proxy.
  console.log('\n>>> starting agentzt-client proxy');
  const client = run('node', ['src/client/index.ts'], { AGENTZT_AGENT_ID: AGENT_ID });
  procs.push(client);
  await waitForHealth(`http://localhost:${CLIENT_PORT}/healthz`);

  // 4. Run the demo agent through the proxy.
  console.log('\n>>> running demo agent (all traffic via the client proxy)');
  await runToCompletion('node', ['examples/demo-agent/agent.ts'], {
    ANTHROPIC_BASE_URL: `http://localhost:${CLIENT_PORT}`,
  });

  // 5. Audit trail.
  console.log('\n>>> gateway audit trail for this run');
  await runToCompletion('node', ['src/cli/index.ts', 'audit', '--limit', '12']);

  cleanup();
  // Give children a moment to exit cleanly.
  await new Promise((r) => setTimeout(r, 200));
  console.log('\n>>> demo complete');
  process.exit(0);
}

main().catch((err) => {
  console.error('demo failed:', err.message);
  cleanup();
  process.exit(1);
});

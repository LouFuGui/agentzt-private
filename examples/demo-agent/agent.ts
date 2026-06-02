/**
 * A minimal AI agent that reaches the enterprise model API and tools ONLY
 * through the agentzt-client local proxy. The agent holds no enterprise
 * credentials and no gateway token — its identity is the cryptographic key the
 * client proxy uses on its behalf.
 *
 * Run order:
 *   1. npm run gateway
 *   2. AGENTZT_AGENT_ID=<id> npm run client
 *   3. ANTHROPIC_BASE_URL=http://localhost:8787 npm run demo:agent
 *
 * The agent talks plain Anthropic Messages API shape to ANTHROPIC_BASE_URL,
 * exactly as a normal SDK would — the redirection to the proxy is transparent.
 */
import { randomUUID } from 'node:crypto';

const PROXY = process.env.ANTHROPIC_BASE_URL ?? 'http://localhost:8787';
const REQUEST_ID_HEADER = 'x-agentzt-request-id';

// A single task gets one request-id; every model/tool call in the task carries
// it, so the gateway audit log reconstructs the whole chain (traceability).
const taskRequestId = `req_${randomUUID()}`;

function banner(title: string) {
  console.log(`\n=== ${title} ===`);
}

async function callModel(model: string, prompt: string) {
  const resp = await fetch(`${PROXY}/v1/messages`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      // The proxy injects the real auth; this key is ignored by design.
      'x-api-key': process.env.ANTHROPIC_API_KEY ?? 'agentzt-managed',
      'anthropic-version': '2023-06-01',
      [REQUEST_ID_HEADER]: taskRequestId,
    },
    body: JSON.stringify({
      model,
      max_tokens: 1024,
      messages: [{ role: 'user', content: prompt }],
    }),
  });
  const data = await resp.json();
  return { status: resp.status, data };
}

async function callTool(name: string, args: Record<string, unknown>) {
  const resp = await fetch(`${PROXY}/v1/tools/${encodeURIComponent(name)}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      [REQUEST_ID_HEADER]: taskRequestId,
    },
    body: JSON.stringify({ arguments: args }),
  });
  const data = await resp.json();
  return { status: resp.status, data };
}

function show(label: string, r: { status: number; data: unknown }) {
  const ok = r.status >= 200 && r.status < 300;
  console.log(`${ok ? '[ALLOW]' : '[DENY] '} (${r.status}) ${label}`);
  console.log('   ' + JSON.stringify(r.data));
}

async function main() {
  console.log(`demo-agent task request-id: ${taskRequestId}`);
  console.log(`routing all model + tool calls through: ${PROXY}`);

  banner('1. Allowed model call (in role scope)');
  show('model claude-sonnet-4-6', await callModel('claude-sonnet-4-6', 'Summarize our zero-trust posture.'));

  banner('2. Denied model call (NOT in role scope)');
  show('model claude-opus-4-8', await callModel('claude-opus-4-8', 'Do something privileged.'));

  banner('3. Allowed tool call (kb.search)');
  show('tool kb.search', await callTool('kb.search', { query: 'zero-trust' }));

  banner('4. Denied tool call (email.send — least agency)');
  show('tool email.send', await callTool('email.send', { to: 'ceo@example.com', body: 'hi' }));

  banner('5. Parameter validation (db.query write attempt)');
  show('tool db.query (write)', await callTool('db.query', { sql: 'DELETE FROM customers' }));

  console.log('\nInspect the full audit trail:  node src/cli/index.ts audit');
}

main().catch((err) => {
  console.error('demo-agent error:', err.message);
  console.error('Is the gateway (npm run gateway) and client (npm run client) running?');
  process.exit(1);
});

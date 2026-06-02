# agentzt — Zero Trust for AI Agents

> Just as a human uses a Zero Trust client to reach enterprise apps through a Zero
> Trust gateway, an **AI agent uses `agentzt-client` to reach enterprise model APIs
> and tools through `agentzt-gateway`** — with cryptographic identity, short-lived
> tokens, deny-by-default authorization, and a full audit trail on every call.

`agentzt` is an open-source reference implementation of the controls in Anthropic's
*Zero Trust for AI Agents* framework, focused on the one chokepoint that matters most
for autonomous agents: **the traffic between an agent and the model APIs / tools it
uses.** It does **not** replace your existing ZTNA for humans — it sits in front of the
agent→model and agent→tool path.

- **`agentzt-client`** — a local proxy + cryptographic identity that runs next to the
  agent. The agent points its model SDK at it (`ANTHROPIC_BASE_URL=http://localhost:8787`)
  and calls tools through it. The client attaches the agent's identity to every request.
- **`agentzt-gateway`** — the policy decision + enforcement point. It authenticates the
  agent, issues short-lived scoped tokens, applies deny-by-default RBAC (which models /
  which tools), validates tool parameters, rate-limits, and audits every action before
  forwarding to the real enterprise model API / tools.

```
  ┌──────────────┐   model & tool calls    ┌────────────────┐   identity + token   ┌──────────────────┐   real key   ┌───────────────────┐
  │   AI agent   │ ───────────────────────▶│  agentzt-client│ ────────────────────▶│  agentzt-gateway  │ ───────────▶ │ Enterprise Model  │
  │ (no secrets) │  ANTHROPIC_BASE_URL ─▶  │  (local proxy) │   short-lived JWT     │  (PDP + PEP)      │              │ API  +  Tools     │
  └──────────────┘                         └────────────────┘                      └──────────────────┘              └───────────────────┘
                                            holds agent key                          deny-by-default policy
                                                                                     + full audit + tracing
```

## Why this shape

The agent holds **no enterprise credentials and no access token**. Its only secret is a
per-agent Ed25519 private key used to prove identity to the gateway. The enterprise model
API key lives **only** on the gateway, so a compromised agent host leaks nothing reusable
(credential isolation). Every model call and tool call is authorized against the agent's
role and written to an append-only audit log, tied together by a request id so a whole
task reconstructs as one chain (traceability).

## Quick start (zero install)

Requires **Node.js ≥ 22.6** — `agentzt` runs TypeScript natively via type stripping, with
**no dependencies and no build step**.

```bash
# Run the full end-to-end demo: enroll an agent, start gateway + client,
# drive an agent through 5 zero-trust controls, then print the audit trail.
npm run demo
```

Or step through it manually:

```bash
# 1. Enroll an agent: generate its keypair + register its public key.
npm run enroll -- --agent demo-agent-01 --role demo-agent

# 2. Start the gateway (PDP + PEP).
npm run gateway

# 3. Start the client proxy for that agent (in another terminal).
AGENTZT_AGENT_ID=demo-agent-01 npm run client

# 4. Point any agent / SDK at the proxy and go (another terminal).
ANTHROPIC_BASE_URL=http://localhost:8787 npm run demo:agent

# 5. Inspect what happened.
node src/cli/index.ts audit
```

The demo exercises five distinct controls:

| Step | Call | Result | Control demonstrated |
|------|------|--------|----------------------|
| 1 | `claude-sonnet-4-6` (in role) | ALLOW | scoped model access |
| 2 | `claude-opus-4-8` (not in role) | DENY 403 | deny-by-default model scope |
| 3 | `kb.search` (in role) | ALLOW | scoped tool access |
| 4 | `email.send` (not in role) | DENY 403 | least agency |
| 5 | `db.query` with `DELETE …` | DENY 400 | tool parameter validation |

## Configuration

- **`config/policy.json`** — deny-by-default RBAC. Roles grant explicit allow-lists of
  models and tools, plus per-role limits.
- **`config/gateway.json`** — gateway port, token TTL, and upstream mode:
  - `mock` (default) — synthetic offline responses, no API key needed.
  - `passthrough` — forwards to a real Anthropic-shaped Model API using the enterprise key
    from the env var named in `upstream.apiKeyEnv` (the agent never sees it).
- **`config/agents.json`** — the gateway's identity registry (public keys only). Populated
  by `npm run enroll`.

Runtime state (private keys, the gateway signing key, audit logs) lives under `.agentzt/`
and is gitignored.

## CLI

```bash
node src/cli/index.ts enroll --agent <id> --role <role> [--description <text>]
node src/cli/index.ts agents     # list registered identities
node src/cli/index.ts roles      # list roles + their allow-lists
node src/cli/index.ts audit [--limit N]
```

## Mapping to the Zero Trust framework (Foundation tier)

| Framework control | Where it lives |
|---|---|
| Unique cryptographic identity per agent | `src/cli` enroll → Ed25519 keypair; `gateway/identity-store.ts` |
| Short-lived IdP-issued tokens, auto-refresh | `gateway/token-service.ts`, `client/token-client.ts` |
| Deny-by-default RBAC / least agency | `gateway/policy-engine.ts`, `config/policy.json` |
| Tool allow-listing + parameter validation | `gateway/server.ts`, `gateway/tool-registry.ts` |
| Credential isolation (enterprise key at gateway only) | `gateway/upstream.ts` |
| Comprehensive action logging | `shared/audit.ts` (JSONL, append-only) |
| Traceability (request-id chain) | `x-agentzt-request-id` propagated client → gateway |
| Resource-exhaustion containment | `gateway/rate-limiter.ts` |

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design, the token flow, and
the roadmap toward the Enterprise and Advanced tiers (mTLS, ABAC, JIT, immutable audit).

## Status

Foundation-tier MVP. Suitable as a reference and a starting point — not yet hardened for
production. Contributions welcome.

## License

[Apache 2.0](LICENSE). Informed by Anthropic's *Zero Trust for AI Agents*; an independent
project, not affiliated with or endorsed by Anthropic.

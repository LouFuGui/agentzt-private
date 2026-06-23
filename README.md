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

The demo exercises seven distinct controls:

| Step | Call | Result | Control demonstrated |
|------|------|--------|----------------------|
| 1 | `claude-sonnet-4-6` (in role) | ALLOW | scoped model access |
| 2 | `claude-opus-4-8` (not in role) | DENY 403 | deny-by-default model scope |
| 3 | `kb.search` (in role) | ALLOW | scoped tool access |
| 4 | `email.send` (not in role) | DENY 403 | least agency |
| 5 | `db.query` with `DELETE …` | DENY 400 | tool parameter validation |
| 6 | prompt with "ignore all previous instructions…" | DENY 403 | input guardrail (prompt injection) |
| 7 | `web.fetch` of a page leaking `sk-ant-…` | ALLOW (redacted) | output guardrail (secret redaction) |
| 8 | `email.send` **with** a JIT elevation grant | ALLOW (`via=jit`) | just-in-time privilege elevation |

## Configuration

- **`config/policy.json`** — deny-by-default RBAC. Roles grant explicit allow-lists of
  models and tools, plus per-role limits.
- **`config/gateway.json`** — gateway port, token TTL, and upstream mode:
  - `mock` (default) — synthetic offline responses, no API key needed.
  - `passthrough` — routes by model to configured providers and forwards using enterprise
    keys from Vault when enabled, otherwise the provider's `apiKeyEnv` (the agent never sees
    it). The default routes send `deepseek-*` to the DeepSeek-compatible
    `/chat/completions` provider and `claude-*` to Anthropic; provider `baseUrl` values can
    point to public APIs or internal compatible endpoints.
- **`config/agents.json`** — the gateway's identity registry (public keys only). Populated
  by `npm run enroll`.
- **Policy export** — `node src/cli/index.ts policy export` emits the enterprise policy,
  roles, resource classes, and lifecycle state for GRC/SIEM/SOAR ingestion without agent
  key material.

Optional **Open Policy Agent (OPA)** enforcement is configured under `opa` in
`config/gateway.json` (or enabled with `AGENTZT_OPA=1`). When enabled, the gateway posts
the call context to OPA's `/v1/data/{policyPath}` endpoint after local RBAC/JIT, guardrails,
and ABAC pass; OPA can only add an extra deny. The default policy path is
`agentzt/authz/decision`, returning either a boolean `result` or
`{ "allow": boolean, "reason": string }`.

Optional **Temporal** workflow orchestration is configured under `temporal` in
`config/gateway.json`. It is disabled by default and uses Temporal's REST API through
Node's built-in `fetch`, so no Temporal SDK dependency or build step is required. Enable it,
point `baseUrl` at your Temporal REST endpoint, set `TEMPORAL_API_KEY` when your endpoint
requires a bearer token, and enroll an agent with the `workflow-agent` role to grant:

- `temporal.workflow.start` — JIT-required: start a workflow with `workflowType`, optional `workflowId`,
  optional `taskQueue`, and JSON `input`.
- `temporal.workflow.signal` — JIT-required: signal a workflow with `workflowId`, `signalName`, optional
  `runId`, and JSON `input`.
- `temporal.workflow.query` — query a workflow with `workflowId`, `queryType`, optional
  `runId`, and JSON `input`.

Runtime state (private keys, the gateway signing key, audit logs) lives under `.agentzt/`
and is gitignored.

### SigNoz observability

The gateway can mirror audit decisions to SigNoz over OTLP/HTTP without adding runtime
dependencies. Enable it in `config/gateway.json` under `signoz`, or with environment
variables:

```bash
export AGENTZT_SIGNOZ=1
export SIGNOZ_OTLP_ENDPOINT=http://localhost:4318
export OTEL_SERVICE_NAME=agentzt-gateway
npm run gateway
```

For SigNoz Cloud, set `SIGNOZ_OTLP_ENDPOINT` to your ingest endpoint and
`SIGNOZ_INGESTION_KEY` to the ingestion key. Telemetry export is best-effort: failures are
warned once and never change authorization or guardrail decisions.

Optional **HashiCorp Vault** integration is configured under `vault` in
`config/gateway.json` or with `VAULT_ADDR` + `VAULT_TOKEN`. When enabled, the gateway
initializes Vault at startup, can load its signing key from Vault, fetches passthrough model
API keys from Vault, and passes tool-specific Vault credentials into tool execution.

Optional **Falco** runtime enforcement is configured under `falco` in `config/gateway.json`
(or enabled with `AGENTZT_FALCO=1`). Point Falco/Falcosidekick HTTP output at
`/v1/falco/events`; the gateway records events and denies future calls from a matching
agent while a recent alert at or above `minimumPriority` is active. Bind events to agents by
including one of the configured `agentIdFields` (default `agentzt.agent_id`,
`container.name`, or `k8s.pod.name`) in Falco `output_fields`.
`maxEvents` bounds the in-memory alert cache for long-running gateways.
Set the configured `sharedSecretEnv` (default `AGENTZT_FALCO_SECRET`) to require a bearer
or `x-agentzt-falco-secret` secret on webhook requests.

### Guardrails (input/output) — powered by OpenGuardrails

The gateway runs a **context-aware guardrail** on every model call (input) and response
(output), configured under `guardrails` in `config/gateway.json`:

- `provider: "auto"` — uses [**OpenGuardrails**](https://openguardrails.com) when
  `OPENGUARDRAILS_API_KEY` is set, otherwise a built-in regex fallback so the demo runs
  offline. Set `"openguardrails"` to require it, or `"local"` to force the offline detector.
- **Input** (`input.mode`): `block` rejects risky prompts (403), `flag` allows but audits,
  `off` disables. Because OpenGuardrails scores the **whole conversation**, it detects
  *indirect* prompt injection — malicious instructions hidden in tool outputs or retrieved
  web pages that were fed back into the messages — which simple pattern matching misses.
- **Output** (`output`): `redactSecrets` scrubs credential-shaped strings (API keys, AWS
  keys, tokens, private-key blocks) from model and tool responses before they reach the
  agent; `check` runs a context-aware output review (OpenGuardrails may return a redacted /
  replacement answer). On detector outage the provider can `failOpen` (allow) or fail
  closed (block) per config.

Enable OpenGuardrails:

```bash
export OPENGUARDRAILS_API_KEY=og-...   # get one at https://openguardrails.com
npm run gateway                         # logs: "guardrail provider: openguardrails"
```

### Context-aware (ABAC) and just-in-time (JIT) authorization

RBAC scope is the floor; two further controls layer on top, both configured per
role in `config/policy.json`:

- **ABAC** (`abac`) re-checks context at *call time*, not just at token issuance:
  - `allowedHoursUTC` — restrict an agent to operating hours (e.g. `ops-agent` is
    business-hours only); calls outside the window are denied.
  - `denyAboveRiskLevel` — risk-adaptive: deny when the request's guardrail risk
    level reaches the threshold (ties guardrail verdicts into authorization).
- **JIT elevation** (`jit`) keeps high-blast-radius resources out of standing
  scope entirely. `email.send` is in no role's `tools`; a role whose `jit.elevatableTools`
  lists it can request a **single-resource, short-lived grant** (`maxTtlSeconds`)
  on demand. The agent just declares intent with a header; the client performs the
  `/v1/elevate` exchange and attaches the grant, which auto-expires:

  ```bash
  # Agent side — declare intent; the client fulfils JIT and attaches the grant.
  curl -H 'x-agentzt-elevate: tool:email.send' \
       -H 'x-agentzt-request-id: req_123' \
       -d '{"arguments":{"to":"c@x.z","body":"…"}}' \
       http://localhost:8787/v1/tools/email.send
  ```

### Tamper-evident audit

The audit log is an append-only hash chain (`hash_i = sha256(hash_{i-1} || event_i)`). Any
insertion, deletion, or edit of a past event breaks the chain:

```bash
node src/cli/index.ts audit --verify
# audit chain OK — 8 event(s), hash chain intact (tamper-evident).
```

### Mutual TLS (opt-in)

For transport-layer mutual authentication, agentzt can run the client↔gateway link over
mTLS with an internal CA. This is **opt-in** (off by default so the zero-setup HTTP demo
works) and uses `openssl` for one-time PKI provisioning; the runtime is pure Node TLS.

```bash
npm run demo:mtls    # init CA, issue certs, run the full path over mutual TLS
```

What it adds on top of the token layer:

- The gateway serves HTTPS with `requestCert + rejectUnauthorized` — a client with **no
  certificate signed by the agentzt CA** can't even complete the handshake.
- The client trusts **only** the agentzt CA (CA pinning), not system roots, and can
  additionally pin the exact server cert (`AGENTZT_TLS_PIN`).
- **Channel binding**: the gateway requires the client cert `CN` to equal the token
  subject, so a stolen token can't be replayed over a different TLS channel.

```bash
node src/cli/index.ts tls init                      # CA + gateway server cert
node src/cli/index.ts enroll --agent a1 --role demo-agent --mtls   # + client cert
AGENTZT_TLS=1 npm run gateway                        # gateway over mutual TLS
AGENTZT_AGENT_ID=a1 npm run client -- --mtls         # client presents its cert
```

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
| Mutual TLS + cert pinning + channel binding (Enterprise) | `gateway/server.ts` (HTTPS), `client/transport.ts`, `cli/tls.ts` |
| Short-lived IdP-issued tokens, auto-refresh | `gateway/token-service.ts`, `client/token-client.ts` |
| Deny-by-default RBAC / least agency | `gateway/policy-engine.ts`, `config/policy.json` |
| Context-aware authorization / ABAC (Enterprise) | `gateway/policy-engine.ts` `decideAbac` (hours + risk) |
| JIT / just-enough-administration (Advanced) | `gateway/token-service.ts` elevation grants, `/v1/elevate` |
| Tool allow-listing + parameter validation | `gateway/server.ts`, `gateway/tool-registry.ts` |
| Credential isolation (enterprise key at gateway only) | `gateway/upstream.ts` |
| Comprehensive action logging | `shared/audit.ts` (JSONL, append-only) |
| Immutable / tamper-evident audit (Enterprise) | `shared/audit.ts` hash chain + `audit --verify` |
| Traceability (request-id chain) | `x-agentzt-request-id` propagated client → gateway |
| Input validation / prompt-injection defense (Enterprise) | `gateway/guardrail-providers.ts` (OpenGuardrails / local) |
| Output filtering / data-leak prevention (Enterprise) | `gateway/guardrails.ts` secret redaction + output check |
| Resource-exhaustion containment | `gateway/rate-limiter.ts` |

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design, the token flow, and
the roadmap toward the Enterprise and Advanced tiers (mTLS, ABAC, JIT, immutable audit).

## Status

Foundation-tier MVP. Suitable as a reference and a starting point — not yet hardened for
production. Contributions welcome.

## License

[Apache 2.0](LICENSE). Informed by Anthropic's *Zero Trust for AI Agents*; an independent
project, not affiliated with or endorsed by Anthropic.

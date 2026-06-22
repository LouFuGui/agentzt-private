# agentzt architecture

## Goal

Apply Zero Trust to the **agent → model / agent → tool** path. Traditional ZTNA secures a
human at a device reaching an enterprise app. `agentzt` secures an autonomous agent
reaching the two resources it actually consumes: **inference (model APIs)** and **tools**.

Three Zero Trust principles drive the design:

1. **Never trust, always verify** — every model/tool call carries a cryptographically
   verifiable, short-lived token; the gateway re-checks policy on every request.
2. **Assume breach** — the agent holds no reusable secrets; the enterprise key never
   leaves the gateway; blast radius is bounded by per-agent identity + per-role scope.
3. **Least privilege / least agency** — deny-by-default. A role grants an explicit
   allow-list of models and tools; tool parameters are validated at the boundary.

## Components

### agentzt-client (`src/client`)
A local HTTP proxy that the agent points its model SDK at, plus the agent's identity.

- `identity.ts` — wraps the per-agent Ed25519 private key; mints signed **client
  assertions** (the proof of identity presented to the gateway).
- `token-client.ts` — exchanges an assertion for a **short-lived access token**, caches it,
  and refreshes ~30s before expiry. No human in the loop, no long-lived secret.
- `proxy.ts` — accepts Anthropic-shaped `/v1/messages` and `/v1/tools/:name`, attaches the
  bearer token + `x-agentzt-request-id` + `x-agentzt-agent-id`, fulfils JIT elevation
  requests, and forwards to the gateway.
- `transport.ts` — unified outbound: HTTPS with client cert + CA/leaf pinning when mTLS is
  on, plain `fetch` otherwise.
- `cli/tls.ts` — openssl-backed PKI: create the CA + gateway server cert, issue client certs.

### agentzt-gateway (`src/gateway`)
The Policy Decision Point (PDP) and Policy Enforcement Point (PEP).

- `gateway-key.ts` — the gateway's own Ed25519 signing key (root of trust for tokens).
- `identity-store.ts` — registry view: agentId → registered public key + role.
- `token-service.ts` — verifies client assertions (signature, audience, freshness,
  anti-replay via `jti`) and issues scoped access tokens.
- `policy-engine.ts` — deny-by-default RBAC over models and tools.
- `rate-limiter.ts` — per-agent sliding-window limiter (resource-exhaustion containment).
- `tool-registry.ts` — built-in tools with per-tool parameter validation.
- `guardrails.ts` — local detection primitives: injection patterns, spotlighting, recursive
  secret redaction, and message flattening.
- `guardrail-providers.ts` — pluggable detector interface with two providers (OpenGuardrails
  API, local regex) and a factory.
- `falco-client.ts` — optional Falco/Falcosidekick webhook monitor that turns runtime
  alerts into per-agent deny decisions.
- `upstream.ts` — `mock` (offline) or `passthrough` (real Model API, enterprise key held here).
- `server.ts` — routing, authorization, guardrails, and audit on every request.

### Guardrail layer (input/output)

Every model call passes through a guardrail provider twice — once on the prompt (input) and
once on the response (output):

```
prompt ─▶ guard.checkInput(messages)   ─▶ block(403) | flag+audit | pass
upstream response ─▶ guard.checkOutput(prompt,resp) ─▶ replace/withhold ─▶ redactSecretsDeep ─▶ agent
```

`createGuardrailProvider` selects the backend:

- **OpenGuardrails** (`https://openguardrails.com`) — LLM-based, context-aware. It scores the
  entire `messages` array, so instructions smuggled into a tool output or retrieved web page
  and then replayed into the conversation are caught: this is how **indirect prompt
  injection** is detected, not just direct overrides in the latest user turn. It also reports
  content-compliance and sensitive-data-leakage categories and can return a redacted
  `suggest_answer`. On detector outage the provider fails closed by default (configurable).
- **Local** — a zero-dependency regex detector used offline / as the default when no
  OpenGuardrails key is set, so the demo and tests need no network.

Tool outputs are additionally run through recursive secret redaction before returning to the
agent, since a leaked credential in a tool result could otherwise be replayed into a prompt.

### shared (`src/shared`)
Types, Ed25519 + compact-JWS crypto, append-only JSONL audit, config loaders, HTTP helpers.

## Token flow

```
agent ──▶ client                          gateway
              │  POST /v1/token
              │  { assertion: JWS(EdDSA, agent key) }
              │ ───────────────────────────────────▶ verify against registered pubkey
              │                                       check aud / iat / exp / jti(replay)
              │                                       look up role → scope (models, tools)
              │  ◀─────────────────────────────────── access_token = JWS(EdDSA, gateway key)
              │                                       { sub, role, scope, exp(≈5m), jti }
   model/tool │
   request    │  POST /v1/messages  (Authorization: Bearer <access_token>)
              │ ───────────────────────────────────▶ verify token (sig, exp, issuer)
              │                                       scope check + live policy check
              │                                       rate limit + param validation
              │                                       forward to upstream / run tool
              │  ◀─────────────────────────────────── response  (+ audit event written)
```

Two token types, both compact JWS over Ed25519:

- **client assertion** (`typ: agentzt-client-assertion`, signed by the *agent* key) — proves
  identity, lifetime ~60s, single-use (`jti` replay cache).
- **access token** (`typ: agentzt-access-token`, signed by the *gateway* key) — bearer token
  for resource calls, lifetime ~5 min, carries the agent's scope snapshot.
- **elevation grant** (`typ: agentzt-elevation-grant`, signed by the *gateway* key) — a
  single-resource, short-lived JIT capability (`{resource:{kind,name}, exp}`) issued by
  `/v1/elevate`; presented on the `x-agentzt-elevation` header to authorize a resource that
  is deliberately *not* in standing scope.

## Authorization decision order

Each model/tool call is authorized in layers — any layer can deny:

0. **Transport (mTLS, optional)** — when enabled, the TLS handshake itself rejects any
   client without a certificate signed by the agentzt CA, and channel binding ties the
   token to the cert (`CN == sub`).
1. **Authentication** — valid, unexpired access token (signature + issuer + exp).
2. **Falco runtime signal** — optional runtime security alerts can temporarily deny a
   matching agent before it reaches model/tool execution.
3. **Resource authorization** — resource in the token's standing scope AND permitted by
   live RBAC; otherwise a valid JIT elevation grant for exactly that resource (`authVia`
   records `scope` vs `jit`).
4. **Rate limit** — per-agent sliding window (resource-exhaustion containment).
5. **Input guardrail** — context-aware prompt-injection / safety check (block | flag | off).
6. **ABAC** — operating hours + risk-adaptive (risk level from the input guardrail).
7. **OPA policy** — optional sidecar PDP check; it receives the request context and can only
   add an extra deny after local least-privilege controls pass.
8. **Execution** — forward to upstream model / run the tool.
9. **Output guardrail** — context-aware output review + secret redaction before the response
   reaches the agent.

## Trust boundaries

| Secret | Lives where | Never crosses to |
|---|---|---|
| Agent private key | agent host (`.agentzt/identities/`) | the gateway |
| Gateway signing key | gateway (`.agentzt/gateway-key.json`) | clients/agents |
| Enterprise model API key | gateway env var only | the agent |
| Access token | client memory (cached) | the agent code |

A compromised agent process can, at most, make calls **within its own role's scope** until
its short-lived token expires — and every one of those calls is logged.

## Audit & traceability

Every decision (allow/deny) is written as one JSONL line: timestamp, request id, agentId,
role, action, resource, decision, reason, latency, and metadata (token usage, upstream
status). A task uses one `x-agentzt-request-id`, propagated through every model/tool call,
so the audit log reconstructs the full chain from triggering event to outcome.

## Implemented beyond Foundation (Enterprise tier)

- **Input validation / prompt-injection defense** — context-aware guardrail on every prompt,
  incl. indirect injection via OpenGuardrails (`guardrail-providers.ts`).
- **Output filtering / data-leak prevention** — context-aware output review + recursive
  credential redaction on model and tool responses.
- **Tamper-evident audit** — append-only SHA-256 hash chain with `audit --verify`.
- **ABAC** — call-time context conditions: operating hours + risk-adaptive (`decideAbac`).
- **JIT elevation** — single-resource, short-lived grants for resources kept out of
  standing scope (`/v1/elevate`); auto-expiring, client-fulfilled from a declared intent.
- **Mutual TLS** — opt-in client↔gateway mTLS with an internal CA (`cli/tls.ts`),
  CA pinning + optional leaf pinning (`client/transport.ts`), and channel binding
  (cert `CN` == token `sub`) so tokens can't be replayed across channels.
- **Falco runtime enforcement** — optional Falco/Falcosidekick webhook ingestion that
  blocks matching agents after high-priority runtime alerts (`falco-client.ts`).

## Roadmap (remaining Enterprise / Advanced tiers)

The codebase is built so these slot in without changing call sites:

- **Immutable audit sink**: ship the hash-chained log to append-only/WORM storage + SIEM.
- **Hardware-bound credentials / attestation** for the gateway signing key (HSM/KMS).
- **Anomaly detection**: baseline per-agent tool/model usage, alert on drift.
- **Hardware-bound credentials / attestation** for the gateway signing key (HSM/KMS).

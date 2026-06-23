# AgentZT Enterprise Roadmap

## Goal

AgentZT Enterprise moves the current zero-trust gateway from a reference implementation toward a governable, auditable, and operable enterprise control plane. The current baseline remains deny-by-default RBAC, short-lived tokens, JIT, ABAC, Guardrails, Falco, OPA, Vault, and SigNoz. The enterprise roadmap organizes those controls into a unified policy model, agent lifecycle governance, centralized audit, and multi-tenant operations.

## Phase 1: Enterprise policy model foundation

- Add an `enterprise` policy model section to `config/policy.json` for decision order, agent lifecycle deny states, and resource classes.
- Keep existing `roles` as the authoritative enforcement source for now; the enterprise model is a stable governance contract for future control-plane work.
- Classify resources by blast radius: approved standing models, read-only tools, and high-blast-radius tools.
- Treat disabled and revoked agents as explicit lifecycle states, denied both at token issuance and when previously issued tokens are presented.

## Phase 2: Organization and tenant governance

- Introduce organization, project, and environment boundaries for agents, roles, resources, and audit events.
- Support policy inheritance: organization defaults, project overrides, and explicit agent exceptions.
- Add approval workflows for high-risk tools, cross-environment access, and temporary elevation.
- Export policy state for GRC, SIEM, SOAR, and internal audit systems.

## Phase 3: Policy execution and adaptive risk

- Feed the enterprise policy model into runtime enforcement, gradually promoting it from governance metadata to PDP input.
- Extend ABAC with environment, data classification, source context, risk score, runtime alerts, and operating windows.
- Keep OPA as an optional external PDP while preserving local deny-first enforcement; OPA can only add extra denials.
- Govern JIT consistently by resource class, risk level, approval reason, and TTL.

## Phase 4: Enterprise audit and operations

- Replicate the local hash-chained audit log to immutable storage or a SIEM.
- Standardize fields for `token.issue`, `token.reject`, `model.call`, `tool.call`, `guardrail.block`, `falco.block`, and related events.
- Add lifecycle audit events for create, disable, revoke, role change, and key rotation.
- Add policy-change audit events for role grants, resource classes, lifecycle rules, and JIT configuration.

## Phase 5: Advanced security controls

- Bind the gateway signing key to HSM/KMS and support key rotation.
- Extend agent identity with certificate revocation, device posture, and runtime attestation.
- Build anomaly detection from audit streams: model-call drift, tool-use drift, denial spikes, and abnormal JIT frequency.
- Support environment-specific deployment baselines for development, test, and production.

## Current implementation boundary

- The enterprise policy model is currently a foundation contract; it does not replace `roles` enforcement yet.
- Agent lifecycle denial is enforced now: `disabled` and `revoked` agents cannot receive new tokens, and already-issued tokens are rejected on use.
- Organization, project, and environment boundaries can be attached to agents, roles, and resource classes; role boundary mismatches are denied at token issuance and token reuse, and agent boundaries are propagated into tokens and audit events.
- Resource classes can govern JIT elevation with required approval reasons, class-level maximum TTLs, and optional allowed risk levels.
- Policy state can be exported with `node src/cli/index.ts policy export` for GRC, SIEM, SOAR, or internal audit ingestion without exposing agent key material.
- The demo is no longer treated as a full compatibility constraint; future demos can be redesigned around the enterprise control plane.

# AgentZT offline private deployment

Milestone 5 starts with a minimal, dependency-locked deployment path for enterprise
networks that cannot fetch code at runtime. The image runs the repository directly on
Node.js 22 native TypeScript support; no build or bundler step is required.

## Milestone 5 completion checklist

This document is the handoff checklist for the first offline private deployment milestone:

- Dockerfile: `Dockerfile` builds a dependency-locked runtime image from the repository.
- Compose: `compose.yml` runs the gateway and an optional client profile with mounted
  `config/` and `.agentzt/` state.
- Kubernetes manifests: `deploy/kubernetes/` contains gateway config, persistent state,
  Deployment, and Service examples for an internal cluster.
- Offline deployment docs: this file covers image export/import, transfer preflight,
  Compose startup, and Kubernetes startup.

Against the enterprise plan, Milestone 5 is complete at the minimal first-delivery level:
the project is packageable, can be installed offline by loading the saved image, and can be
deployed inside an enterprise network with either Compose or Kubernetes.

## Build the image online

```bash
docker build -t agentzt:local .
docker save agentzt:local -o agentzt-local.tar
```

Move `agentzt-local.tar`, `compose.yml`, `deploy/kubernetes/`, `config/`, and any prepared
`.agentzt` runtime state into the offline environment.

## Preflight before transfer

Run the normal repository checks before exporting the image:

```bash
npm test
npm run typecheck
```

Confirm the bundle contains only deployment inputs that can be published inside the target
network:

- the saved image tar;
- `compose.yml` or the Kubernetes manifests;
- sanitized `config/` files with public agent keys only;
- `.agentzt/` runtime state only when it was intentionally generated for that environment.

Do not include local API keys, private agent identities for other environments, or audit logs
that should remain in the source environment.

## Run with Docker Compose

```bash
docker load -i agentzt-local.tar
docker compose up gateway
```

The gateway listens on `http://localhost:8700` and serves the console at `/console`.
State is persisted in `.agentzt/`; policy, gateway config, and the public-key agent
registry are mounted from `config/`.

To run a local client proxy in the same Compose project:

```bash
AGENTZT_AGENT_ID=demo-agent-01 docker compose --profile client up client
```

Enroll or copy the agent identity before starting the client. Private agent keys stay
under `.agentzt/identities/` and must not be committed.

## Run on Kubernetes

Load or mirror the `agentzt:local` image into the cluster's private registry, then update
the image reference in `deploy/kubernetes/gateway.yaml` if needed.

```bash
kubectl apply -f deploy/kubernetes/agentzt-config.yaml
kubectl apply -f deploy/kubernetes/gateway.yaml
```

The manifests create:

- a ConfigMap for `gateway.json`, `policy.json`, and an empty public-key `agents.json`;
- a PVC for `.agentzt` runtime state and audit logs;
- a gateway Deployment and ClusterIP Service.

Before production use, replace the sample ConfigMap values with enterprise policy,
registered public agent identities, mTLS material, and provider/Vault settings.

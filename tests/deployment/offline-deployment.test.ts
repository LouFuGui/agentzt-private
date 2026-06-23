import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const root = resolve(import.meta.dirname, '..', '..');

function read(path: string) {
  return readFileSync(resolve(root, path), 'utf8');
}

describe('offline private deployment artifacts', () => {
  it('keeps the Docker image dependency-locked and runtime-only', () => {
    const dockerfile = read('Dockerfile');
    const dockerignore = read('.dockerignore');

    expect(dockerfile).toContain('FROM node:22-slim');
    expect(dockerfile).toContain('COPY package.json package-lock.json ./');
    expect(dockerfile).toContain('RUN npm ci --omit=dev');
    expect(dockerfile).toContain('COPY config ./config');
    expect(dockerfile).toContain('COPY src ./src');
    expect(dockerfile).toContain('CMD ["npm", "run", "gateway"]');
    expect(dockerignore).toContain('.agentzt');
    expect(dockerignore).toContain('node_modules');
    expect(dockerignore).toContain('.git');
  });

  it('keeps Compose gateway and client paths offline-state mounted', () => {
    const compose = read('compose.yml');

    expect(compose).toContain('image: agentzt:local');
    expect(compose).toContain('command: npm run gateway');
    expect(compose).toContain('./config:/app/config');
    expect(compose).toContain('./.agentzt:/app/.agentzt');
    expect(compose).toContain('profiles: ["client"]');
    expect(compose).toContain('AGENTZT_GATEWAY_URL: http://gateway:8700');
  });

  it('ships Kubernetes gateway config, state, deployment, and service manifests', () => {
    const config = read('deploy/kubernetes/agentzt-config.yaml');
    const gateway = read('deploy/kubernetes/gateway.yaml');

    expect(config).toContain('kind: ConfigMap');
    expect(config).toContain('"mode": "mock"');
    expect(config).toContain('"agents": []');
    expect(config).toContain('"enabled": false');
    expect(gateway).toContain('kind: PersistentVolumeClaim');
    expect(gateway).toContain('kind: Deployment');
    expect(gateway).toContain('image: agentzt:local');
    expect(gateway).toContain('mountPath: /app/config');
    expect(gateway).toContain('mountPath: /app/.agentzt');
    expect(gateway).toContain('kind: Service');
  });

  it('documents image export, offline import, Compose, and Kubernetes deployment', () => {
    const docs = read('docs/OFFLINE_DEPLOYMENT.md');

    expect(docs).toContain('docker build -t agentzt:local .');
    expect(docs).toContain('docker save agentzt:local -o agentzt-local.tar');
    expect(docs).toContain('docker load -i agentzt-local.tar');
    expect(docs).toContain('docker compose up gateway');
    expect(docs).toContain('kubectl apply -f deploy/kubernetes/agentzt-config.yaml');
    expect(docs).toContain('kubectl apply -f deploy/kubernetes/gateway.yaml');
  });
});

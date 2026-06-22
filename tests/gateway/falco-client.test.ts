import { afterEach, describe, expect, it } from 'vitest';
import { FalcoRuntimeMonitor, normalizeFalcoPriority, resolveFalcoConfig } from '../../src/gateway/falco-client.ts';

const config = {
  enabled: true,
  webhookPath: '/v1/falco/events',
  sharedSecretEnv: 'AGENTZT_FALCO_WEBHOOK_SECRET',
  minimumPriority: 'warning' as const,
  denyWindowSeconds: 300,
  maxEvents: 1000,
  agentIdFields: ['agentzt.agent_id', 'container.name'],
};

describe('Falco runtime monitor', () => {
  afterEach(() => {
    delete process.env.AGENTZT_FALCO;
    delete process.env.AGENTZT_FALCO_WEBHOOK_SECRET;
  });

  it('resolves config only when explicitly enabled', () => {
    expect(resolveFalcoConfig()).toBeNull();
    expect(resolveFalcoConfig(config)?.webhookPath).toBe('/v1/falco/events');

    process.env.AGENTZT_FALCO = '1';
    expect(resolveFalcoConfig({ ...config, enabled: false })?.enabled).toBe(true);
  });

  it('normalizes Falco priorities defensively', () => {
    expect(normalizeFalcoPriority('Critical')).toBe('critical');
    expect(normalizeFalcoPriority('WARNING')).toBe('warning');
    expect(normalizeFalcoPriority('unexpected')).toBe('debug');
  });

  it('denies an agent with a recent matching Falco alert above the threshold', () => {
    const monitor = new FalcoRuntimeMonitor(config);
    monitor.record({
      priority: 'Critical',
      rule: 'Terminal shell in container',
      output: 'shell spawned',
      time: '2026-06-22T02:30:00.000Z',
      output_fields: { 'agentzt.agent_id': 'agent-1' },
    });

    const decision = monitor.decideAgent('agent-1', new Date('2026-06-22T02:31:00.000Z'));
    expect(decision.allow).toBe(false);
    expect(decision.reason).toContain('Terminal shell in container');
  });

  it('allows nonmatching, low priority, and expired Falco alerts', () => {
    const monitor = new FalcoRuntimeMonitor(config);
    monitor.recordMany([
      {
        priority: 'Notice',
        rule: 'Low priority event',
        time: '2026-06-22T02:30:00.000Z',
        output_fields: { 'agentzt.agent_id': 'agent-1' },
      },
      {
        priority: 'Critical',
        rule: 'Other agent event',
        time: '2026-06-22T02:30:00.000Z',
        output_fields: { 'agentzt.agent_id': 'agent-2' },
      },
      {
        priority: 'Critical',
        rule: 'Expired event',
        time: '2026-06-22T02:00:00.000Z',
        output_fields: { 'agentzt.agent_id': 'agent-1' },
      },
    ]);

    expect(monitor.decideAgent('agent-1', new Date('2026-06-22T02:31:00.000Z')).allow).toBe(true);
  });

  it('requires the webhook secret when configured', () => {
    process.env.AGENTZT_FALCO_WEBHOOK_SECRET = 'test-secret';
    const monitor = new FalcoRuntimeMonitor(config);
    const auth = ['Bearer', 'test-secret'].join(' ');

    expect(monitor.verifySecret(null, null).allow).toBe(false);
    expect(monitor.verifySecret(null, 'test-secret').allow).toBe(true);
    expect(monitor.verifySecret(auth, null).allow).toBe(true);
  });
});

import { afterEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => {
  const handle = {
    signal: vi.fn(),
    query: vi.fn(),
  };

  return {
    connect: vi.fn(),
    clientCtor: vi.fn(),
    start: vi.fn(),
    getHandle: vi.fn(() => handle),
    handle,
  };
});

vi.mock('@temporalio/client', () => {
  function MockClient(this: unknown, options: unknown) {
    mocks.clientCtor(options);
    return {
      workflow: {
        start: mocks.start,
        getHandle: mocks.getHandle,
      },
    };
  }

  return {
    Connection: {
      connect: mocks.connect,
    },
    Client: vi.fn(MockClient),
  };
});

import { TemporalClient, resolveTemporalConfig } from '../../src/gateway/temporal-client.ts';

describe('TemporalClient', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.clearAllMocks();
  });

  it('does not connect to Temporal when disabled', async () => {
    const client = new TemporalClient({ enabled: false });
    const result = await client.startWorkflow({ workflowType: 'DemoWorkflow' });

    expect(result.ok).toBe(false);
    expect(result.status).toBe(503);
    expect(mocks.connect).not.toHaveBeenCalled();
  });

  it('starts a workflow with namespace, task queue, input, and gateway-held token', async () => {
    vi.stubEnv('TEMPORAL_API_KEY', 'temporal-test-token');

    mocks.connect.mockResolvedValue({ connection: 'mock' });
    mocks.start.mockResolvedValue({
      workflowId: 'wf_123',
      firstExecutionRunId: 'run_123',
    });

    const client = new TemporalClient({
      enabled: true,
      baseUrl: 'https://temporal.example:7233/api/v1/',
      namespace: 'prod.ns',
      defaultTaskQueue: 'agentzt',
      timeoutMs: 1000,
      apiKeyEnv: 'TEMPORAL_API_KEY',
    });

    const result = await client.startWorkflow({
      workflowType: 'RiskReviewWorkflow',
      workflowId: 'wf_123',
      input: { requestId: 'req_123' },
    });

    expect(result).toEqual({
      ok: true,
      status: 200,
      body: {
        workflowId: 'wf_123',
        firstExecutionRunId: 'run_123',
      },
    });

    expect(mocks.connect).toHaveBeenCalledWith({
      address: 'temporal.example:7233',
      metadata: {
        authorization: 'Bearer temporal-test-token',
      },
    });

    expect(mocks.clientCtor).toHaveBeenCalledWith({
      connection: { connection: 'mock' },
      namespace: 'prod.ns',
    });

    expect(mocks.start).toHaveBeenCalledWith('RiskReviewWorkflow', {
      workflowId: 'wf_123',
      taskQueue: 'agentzt',
      args: [{ requestId: 'req_123' }],
    });
  });

  it('normalizes gRPC addresses and legacy URL-like values', () => {
    expect(resolveTemporalConfig({ baseUrl: '127.0.0.1:7233' }).baseUrl)
      .toBe('127.0.0.1:7233');

    expect(resolveTemporalConfig({ baseUrl: 'http://localhost:7243/api/v1/' }).baseUrl)
      .toBe('localhost:7243');
  });
});

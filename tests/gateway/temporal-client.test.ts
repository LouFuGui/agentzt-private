import { describe, it, expect, vi, afterEach } from 'vitest';
import { TemporalClient, resolveTemporalConfig } from '../../src/gateway/temporal-client.ts';

describe('TemporalClient', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it('does not call Temporal when disabled', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const client = new TemporalClient({ enabled: false });
    const result = await client.startWorkflow({ workflowType: 'DemoWorkflow' });

    expect(result.ok).toBe(false);
    expect(result.status).toBe(503);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('starts a workflow with namespace, task queue, input, and gateway-held token', async () => {
    vi.stubEnv('TEMPORAL_API_KEY', 'temporal-test-token');
    const fetchMock = vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ run_id: 'run_123' }),
      { status: 200 },
    ));
    vi.stubGlobal('fetch', fetchMock);

    const client = new TemporalClient({
      enabled: true,
      baseUrl: 'https://temporal.example/api/v1/',
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

    expect(result).toEqual({ ok: true, status: 200, body: { run_id: 'run_123' } });
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://temporal.example/api/v1/namespaces/prod.ns/workflows');
    expect(init.headers).toMatchObject({
      authorization: ['Bearer', 'temporal-test-token'].join(' '),
      'content-type': 'application/json',
    });

    const body = JSON.parse(String(init.body));
    expect(body.workflow_id).toBe('wf_123');
    expect(body.workflow_type).toEqual({ name: 'RiskReviewWorkflow' });
    expect(body.task_queue).toEqual({ name: 'agentzt' });
    expect(body.input.payloads[0].metadata.encoding).toBe(Buffer.from('json/plain').toString('base64'));
    expect(JSON.parse(Buffer.from(body.input.payloads[0].data, 'base64').toString('utf8'))).toEqual({ requestId: 'req_123' });
  });

  it('normalizes default config', () => {
    expect(resolveTemporalConfig({ baseUrl: 'http://localhost:7243/api/v1/' }).baseUrl)
      .toBe('http://localhost:7243/api/v1');
  });
});

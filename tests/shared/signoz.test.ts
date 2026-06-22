import { describe, expect, it, afterEach } from 'vitest';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  buildLogPayload,
  buildTracePayload,
  recordAuditWithTelemetry,
  resolveSignozConfig,
  SigNozTelemetry,
} from '../../src/shared/signoz.ts';
import type { AuditEvent } from '../../src/shared/types.ts';

const OLD_ENV = { ...process.env };

afterEach(() => {
  process.env = { ...OLD_ENV };
});

function event(): AuditEvent {
  return {
    ts: '2026-06-22T02:33:54.371Z',
    requestId: 'req_test',
    agentId: 'agent_1',
    role: 'demo-agent',
    action: 'model.call',
    resource: 'claude-sonnet-4-6',
    decision: 'allow',
    reason: 'authorized',
    latencyMs: 12,
    meta: { authVia: 'scope' },
    seq: 1,
    hash: 'abc',
  };
}

describe('SigNoz telemetry', () => {
  it('stays disabled by default', () => {
    delete process.env.AGENTZT_SIGNOZ;
    expect(resolveSignozConfig()).toBeNull();
  });

  it('builds OTLP traces and logs from audit events', () => {
    const tracePayload = buildTracePayload('agentzt-test', [event()]) as {
      resourceSpans: Array<{ scopeSpans: Array<{ spans: Array<{ name: string }> }> }>;
    };
    const logPayload = buildLogPayload('agentzt-test', [event()]) as {
      resourceLogs: Array<{ scopeLogs: Array<{ logRecords: Array<{ body: { stringValue: string } }> }> }>;
    };

    expect(tracePayload.resourceSpans[0]?.scopeSpans[0]?.spans[0]?.name).toBe('model.call claude-sonnet-4-6');
    expect(logPayload.resourceLogs[0]?.scopeLogs[0]?.logRecords[0]?.body.stringValue).toBe('authorized');
  });

  it('exports audit events to OTLP HTTP endpoints', async () => {
    const requests: Array<{ url: string; headers: Record<string, string | string[] | undefined>; body: string }> = [];
    const server = createServer((req, res) => {
      let body = '';
      req.setEncoding('utf8');
      req.on('data', chunk => {
        body += chunk;
      });
      req.on('end', () => {
        requests.push({ url: req.url ?? '', headers: req.headers, body });
        res.writeHead(200).end();
      });
    });

    await new Promise<void>(resolve => server.listen(0, resolve));
    const port = (server.address() as AddressInfo).port;
    process.env.SIGNOZ_INGESTION_KEY = 'test-ingestion-key';

    const telemetry = new SigNozTelemetry({
      enabled: true,
      endpoint: `http://localhost:${port}`,
      serviceName: 'agentzt-test',
      timeoutMs: 1000,
      exportIntervalMs: 0,
    });

    telemetry.recordAudit(event());
    await telemetry.flush();
    telemetry.close();
    await new Promise<void>(resolve => server.close(() => resolve()));

    expect(requests.map(r => r.url).sort()).toEqual(['/v1/logs', '/v1/traces']);
    expect(requests[0]?.headers['signoz-ingestion-key']).toBe('test-ingestion-key');
    expect(requests.some(r => r.body.includes('agentzt-test'))).toBe(true);
  });

  it('mirrors recorded audit events to telemetry when configured', () => {
    const recorded = event();
    let mirrored: AuditEvent | null = null;
    const audit = {
      record: () => recorded,
    };
    const telemetry = {
      recordAudit: (ev: AuditEvent) => {
        mirrored = ev;
      },
    };

    const result = recordAuditWithTelemetry(audit, telemetry, {
      requestId: recorded.requestId,
      agentId: recorded.agentId,
      role: recorded.role,
      action: recorded.action,
      resource: recorded.resource,
      decision: recorded.decision,
      reason: recorded.reason,
    });

    expect(result).toBe(recorded);
    expect(mirrored).toBe(recorded);
  });
});

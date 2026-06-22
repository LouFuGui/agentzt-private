import { createHash } from 'node:crypto';
import type { AuditEvent, SignozConfig } from './types.ts';
import type { Logger } from './log.ts';

type OtlpAnyValue =
  | { stringValue: string }
  | { intValue: string }
  | { doubleValue: number }
  | { boolValue: boolean };

type OtlpAttribute = {
  key: string;
  value: OtlpAnyValue;
};

const DEFAULT_ENDPOINT = 'http://localhost:4318';
const DEFAULT_SERVICE = 'agentzt-gateway';
const DEFAULT_TIMEOUT_MS = 3000;
const MAX_META_LENGTH = 4096;

export type ResolvedSignozConfig = SignozConfig & {
  endpoint: string;
  serviceName: string;
  timeoutMs: number;
  exportIntervalMs: number;
};

export function resolveSignozConfig(config?: SignozConfig): ResolvedSignozConfig | null {
  const enabled = process.env.AGENTZT_SIGNOZ === '1' || config?.enabled === true;
  if (!enabled) return null;

  return {
    enabled: true,
    endpoint: process.env.SIGNOZ_OTLP_ENDPOINT
      ?? process.env.OTEL_EXPORTER_OTLP_ENDPOINT
      ?? config?.endpoint
      ?? DEFAULT_ENDPOINT,
    serviceName: process.env.OTEL_SERVICE_NAME
      ?? config?.serviceName
      ?? DEFAULT_SERVICE,
    ingestionKeyEnv: config?.ingestionKeyEnv ?? 'SIGNOZ_INGESTION_KEY',
    headers: {
      ...config?.headers,
      ...parseHeaders(process.env.OTEL_EXPORTER_OTLP_HEADERS),
    },
    timeoutMs: Number(process.env.SIGNOZ_TIMEOUT_MS ?? config?.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    exportIntervalMs: Number(process.env.SIGNOZ_EXPORT_INTERVAL_MS ?? config?.exportIntervalMs ?? 0),
  };
}

export class SigNozTelemetry {
  private config: ResolvedSignozConfig;
  private log?: Logger;
  private queue: AuditEvent[] = [];
  private flushing = false;
  private timer?: NodeJS.Timeout;
  private warned = false;

  constructor(config: ResolvedSignozConfig, log?: Logger) {
    this.config = config;
    this.log = log;

    if ((config.exportIntervalMs ?? 0) > 0) {
      this.timer = setInterval(() => {
        void this.flush();
      }, config.exportIntervalMs);
      this.timer.unref();
    }
  }

  recordAudit(event: AuditEvent): void {
    this.queue.push(event);
    if ((this.config.exportIntervalMs ?? 0) <= 0) {
      void this.flush();
    }
  }

  async flush(): Promise<void> {
    if (this.flushing || this.queue.length === 0) return;
    this.flushing = true;
    const batch = this.queue.splice(0);
    try {
      await Promise.all([
        this.post('/v1/traces', buildTracePayload(this.config.serviceName, batch)),
        this.post('/v1/logs', buildLogPayload(this.config.serviceName, batch)),
      ]);
    } catch (err) {
      this.queue.unshift(...batch);
      if (!this.warned) {
        this.warned = true;
        this.log?.warn(`SigNoz export failed: ${(err as Error).message}`);
      }
    } finally {
      this.flushing = false;
    }
  }

  close(): void {
    if (this.timer) clearInterval(this.timer);
  }

  private async post(path: string, body: unknown): Promise<void> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
    try {
      const res = await fetch(`${this.config.endpoint.replace(/\/+$/, '')}${path}`, {
        method: 'POST',
        headers: this.headers(),
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      if (!res.ok) throw new Error(`OTLP ${path} returned ${res.status}`);
    } finally {
      clearTimeout(timeout);
    }
  }

  private headers(): Record<string, string> {
    const headers: Record<string, string> = {
      'content-type': 'application/json',
      ...(this.config.headers ?? {}),
    };
    const keyEnv = this.config.ingestionKeyEnv ?? 'SIGNOZ_INGESTION_KEY';
    const ingestionKey = process.env[keyEnv];
    if (ingestionKey) headers['signoz-ingestion-key'] = ingestionKey;
    return headers;
  }
}

export function buildTracePayload(serviceName: string, events: AuditEvent[]): unknown {
  return {
    resourceSpans: [{
      resource: { attributes: resourceAttributes(serviceName) },
      scopeSpans: [{
        scope: { name: 'agentzt.audit' },
        spans: events.map(toSpan),
      }],
    }],
  };
}

export function buildLogPayload(serviceName: string, events: AuditEvent[]): unknown {
  return {
    resourceLogs: [{
      resource: { attributes: resourceAttributes(serviceName) },
      scopeLogs: [{
        scope: { name: 'agentzt.audit' },
        logRecords: events.map(toLogRecord),
      }],
    }],
  };
}

function toSpan(event: AuditEvent): unknown {
  const end = unixNano(event.ts);
  const latencyNs = BigInt(Math.max(event.latencyMs ?? 0, 0)) * 1_000_000n;
  return {
    traceId: hex(event.requestId, 32),
    spanId: hex(`${event.seq ?? 0}:${event.action}:${event.resource}`, 16),
    name: `${event.action} ${event.resource}`,
    kind: 2,
    startTimeUnixNano: (end - latencyNs).toString(),
    endTimeUnixNano: end.toString(),
    attributes: eventAttributes(event),
    status: {
      code: event.decision === 'allow' ? 1 : 2,
      message: event.reason,
    },
  };
}

function toLogRecord(event: AuditEvent): unknown {
  return {
    timeUnixNano: unixNano(event.ts).toString(),
    severityText: event.decision === 'allow' ? 'INFO' : 'WARN',
    body: { stringValue: event.reason },
    attributes: eventAttributes(event),
  };
}

function eventAttributes(event: AuditEvent): OtlpAttribute[] {
  const attrs: Record<string, unknown> = {
    'agentzt.request_id': event.requestId,
    'agentzt.agent_id': event.agentId,
    'agentzt.role': event.role,
    'agentzt.action': event.action,
    'agentzt.resource': event.resource,
    'agentzt.decision': event.decision,
    'agentzt.reason': event.reason,
    'agentzt.seq': event.seq,
    'agentzt.app_id': event.appId,
    'agentzt.user_id': event.userId,
    'agentzt.latency_ms': event.latencyMs,
    'agentzt.categories': event.categories?.join(','),
    'agentzt.score': event.score,
    'agentzt.meta': event.meta ? truncate(JSON.stringify(event.meta), MAX_META_LENGTH) : undefined,
  };
  return Object.entries(attrs).flatMap(([key, value]) => toAttribute(key, value));
}

function resourceAttributes(serviceName: string): OtlpAttribute[] {
  return [
    { key: 'service.name', value: { stringValue: serviceName } },
    { key: 'telemetry.sdk.name', value: { stringValue: 'agentzt-signoz' } },
    { key: 'telemetry.sdk.language', value: { stringValue: 'nodejs' } },
  ];
}

function toAttribute(key: string, value: unknown): OtlpAttribute[] {
  if (value === undefined || value === null) return [];
  if (typeof value === 'boolean') return [{ key, value: { boolValue: value } }];
  if (typeof value === 'number') {
    return Number.isInteger(value)
      ? [{ key, value: { intValue: String(value) } }]
      : [{ key, value: { doubleValue: value } }];
  }
  return [{ key, value: { stringValue: String(value) } }];
}

function unixNano(ts: string): bigint {
  return BigInt(new Date(ts).getTime()) * 1_000_000n;
}

function hex(input: string, length: number): string {
  return createHash('sha256').update(input).digest('hex').slice(0, length);
}

function parseHeaders(raw?: string): Record<string, string> {
  if (!raw) return {};
  const headers: Record<string, string> = {};
  for (const pair of raw.split(',')) {
    const [key, ...rest] = pair.split('=');
    const value = rest.join('=');
    if (!key || !value) continue;
    headers[decodeURIComponent(key.trim())] = decodeURIComponent(value.trim());
  }
  return headers;
}

function truncate(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, max)}…`;
}

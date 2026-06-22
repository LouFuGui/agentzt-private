import { randomUUID } from 'node:crypto';
import type { TemporalConfig } from '../shared/types.ts';

export type TemporalApiResult = {
  ok: boolean;
  status: number;
  body?: unknown;
  error?: string;
};

export type TemporalStartWorkflowArgs = {
  workflowType: string;
  workflowId?: string;
  taskQueue?: string;
  input?: unknown;
};

export type TemporalSignalWorkflowArgs = {
  workflowId: string;
  signalName: string;
  runId?: string;
  input?: unknown;
};

export type TemporalQueryWorkflowArgs = {
  workflowId: string;
  queryType: string;
  runId?: string;
  input?: unknown;
};

type TemporalPayloads = {
  payloads: Array<{
    metadata: { encoding: string };
    data: string;
  }>;
};

export const DEFAULT_TEMPORAL_CONFIG: TemporalConfig = {
  enabled: false,
  baseUrl: 'http://localhost:7243/api/v1',
  namespace: 'default',
  defaultTaskQueue: 'agentzt-tasks',
  timeoutMs: 5000,
  apiKeyEnv: 'TEMPORAL_API_KEY',
};

function trimSlash(value: string): string {
  return value.endsWith('/') ? value.slice(0, -1) : value;
}

function temporalPayloads(input: unknown): TemporalPayloads | undefined {
  if (input === undefined) return undefined;
  return {
    payloads: [{
      metadata: { encoding: Buffer.from('json/plain').toString('base64') },
      data: Buffer.from(JSON.stringify(input)).toString('base64'),
    }],
  };
}

export function resolveTemporalConfig(config?: Partial<TemporalConfig>): TemporalConfig {
  return {
    ...DEFAULT_TEMPORAL_CONFIG,
    ...config,
    baseUrl: trimSlash(config?.baseUrl ?? DEFAULT_TEMPORAL_CONFIG.baseUrl),
  };
}

export class TemporalClient {
  readonly config: TemporalConfig;

  constructor(config?: Partial<TemporalConfig>) {
    this.config = resolveTemporalConfig(config);
  }

  async startWorkflow(args: TemporalStartWorkflowArgs): Promise<TemporalApiResult> {
    const body: Record<string, unknown> = {
      workflow_id: args.workflowId ?? `workflow_${randomUUID()}`,
      workflow_type: { name: args.workflowType },
      task_queue: { name: args.taskQueue ?? this.config.defaultTaskQueue },
    };
    const input = temporalPayloads(args.input);
    if (input) body.input = input;
    return this.request('/workflows', body);
  }

  async signalWorkflow(args: TemporalSignalWorkflowArgs): Promise<TemporalApiResult> {
    const body: Record<string, unknown> = {};
    if (args.runId) body.workflow_run_id = args.runId;
    const input = temporalPayloads(args.input);
    if (input) body.input = input;
    return this.request(`/workflows/${encodeURIComponent(args.workflowId)}/signal/${encodeURIComponent(args.signalName)}`, body);
  }

  async queryWorkflow(args: TemporalQueryWorkflowArgs): Promise<TemporalApiResult> {
    const body: Record<string, unknown> = {};
    if (args.runId) body.workflow_run_id = args.runId;
    const input = temporalPayloads(args.input);
    if (input) body.input = input;
    return this.request(`/workflows/${encodeURIComponent(args.workflowId)}/query/${encodeURIComponent(args.queryType)}`, body);
  }

  private async request(path: string, body: Record<string, unknown>): Promise<TemporalApiResult> {
    if (!this.config.enabled) {
      return { ok: false, status: 503, error: 'Temporal integration is disabled' };
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    const apiKey = this.config.apiKeyEnv ? process.env[this.config.apiKeyEnv] : undefined;
    if (apiKey) headers.authorization = ['Bearer', apiKey].join(' ');

    try {
      const response = await fetch(
        `${this.config.baseUrl}/namespaces/${encodeURIComponent(this.config.namespace)}${path}`,
        {
          method: 'POST',
          headers,
          body: JSON.stringify(body),
          signal: controller.signal,
        },
      );
      const responseBody = await readResponseBody(response);
      if (!response.ok) {
        return {
          ok: false,
          status: response.status,
          error: typeof responseBody === 'string' ? responseBody : JSON.stringify(responseBody),
          body: responseBody,
        };
      }
      return { ok: true, status: response.status, body: responseBody };
    } catch (err) {
      const message = (err as Error).name === 'AbortError'
        ? `Temporal request timed out after ${this.config.timeoutMs}ms`
        : (err as Error).message;
      return { ok: false, status: 502, error: message };
    } finally {
      clearTimeout(timeout);
    }
  }
}

async function readResponseBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

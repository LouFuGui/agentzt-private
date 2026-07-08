import { randomUUID } from 'node:crypto';
import { Client, Connection } from '@temporalio/client';
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

export const DEFAULT_TEMPORAL_CONFIG: TemporalConfig = {
  enabled: false,
  // With the SDK this is the Temporal frontend gRPC address.
  // Keep the existing field name for backward-compatible config shape.
  baseUrl: '127.0.0.1:7233',
  namespace: 'default',
  defaultTaskQueue: 'agentzt-tasks',
  timeoutMs: 5000,
  apiKeyEnv: 'TEMPORAL_API_KEY',
};

function normalizeAddress(value: string): string {
  // Accept either "127.0.0.1:7233" or legacy URL-like values.
  if (!value.includes('://')) return value.replace(/\/+$/, '');

  const url = new URL(value);
  return `${url.hostname}${url.port ? `:${url.port}` : ''}`;
}

export function resolveTemporalConfig(config?: Partial<TemporalConfig>): TemporalConfig {
  return {
    ...DEFAULT_TEMPORAL_CONFIG,
    ...config,
    baseUrl: normalizeAddress(config?.baseUrl ?? DEFAULT_TEMPORAL_CONFIG.baseUrl),
  };
}

export class TemporalClient {
  readonly config: TemporalConfig;
  private clientPromise?: Promise<Client>;

  constructor(config?: Partial<TemporalConfig>) {
    this.config = resolveTemporalConfig(config);
  }

  async startWorkflow(args: TemporalStartWorkflowArgs): Promise<TemporalApiResult> {
    if (!this.config.enabled) {
      return { ok: false, status: 503, error: 'Temporal integration is disabled' };
    }

    try {
      const client = await this.getClient();
      const workflowId = args.workflowId ?? `agentzt_wf_${randomUUID()}`;

      const handle = await withTimeout(
        client.workflow.start(args.workflowType, {
          workflowId,
          taskQueue: args.taskQueue ?? this.config.defaultTaskQueue,
          args: args.input === undefined ? [] : [args.input],
        }),
        this.config.timeoutMs,
        'Temporal startWorkflow',
      );

      return {
        ok: true,
        status: 200,
        body: {
          workflowId: handle.workflowId,
          firstExecutionRunId: handle.firstExecutionRunId,
        },
      };
    } catch (err) {
      return temporalError(err);
    }
  }

  async signalWorkflow(args: TemporalSignalWorkflowArgs): Promise<TemporalApiResult> {
    if (!this.config.enabled) {
      return { ok: false, status: 503, error: 'Temporal integration is disabled' };
    }

    try {
      const client = await this.getClient();
      const handle = client.workflow.getHandle(args.workflowId, args.runId);

      await withTimeout(
        handle.signal(args.signalName, ...(args.input === undefined ? [] : [args.input])),
        this.config.timeoutMs,
        'Temporal signalWorkflow',
      );

      return {
        ok: true,
        status: 200,
        body: {
          workflowId: args.workflowId,
          runId: args.runId,
          signalName: args.signalName,
        },
      };
    } catch (err) {
      return temporalError(err);
    }
  }

  async queryWorkflow(args: TemporalQueryWorkflowArgs): Promise<TemporalApiResult> {
    if (!this.config.enabled) {
      return { ok: false, status: 503, error: 'Temporal integration is disabled' };
    }

    try {
      const client = await this.getClient();
      const handle = client.workflow.getHandle(args.workflowId, args.runId);

      const result = await withTimeout(
        handle.query(args.queryType, ...(args.input === undefined ? [] : [args.input])),
        this.config.timeoutMs,
        'Temporal queryWorkflow',
      );

      return {
        ok: true,
        status: 200,
        body: {
          workflowId: args.workflowId,
          runId: args.runId,
          queryType: args.queryType,
          result,
        },
      };
    } catch (err) {
      return temporalError(err);
    }
  }

  private async getClient(): Promise<Client> {
    if (!this.clientPromise) {
      this.clientPromise = this.connect();
    }
    return await this.clientPromise;
  }

  private async connect(): Promise<Client> {
    const headers: Record<string, string> = {};
    const apiKey = this.config.apiKeyEnv ? process.env[this.config.apiKeyEnv] : undefined;
    if (apiKey) headers.authorization = ['Bearer', apiKey].join(' ');

    const connection = await withTimeout(
      Connection.connect({
        address: this.config.baseUrl,
        metadata: headers,
      }),
      this.config.timeoutMs,
      'Temporal connect',
    );

    return new Client({
      connection,
      namespace: this.config.namespace,
    });
  }
}

async function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  label: string,
): Promise<T> {
  const timeout = new Promise<never>((_, reject) => {
    const timer = setTimeout(() => {
      clearTimeout(timer);
      reject(new Error(`${label} timed out after ${timeoutMs}ms`));
    }, timeoutMs);
  });

  return await Promise.race([promise, timeout]);
}

function temporalError(err: unknown): TemporalApiResult {
  const message = err instanceof Error ? err.message : String(err);
  return {
    ok: false,
    status: 502,
    error: message,
    body: {
      message,
      name: err instanceof Error ? err.name : 'TemporalError',
    },
  };
}

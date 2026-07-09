import { DockerSandboxRuntime } from './docker-sandbox.ts';
import type { GatewayConfig } from '../shared/types.ts';
import type {
  DockerSandboxConfig,
  SandboxAgentCreateRequest,
  SandboxAgentLifecycleResult,
  SandboxExecuteRequest,
  SandboxExecuteResult,
  SandboxHealth,
} from './docker-sandbox.ts';

export type SandboxRuntimeName = 'docker' | 'aiosandbox' | 'opensandbox' | 'http';
const SANDBOX_HEALTH_TIMEOUT_MS = 5000;

export type SandboxRuntime = {
  readonly name: SandboxRuntimeName;
  health(): Promise<SandboxHealth>;
  execute(input: SandboxExecuteRequest): Promise<SandboxExecuteResult>;
  createAgent?(input: SandboxAgentCreateRequest): Promise<SandboxAgentLifecycleResult>;
  startAgent?(sandboxId: string): Promise<SandboxAgentLifecycleResult>;
  execAgent?(sandboxId: string, input: SandboxExecuteRequest): Promise<SandboxExecuteResult>;
  stopAgent?(sandboxId: string): Promise<SandboxAgentLifecycleResult>;
  destroyAgent?(sandboxId: string): Promise<SandboxAgentLifecycleResult>;
};

export type HttpSandboxRuntimeConfig = {
  name: Exclude<SandboxRuntimeName, 'docker'>;
  baseUrl: string;
  executePath?: string;
  healthPath?: string;
  agentPath?: string;
  timeoutMs?: number;
  defaultImage?: string;
};

type HttpSandboxResponse = Partial<SandboxExecuteResult> & {
  ok?: boolean;
  success?: boolean;
  stdout?: string;
  stderr?: string;
  output?: string;
  exitCode?: number;
  exit_code?: number;
  sandboxId?: string;
  sandbox_id?: string;
};

export class HttpSandboxRuntime implements SandboxRuntime {
  readonly name: Exclude<SandboxRuntimeName, 'docker'>;
  private baseUrl: string;
  private executePath: string;
  private healthPath: string;
  private agentPath: string;
  private timeoutMs: number;
  private defaultImage: string;

  constructor(config: HttpSandboxRuntimeConfig) {
    this.name = config.name;
    this.baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.executePath = config.executePath ?? '/v1/sandbox/execute';
    this.healthPath = config.healthPath ?? '/v1/sandbox/health';
    this.agentPath = config.agentPath ?? '/v1/sandbox/agents';
    this.timeoutMs = config.timeoutMs ?? 30000;
    this.defaultImage = config.defaultImage ?? this.name;
  }

  async health(): Promise<SandboxHealth> {
    try {
      const res = await fetch(`${this.baseUrl}${this.healthPath}`, {
        method: 'GET',
        signal: AbortSignal.timeout(Math.min(this.timeoutMs, SANDBOX_HEALTH_TIMEOUT_MS)),
      });
      if (!res.ok) return { runtime: this.name, healthy: false, reason: `HTTP ${res.status}` };
      return { runtime: this.name, healthy: true };
    } catch (err) {
      return { runtime: this.name, healthy: false, reason: (err as Error).message };
    }
  }

  async execute(input: SandboxExecuteRequest): Promise<SandboxExecuteResult> {
    const start = Date.now();
    const res = await fetch(`${this.baseUrl}${this.executePath}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(input),
      signal: AbortSignal.timeout(input.timeoutMs ?? this.timeoutMs),
    });
    const text = await res.text();
    const body = parseHttpSandboxJson<HttpSandboxResponse>(text, this.executePath);
    const exitCode = resolveExitCode(res.ok, body);
    const output = resolveOutput(body);
    return {
      sandboxId: body.sandboxId ?? body.sandbox_id ?? `remote-${Date.now()}`,
      runtime: this.name,
      mode: input.mode,
      language: input.mode === 'code' ? input.language : undefined,
      image: body.image ?? this.defaultImage,
      command: body.command ?? [],
      exitCode,
      output: String(output ?? ''),
      timedOut: body.timedOut ?? false,
      metrics: {
        executionTime: body.metrics?.executionTime ?? Date.now() - start,
        memoryLimitMb: body.metrics?.memoryLimitMb ?? input.memoryMb ?? 0,
        networkAccess: body.metrics?.networkAccess ?? input.networkAccess ?? false,
      },
    };
  }

  async createAgent(input: SandboxAgentCreateRequest): Promise<SandboxAgentLifecycleResult> {
    const body = await this.postJson<Partial<SandboxAgentLifecycleResult>>(this.agentPath, input);
    return {
      sandboxId: body.sandboxId ?? `remote-agent-${Date.now()}`,
      runtime: body.runtime ?? this.name,
      status: body.status ?? 'created',
      image: body.image,
      command: body.command,
    };
  }

  async startAgent(sandboxId: string): Promise<SandboxAgentLifecycleResult> {
    return await this.lifecyclePost(sandboxId, 'start', 'started');
  }

  async execAgent(sandboxId: string, input: SandboxExecuteRequest): Promise<SandboxExecuteResult> {
    const body = await this.postJson<HttpSandboxResponse>(`${this.agentPath}/${encodeURIComponent(sandboxId)}/exec`, input);
    return this.responseToExecuteResult(body, input, sandboxId);
  }

  async stopAgent(sandboxId: string): Promise<SandboxAgentLifecycleResult> {
    return await this.lifecyclePost(sandboxId, 'stop', 'stopped');
  }

  async destroyAgent(sandboxId: string): Promise<SandboxAgentLifecycleResult> {
    return await this.lifecyclePost(sandboxId, 'destroy', 'destroyed');
  }

  private async lifecyclePost(
    sandboxId: string,
    operation: string,
    status: SandboxAgentLifecycleResult['status'],
  ): Promise<SandboxAgentLifecycleResult> {
    const body = await this.postJson<Partial<SandboxAgentLifecycleResult>>(
      `${this.agentPath}/${encodeURIComponent(sandboxId)}/${operation}`,
      {},
    );
    return { sandboxId: body.sandboxId ?? sandboxId, runtime: body.runtime ?? this.name, status: body.status ?? status };
  }

  private async postJson<T>(path: string, input: unknown): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(input),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    const text = await res.text();
    const body = parseHttpSandboxJson<T>(text, path);
    if (!res.ok) throw new Error(`HTTP sandbox ${path} failed: ${res.status}`);
    return body;
  }

  private responseToExecuteResult(
    body: HttpSandboxResponse,
    input: SandboxExecuteRequest,
    fallbackSandboxId?: string,
  ): SandboxExecuteResult {
    const exitCode = resolveExitCode(true, body);
    const output = resolveOutput(body);
    return {
      sandboxId: body.sandboxId ?? body.sandbox_id ?? fallbackSandboxId ?? `remote-${Date.now()}`,
      runtime: this.name,
      mode: input.mode,
      language: input.mode === 'code' ? input.language : undefined,
      image: body.image ?? this.defaultImage,
      command: body.command ?? [],
      exitCode,
      output: String(output ?? ''),
      timedOut: body.timedOut ?? false,
      metrics: {
        executionTime: body.metrics?.executionTime ?? 0,
        memoryLimitMb: body.metrics?.memoryLimitMb ?? input.memoryMb ?? 0,
        networkAccess: body.metrics?.networkAccess ?? input.networkAccess ?? false,
      },
    };
  }

}

function parseHttpSandboxJson<T>(text: string, path: string): T {
  if (!text) return {} as T;
  try {
    return JSON.parse(text) as T;
  } catch (err) {
    throw new Error(`HTTP sandbox ${path} returned invalid JSON: ${(err as Error).message}`);
  }
}

function resolveExitCode(httpOk: boolean, body: HttpSandboxResponse): number {
  if (body.exitCode !== undefined) return body.exitCode;
  if (body.exit_code !== undefined) return body.exit_code;
  const reportedOk = body.ok ?? body.success ?? httpOk;
  return httpOk && reportedOk ? 0 : 1;
}

function resolveOutput(body: HttpSandboxResponse): string {
  if (body.output !== undefined) return String(body.output);
  return [body.stdout, body.stderr].filter(Boolean).join('');
}

export function createSandboxRuntime(cfg: GatewayConfig['sandbox']): SandboxRuntime {
  const runtime = cfg?.runtime ?? 'docker';
  if (runtime === 'docker') {
    const dockerConfig: DockerSandboxConfig = {
      socketPath: cfg?.dockerSocketPath,
      apiVersion: cfg?.dockerApiVersion,
      defaultImage: cfg?.defaultImage,
      images: cfg?.images,
      timeoutMs: cfg?.timeoutMs,
      maxTimeoutMs: cfg?.maxTimeoutMs,
      memoryMb: cfg?.memoryMb,
      maxMemoryMb: cfg?.maxMemoryMb,
      networkAccess: cfg?.networkAccess,
    };
    return new DockerSandboxRuntime(dockerConfig);
  }
  return new HttpSandboxRuntime({
    name: runtime,
    baseUrl: cfg?.baseUrl ?? 'http://localhost:8080',
    executePath: cfg?.executePath,
    healthPath: cfg?.healthPath,
    agentPath: cfg?.agentPath,
    timeoutMs: cfg?.timeoutMs,
    defaultImage: cfg?.defaultImage,
  });
}

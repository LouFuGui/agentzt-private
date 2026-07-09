import { DockerSandboxRuntime } from './docker-sandbox.ts';
import type { GatewayConfig } from '../shared/types.ts';
import type {
  DockerSandboxConfig,
  SandboxExecuteRequest,
  SandboxExecuteResult,
} from './docker-sandbox.ts';

export type SandboxRuntimeName = 'docker' | 'aiosandbox' | 'opensandbox' | 'http';

export type SandboxRuntime = {
  readonly name: SandboxRuntimeName;
  execute(input: SandboxExecuteRequest): Promise<SandboxExecuteResult>;
};

export type HttpSandboxRuntimeConfig = {
  name: Exclude<SandboxRuntimeName, 'docker'>;
  baseUrl: string;
  executePath?: string;
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
  private timeoutMs: number;
  private defaultImage: string;

  constructor(config: HttpSandboxRuntimeConfig) {
    this.name = config.name;
    this.baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.executePath = config.executePath ?? '/v1/sandbox/execute';
    this.timeoutMs = config.timeoutMs ?? 30000;
    this.defaultImage = config.defaultImage ?? this.name;
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
    const body = text ? JSON.parse(text) as HttpSandboxResponse : {};
    const exitCode = resolveExitCode(res.ok, body);
    const output = body.output ?? [body.stdout, body.stderr].filter(Boolean).join('');
    return {
      sandboxId: body.sandboxId ?? body.sandbox_id ?? `remote-${Date.now()}`,
      runtime: this.name,
      mode: input.mode,
      language: input.mode === 'code' ? input.language : undefined,
      image: body.image ?? this.defaultImage,
      command: body.command ?? commandFor(input),
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
}

function resolveExitCode(httpOk: boolean, body: HttpSandboxResponse): number {
  if (body.exitCode !== undefined) return body.exitCode;
  if (body.exit_code !== undefined) return body.exit_code;
  const reportedOk = body.ok ?? body.success ?? httpOk;
  return httpOk && reportedOk ? 0 : 1;
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
    timeoutMs: cfg?.timeoutMs,
    defaultImage: cfg?.defaultImage,
  });
}

function commandFor(input: SandboxExecuteRequest): string[] {
  if (input.mode === 'command') return ['sh', '-c', input.command];
  if (input.language === 'python') return ['python3', '-c', input.code];
  if (input.language === 'javascript') return ['node', '-e', input.code];
  return ['bash', '-c', input.code];
}

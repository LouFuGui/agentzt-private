import { DockerSandboxRuntime } from './docker-sandbox.ts';
import type { GatewayConfig, SandboxRuntimeProviderConfig } from '../shared/types.ts';
import type {
  DockerSandboxConfig,
  SandboxAgentCreateRequest,
  SandboxAgentLifecycleResult,
  SandboxExecuteRequest,
  SandboxExecuteResult,
  SandboxHealth,
} from './docker-sandbox.ts';

export type SandboxRuntimeName = 'docker' | 'aiosandbox' | 'opensandbox' | 'http';
export type SandboxRuntimeSelection = {
  tenantId?: string;
  role?: string;
  projectId?: string;
  resource?: string;
  capability?: string;
};
// Health checks stay short even for long-running execution runtimes.
const SANDBOX_HEALTH_CHECK_TIMEOUT_MS = 5000;

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

export type SandboxRuntimeRegistryEntry = SandboxRuntimeProviderConfig & {
  eligible: boolean;
  selected: boolean;
  reason?: string;
  health?: SandboxHealth;
};

export type SandboxRuntimeRegistry = {
  selected?: SandboxRuntimeProviderConfig;
  scheduling: 'capacity' | 'priority';
  selection: SandboxRuntimeSelection;
  health?: SandboxHealth;
  runtimes: SandboxRuntimeRegistryEntry[];
};

export type HttpSandboxRuntimeConfig = {
  name: Exclude<SandboxRuntimeName, 'docker'>;
  baseUrl: string;
  executePath?: string;
  healthPath?: string;
  agentPath?: string;
  timeoutMs?: number;
  defaultImage?: string;
  apiKeyEnv?: string;
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

type SandboxSchedulingPolicy = 'capacity' | 'priority';

export class HttpSandboxRuntime implements SandboxRuntime {
  readonly name: Exclude<SandboxRuntimeName, 'docker'>;
  protected baseUrl: string;
  private executePath: string;
  private healthPath: string;
  private agentPath: string;
  protected timeoutMs: number;
  protected defaultImage: string;
  protected headers: Record<string, string>;

  constructor(config: HttpSandboxRuntimeConfig) {
    this.name = config.name;
    this.baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.executePath = config.executePath ?? '/v1/sandbox/execute';
    this.healthPath = config.healthPath ?? '/v1/sandbox/health';
    this.agentPath = config.agentPath ?? '/v1/sandbox/agents';
    this.timeoutMs = config.timeoutMs ?? 30000;
    this.defaultImage = config.defaultImage ?? this.name;
    this.headers = sandboxAuthHeaders(config.apiKeyEnv);
  }

  async health(): Promise<SandboxHealth> {
    try {
      const res = await fetch(`${this.baseUrl}${this.healthPath}`, {
        method: 'GET',
        headers: this.headers,
        signal: AbortSignal.timeout(Math.min(this.timeoutMs, SANDBOX_HEALTH_CHECK_TIMEOUT_MS)),
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
      headers: { ...this.headers, 'content-type': 'application/json' },
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

  protected async postJson<T>(path: string, input: unknown, timeoutMs = this.timeoutMs): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: { ...this.headers, 'content-type': 'application/json' },
      body: JSON.stringify(input),
      signal: AbortSignal.timeout(timeoutMs),
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

export class AioSandboxRuntime extends HttpSandboxRuntime {
  constructor(config: HttpSandboxRuntimeConfig) {
    super({
      ...config,
      healthPath: config.healthPath ?? '/healthz',
      executePath: config.executePath ?? '/v1/shell/exec',
      defaultImage: config.defaultImage ?? 'ghcr.io/agent-infra/sandbox:latest',
    });
  }

  override async execute(input: SandboxExecuteRequest): Promise<SandboxExecuteResult> {
    if (input.mode === 'code' && input.language === 'python') {
      return await this.executeAio(input, '/v1/jupyter/execute', { code: input.code });
    }
    const command = input.mode === 'command' ? input.command : codeShellCommand(input);
    return await this.executeAio(input, '/v1/shell/exec', { command });
  }

  private async executeAio(
    input: SandboxExecuteRequest,
    path: string,
    body: Record<string, unknown>,
  ): Promise<SandboxExecuteResult> {
    const start = Date.now();
    const response = await this.postJson<AioSandboxResponse>(path, body, input.timeoutMs);
    const data = isRecord(response.data) ? response.data : response as Record<string, unknown>;
    const output = response.output ?? data['output'] ?? data['stdout'] ?? data['result'] ?? '';
    const exitCode = response.exitCode ?? response.exit_code ?? numberValue(data['exitCode'])
      ?? numberValue(data['exit_code']) ?? (response.success === false ? 1 : 0);
    return {
      sandboxId: stringValue(response.sandboxId) ?? stringValue(data['sandboxId']) ?? `aio-${Date.now()}`,
      runtime: 'aiosandbox',
      mode: input.mode,
      language: input.mode === 'code' ? input.language : undefined,
      image: 'ghcr.io/agent-infra/sandbox:latest',
      command: input.mode === 'command' ? ['sh', '-c', input.command] : codeCommand(input),
      exitCode,
      output: Array.isArray(output) ? output.join('') : String(output),
      timedOut: false,
      metrics: {
        executionTime: Date.now() - start,
        memoryLimitMb: input.memoryMb ?? 0,
        networkAccess: input.networkAccess ?? false,
      },
    };
  }
}

export class OpenSandboxRuntime extends HttpSandboxRuntime {
  constructor(config: HttpSandboxRuntimeConfig) {
    super({
      ...config,
      healthPath: config.healthPath ?? '/v1/health',
      executePath: config.executePath ?? '/v1/sandbox/execute',
      agentPath: config.agentPath ?? '/v1/sandboxes',
      defaultImage: config.defaultImage ?? 'opensandbox/code-interpreter:v1.1.0',
    });
  }

  override async health(): Promise<SandboxHealth> {
    const lifecycle = await this.getHealth('/v1/health');
    if (lifecycle.healthy) return lifecycle;
    const fallback = await this.getHealth('/healthz');
    return fallback.healthy ? fallback : lifecycle;
  }

  override async createAgent(input: SandboxAgentCreateRequest): Promise<SandboxAgentLifecycleResult> {
    const body = await this.postOpenSandbox<OpenSandboxCreateResponse>('/v1/sandboxes', {
      image: input.image ?? this.defaultImage,
      entrypoint: input.command ? ['sh', '-c', input.command] : undefined,
      env: input.env,
      timeout: input.timeoutMs ? `${Math.ceil(input.timeoutMs / 1000)}s` : undefined,
      resources: {
        memory: input.memoryMb ? `${input.memoryMb}Mi` : undefined,
      },
      metadata: {
        agentId: input.agentId,
        projectId: input.projectId,
        controlPlane: 'agentzt',
      },
      extensions: {
        networkAccess: input.networkAccess ?? false,
        mounts: input.mounts ?? [],
      },
    });
    const sandboxId = body.sandboxId ?? body.id ?? body.sandbox_id;
    if (!sandboxId) throw new Error('OpenSandbox create response missing sandbox id');
    return {
      sandboxId,
      runtime: 'opensandbox',
      status: body.state === 'Running' ? 'started' : 'created',
      image: body.image,
      command: input.command ? ['sh', '-c', input.command] : undefined,
    };
  }

  override async startAgent(sandboxId: string): Promise<SandboxAgentLifecycleResult> {
    const body = await this.postOpenSandbox<OpenSandboxCreateResponse>(`/v1/sandboxes/${encodeURIComponent(sandboxId)}/resume`, {});
    return { sandboxId: body.sandboxId ?? body.id ?? sandboxId, runtime: 'opensandbox', status: 'started' };
  }

  override async stopAgent(sandboxId: string): Promise<SandboxAgentLifecycleResult> {
    await this.postOpenSandbox(`/v1/sandboxes/${encodeURIComponent(sandboxId)}/pause`, {});
    return { sandboxId, runtime: 'opensandbox', status: 'stopped' };
  }

  override async destroyAgent(sandboxId: string): Promise<SandboxAgentLifecycleResult> {
    await this.requestOpenSandbox('DELETE', `/v1/sandboxes/${encodeURIComponent(sandboxId)}`, undefined);
    return { sandboxId, runtime: 'opensandbox', status: 'destroyed' };
  }

  private async getHealth(path: string): Promise<SandboxHealth> {
    try {
      const res = await fetch(`${this.baseUrl}${path}`, {
        method: 'GET',
        headers: this.headers,
        signal: AbortSignal.timeout(Math.min(this.timeoutMs, SANDBOX_HEALTH_CHECK_TIMEOUT_MS)),
      });
      if (!res.ok) return { runtime: 'opensandbox', healthy: false, reason: `HTTP ${res.status}` };
      return { runtime: 'opensandbox', healthy: true };
    } catch (err) {
      return { runtime: 'opensandbox', healthy: false, reason: (err as Error).message };
    }
  }

  private async postOpenSandbox<T = unknown>(path: string, body: unknown): Promise<T> {
    return await this.requestOpenSandbox<T>('POST', path, body);
  }

  private async requestOpenSandbox<T = unknown>(method: string, path: string, body: unknown): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: { ...this.headers, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    const text = await res.text();
    const parsed = parseHttpSandboxJson<T>(text, path);
    if (!res.ok) throw new Error(`OpenSandbox ${method} ${path} failed: ${res.status}`);
    return parsed;
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

type AioSandboxResponse = HttpSandboxResponse & {
  data?: unknown;
  exit_code?: number;
};

type OpenSandboxCreateResponse = {
  id?: string;
  sandboxId?: string;
  sandbox_id?: string;
  state?: string;
  image?: string;
};

function codeCommand(input: Extract<SandboxExecuteRequest, { mode: 'code' }>): string[] {
  if (input.language === 'python') return ['python3', '-c', input.code];
  if (input.language === 'javascript') return ['node', '-e', input.code];
  return ['bash', '-c', input.code];
}

function codeShellCommand(input: Extract<SandboxExecuteRequest, { mode: 'code' }>): string {
  return codeCommand(input).map(shellQuote).join(' ');
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function numberValue(value: unknown): number | undefined {
  return typeof value === 'number' ? value : undefined;
}

function sandboxAuthHeaders(apiKeyEnv?: string): Record<string, string> {
  if (!apiKeyEnv) return {};
  const token = process.env[apiKeyEnv];
  if (!token) return {};
  return {
    authorization: ['Bearer', token].join(' '),
    'OPEN-SANDBOX-API-KEY': token,
    'X-AIO-API-Key': token,
  };
}

function runtimeProviders(cfg: GatewayConfig['sandbox']): SandboxRuntimeProviderConfig[] {
  if (cfg?.runtimes?.length) return cfg.runtimes;
  return [{
    name: cfg?.runtime ?? 'docker',
    type: cfg?.runtime ?? 'docker',
    enabled: cfg?.enabled !== false,
    baseUrl: cfg?.baseUrl,
    healthPath: cfg?.healthPath,
    executePath: cfg?.executePath,
    agentPath: cfg?.agentPath,
    capacity: 1,
    defaultImage: cfg?.defaultImage,
  }];
}

export function selectSandboxRuntimeProvider(
  cfg: GatewayConfig['sandbox'],
  selection: SandboxRuntimeSelection = {},
): SandboxRuntimeProviderConfig | undefined {
  const providers = runtimeProviders(cfg).filter((provider) => provider.enabled !== false);
  const target = cfg?.runtime ?? 'docker';
  const candidates = providers.filter((provider) =>
    provider.name === target || provider.type === target);
  const pool = candidates.length ? candidates : providers;
  const compatible = pool.filter((provider) => providerMatchReason(provider, selection) === undefined);
  return compatible.sort((a, b) => compareProviders(a, b, cfg?.scheduling?.policy))[0];
}

export async function describeSandboxRuntimeRegistry(
  cfg: GatewayConfig['sandbox'],
  selection: SandboxRuntimeSelection = {},
): Promise<SandboxRuntimeRegistry> {
  const selected = selectSandboxRuntimeProvider(cfg, selection);
  const health = cfg?.enabled === false
    ? { runtime: cfg?.runtime ?? 'docker', healthy: false, reason: 'sandbox disabled' }
    : await createSandboxRuntime(cfg, selection).health();
  return {
    selected,
    scheduling: cfg?.scheduling?.policy ?? 'capacity',
    selection,
    health,
    runtimes: runtimeProviders(cfg).map((provider) => {
      const reason = provider.enabled === false ? 'runtime disabled' : providerMatchReason(provider, selection);
      return {
        ...provider,
        eligible: reason === undefined,
        selected: selected?.name === provider.name,
        reason,
        health: selected?.name === provider.name ? health : undefined,
      };
    }),
  };
}

function compareProviders(
  a: SandboxRuntimeProviderConfig,
  b: SandboxRuntimeProviderConfig,
  policy: SandboxSchedulingPolicy = 'capacity',
): number {
  const priorityDelta = (b.priority ?? 0) - (a.priority ?? 0);
  const capacityDelta = (b.capacity ?? 1) - (a.capacity ?? 1);
  if (policy === 'priority') return priorityDelta || capacityDelta;
  return capacityDelta || priorityDelta;
}

function providerMatchReason(provider: SandboxRuntimeProviderConfig, selection: SandboxRuntimeSelection): string | undefined {
  const tenantReason = allowlistDenyReason('tenant', selection.tenantId, provider.allowedTenantIds);
  if (tenantReason) return tenantReason;
  const roleReason = allowlistDenyReason('role', selection.role, provider.allowedRoles);
  if (roleReason) return roleReason;
  const projectReason = allowlistDenyReason('project', selection.projectId, provider.allowedProjectIds);
  if (projectReason) return projectReason;
  const resource = selection.resource ?? selection.capability;
  if (resource && provider.resources && !provider.resources.includes(resource)) {
    return `resource "${resource}" is not allowed`;
  }
  if (selection.capability && provider.capabilities && !provider.capabilities.includes(selection.capability)) {
    return `capability "${selection.capability}" is not declared`;
  }
  return undefined;
}

function allowlistDenyReason(kind: string, value: string | undefined, allowlist: string[] | undefined): string | undefined {
  if (!value || !allowlist || allowlist.includes(value)) return undefined;
  return `${kind} "${value}" is not allowed`;
}

export function createSandboxRuntime(
  cfg: GatewayConfig['sandbox'],
  selection: SandboxRuntimeSelection = {},
): SandboxRuntime {
  const provider = selectSandboxRuntimeProvider(cfg, selection);
  const runtime = provider?.type ?? cfg?.runtime ?? 'docker';
  if (runtime === 'docker') {
    const dockerConfig: DockerSandboxConfig = {
      socketPath: cfg?.dockerSocketPath,
      apiVersion: cfg?.dockerApiVersion,
      defaultImage: provider?.defaultImage ?? cfg?.defaultImage,
      images: cfg?.images,
      timeoutMs: cfg?.timeoutMs,
      maxTimeoutMs: cfg?.maxTimeoutMs,
      memoryMb: cfg?.memoryMb,
      maxMemoryMb: cfg?.maxMemoryMb,
      networkAccess: provider?.networkPolicy?.defaultAccess ?? cfg?.networkAccess,
    };
    return new DockerSandboxRuntime(dockerConfig);
  }
  const config = {
    name: runtime,
    baseUrl: provider?.baseUrl ?? cfg?.baseUrl ?? 'http://localhost:8080',
    executePath: provider?.executePath ?? cfg?.executePath,
    healthPath: provider?.healthPath ?? cfg?.healthPath,
    agentPath: provider?.agentPath ?? cfg?.agentPath,
    timeoutMs: cfg?.timeoutMs,
    defaultImage: provider?.defaultImage ?? cfg?.defaultImage,
    apiKeyEnv: provider?.apiKeyEnv,
  };
  if (runtime === 'aiosandbox') return new AioSandboxRuntime(config);
  if (runtime === 'opensandbox') return new OpenSandboxRuntime(config);
  return new HttpSandboxRuntime(config);
}

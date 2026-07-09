import { request } from 'node:http';
import { makeLogger } from '../shared/log.ts';
import { newId } from '../shared/crypto.ts';

const log = makeLogger('docker-sandbox');
// Exit code 124 follows the GNU coreutils timeout(1) convention.
const SANDBOX_TIMEOUT_EXIT_CODE_GNU_COMPAT = 124;

export type SandboxExecuteMode = 'command' | 'code';
export type SandboxCodeLanguage = 'python' | 'javascript' | 'bash';

export type DockerSandboxConfig = {
  socketPath?: string;
  apiVersion?: string;
  defaultImage?: string;
  images?: Partial<Record<SandboxCodeLanguage, string>>;
  timeoutMs?: number;
  maxTimeoutMs?: number;
  memoryMb?: number;
  maxMemoryMb?: number;
  networkAccess?: boolean;
};

export type SandboxExecuteRequest =
  | {
      mode: 'command';
      command: string;
      timeoutMs?: number;
      memoryMb?: number;
      networkAccess?: boolean;
    }
  | {
      mode: 'code';
      language: SandboxCodeLanguage;
      code: string;
      timeoutMs?: number;
      memoryMb?: number;
      networkAccess?: boolean;
    };

export type SandboxExecuteResult = {
  sandboxId: string;
  runtime: string;
  mode: SandboxExecuteMode;
  language?: SandboxCodeLanguage;
  image: string;
  command: string[];
  exitCode: number;
  output: string;
  timedOut: boolean;
  metrics: {
    executionTime: number;
    memoryLimitMb: number;
    networkAccess: boolean;
  };
};

export type SandboxHealth = {
  runtime: string;
  healthy: boolean;
  reason?: string;
};

export type SandboxAgentCreateRequest = {
  image?: string;
  command?: string;
  timeoutMs?: number;
  memoryMb?: number;
  networkAccess?: boolean;
  env?: Record<string, string>;
  mounts?: Array<{ source: string; target: string; readonly?: boolean }>;
  projectId?: string;
  agentId?: string;
};

export type SandboxAgentLifecycleResult = {
  sandboxId: string;
  runtime: string;
  status: 'created' | 'started' | 'stopped' | 'destroyed';
  image?: string;
  command?: string[];
};

type DockerCreateResponse = { Id?: string };
type DockerWaitResponse = { StatusCode?: number; Error?: { Message?: string } };
type DockerExecCreateResponse = { Id?: string };
type DockerExecInspectResponse = { ExitCode?: number | null };

export class DockerApiError extends Error {
  readonly statusCode: number;
  readonly body: string;

  constructor(method: string, path: string, statusCode: number, body: string) {
    super(`Docker ${method} ${path} failed: ${statusCode}${body ? ` ${body}` : ''}`);
    this.statusCode = statusCode;
    this.body = body;
  }
}

export class DockerApiClient {
  private socketPath: string;
  private apiVersion: string;

  constructor(config: Pick<DockerSandboxConfig, 'socketPath' | 'apiVersion'> = {}) {
    this.socketPath = config.socketPath ?? '/var/run/docker.sock';
    this.apiVersion = config.apiVersion ?? 'v1.41';
  }

  async request<T = unknown>(
    method: string,
    path: string,
    body?: unknown,
    timeoutMs = 30000,
  ): Promise<T | undefined> {
    const versionedPath = `/${this.apiVersion}${path}`;
    const payload = body === undefined ? undefined : JSON.stringify(body);
    return await new Promise<T | undefined>((resolve, reject) => {
      const req = request({
        socketPath: this.socketPath,
        path: versionedPath,
        method,
        headers: payload
          ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) }
          : undefined,
        signal: AbortSignal.timeout(timeoutMs),
      }, (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          const status = res.statusCode ?? 0;
          if (status < 200 || status >= 300) {
            reject(new DockerApiError(method, versionedPath, status, text));
            return;
          }
          if (!text) {
            resolve(undefined);
            return;
          }
          const contentType = String(res.headers['content-type'] ?? '');
          if (contentType.includes('application/json')) {
            resolve(JSON.parse(text) as T);
          } else {
            resolve(text as T);
          }
        });
      });
      req.on('error', reject);
      if (payload) req.write(payload);
      req.end();
    });
  }
}

export class DockerSandboxRuntime {
  readonly name = 'docker';

  private client: DockerApiClient;
  private agents = new Map<string, string>();
  private config: Required<Omit<DockerSandboxConfig, 'images'>> & {
    images: Record<SandboxCodeLanguage, string>;
  };

  constructor(config: DockerSandboxConfig = {}, client?: DockerApiClient) {
    this.config = {
      socketPath: config.socketPath ?? '/var/run/docker.sock',
      apiVersion: config.apiVersion ?? 'v1.41',
      defaultImage: config.defaultImage ?? 'alpine:3.20',
      images: {
        python: config.images?.python ?? 'python:3.11-slim',
        javascript: config.images?.javascript ?? 'node:22-alpine',
        bash: config.images?.bash ?? 'bash:5.2',
      },
      timeoutMs: config.timeoutMs ?? 30000,
      maxTimeoutMs: config.maxTimeoutMs ?? 60000,
      memoryMb: config.memoryMb ?? 256,
      maxMemoryMb: config.maxMemoryMb ?? 512,
      networkAccess: config.networkAccess ?? false,
    };
    this.client = client ?? new DockerApiClient(this.config);
  }

  async health(): Promise<SandboxHealth> {
    try {
      await this.client.request<string>('GET', '/_ping', undefined, 5000);
      return { runtime: this.name, healthy: true };
    } catch (err) {
      return { runtime: this.name, healthy: false, reason: (err as Error).message };
    }
  }

  async execute(input: SandboxExecuteRequest): Promise<SandboxExecuteResult> {
    const start = Date.now();
    const timeoutMs = Math.min(input.timeoutMs ?? this.config.timeoutMs, this.config.maxTimeoutMs);
    const memoryLimitMb = Math.min(input.memoryMb ?? this.config.memoryMb, this.config.maxMemoryMb);
    const networkAccess = input.networkAccess ?? this.config.networkAccess;
    const sandboxId = newId('sbx');
    const image = input.mode === 'code' ? this.config.images[input.language] : this.config.defaultImage;
    const cmd = this.commandFor(input);
    let containerId: string | undefined;
    let timedOut = false;

    try {
      const created = await this.client.request<DockerCreateResponse>('POST', '/containers/create', {
        Image: image,
        Cmd: cmd,
        Tty: false,
        AttachStdout: true,
        AttachStderr: true,
        Labels: {
          'agentzt.sandbox_id': sandboxId,
          'agentzt.runtime': 'docker',
        },
        HostConfig: {
          AutoRemove: false,
          NetworkMode: networkAccess ? 'bridge' : 'none',
          Memory: memoryLimitMb * 1024 * 1024,
        },
      }, 10000);
      if (!created?.Id) throw new Error('Docker create response missing container id');
      containerId = created.Id;

      await this.client.request('POST', `/containers/${containerId}/start`, undefined, 10000);

      let wait: DockerWaitResponse | undefined;
      try {
        wait = await this.client.request<DockerWaitResponse>(
          'POST',
          `/containers/${containerId}/wait?condition=not-running`,
          undefined,
          timeoutMs,
        );
      } catch (err) {
        const errorName = (err as Error).name;
        if (errorName !== 'AbortError' && errorName !== 'TimeoutError') throw err;
        timedOut = true;
        await this.kill(containerId);
        // Match the conventional timeout(1) exit code so callers can classify timeouts.
        wait = { StatusCode: SANDBOX_TIMEOUT_EXIT_CODE_GNU_COMPAT, Error: { Message: 'sandbox execution timed out' } };
      }

      const output = await this.client.request<string>(
        'GET',
        `/containers/${containerId}/logs?stdout=true&stderr=true`,
        undefined,
        10000,
      );
      if (wait?.Error?.Message) log.warn(`sandbox ${sandboxId} wait error: ${wait.Error.Message}`);

      return {
        sandboxId,
        runtime: this.name,
        mode: input.mode,
        language: input.mode === 'code' ? input.language : undefined,
        image,
        command: cmd,
        exitCode: wait?.StatusCode ?? 1,
        output: String(output ?? ''),
        timedOut,
        metrics: {
          executionTime: Date.now() - start,
          memoryLimitMb,
          networkAccess,
        },
      };
    } finally {
      if (containerId) {
        await this.remove(containerId);
      }
    }
  }

  private commandFor(input: SandboxExecuteRequest): string[] {
    return dockerSandboxCommandFor(input);
  }

  async createAgent(input: SandboxAgentCreateRequest = {}): Promise<SandboxAgentLifecycleResult> {
    const sandboxId = newId('agent-sbx');
    const timeoutMs = input.timeoutMs ?? this.config.timeoutMs;
    const memoryLimitMb = Math.min(input.memoryMb ?? this.config.memoryMb, this.config.maxMemoryMb);
    const networkAccess = input.networkAccess ?? this.config.networkAccess;
    const image = input.image ?? this.config.defaultImage;
    const cmd = input.command ? ['sh', '-c', input.command] : ['sh', '-c', 'sleep infinity'];
    const env = Object.entries(input.env ?? {}).map(([key, value]) => `${key}=${value}`);
    const binds = (input.mounts ?? []).map((mount) =>
      `${mount.source}:${mount.target}${mount.readonly ? ':ro' : ''}`);
    const created = await this.client.request<DockerCreateResponse>('POST', '/containers/create', {
      Image: image,
      Cmd: cmd,
      Tty: false,
      Env: env.length ? env : undefined,
      Labels: {
        'agentzt.sandbox_id': sandboxId,
        'agentzt.runtime': 'docker',
        'agentzt.sandbox_type': 'agent-process',
        ...(input.agentId ? { 'agentzt.agent_id': input.agentId } : {}),
        ...(input.projectId ? { 'agentzt.project_id': input.projectId } : {}),
      },
      HostConfig: {
        AutoRemove: false,
        NetworkMode: networkAccess ? 'bridge' : 'none',
        Memory: memoryLimitMb * 1024 * 1024,
        Binds: binds.length ? binds : undefined,
      },
    }, timeoutMs);
    if (!created?.Id) throw new Error('Docker create response missing container id');
    this.agents.set(sandboxId, created.Id);
    return { sandboxId, runtime: this.name, status: 'created', image, command: cmd };
  }

  async startAgent(sandboxId: string): Promise<SandboxAgentLifecycleResult> {
    const containerId = this.containerFor(sandboxId);
    await this.client.request('POST', `/containers/${containerId}/start`, undefined, 10000);
    return { sandboxId, runtime: this.name, status: 'started' };
  }

  async execAgent(sandboxId: string, input: SandboxExecuteRequest): Promise<SandboxExecuteResult> {
    const start = Date.now();
    const containerId = this.containerFor(sandboxId);
    const timeoutMs = Math.min(input.timeoutMs ?? this.config.timeoutMs, this.config.maxTimeoutMs);
    const memoryLimitMb = Math.min(input.memoryMb ?? this.config.memoryMb, this.config.maxMemoryMb);
    const cmd = this.commandFor(input);
    const created = await this.client.request<DockerExecCreateResponse>('POST', `/containers/${containerId}/exec`, {
      AttachStdout: true,
      AttachStderr: true,
      Tty: false,
      Cmd: cmd,
    }, 10000);
    if (!created?.Id) throw new Error('Docker exec create response missing exec id');
    const output = await this.client.request<string>('POST', `/exec/${created.Id}/start`, {
      Detach: false,
      Tty: false,
    }, timeoutMs);
    const inspect = await this.client.request<DockerExecInspectResponse>('GET', `/exec/${created.Id}/json`, undefined, 10000);
    return {
      sandboxId,
      runtime: this.name,
      mode: input.mode,
      language: input.mode === 'code' ? input.language : undefined,
      image: 'agent-process',
      command: cmd,
      exitCode: inspect?.ExitCode ?? 0,
      output: String(output ?? ''),
      timedOut: false,
      metrics: {
        executionTime: Date.now() - start,
        memoryLimitMb,
        networkAccess: input.networkAccess ?? this.config.networkAccess,
      },
    };
  }

  async stopAgent(sandboxId: string): Promise<SandboxAgentLifecycleResult> {
    const containerId = this.containerFor(sandboxId);
    await this.client.request('POST', `/containers/${containerId}/stop`, undefined, 10000);
    return { sandboxId, runtime: this.name, status: 'stopped' };
  }

  async destroyAgent(sandboxId: string): Promise<SandboxAgentLifecycleResult> {
    const containerId = this.containerFor(sandboxId);
    await this.remove(containerId);
    this.agents.delete(sandboxId);
    return { sandboxId, runtime: this.name, status: 'destroyed' };
  }

  private containerFor(sandboxId: string): string {
    const containerId = this.agents.get(sandboxId);
    if (!containerId) throw new Error(`agent sandbox "${sandboxId}" not found`);
    return containerId;
  }

  private async kill(containerId: string): Promise<void> {
    try {
      await this.client.request('POST', `/containers/${containerId}/kill`, undefined, 5000);
    } catch (err) {
      log.warn(`failed to kill sandbox container ${containerId}: ${(err as Error).message}`);
    }
  }

  private async remove(containerId: string): Promise<void> {
    try {
      await this.client.request('DELETE', `/containers/${containerId}?force=true&v=true`, undefined, 10000);
    } catch (err) {
      log.warn(`failed to remove sandbox container ${containerId}: ${(err as Error).message}`);
    }
  }
}

export function dockerSandboxCommandFor(input: SandboxExecuteRequest): string[] {
  if (input.mode === 'command') return ['sh', '-c', input.command];
  if (input.language === 'python') return ['python3', '-c', input.code];
  if (input.language === 'javascript') return ['node', '-e', input.code];
  return ['bash', '-c', input.code];
}

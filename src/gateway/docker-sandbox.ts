import { request } from 'node:http';
import { makeLogger } from '../shared/log.ts';
import { newId } from '../shared/crypto.ts';

const log = makeLogger('docker-sandbox');
// 124 matches timeout(1), giving callers a familiar way to classify timeouts.
const SANDBOX_TIMEOUT_EXIT_CODE = 124;

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

type DockerCreateResponse = { Id?: string };
type DockerWaitResponse = { StatusCode?: number; Error?: { Message?: string } };

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
        if ((err as Error).name !== 'AbortError' && (err as Error).name !== 'TimeoutError') throw err;
        timedOut = true;
        await this.kill(containerId);
        // Match the conventional timeout(1) exit code so callers can classify timeouts.
        wait = { StatusCode: SANDBOX_TIMEOUT_EXIT_CODE, Error: { Message: 'sandbox execution timed out' } };
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
    if (input.mode === 'command') return ['sh', '-c', input.command];
    if (input.language === 'python') return ['python3', '-c', input.code];
    if (input.language === 'javascript') return ['node', '-e', input.code];
    return ['bash', '-c', input.code];
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

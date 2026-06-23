/**
 * AgentZT AIOsandbox 集成层
 * 基于 https://sandbox.agent-infra.com 的 All-in-One Agent Sandbox Environment
 *
 * 功能:
 * - Shell 执行 (bash/命令)
 * - 文件操作 (读写列出)
 * - 浏览器自动化 (截图、CDP)
 * - Jupyter 代码执行
 * - MCP 服务器
 */

import { makeLogger } from '../shared/log.ts';
import { newId } from '../shared/crypto.ts';

const log = makeLogger('aiosandbox');

// ============== AIOsandbox 客户端配置 ==============

export interface AIOsandboxConfig {
  baseUrl: string;              // AIOsandbox 服务地址 (默认 http://localhost:8080)
  containerId?: string;         // Docker 容器 ID (用于管理)
  autoStart?: boolean;          // 是否自动启动容器
  autoRemove?: boolean;         // 容器停止后自动删除
  startupTimeout?: number;      // 启动等待超时 (ms)
}

type ResolvedAIOsandboxConfig = Omit<Required<AIOsandboxConfig>, 'containerId'> & {
  containerId?: string;
};

export interface AIOsandboxStatus {
  healthy: boolean;
  version?: string;
  uptime?: number;
  containerId?: string;
}

// ============== API 响应类型 ==============

export interface APIResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
}

export interface ShellExecResult {
  output: string;
  exitCode: number;
}

export interface FileReadResult {
  content: string;
  size: number;
}

export interface BrowserInfo {
  cdp_url: string;
  viewport: { width: number; height: number };
  user_agent: string;
}

export interface BrowserScreenshot {
  screenshot: string;  // base64 encoded
}

export interface JupyterExecuteResult {
  output: string;
  logs: string[];
}

// ============== AIOsandbox 客户端 ==============

export class AIOsandboxClient {
  readonly id: string;
  private config: ResolvedAIOsandboxConfig;
  private containerId?: string;

  constructor(config: AIOsandboxConfig) {
    this.id = newId('aiosb');
    this.config = {
      baseUrl: config.baseUrl || 'http://localhost:8080',
      containerId: config.containerId,
      autoStart: config.autoStart ?? false,
      autoRemove: config.autoRemove ?? true,
      startupTimeout: config.startupTimeout ?? 60000,
    };
  }

  // ============== 生命周期管理 ==============

  /**
   * 检查服务是否可用
   */
  async ping(): Promise<boolean> {
    try {
      const res = await fetch(`${this.config.baseUrl}/healthz`, {
        method: 'GET',
        signal: AbortSignal.timeout(5000),
      });
      return res.ok;
    } catch {
      return false;
    }
  }

  /**
   * 获取服务状态
   */
  async getStatus(): Promise<AIOsandboxStatus> {
    try {
      const res = await fetch(`${this.config.baseUrl}/v1/status`, {
        method: 'GET',
        signal: AbortSignal.timeout(5000),
      });
      if (res.ok) {
        const data = await res.json() as Record<string, unknown>;
        return {
          healthy: true,
          version: data['version'] as string,
          uptime: data['uptime'] as number,
        };
      }
    } catch {
      // Ignore
    }
    return { healthy: false };
  }

  /**
   * 启动 AIOsandbox Docker 容器
   * 仅在 autoStart=true 且容器未运行时调用
   */
  async startContainer(image?: string): Promise<void> {
    if (!this.config.autoStart) {
      log.warn(`AIOsandbox autoStart is disabled, skipping container start`);
      return;
    }

    // 检查是否已运行
    if (await this.ping()) {
      log.info(`AIOsandbox already running at ${this.config.baseUrl}`);
      return;
    }

    const dockerImage = image || 'ghcr.io/agent-infra/sandbox:latest';
    log.info(`Starting AIOsandbox container: ${dockerImage}`);

    try {
      // 使用 Docker API 启动容器
      const createRes = await fetch('unix:///var/run/docker.sock/v1.41/containers/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          Image: dockerImage,
          Env: ['SECCOMP=unconfined'],
          HostConfig: {
            PortBindings: {
              '8080/tcp': [{ HostPort: '8080' }],
            },
            AutoRemove: this.config.autoRemove,
            SecurityOpt: ['seccomp=unconfined'],
          },
          ExposedPorts: { '8080/tcp': {} },
        }),
      });

      if (!createRes.ok) {
        const errText = await createRes.text();
        throw new Error(`Docker create failed: ${createRes.status} ${errText}`);
      }

      const container = await createRes.json() as { Id: string };
      this.containerId = container.Id;

      // 启动容器
      const startRes = await fetch(
        `unix:///var/run/docker.sock/v1.41/containers/${container.Id}/start`,
        { method: 'POST' }
      );

      if (!startRes.ok && startRes.status !== 304) { // 304 = already started
        throw new Error(`Docker start failed: ${startRes.status}`);
      }

      // 等待服务就绪
      const startedAt = Date.now();
      while (Date.now() - startedAt < this.config.startupTimeout) {
        if (await this.ping()) {
          log.info(`AIOsandbox container started: ${container.Id}`);
          return;
        }
        await new Promise(resolve => setTimeout(resolve, 1000));
      }

      throw new Error(`AIOsandbox failed to start within ${this.config.startupTimeout}ms`);
    } catch (err) {
      log.error(`Failed to start AIOsandbox: ${(err as Error).message}`);
      throw err;
    }
  }

  /**
   * 停止 AIOsandbox 容器
   */
  async stopContainer(): Promise<void> {
    if (!this.containerId && !this.config.containerId) {
      return;
    }

    const containerId = this.containerId || this.config.containerId;
    if (!containerId) return;

    try {
      await fetch(`unix:///var/run/docker.sock/v1.41/containers/${containerId}/stop`, {
        method: 'POST',
        signal: AbortSignal.timeout(30000),
      });
      log.info(`AIOsandbox container stopped: ${containerId}`);
    } catch (err) {
      log.warn(`Failed to stop container: ${(err as Error).message}`);
    }
  }

  /**
   * 初始化客户端 - 确保服务可用
   */
  async initialize(): Promise<void> {
    await this.startContainer();

    if (!await this.ping()) {
      throw new Error(`AIOsandbox is not available at ${this.config.baseUrl}`);
    }

    log.info(`AIOsandbox client ${this.id} initialized`);
  }

  /**
   * 销毁客户端 - 清理资源
   */
  async destroy(): Promise<void> {
    if (this.config.autoRemove) {
      await this.stopContainer();
    }
    log.info(`AIOsandbox client ${this.id} destroyed`);
  }

  // ============== Shell API ==============

  /**
   * 执行 Shell 命令
   */
  async shellExec(command: string, cwd?: string): Promise<APIResponse<ShellExecResult>> {
    try {
      const body: Record<string, string> = { command };
      if (cwd) body['cwd'] = cwd;

      const res = await fetch(`${this.config.baseUrl}/shell/exec`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(60000),
      });

      const data = await res.json() as Record<string, unknown>;

      if (res.ok) {
        return {
          success: true,
          data: {
            output: (data['output'] as string) || '',
            exitCode: (data['exit_code'] as number) || 0,
          },
        };
      }

      return { success: false, error: data['error'] as string || 'Unknown error' };
    } catch (err) {
      return { success: false, error: (err as Error).message };
    }
  }

  // ============== File API ==============

  /**
   * 读取文件
   */
  async fileRead(file: string): Promise<APIResponse<FileReadResult>> {
    try {
      const res = await fetch(`${this.config.baseUrl}/file/read?file=${encodeURIComponent(file)}`, {
        method: 'GET',
        signal: AbortSignal.timeout(30000),
      });

      const data = await res.json() as Record<string, unknown>;

      if (res.ok) {
        return {
          success: true,
          data: {
            content: (data['content'] as string) || '',
            size: (data['size'] as number) || 0,
          },
        };
      }

      return { success: false, error: data['error'] as string || 'Unknown error' };
    } catch (err) {
      return { success: false, error: (err as Error).message };
    }
  }

  /**
   * 写入文件
   */
  async fileWrite(file: string, content: string): Promise<APIResponse<{ path: string }>> {
    try {
      const res = await fetch(`${this.config.baseUrl}/file/write`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ file, content }),
        signal: AbortSignal.timeout(30000),
      });

      const data = await res.json() as Record<string, unknown>;

      if (res.ok) {
        return { success: true, data: { path: data['path'] as string || file } };
      }

      return { success: false, error: data['error'] as string || 'Unknown error' };
    } catch (err) {
      return { success: false, error: (err as Error).message };
    }
  }

  /**
   * 列出目录
   */
  async fileList(path: string): Promise<APIResponse<{ entries: Array<{ name: string; isDir: boolean; size: number }> }>> {
    try {
      const res = await fetch(`${this.config.baseUrl}/file/list?path=${encodeURIComponent(path)}`, {
        method: 'GET',
        signal: AbortSignal.timeout(30000),
      });

      const data = await res.json() as Record<string, unknown>;

      if (res.ok) {
        return {
          success: true,
          data: {
            entries: (data['entries'] as Array<{ name: string; is_dir: boolean; size: number }>)?.map(e => ({
              name: e.name,
              isDir: e.is_dir,
              size: e.size,
            })) || [],
          },
        };
      }

      return { success: false, error: data['error'] as string || 'Unknown error' };
    } catch (err) {
      return { success: false, error: (err as Error).message };
    }
  }

  /**
   * 创建目录
   */
  async fileMkdir(path: string): Promise<APIResponse<{ path: string }>> {
    try {
      const res = await fetch(`${this.config.baseUrl}/file/mkdir`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path }),
        signal: AbortSignal.timeout(10000),
      });

      const data = await res.json() as Record<string, unknown>;

      if (res.ok) {
        return { success: true, data: { path: data['path'] as string || path } };
      }

      return { success: false, error: data['error'] as string || 'Unknown error' };
    } catch (err) {
      return { success: false, error: (err as Error).message };
    }
  }

  // ============== Browser API ==============

  /**
   * 获取浏览器信息 (CDP URL)
   */
  async browserGetInfo(): Promise<APIResponse<BrowserInfo>> {
    try {
      const res = await fetch(`${this.config.baseUrl}/browser/info`, {
        method: 'GET',
        signal: AbortSignal.timeout(10000),
      });

      const data = await res.json() as Record<string, unknown>;

      if (res.ok) {
        return {
          success: true,
          data: {
            cdp_url: data['cdp_url'] as string,
            viewport: data['viewport'] as { width: number; height: number },
            user_agent: data['user_agent'] as string || '',
          },
        };
      }

      return { success: false, error: data['error'] as string || 'Unknown error' };
    } catch (err) {
      return { success: false, error: (err as Error).message };
    }
  }

  /**
   * 截图
   */
  async browserScreenshot(): Promise<APIResponse<BrowserScreenshot>> {
    try {
      const res = await fetch(`${this.config.baseUrl}/browser/screenshot`, {
        method: 'GET',
        signal: AbortSignal.timeout(30000),
      });

      const data = await res.json() as Record<string, unknown>;

      if (res.ok) {
        return {
          success: true,
          data: {
            screenshot: data['screenshot'] as string,
          },
        };
      }

      return { success: false, error: data['error'] as string || 'Unknown error' };
    } catch (err) {
      return { success: false, error: (err as Error).message };
    }
  }

  /**
   * 执行浏览器操作
   */
  async browserAction(action: Record<string, unknown>): Promise<APIResponse> {
    try {
      const res = await fetch(`${this.config.baseUrl}/browser/actions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(action),
        signal: AbortSignal.timeout(30000),
      });

      const data = await res.json() as Record<string, unknown>;

      if (res.ok) {
        return { success: true, data };
      }

      return { success: false, error: data['error'] as string || 'Unknown error' };
    } catch (err) {
      return { success: false, error: (err as Error).message };
    }
  }

  /**
   * 导航到 URL
   */
  async browserNavigate(url: string): Promise<APIResponse> {
    return this.browserAction({ action_type: 'navigate', url });
  }

  // ============== Jupyter API ==============

  /**
   * 执行 Jupyter 代码
   */
  async jupyterExecute(code: string): Promise<APIResponse<JupyterExecuteResult>> {
    try {
      const res = await fetch(`${this.config.baseUrl}/jupyter/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
        signal: AbortSignal.timeout(60000),
      });

      const data = await res.json() as Record<string, unknown>;

      if (res.ok) {
        return {
          success: true,
          data: {
            output: (data['output'] as string) || '',
            logs: (data['logs'] as string[]) || [],
          },
        };
      }

      return { success: false, error: data['error'] as string || 'Unknown error' };
    } catch (err) {
      return { success: false, error: (err as Error).message };
    }
  }

  // ============== MCP API ==============

  /**
   * 获取 MCP 服务器信息
   */
  async mcpList(): Promise<APIResponse<{ servers: Array<{ name: string; status: string }> }>> {
    try {
      const res = await fetch(`${this.config.baseUrl}/mcp`, {
        method: 'GET',
        signal: AbortSignal.timeout(10000),
      });

      if (res.ok) {
        return { success: true, data: { servers: [] } }; // MCP 端点返回 SSE/流
      }

      return { success: true, data: { servers: [] } }; // 降级
    } catch (err) {
      return { success: false, error: (err as Error).message };
    }
  }

  // ============== 上下文信息 ==============

  /**
   * 获取沙盒上下文 (主目录等)
   */
  async getContext(): Promise<APIResponse<{ home_dir: string; workspace: string }>> {
    // AIOsandbox 不直接提供此 API，通过 shell 获取
    const res = await this.shellExec('echo $HOME');
    if (res.success && res.data) {
      const homeDir = res.data.output.trim();
      return {
        success: true,
        data: { home_dir: homeDir, workspace: homeDir },
      };
    }
    return { success: false, error: 'Failed to get context' };
  }
}

// ============== AIOsandbox 管理器 ==============

export class AIOsandboxManager {
  private clients: Map<string, AIOsandboxClient> = new Map();
  private defaultClient?: AIOsandboxClient;

  /**
   * 创建并初始化一个 AIOsandbox 客户端
   */
  async createClient(config?: Partial<AIOsandboxConfig>): Promise<AIOsandboxClient> {
    const client = new AIOsandboxClient({
      baseUrl: config?.baseUrl || 'http://localhost:8080',
      autoStart: config?.autoStart ?? false,
    });

    await client.initialize();
    this.clients.set(client.id, client);

    if (!this.defaultClient) {
      this.defaultClient = client;
    }

    return client;
  }

  /**
   * 获取默认客户端
   */
  getDefault(): AIOsandboxClient | undefined {
    return this.defaultClient;
  }

  /**
   * 获取客户端
   */
  getClient(id: string): AIOsandboxClient | undefined {
    return this.clients.get(id);
  }

  /**
   * 销毁客户端
   */
  async destroy(id: string): Promise<void> {
    const client = this.clients.get(id);
    if (client) {
      await client.destroy();
      this.clients.delete(id);
    }
  }

  /**
   * 销毁所有客户端
   */
  async destroyAll(): Promise<void> {
    await Promise.all([...this.clients.keys()].map(id => this.destroy(id)));
  }

  /**
   * 检查是否有可用的沙盒
   */
  async isAvailable(): Promise<boolean> {
    if (this.defaultClient) {
      return this.defaultClient.ping();
    }

    // 尝试检测默认地址
    try {
      const res = await fetch('http://localhost:8080/healthz', {
        method: 'GET',
        signal: AbortSignal.timeout(3000),
      });
      return res.ok;
    } catch {
      return false;
    }
  }
}

// 导出单例
export const aiosandboxManager = new AIOsandboxManager();

// ============== 便捷函数 ==============

/**
 * 执行单条 shell 命令的便捷函数
 */
export async function execInSandbox(command: string, baseUrl = 'http://localhost:8080'): Promise<ShellExecResult> {
  const client = new AIOsandboxClient({ baseUrl });
  const result = await client.shellExec(command);
  await client.destroy();
  if (!result.success) {
    return { output: '', exitCode: 1 };
  }
  return result.data!;
}

/**
 * 读取沙盒文件的便捷函数
 */
export async function readSandboxFile(file: string, baseUrl = 'http://localhost:8080'): Promise<string> {
  const client = new AIOsandboxClient({ baseUrl });
  const result = await client.fileRead(file);
  await client.destroy();
  if (!result.success) {
    throw new Error(result.error || 'Failed to read file');
  }
  return result.data!.content;
}

/**
 * 写入沙盒文件的便捷函数
 */
export async function writeSandboxFile(file: string, content: string, baseUrl = 'http://localhost:8080'): Promise<void> {
  const client = new AIOsandboxClient({ baseUrl });
  const result = await client.fileWrite(file, content);
  await client.destroy();
  if (!result.success) {
    throw new Error(result.error || 'Failed to write file');
  }
}

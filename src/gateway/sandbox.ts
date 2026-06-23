/**
 * AgentZT 沙盒集成层
 * 基于你的 OpenSandbox/AIOsandbox 经验设计
 */

import { makeLogger } from '../shared/log.ts';
import { newId } from '../shared/crypto.ts';

const log = makeLogger('sandbox');

// ============== 沙盒类型定义 ==============

export type SandboxType = 'web' | 'code' | 'file' | 'process';

export interface SandboxConfig {
  timeout: number;           // 超时时间 (ms)
  memoryLimit: number;       // 内存限制 (MB)
  networkAccess: boolean;    // 网络访问
  filesystemAccess: string[]; // 允许的文件路径
  env: Record<string, string>;
}

export interface SandboxResult {
  success: boolean;
  output?: string;
  error?: string;
  metrics: {
    executionTime: number;
    memoryUsed: number;
    networkRequests: number;
  };
  artifacts?: Array<{
    name: string;
    type: string;
    path: string;
  }>;
}

// ============== 沙盒接口 ==============

export interface Sandbox {
  readonly type: SandboxType;
  readonly id: string;
  initialize(): Promise<void>;
  execute(input: string, config: SandboxConfig): Promise<SandboxResult>;
  destroy(): Promise<void>;
}

// ============== Web 沙盒 (基于 Puppeteer/Chromium) ==============

export interface WebSandboxConfig extends SandboxConfig {
  viewport?: { width: number; height: number };
  userAgent?: string;
  blockAds?: boolean;
}

export class WebSandbox implements Sandbox {
  readonly type: SandboxType = 'web';
  readonly id: string;

  private browser?: unknown; // Puppeteer Browser
  private page?: unknown;    // Puppeteer Page

  constructor(private config: WebSandboxConfig) {
    this.id = newId('web');
  }

  async initialize(): Promise<void> {
    // 动态导入 Puppeteer (可选依赖)
    try {
      // @ts-expect-error Optional dependency; runtime falls back to mock mode when absent.
      const puppeteer = await import('puppeteer');
      this.browser = await puppeteer.default.launch({
        headless: true,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-gpu',
          '--single-process',
        ],
      });
      log.info(`Web sandbox ${this.id} initialized`);
    } catch (err) {
      log.warn(`Puppeteer not available, using mock mode: ${(err as Error).message}`);
    }
  }

  async execute(url: string, config: SandboxConfig): Promise<SandboxResult> {
    const start = Date.now();

    if (!this.browser) {
      // Mock 模式 - 用于测试
      return {
        success: true,
        output: `Mock fetch: ${url}`,
        metrics: {
          executionTime: Date.now() - start,
          memoryUsed: 0,
          networkRequests: 1,
        },
      };
    }

    try {
      const page = await (this.browser as { newPage(): Promise<unknown> }).newPage();
      await (page as { setViewport(_: { width: number; height: number }): Promise<void> }).setViewport(
        this.config.viewport || { width: 1280, height: 720 }
      );

      await (page as { goto(url: string, opts: { timeout: number }): Promise<unknown> }).goto(url, {
        timeout: config.timeout,
      });

      const content = await (page as { content(): Promise<string> }).content();

      await (page as { close(): Promise<void> }).close();

      return {
        success: true,
        output: content,
        metrics: {
          executionTime: Date.now() - start,
          memoryUsed: 0,
          networkRequests: 1,
        },
      };
    } catch (err) {
      return {
        success: false,
        error: (err as Error).message,
        metrics: {
          executionTime: Date.now() - start,
          memoryUsed: 0,
          networkRequests: 0,
        },
      };
    }
  }

  async destroy(): Promise<void> {
    if (this.browser) {
      await (this.browser as { close(): Promise<void> }).close();
    }
    log.info(`Web sandbox ${this.id} destroyed`);
  }
}

// ============== 代码执行沙盒 (基于 Docker/Isolate) ==============

export interface CodeSandboxConfig extends SandboxConfig {
  language: 'python' | 'javascript' | 'bash';
  packages?: string[]; // 预安装的包
  networkAccess: false; // 代码沙盒禁用网络
}

export class CodeSandbox implements Sandbox {
  readonly type: SandboxType = 'code';
  readonly id: string;

  private containerId?: string;
  private dockerAvailable: boolean = false;

  constructor(private config: CodeSandboxConfig) {
    this.id = newId('code');
  }

  async initialize(): Promise<void> {
    // 检测 Docker 是否可用
    try {
      const result = await fetch('unix:///var/run/docker.sock/v1.41/info', {
        method: 'GET',
      }).catch(() => null);

      if (result?.ok) {
        this.dockerAvailable = true;
        log.info(`Code sandbox ${this.id} initialized with Docker`);
      } else {
        log.warn(`Docker not available, using native execution mode`);
      }
    } catch {
      log.warn(`Docker check failed, using mock mode`);
    }
  }

  async execute(code: string, config: SandboxConfig): Promise<SandboxResult> {
    const start = Date.now();

    if (!this.dockerAvailable) {
      // Native 执行模式 (安全限制内)
      return this.nativeExecute(code, config);
    }

    return this.dockerExecute(code, config, start);
  }

  private async nativeExecute(code: string, config: SandboxConfig): Promise<SandboxResult> {
    const start = Date.now();

    // 简单的代码执行器 - 实际生产应该用 Isolate 或 Docker
    try {
      let output = '';

      if (this.config.language === 'javascript') {
        // 使用 vm 模块创建隔离的 JS 执行环境
        const vm = await import('node:vm');
        const context = vm.createContext({
          console: {
            log: (...args: unknown[]) => { output += args.join(' ') + '\n'; },
          },
          setTimeout: undefined,
          setInterval: undefined,
          fetch: undefined,
        });

        vm.runInContext(code, context, { timeout: config.timeout });
      } else if (this.config.language === 'python') {
        // Python 需要外部解释器，这里返回错误
        return {
          success: false,
          error: 'Python execution requires Docker/Isolate',
          metrics: { executionTime: Date.now() - start, memoryUsed: 0, networkRequests: 0 },
        };
      }

      return {
        success: true,
        output,
        metrics: {
          executionTime: Date.now() - start,
          memoryUsed: 0,
          networkRequests: 0,
        },
      };
    } catch (err) {
      return {
        success: false,
        error: (err as Error).message,
        metrics: { executionTime: Date.now() - start, memoryUsed: 0, networkRequests: 0 },
      };
    }
  }

  private async dockerExecute(
    code: string,
    config: SandboxConfig,
    start: number
  ): Promise<SandboxResult> {
    const imageMap: Record<string, string> = {
      python: 'python:3.11-slim',
      javascript: 'node:22-alpine',
      bash: 'bash:5.2',
    };

    try {
      // 创建临时容器
      const createRes = await fetch('unix:///var/run/docker.sock/v1.41/containers/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          Image: imageMap[this.config.language],
          Cmd: ['sh', '-c', code],
          Memory: config.memoryLimit * 1024 * 1024,
          NetworkDisabled: !config.networkAccess,
          AutoRemove: true,
        }),
      });

      if (!createRes.ok) {
        throw new Error(`Docker create failed: ${createRes.status}`);
      }

      const container = await createRes.json() as { Id: string };
      this.containerId = container.Id;

      // 启动并等待完成
      await fetch(`unix:///var/run/docker.sock/v1.41/containers/${container.Id}/start`, {
        method: 'POST',
      });

      // 等待执行完成 (简化版，实际应该用 wait)
      await new Promise(resolve => setTimeout(resolve, 100));

      // 获取日志
      const logsRes = await fetch(
        `unix:///var/run/docker.sock/v1.41/containers/${container.Id}/logs?stdout=true`
      );

      const logs = await logsRes.text();

      return {
        success: true,
        output: logs,
        metrics: {
          executionTime: Date.now() - start,
          memoryUsed: config.memoryLimit,
          networkRequests: config.networkAccess ? 1 : 0,
        },
      };
    } catch (err) {
      return {
        success: false,
        error: (err as Error).message,
        metrics: { executionTime: Date.now() - start, memoryUsed: 0, networkRequests: 0 },
      };
    }
  }

  async destroy(): Promise<void> {
    if (this.containerId) {
      try {
        await fetch(`unix:///var/run/docker.sock/v1.41/containers/${this.containerId}`, {
          method: 'DELETE',
        });
      } catch {
        // Ignore cleanup errors
      }
    }
    log.info(`Code sandbox ${this.id} destroyed`);
  }
}

// ============== 文件系统沙盒 ==============

export class FileSandbox implements Sandbox {
  readonly type: SandboxType = 'file';
  readonly id: string;

  private allowedPaths: Set<string>;

  constructor(private config: SandboxConfig) {
    this.id = newId('file');
    this.allowedPaths = new Set(config.filesystemAccess || []);
  }

  async initialize(): Promise<void> {
    log.info(`File sandbox ${this.id} initialized with paths: ${[...this.allowedPaths].join(', ')}`);
  }

  async execute(
    operation: string,
    args: SandboxConfig | { path: string; content?: string }
  ): Promise<SandboxResult> {
    const start = Date.now();
    if (!('path' in args)) {
      return {
        success: false,
        error: 'File sandbox requires a path',
        metrics: { executionTime: Date.now() - start, memoryUsed: 0, networkRequests: 0 },
      };
    }

    // 路径安全检查
    if (!this.isPathAllowed(args.path)) {
      return {
        success: false,
        error: `Access denied: path "${args.path}" is not in allowed list`,
        metrics: { executionTime: Date.now() - start, memoryUsed: 0, networkRequests: 0 },
      };
    }

    try {
      const fs = await import('node:fs/promises');

      switch (operation) {
        case 'read': {
          const content = await fs.readFile(args.path, 'utf-8');
          return {
            success: true,
            output: content,
            metrics: { executionTime: Date.now() - start, memoryUsed: 0, networkRequests: 0 },
          };
        }
        case 'write': {
          await fs.writeFile(args.path, args.content || '');
          return {
            success: true,
            output: `Written to ${args.path}`,
            metrics: { executionTime: Date.now() - start, memoryUsed: 0, networkRequests: 0 },
          };
        }
        case 'list': {
          const entries = await fs.readdir(args.path, { withFileTypes: true });
          const result = entries.map(e => `${e.isDirectory() ? 'd' : '-'} ${e.name}`).join('\n');
          return {
            success: true,
            output: result,
            metrics: { executionTime: Date.now() - start, memoryUsed: 0, networkRequests: 0 },
          };
        }
        default:
          return {
            success: false,
            error: `Unknown operation: ${operation}`,
            metrics: { executionTime: Date.now() - start, memoryUsed: 0, networkRequests: 0 },
          };
      }
    } catch (err) {
      return {
        success: false,
        error: (err as Error).message,
        metrics: { executionTime: Date.now() - start, memoryUsed: 0, networkRequests: 0 },
      };
    }
  }

  private isPathAllowed(path: string): boolean {
    for (const allowed of this.allowedPaths) {
      if (path.startsWith(allowed)) return true;
    }
    return false;
  }

  async destroy(): Promise<void> {
    log.info(`File sandbox ${this.id} destroyed`);
  }
}

// ============== 沙盒管理器 ==============

export class SandboxManager {
  private sandboxes: Map<string, Sandbox> = new Map();

  async createWebSandbox(config?: Partial<WebSandboxConfig>): Promise<WebSandbox> {
    const sandbox = new WebSandbox({
      timeout: config?.timeout || 30000,
      memoryLimit: config?.memoryLimit || 512,
      networkAccess: config?.networkAccess ?? true,
      filesystemAccess: [],
      env: {},
      viewport: config?.viewport,
    } as WebSandboxConfig);
    await sandbox.initialize();
    this.sandboxes.set(sandbox.id, sandbox);
    return sandbox;
  }

  async createCodeSandbox(config: { language: 'python' | 'javascript' | 'bash' }): Promise<CodeSandbox> {
    const sandbox = new CodeSandbox({
      timeout: config?.language === 'python' ? 60000 : 30000,
      memoryLimit: 256,
      networkAccess: false,
      filesystemAccess: [],
      env: {},
      language: config.language,
    });
    await sandbox.initialize();
    this.sandboxes.set(sandbox.id, sandbox);
    return sandbox;
  }

  async createFileSandbox(allowedPaths: string[]): Promise<FileSandbox> {
    const sandbox = new FileSandbox({
      timeout: 10000,
      memoryLimit: 128,
      networkAccess: false,
      filesystemAccess: allowedPaths,
      env: {},
    });
    await sandbox.initialize();
    this.sandboxes.set(sandbox.id, sandbox);
    return sandbox;
  }

  async destroy(id: string): Promise<void> {
    const sandbox = this.sandboxes.get(id);
    if (sandbox) {
      await sandbox.destroy();
      this.sandboxes.delete(id);
    }
  }

  async destroyAll(): Promise<void> {
    await Promise.all([...this.sandboxes.keys()].map(id => this.destroy(id)));
  }
}

// 导出单例
export const sandboxManager = new SandboxManager();

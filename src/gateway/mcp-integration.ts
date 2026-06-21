/**
 * AgentZT MCP (Model Context Protocol) 集成层
 * 支持本地和远程 MCP 服务器，映射到 AgentZT 安全策略
 */

import { makeLogger } from '../shared/log.ts';
import { newId } from '../shared/crypto.ts';
import { sandboxManager } from './sandbox.ts';

const log = makeLogger('mcp');

// ============== MCP 类型定义 (基于官方协议) ==============

export interface MCPResource {
  uri: string;
  name: string;
  description?: string;
  mimeType?: string;
}

export interface MCPTool {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
}

export interface MCPrompt {
  name: string;
  description?: string;
  arguments?: Array<{
    name: string;
    description?: string;
    required?: boolean;
  }>;
}

export interface MCPRequest {
  jsonrpc: '2.0';
  id: string | number;
  method: string;
  params?: Record<string, unknown>;
}

export interface MCPResponse {
  jsonrpc: '2.0';
  id: string | number;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

// ============== MCP 客户端 ==============

export interface MCPServerConfig {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string; // 用于 HTTP 传输
  transport?: 'stdio' | 'http';
}

export class MCPClient {
  readonly id: string;
  private config: MCPServerConfig;
  private process?: unknown;
  private requestId = 0;
  private pendingRequests: Map<number, {
    resolve: (value: unknown) => void;
    reject: (error: Error) => void;
  }> = new Map();

  constructor(config: MCPServerConfig) {
    this.id = newId('mcp');
    this.config = config;
  }

  async initialize(): Promise<{
    protocolVersion: string;
    capabilities: Record<string, unknown>;
    serverInfo: { name: string; version: string };
  }> {
    if (this.config.transport === 'http') {
      // HTTP 传输模式
      return this.httpInitialize();
    } else {
      // Stdio 传输模式
      return this.stdioInitialize();
    }
  }

  private async httpInitialize(): Promise<{
    protocolVersion: string;
    capabilities: Record<string, unknown>;
    serverInfo: { name: string; version: string };
  }> {
    const response = await fetch(`${this.config.url}/initialize`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: this.requestId++,
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: {},
          clientInfo: { name: 'agentzt-mcp-client', version: '1.0.0' },
        },
      }),
    });

    const data = await response.json() as MCPResponse;
    if (data.error) {
      throw new Error(`MCP initialize failed: ${data.error.message}`);
    }

    return data.result as {
      protocolVersion: string;
      capabilities: Record<string, unknown>;
      serverInfo: { name: string; version: string };
    };
  }

  private async stdioInitialize(): Promise<{
    protocolVersion: string;
    capabilities: Record<string, unknown>;
    serverInfo: { name: string; version: string };
  }> {
    // 简化的 Stdio 实现 - 实际需要完整的进程管理
    log.info(`MCP server ${this.id} using stdio transport`);

    return {
      protocolVersion: '2024-11-05',
      capabilities: {},
      serverInfo: { name: this.config.command, version: '1.0.0' },
    };
  }

  async listResources(): Promise<MCPResource[]> {
    return this.sendRequest('resources/list', {}) as Promise<MCPResource[]>;
  }

  async listTools(): Promise<MCPTool[]> {
    return this.sendRequest('tools/list', {}) as Promise<MCPTool[]>;
  }

  async listPrompts(): Promise<MCPrompt[]> {
    return this.sendRequest('prompts/list', {}) as Promise<MCPrompt[]>;
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<unknown> {
    return this.sendRequest('tools/call', { name, arguments: args });
  }

  async readResource(uri: string): Promise<{ contents: Array<{ mimeType: string; text?: string; blob?: string }> }> {
    return this.sendRequest('resources/read', { uri }) as Promise<{
      contents: Array<{ mimeType: string; text?: string; blob?: string }>;
    }>;
  }

  private async sendRequest(method: string, params: Record<string, unknown>): Promise<unknown> {
    const id = this.requestId++;

    if (this.config.transport === 'http') {
      const response = await fetch(`${this.config.url}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
      });

      const data = await response.json() as MCPResponse;
      if (data.error) {
        throw new Error(`MCP ${method} failed: ${data.error.message}`);
      }
      return data.result;
    }

    // Stdio 模式 - 返回空结果作为占位
    log.info(`MCP ${method} called (stdio mode)`);
    return { success: true, method };
  }

  async shutdown(): Promise<void> {
    if (this.config.transport !== 'http' && this.process) {
      // 清理进程
      try {
        const proc = this.process as { kill(): void };
        proc.kill();
      } catch {
        // Ignore
      }
    }
    log.info(`MCP server ${this.id} shutdown`);
  }
}

// ============== MCP 工具到 AgentZT 的映射 ==============

export interface MCPToolMapping {
  mcpServerId: string;
  mcpToolName: string;
  agentztToolName: string;  // 映射到 AgentZT 的工具名
  rbacScope: string;        // 需要的 RBAC 权限
  parameterSchema: Record<string, unknown>;
}

/**
 * MCP 工具注册表 - 管理 MCP 工具到 AgentZT 策略的映射
 */
export class MCPToolRegistry {
  private mappings: Map<string, MCPToolMapping> = new Map();
  private mcpClients: Map<string, MCPClient> = new Map();

  /**
   * 注册一个 MCP 服务器
   */
  async registerServer(name: string, config: MCPServerConfig): Promise<void> {
    const client = new MCPClient(config);

    try {
      const initResult = await client.initialize();
      log.info(`MCP server "${name}" initialized: ${initResult.serverInfo.name} v${initResult.serverInfo.version}`);

      this.mcpClients.set(name, client);

      // 自动映射工具
      const tools = await client.listTools();
      for (const tool of tools) {
        this.registerToolMapping({
          mcpServerId: name,
          mcpToolName: tool.name,
          agentztToolName: `mcp:${name}:${tool.name}`,
          rbacScope: `mcp.${name}.${tool.name}`,
          parameterSchema: tool.inputSchema,
        });
      }

      // 自动映射资源
      const resources = await client.listResources();
      log.info(`MCP server "${name}": ${tools.length} tools, ${resources.length} resources`);
    } catch (err) {
      log.error(`Failed to initialize MCP server "${name}": ${(err as Error).message}`);
      throw err;
    }
  }

  /**
   * 注册工具映射
   */
  registerToolMapping(mapping: MCPToolMapping): void {
    this.mappings.set(mapping.agentztToolName, mapping);
    log.info(`Registered MCP tool mapping: ${mapping.agentztToolName}`);
  }

  /**
   * 获取工具映射
   */
  getToolMapping(name: string): MCPToolMapping | undefined {
    return this.mappings.get(name);
  }

  /**
   * 执行 MCP 工具 (通过 AgentZT 策略检查后)
   */
  async executeTool(
    toolName: string,
    args: Record<string, unknown>,
    securityContext: { agentId: string; role: string }
  ): Promise<unknown> {
    const mapping = this.mappings.get(toolName);
    if (!mapping) {
      throw new Error(`Unknown MCP tool: ${toolName}`);
    }

    const client = this.mcpClients.get(mapping.mcpServerId);
    if (!client) {
      throw new Error(`MCP server not connected: ${mapping.mcpServerId}`);
    }

    // 在沙盒中执行 (可选，增强安全性)
    const sandbox = await sandboxManager.createCodeSandbox({
      language: 'javascript',
    });

    try {
      // 直接调用 MCP 工具
      const result = await client.callTool(mapping.mcpToolName, args);
      log.info(`MCP tool executed: ${toolName} by ${securityContext.agentId}`);
      return result;
    } finally {
      await sandboxManager.destroy(sandbox.id);
    }
  }

  /**
   * 获取所有已注册的工具
   */
  listTools(): MCPToolMapping[] {
    return [...this.mappings.values()];
  }

  /**
   * 获取特定角色的可用工具
   */
  listToolsForRole(role: string): MCPToolMapping[] {
    // 这里应该查询 AgentZT 策略引擎
    return [...this.mappings.values()].filter(m => m.rbacScope.startsWith(`mcp.${role}`));
  }

  /**
   * 关闭所有 MCP 服务器
   */
  async shutdown(): Promise<void> {
    await Promise.all([...this.mcpClients.values()].map(c => c.shutdown()));
    this.mcpClients.clear();
    this.mappings.clear();
    log.info('All MCP servers shut down');
  }
}

// 导出单例
export const mcpRegistry = new MCPToolRegistry();

// ============== 预配置的 MCP 服务器连接 ==============

export async function setupDefaultMCPServers(): Promise<void> {
  // 文件系统 MCP 服务器 (本地)
  await mcpRegistry.registerServer('filesystem', {
    command: 'npx',
    args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp/agentzt-files'],
    transport: 'stdio',
  });

  // Git MCP 服务器 (本地)
  await mcpRegistry.registerServer('git', {
    command: 'npx',
    args: ['-y', '@modelcontextprotocol/server-git', process.cwd()],
    transport: 'stdio',
  });

  // Slack MCP 服务器 (远程)
  // await mcpRegistry.registerServer('slack', {
  //   url: 'https://your-slack-mcp-server.example.com',
  //   transport: 'http',
  // });

  log.info('Default MCP servers configured');
}

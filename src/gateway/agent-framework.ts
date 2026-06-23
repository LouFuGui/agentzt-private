/**
 * AgentZT 智能体框架
 * 基于 AgentZT 安全策略的自主执行智能体
 */

import { makeLogger } from '../shared/log.ts';
import { newId } from '../shared/crypto.ts';
import { llmGateway, type LLMRequest } from './llm-gateway.ts';
import { mcpRegistry } from './mcp-integration.ts';
import { sandboxManager } from './sandbox.ts';

const log = makeLogger('agent');

// ============== 智能体类型定义 ==============

export interface AgentConfig {
  agentId: string;
  role: string;
  llmProvider?: 'deepseek' | 'anthropic';
  maxIterations?: number;
  systemPrompt?: string;
}

export interface AgentTask {
  id: string;
  description: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  result?: unknown;
  error?: string;
  iterations: number;
  steps: AgentStep[];
}

export interface AgentStep {
  stepNumber: number;
  action: string;
  tool?: string;
  input: Record<string, unknown>;
  output?: unknown;
  timestamp: number;
}

export interface AgentMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
  toolCall?: {
    name: string;
    arguments: Record<string, unknown>;
  };
  toolResult?: unknown;
}

// ============== 工具执行器 ==============

export interface ToolDefinition {
  name: string;
  description: string;
  schema: Record<string, unknown>;
  execute: (args: Record<string, unknown>, context: AgentContext) => Promise<unknown>;
}

export interface AgentContext {
  agentId: string;
  role: string;
  taskId: string;
  requestId: string;
}

export class ToolExecutor {
  private tools: Map<string, ToolDefinition> = new Map();

  register(tool: ToolDefinition): void {
    this.tools.set(tool.name, tool);
    log.info(`Tool registered: ${tool.name}`);
  }

  async execute(
    toolName: string,
    args: Record<string, unknown>,
    context: AgentContext
  ): Promise<unknown> {
    const tool = this.tools.get(toolName);
    if (!tool) {
      throw new Error(`Unknown tool: ${toolName}`);
    }

    try {
      const result = await tool.execute(args, context);
      log.info(`Tool executed: ${toolName} by ${context.agentId}`);
      return result;
    } catch (err) {
      log.error(`Tool execution failed: ${toolName} - ${(err as Error).message}`);
      throw err;
    }
  }

  listTools(): ToolDefinition[] {
    return [...this.tools.values()];
  }

  getTool(name: string): ToolDefinition | undefined {
    return this.tools.get(name);
  }
}

// ============== 内置工具 ==============

export function createBuiltinTools(): ToolDefinition[] {
  return [
    // Web 搜索工具
    {
      name: 'web_search',
      description: 'Search the web for information',
      schema: {
        type: 'object',
        properties: {
          query: { type: 'string', description: 'Search query' },
          limit: { type: 'number', description: 'Maximum results', default: 5 },
        },
        required: ['query'],
      },
      execute: async (args, context) => {
        const webSandbox = await sandboxManager.createWebSandbox();
        try {
          const result = await webSandbox.execute(
            `https://www.google.com/search?q=${encodeURIComponent(args.query as string)}`,
            { timeout: 30000, memoryLimit: 512, networkAccess: true, filesystemAccess: [], env: {} }
          );
          return { results: result.output, success: result.success };
        } finally {
          await sandboxManager.destroy(webSandbox.id);
        }
      },
    },

    // 代码执行工具
    {
      name: 'code_execute',
      description: 'Execute code in a sandboxed environment',
      schema: {
        type: 'object',
        properties: {
          language: { type: 'string', enum: ['javascript', 'python', 'bash'] },
          code: { type: 'string', description: 'Code to execute' },
        },
        required: ['language', 'code'],
      },
      execute: async (args, context) => {
        const codeSandbox = await sandboxManager.createCodeSandbox({
          language: args.language as 'javascript' | 'python' | 'bash',
        });
        try {
          const result = await codeSandbox.execute(args.code as string, {
            timeout: 30000,
            memoryLimit: 256,
            networkAccess: false,
            filesystemAccess: [],
            env: {},
          });
          return result;
        } finally {
          await sandboxManager.destroy(codeSandbox.id);
        }
      },
    },

    // 文件操作工具
    {
      name: 'file_read',
      description: 'Read contents of a file',
      schema: {
        type: 'object',
        properties: {
          path: { type: 'string', description: 'File path to read' },
        },
        required: ['path'],
      },
      execute: async (args, context) => {
        const fileSandbox = await sandboxManager.createFileSandbox(['/tmp', '.']);
        try {
          if (typeof args.path !== 'string') {
            throw new Error('file_read requires a string path');
          }
          const result = await fileSandbox.execute('read', { path: args.path });
          return result;
        } finally {
          await sandboxManager.destroy(fileSandbox.id);
        }
      },
    },

    // MCP 工具代理
    {
      name: 'mcp_tool',
      description: 'Execute a tool from an MCP server',
      schema: {
        type: 'object',
        properties: {
          server: { type: 'string', description: 'MCP server name' },
          tool: { type: 'string', description: 'Tool name' },
          arguments: { type: 'object', description: 'Tool arguments' },
        },
        required: ['server', 'tool'],
      },
      execute: async (args, context) => {
        const toolName = `mcp:${args.server}:${args.tool}`;
        return mcpRegistry.executeTool(toolName, args.arguments as Record<string, unknown> || {}, {
          agentId: context.agentId,
          role: context.role,
        });
      },
    },
  ];
}

// ============== 智能体实现 ==============

export class Agent {
  readonly id: string;
  readonly role: string;

  private config: AgentConfig;
  private tools: ToolExecutor;
  private messages: AgentMessage[] = [];
  private currentTask?: AgentTask;

  constructor(config: AgentConfig) {
    this.id = config.agentId;
    this.role = config.role;
    this.config = {
      maxIterations: 10,
      ...config,
    };
    this.tools = new ToolExecutor();

    // 注册内置工具
    for (const tool of createBuiltinTools()) {
      this.tools.register(tool);
    }
  }

  /**
   * 注册额外工具
   */
  registerTool(tool: ToolDefinition): void {
    this.tools.register(tool);
  }

  /**
   * 注册 MCP 工具
   */
  async registerMCPTools(): Promise<void> {
    for (const mapping of mcpRegistry.listToolsForRole(this.role)) {
      this.tools.register({
        name: mapping.agentztToolName,
        description: `MCP tool: ${mapping.mcpToolName}`,
        schema: mapping.parameterSchema,
        execute: async (args, ctx) => {
          return mcpRegistry.executeTool(mapping.agentztToolName, args, {
            agentId: ctx.agentId,
            role: ctx.role,
          });
        },
      });
    }
  }

  /**
   * 执行任务
   */
  async runTask(description: string): Promise<AgentTask> {
    const task: AgentTask = {
      id: newId('task'),
      description,
      status: 'running',
      iterations: 0,
      steps: [],
    };
    this.currentTask = task;

    // 设置系统提示词
    if (this.config.systemPrompt) {
      this.messages = [{
        role: 'system',
        content: this.config.systemPrompt,
      }];
    }

    this.messages.push({
      role: 'user',
      content: description,
    });

    try {
      while (task.iterations < (this.config.maxIterations || 10)) {
        task.iterations++;

        // 调用 LLM
        const response = await this.think();

        if (!response.toolCalls || response.toolCalls.length === 0) {
          // 没有更多工具调用，任务完成
          task.status = 'completed';
          task.result = response.content;
          break;
        }

        // 执行工具调用
        for (const call of response.toolCalls) {
          const step: AgentStep = {
            stepNumber: task.steps.length + 1,
            action: `Call tool: ${call.name}`,
            tool: call.name,
            input: call.arguments,
            timestamp: Date.now(),
          };

          try {
            const result = await this.tools.execute(call.name, call.arguments, {
              agentId: this.id,
              role: this.role,
              taskId: task.id,
              requestId: newId('req'),
            });

            step.output = result;

            this.messages.push({
              role: 'tool',
              content: JSON.stringify(result),
              toolResult: result,
            });
          } catch (err) {
            step.output = { error: (err as Error).message };
            this.messages.push({
              role: 'tool',
              content: `Error: ${(err as Error).message}`,
              toolResult: { error: (err as Error).message },
            });
          }

          task.steps.push(step);
        }
      }

      if (task.status === 'running' && task.iterations >= (this.config.maxIterations || 10)) {
        task.status = 'failed';
        task.error = 'Max iterations exceeded';
      }
    } catch (err) {
      task.status = 'failed';
      task.error = (err as Error).message;
    }

    return task;
  }

  /**
   * LLM 思考
   */
  private async think(): Promise<{
    content: string;
    toolCalls: Array<{ name: string; arguments: Record<string, unknown> }>;
  }> {
    // 构造工具描述
    const toolDefinitions = this.tools.listTools().map(t => ({
      name: t.name,
      description: t.description,
      input_schema: t.schema,
    }));

    // 构建消息
    const llmRequest: LLMRequest = {
      model: this.config.llmProvider === 'anthropic' ? 'claude-sonnet-4-6' : 'deepseek-chat',
      messages: this.messages.map(m => ({
        role: m.role === 'system' ? 'system' : m.role === 'user' ? 'user' : m.role === 'assistant' ? 'assistant' : 'user',
        content: m.content,
      })),
      max_tokens: 1024,
    };

    // 调用 LLM
    const response = await llmGateway.chat({
      ...llmRequest,
      provider: this.config.llmProvider,
    });

    // 添加助手响应
    this.messages.push({
      role: 'assistant',
      content: response.content,
    });

    // 解析工具调用 (简单实现 - 实际应该用更好的解析)
    const toolCalls = this.parseToolCalls(response.content);

    return {
      content: response.content,
      toolCalls,
    };
  }

  /**
   * 解析工具调用 (从 LLM 输出中提取)
   * 简化实现 - 实际应该用更可靠的 JSON 解析或结构化输出
   */
  private parseToolCalls(content: string): Array<{ name: string; arguments: Record<string, unknown> }> {
    const calls: Array<{ name: string; arguments: Record<string, unknown> }> = [];

    // 尝试匹配 JSON 格式的工具调用
    const jsonMatch = content.match(/```json\n([\s\S]*?)\n```/);
    if (jsonMatch) {
      try {
        const parsed = JSON.parse(jsonMatch[1] ?? '');
        if (Array.isArray(parsed)) {
          for (const item of parsed) {
            if (
              item &&
              typeof item === 'object' &&
              'name' in item &&
              'arguments' in item &&
              typeof item.name === 'string' &&
              item.arguments &&
              typeof item.arguments === 'object'
            ) {
              calls.push(item);
            }
          }
        }
      } catch {
        // Ignore parse errors
      }
    }

    return calls;
  }

  /**
   * 获取聊天历史
   */
  getMessages(): AgentMessage[] {
    return [...this.messages];
  }

  /**
   * 清空历史
   */
  clearHistory(): void {
    this.messages = [];
  }
}

// ============== 智能体工厂 ==============

export class AgentFactory {
  private agents: Map<string, Agent> = new Map();

  create(config: AgentConfig): Agent {
    const agent = new Agent(config);
    this.agents.set(agent.id, agent);
    log.info(`Agent created: ${agent.id} (role: ${agent.role})`);
    return agent;
  }

  get(id: string): Agent | undefined {
    return this.agents.get(id);
  }

  list(): Agent[] {
    return [...this.agents.values()];
  }

  destroy(id: string): void {
    this.agents.delete(id);
    log.info(`Agent destroyed: ${id}`);
  }
}

// 导出单例
export const agentFactory = new AgentFactory();

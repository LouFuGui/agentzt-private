/**
 * AgentZT LLM 集成层
 * 支持 DeepSeek + Anthropic 多模型路由
 */

import { loadGatewayConfig } from '../shared/config.ts';
import type { AccessTokenClaims } from '../shared/types.ts';

// DeepSeek API 配置
const DEEPSEEK_CONFIG = {
  baseUrl: 'https://api.deepseek.com/v1',
  model: 'deepseek-chat',
  apiKey: process.env.DEEPSEEK_API_KEY || '',
};

export type LLMProvider = 'deepseek' | 'anthropic';

export interface LLMRequest {
  model: string;
  messages: Array<{ role: string; content: string }>;
  max_tokens?: number;
  temperature?: number;
  provider?: LLMProvider;
}

export interface LLMResponse {
  id: string;
  model: string;
  provider: LLMProvider;
  content: string;
  usage: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
  latencyMs: number;
}

/**
 * LLM 路由器 - 根据模型选择对应的 provider
 */
export class LLMRouter {
  private providers: Map<string, LLMProvider> = new Map([
    ['deepseek-chat', 'deepseek'],
    ['deepseek-coder', 'deepseek'],
    ['claude-3-5-sonnet', 'anthropic'],
    ['claude-3-5-haiku', 'anthropic'],
    ['claude-opus-4-8', 'anthropic'],
    ['claude-sonnet-4-6', 'anthropic'],
  ]);

  resolveProvider(model: string): LLMProvider {
    return this.providers.get(model) || 'deepseek';
  }

  registerModel(model: string, provider: LLMProvider) {
    this.providers.set(model, provider);
  }
}

/**
 * DeepSeek API 客户端
 */
export class DeepSeekClient {
  private baseUrl: string;
  private apiKey: string;

  constructor(apiKey?: string) {
    this.apiKey = apiKey ?? DEEPSEEK_CONFIG.apiKey;
    this.baseUrl = DEEPSEEK_CONFIG.baseUrl;
  }

  async chat(request: Omit<LLMRequest, 'provider'>): Promise<LLMResponse> {
    const start = Date.now();

    if (!this.apiKey) {
      throw new Error('DeepSeek API key is required in DEEPSEEK_API_KEY');
    }

    const response = await fetch(`${this.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        model: request.model || DEEPSEEK_CONFIG.model,
        messages: request.messages,
        max_tokens: request.max_tokens || 1024,
        temperature: request.temperature || 0.7,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`DeepSeek API error: ${response.status} - ${error}`);
    }

    const data = await response.json() as {
      id: string;
      model: string;
      choices: Array<{ message: { content: string } }>;
      usage: {
        prompt_tokens: number;
        completion_tokens: number;
        total_tokens: number;
      };
    };

    return {
      id: data.id,
      model: data.model,
      provider: 'deepseek',
      content: data.choices[0]?.message?.content || '',
      usage: data.usage,
      latencyMs: Date.now() - start,
    };
  }
}

/**
 * Anthropic API 客户端 (保持原有逻辑)
 */
export class AnthropicClient {
  private baseUrl: string;
  private apiKey: string;

  constructor() {
    this.apiKey = process.env.ANTHROPIC_API_KEY || '';
    this.baseUrl = process.env.ANTHROPIC_BASE_URL || 'https://api.anthropic.com/v1';
  }

  async messages(request: {
    model: string;
    messages: Array<{ role: string; content: string }>;
    max_tokens?: number;
  }): Promise<LLMResponse> {
    const start = Date.now();

    const response = await fetch(`${this.baseUrl}/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.apiKey,
        'anthropic-version': '2023-06-01',
        'anthropic-dangerous-direct-browser-access': 'true',
      },
      body: JSON.stringify({
        model: request.model,
        messages: request.messages,
        max_tokens: request.max_tokens || 1024,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Anthropic API error: ${response.status} - ${error}`);
    }

    const data = await response.json() as {
      id: string;
      model: string;
      content: Array<{ type: string; text: string }>;
      usage: {
        input_tokens: number;
        output_tokens: number;
      };
    };

    return {
      id: data.id,
      model: data.model,
      provider: 'anthropic',
      content: data.content[0]?.text || '',
      usage: {
        prompt_tokens: data.usage.input_tokens,
        completion_tokens: data.usage.output_tokens,
        total_tokens: data.usage.input_tokens + data.usage.output_tokens,
      },
      latencyMs: Date.now() - start,
    };
  }
}

/**
 * 统一 LLM 网关
 */
export class LLMGateway {
  private router: LLMRouter;
  private deepseek: DeepSeekClient;
  private anthropic: AnthropicClient;

  constructor() {
    this.router = new LLMRouter();
    this.deepseek = new DeepSeekClient();
    this.anthropic = new AnthropicClient();
  }

  async chat(request: LLMRequest): Promise<LLMResponse> {
    const provider = request.provider || this.router.resolveProvider(request.model);

    switch (provider) {
      case 'deepseek':
        return this.deepseek.chat(request);
      case 'anthropic':
        return this.anthropic.messages(request as {
          model: string;
          messages: Array<{ role: string; content: string }>;
          max_tokens?: number;
        });
      default:
        throw new Error(`Unknown provider: ${provider}`);
    }
  }

  registerModel(model: string, provider: LLMProvider) {
    this.router.registerModel(model, provider);
  }
}

// 导出单例
export const llmGateway = new LLMGateway();

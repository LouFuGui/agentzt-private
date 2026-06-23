/**
 * AgentZT LLM 集成层
 * 支持 DeepSeek + Anthropic 多模型路由
 */

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

export interface RouteRule {
  pattern: string;
  provider: LLMProvider;
  priority: number;
  conditions?: {
    max_tokens?: number;
    required_capabilities?: string[];
  };
}

type CompiledRouteRule = RouteRule & {
  regex: RegExp;
};

/**
 * LLM 路由器 - 根据模型选择对应的 provider
 */
export class LLMRouter {
  private rules: CompiledRouteRule[];

  constructor(rules: RouteRule[] = [
    { pattern: 'claude-opus-*', provider: 'anthropic', priority: 1 },
    { pattern: 'claude-sonnet-*', provider: 'anthropic', priority: 1 },
    { pattern: 'claude-haiku-*', provider: 'anthropic', priority: 1 },
    { pattern: 'claude-3-*-sonnet*', provider: 'anthropic', priority: 1 },
    { pattern: 'claude-3-*-haiku*', provider: 'anthropic', priority: 1 },
    { pattern: 'deepseek-*', provider: 'deepseek', priority: 1 },
    { pattern: '*', provider: 'deepseek', priority: 99 },
  ]) {
    this.rules = rules.map((rule) => compileRouteRule(rule));
  }

  resolveProvider(model: string, request?: Pick<LLMRequest, 'max_tokens'>): LLMProvider {
    const rule = this.rules
      .filter((candidate) => this.matches(candidate, model, request))
      .sort((a, b) => a.priority - b.priority)[0];
    return rule?.provider ?? 'deepseek';
  }

  registerModel(model: string, provider: LLMProvider): void {
    this.registerRule({ pattern: model, provider, priority: 0 });
  }

  registerRule(rule: RouteRule): void {
    this.rules.push(compileRouteRule(rule));
  }

  listRules(): RouteRule[] {
    return this.rules.map(({ regex: _regex, ...rule }) => ({
      ...rule,
      conditions: rule.conditions ? { ...rule.conditions } : undefined,
    }));
  }

  private matches(rule: CompiledRouteRule, model: string, request?: Pick<LLMRequest, 'max_tokens'>): boolean {
    if (!rule.regex.test(model)) return false;
    const maxTokens = rule.conditions?.max_tokens;
    if (maxTokens !== undefined && (request?.max_tokens ?? 0) > maxTokens) return false;
    return true;
  }
}

function compileRouteRule(rule: RouteRule): CompiledRouteRule {
  // Treat "/" as the model namespace boundary. Hyphens remain valid within one
  // model name segment (for example claude-sonnet-4-6 and deepseek-coder).
  const escaped = rule.pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*');
  return {
    ...rule,
    conditions: rule.conditions ? { ...rule.conditions } : undefined,
    regex: new RegExp(`^${escaped}$`),
  };
}

/**
 * DeepSeek API 客户端
 */
export class DeepSeekClient {
  private baseUrl: string;
  private apiKey: string;
  private defaultModel: string;

  constructor(apiKey?: string, baseUrl = 'https://api.deepseek.com/v1', defaultModel = 'deepseek-chat') {
    this.apiKey = apiKey ?? process.env.DEEPSEEK_API_KEY ?? '';
    this.baseUrl = baseUrl;
    this.defaultModel = defaultModel;
  }

  async chat(request: Omit<LLMRequest, 'provider'>): Promise<LLMResponse> {
    const start = Date.now();

    if (!this.apiKey) {
      throw new Error('DeepSeek API key is required via constructor parameter or DEEPSEEK_API_KEY');
    }

    const response = await fetch(`${this.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        model: request.model || this.defaultModel,
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

  constructor(apiKey?: string, baseUrl?: string) {
    this.apiKey = apiKey ?? process.env.ANTHROPIC_API_KEY ?? '';
    this.baseUrl = baseUrl ?? process.env.ANTHROPIC_BASE_URL ?? 'https://api.anthropic.com/v1';
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
    const provider = request.provider || this.router.resolveProvider(request.model, request);

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

  registerModel(model: string, provider: LLMProvider): void {
    this.router.registerModel(model, provider);
  }

  registerRouteRule(rule: RouteRule): void {
    this.router.registerRule(rule);
  }
}

// 导出单例
export const llmGateway = new LLMGateway();

import type { GatewayConfig } from '../shared/types.ts';
import { newId } from '../shared/crypto.ts';
import { getModelApiKeyFromVault } from './vault-secrets.ts';

export type ModelRequest = {
  model: string;
  body: Record<string, unknown>;
  protocol?: 'anthropic-messages' | 'openai-chat';
};

export type ModelResponse = {
  status: number;
  body: unknown;
  usage?: { input_tokens?: number; output_tokens?: number };
  provider?: string;
};

type UpstreamProviderConfig = NonNullable<GatewayConfig['upstream']['providers']>[string];

type ResolvedProvider = UpstreamProviderConfig & {
  name: string;
};

type UpstreamProvider = {
  call(apiKey: string, req: ModelRequest): Promise<ModelResponse>;
};

type CompiledRoute = {
  pattern: string;
  provider: string;
  priority: number;
  regex: RegExp;
};

class UpstreamConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UpstreamConfigurationError';
  }
}

function estimateTokens(obj: unknown): number {
  return Math.ceil(JSON.stringify(obj ?? '').length / 4);
}

function extractPromptText(body: Record<string, unknown>): string {
  const messages = body['messages'];
  if (!Array.isArray(messages)) return '';
  const parts: string[] = [];
  for (const m of messages) {
    const content = (m as Record<string, unknown>)['content'];
    if (typeof content === 'string') parts.push(content);
    else if (Array.isArray(content)) {
      for (const block of content) {
        const t = (block as Record<string, unknown>)['text'];
        if (typeof t === 'string') parts.push(t);
      }
    }
  }
  return parts.join('\n');
}

/**
 * Upstream model adapter.
 *  - mock: returns an Anthropic Messages-shaped response, fully offline. The
 *    reply echoes that it passed through the zero-trust gateway so the demo is
 *    legible.
 *  - passthrough: forwards to a real Model API using the ENTERPRISE key held by
 *    the gateway. The agent never receives that key — credential isolation.
 */
export async function callModel(
  cfg: GatewayConfig,
  req: ModelRequest,
): Promise<ModelResponse> {
  if (cfg.upstream.mode === 'mock') {
    return mockModel(req);
  }
  return passthroughModel(cfg, req);
}

export function resolveUpstreamProvider(cfg: GatewayConfig, model: string): ResolvedProvider {
  const providers = configuredProviders(cfg);
  const route = configuredRoutes(cfg)
    .filter((candidate) => candidate.regex.test(model))
    .sort((a, b) => a.priority - b.priority)[0];
  const providerName = route?.provider ?? cfg.upstream.defaultProvider ?? 'anthropic';
  const provider = providers[providerName];
  if (!provider) {
    throw new UpstreamConfigurationError(`upstream provider "${providerName}" is not configured`);
  }
  return provider;
}

function mockModel(req: ModelRequest): ModelResponse {
  const prompt = extractPromptText(req.body);
  const inputTokens = estimateTokens(req.body['messages']);
  const text =
    `[agentzt mock model "${req.model}"] Your request reached the enterprise ` +
    `model API through the zero-trust gateway. Prompt received ` +
    `(${prompt.length} chars). This is a synthetic offline response.`;
  const outputTokens = estimateTokens(text);
  return {
    status: 200,
    provider: 'mock',
    usage: { input_tokens: inputTokens, output_tokens: outputTokens },
    body: {
      id: newId('msg'),
      type: 'message',
      role: 'assistant',
      model: req.model,
      content: [{ type: 'text', text }],
      stop_reason: 'end_turn',
      stop_sequence: null,
      usage: { input_tokens: inputTokens, output_tokens: outputTokens },
    },
  };
}

async function passthroughModel(
  cfg: GatewayConfig,
  req: ModelRequest,
): Promise<ModelResponse> {
  let provider: ResolvedProvider;
  try {
    provider = resolveUpstreamProvider(cfg, req.model);
  } catch (err) {
    if (err instanceof UpstreamConfigurationError) {
      return {
        status: 502,
        body: {
          type: 'error',
          error: {
            type: 'upstream_misconfigured',
            message: err.message,
          },
        },
      };
    }
    throw err;
  }
  const apiKey = await getModelApiKeyFromVault(cfg.vault, provider.apiKeyEnv);
  if (!apiKey) {
    return {
      status: 502,
      provider: provider.name,
      body: {
        type: 'error',
        error: {
          type: 'upstream_misconfigured',
          message: cfg.vault?.enabled
            ? `passthrough mode requires the ${provider.name} enterprise key in Vault or the configured fallback env var`
            : `passthrough mode requires the ${provider.name} enterprise key in env ${provider.apiKeyEnv}`,
        },
      },
    };
  }
  return createUpstreamProvider(provider).call(apiKey, req);
}

function createUpstreamProvider(provider: ResolvedProvider): UpstreamProvider {
  if (provider.type === 'deepseek') return new DeepSeekProvider(provider);
  return new AnthropicProvider(provider);
}

class AnthropicProvider implements UpstreamProvider {
  private readonly provider: ResolvedProvider;

  constructor(provider: ResolvedProvider) {
    this.provider = provider;
  }

  async call(apiKey: string, req: ModelRequest): Promise<ModelResponse> {
    const url = `${this.provider.baseUrl.replace(/\/$/, '')}/v1/messages`;
    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(req.body),
    });
    const body = await resp.json().catch(() => ({}));
    const usage = (body as Record<string, unknown>)['usage'] as
      | { input_tokens?: number; output_tokens?: number }
      | undefined;
    return { status: resp.status, body, usage, provider: this.provider.name };
  }
}

class DeepSeekProvider implements UpstreamProvider {
  private readonly provider: ResolvedProvider;

  constructor(provider: ResolvedProvider) {
    this.provider = provider;
  }

  async call(apiKey: string, req: ModelRequest): Promise<ModelResponse> {
    const openAiBody = toOpenAiChatBody(req.body, req.model, this.provider.defaultModel);
    const url = `${this.provider.baseUrl.replace(/\/$/, '')}/chat/completions`;
    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: ['Bearer', apiKey].join(' '),
      },
      body: JSON.stringify(openAiBody),
    });
    const body = await resp.json().catch(() => ({}));
    const usage = openAiUsage(body);
    if (req.protocol === 'openai-chat') {
      return { status: resp.status, body, usage, provider: this.provider.name };
    }
    return {
      status: resp.status,
      body: resp.ok ? toAnthropicMessage(body, req.model) : body,
      usage,
      provider: this.provider.name,
    };
  }
}

function configuredProviders(cfg: GatewayConfig): Record<string, ResolvedProvider> {
  const providers: Record<string, ResolvedProvider> = {
    anthropic: {
      name: 'anthropic',
      type: 'anthropic',
      baseUrl: cfg.upstream.anthropicBaseUrl,
      apiKeyEnv: cfg.upstream.apiKeyEnv,
    },
    deepseek: {
      name: 'deepseek',
      type: 'deepseek',
      baseUrl: 'https://api.deepseek.com/v1',
      apiKeyEnv: 'AGENTZT_UPSTREAM_DEEPSEEK_KEY',
      defaultModel: 'deepseek-chat',
    },
  };
  for (const [name, provider] of Object.entries(cfg.upstream.providers ?? {})) {
    providers[name] = { name, ...provider };
  }
  return providers;
}

function configuredRoutes(cfg: GatewayConfig): CompiledRoute[] {
  const routes = cfg.upstream.routes ?? [
    { pattern: 'deepseek-*', provider: 'deepseek', priority: 10 },
    { pattern: 'claude-*', provider: 'anthropic', priority: 20 },
    { pattern: '*', provider: cfg.upstream.defaultProvider ?? 'anthropic', priority: 99 },
  ];
  return routes.map((route) => ({
    pattern: route.pattern,
    provider: route.provider,
    priority: route.priority ?? 50,
    regex: wildcardToRegex(route.pattern),
  }));
}

function wildcardToRegex(pattern: string): RegExp {
  // Treat "/" as the model namespace boundary. Hyphens remain valid within one
  // model name segment (for example claude-sonnet-4-6 and deepseek-coder).
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*');
  return new RegExp(`^${escaped}$`);
}

function toOpenAiChatBody(
  body: Record<string, unknown>,
  requestedModel: string,
  defaultModel?: string,
): Record<string, unknown> {
  const messages = normalizeMessages(body);
  return {
    ...body,
    model: requestedModel || defaultModel || 'deepseek-chat',
    messages,
  };
}

function normalizeMessages(body: Record<string, unknown>): Array<{ role: string; content: string }> {
  const messages = body['messages'];
  const out: Array<{ role: string; content: string }> = [];
  const system = body['system'];
  if (typeof system === 'string' && system) {
    out.push({ role: 'system', content: system });
  }
  if (!Array.isArray(messages)) return out;
  for (const msg of messages) {
    const m = msg as Record<string, unknown>;
    const role = typeof m['role'] === 'string' ? m['role'] : 'user';
    out.push({ role, content: contentToText(m['content']) });
  }
  return out;
}

function contentToText(content: unknown): string {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  const parts: string[] = [];
  for (const block of content) {
    const b = block as Record<string, unknown>;
    if (typeof b['text'] === 'string') parts.push(b['text']);
  }
  return parts.join('\n');
}

function openAiUsage(body: unknown): { input_tokens?: number; output_tokens?: number } | undefined {
  const usage = (body as Record<string, unknown>)['usage'] as
    | { prompt_tokens?: number; completion_tokens?: number }
    | undefined;
  if (!usage) return undefined;
  return { input_tokens: usage.prompt_tokens, output_tokens: usage.completion_tokens };
}

function toAnthropicMessage(body: unknown, fallbackModel: string): Record<string, unknown> {
  const data = body as Record<string, unknown>;
  const choice = ((data['choices'] as unknown[])?.[0] ?? {}) as Record<string, unknown>;
  const message = (choice['message'] as Record<string, unknown> | undefined) ?? {};
  const usage = openAiUsage(body) ?? {};
  return {
    id: typeof data['id'] === 'string' ? data['id'] : newId('msg'),
    type: 'message',
    role: 'assistant',
    model: typeof data['model'] === 'string' ? data['model'] : fallbackModel,
    content: [{ type: 'text', text: typeof message['content'] === 'string' ? message['content'] : '' }],
    stop_reason: choice['finish_reason'] === 'length' ? 'max_tokens' : 'end_turn',
    stop_sequence: null,
    usage,
  };
}

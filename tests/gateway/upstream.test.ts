import { afterEach, describe, expect, it, vi } from 'vitest';
import { callModel, resolveUpstreamProvider } from '../../src/gateway/upstream.ts';
import type { GatewayConfig } from '../../src/shared/types.ts';

function config(overrides: Partial<GatewayConfig['upstream']> = {}): GatewayConfig {
  return {
    port: 0,
    issuer: 'agentzt-gateway',
    tokenTtlSeconds: 300,
    assertionMaxAgeSeconds: 60,
    upstream: {
      mode: 'passthrough',
      anthropicBaseUrl: 'https://anthropic.example',
      apiKeyEnv: 'ANTHROPIC_TEST_KEY',
      ...overrides,
    },
  };
}

describe('upstream provider routing', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it('routes DeepSeek and Claude models to their providers by default', () => {
    expect(resolveUpstreamProvider(config(), 'deepseek-chat').name).toBe('deepseek');
    expect(resolveUpstreamProvider(config(), 'claude-sonnet-4-6').name).toBe('anthropic');
    expect(resolveUpstreamProvider(config(), 'deepseek-prod/admin').name).toBe('anthropic');
  });

  it('honors configured provider routes and DeepSeek baseUrl', async () => {
    vi.stubEnv('CUSTOM_DEEPSEEK_KEY', 'test-deepseek-key');
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      id: 'chat-1',
      model: 'internal-qwen-32b',
      choices: [{ message: { content: 'ok' }, finish_reason: 'stop' }],
      usage: { prompt_tokens: 2, completion_tokens: 3, total_tokens: 5 },
    }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    const result = await callModel(config({
      providers: {
        internal: {
          type: 'deepseek',
          baseUrl: 'http://deepseek.internal/v1',
          apiKeyEnv: 'CUSTOM_DEEPSEEK_KEY',
        },
      },
      routes: [{ pattern: 'internal-*', provider: 'internal', priority: 1 }],
    }), {
      model: 'internal-qwen-32b',
      protocol: 'anthropic-messages',
      body: {
        model: 'internal-qwen-32b',
        system: 'You are helpful.',
        messages: [{ role: 'user', content: [{ type: 'text', text: 'hello' }] }],
        max_tokens: 64,
      },
    });

    expect(result.status).toBe(200);
    expect(result.body).toMatchObject({
      type: 'message',
      model: 'internal-qwen-32b',
      content: [{ type: 'text', text: 'ok' }],
      usage: { input_tokens: 2, output_tokens: 3 },
    });
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('http://deepseek.internal/v1/chat/completions');
    expect(init.headers).toMatchObject({ authorization: ['Bearer', 'test-deepseek-key'].join(' ') });
    expect(JSON.parse(init.body as string)).toMatchObject({
      model: 'internal-qwen-32b',
      messages: [
        { role: 'system', content: 'You are helpful.' },
        { role: 'user', content: 'hello' },
      ],
    });
  });

  it('keeps OpenAI chat responses raw for chat completions callers', async () => {
    vi.stubEnv('AGENTZT_UPSTREAM_DEEPSEEK_KEY', 'test-deepseek-key');
    const body = {
      id: 'chat-1',
      model: 'deepseek-chat',
      choices: [{ message: { content: 'ok' }, finish_reason: 'stop' }],
      usage: { prompt_tokens: 2, completion_tokens: 3, total_tokens: 5 },
    };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(body), { status: 200 })));

    const result = await callModel(config(), {
      model: 'deepseek-chat',
      protocol: 'openai-chat',
      body: {
        model: 'deepseek-chat',
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(result.body).toEqual(body);
    expect(result.usage).toEqual({ input_tokens: 2, output_tokens: 3 });
  });
});

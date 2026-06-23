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

  it('keeps mock mode offline and reports the mock provider', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const result = await callModel(config({ mode: 'mock' }), {
      model: 'deepseek-chat',
      body: {
        model: 'deepseek-chat',
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(result.status).toBe(200);
    expect(result.provider).toBe('mock');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('fails closed when a route references an unknown provider', async () => {
    const result = await callModel(config({
      routes: [{ pattern: 'internal-*', provider: 'missing-provider', priority: 1 }],
    }), {
      model: 'internal-qwen-32b',
      body: {
        model: 'internal-qwen-32b',
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(result).toMatchObject({
      status: 502,
      body: {
        error: {
          type: 'upstream_misconfigured',
          message: 'upstream provider "missing-provider" is not configured',
        },
      },
    });
  });

  it('reports the selected provider when its key is missing', async () => {
    const result = await callModel(config(), {
      model: 'deepseek-chat',
      body: {
        model: 'deepseek-chat',
        messages: [{ role: 'user', content: 'hello' }],
      },
    });

    expect(result.status).toBe(502);
    expect(result.provider).toBe('deepseek');
    expect(result.body).toMatchObject({
      error: {
        type: 'upstream_misconfigured',
        message: 'passthrough mode requires the deepseek enterprise key in env AGENTZT_UPSTREAM_DEEPSEEK_KEY',
      },
    });
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
    expect(result.provider).toBe('internal');
    expect(result.body).toMatchObject({
      type: 'message',
      model: 'internal-qwen-32b',
      content: [{ type: 'text', text: 'ok' }],
      usage: { input_tokens: 2, output_tokens: 3 },
    });
    expect(fetchMock).toHaveBeenCalledOnce();
    const call = fetchMock.mock.calls[0] as [string, RequestInit];
    const [url, init] = call;
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

  it('delegates Anthropic routes through the configured provider adapter', async () => {
    vi.stubEnv('CUSTOM_ANTHROPIC_KEY', 'test-anthropic-key');
    const body = {
      id: 'msg-1',
      type: 'message',
      role: 'assistant',
      model: 'claude-sonnet-4-6',
      content: [{ type: 'text', text: 'ok' }],
      usage: { input_tokens: 4, output_tokens: 5 },
    };
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(body), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    const result = await callModel(config({
      providers: {
        anthropic: {
          type: 'anthropic',
          baseUrl: 'http://anthropic.internal',
          apiKeyEnv: 'CUSTOM_ANTHROPIC_KEY',
        },
      },
      routes: [{ pattern: 'claude-*', provider: 'anthropic', priority: 1 }],
    }), {
      model: 'claude-sonnet-4-6',
      protocol: 'anthropic-messages',
      body: {
        model: 'claude-sonnet-4-6',
        messages: [{ role: 'user', content: 'hello' }],
        max_tokens: 64,
      },
    });

    expect(result).toEqual({
      status: 200,
      body,
      usage: { input_tokens: 4, output_tokens: 5 },
      provider: 'anthropic',
    });
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('http://anthropic.internal/v1/messages');
    expect(init.headers).toMatchObject({
      'x-api-key': 'test-anthropic-key',
      'anthropic-version': '2023-06-01',
    });
    expect(JSON.parse(init.body as string)).toMatchObject({
      model: 'claude-sonnet-4-6',
      messages: [{ role: 'user', content: 'hello' }],
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
    expect(result.provider).toBe('deepseek');
    expect(result.usage).toEqual({ input_tokens: 2, output_tokens: 3 });
  });
});

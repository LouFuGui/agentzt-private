import { afterEach, describe, expect, it, vi } from 'vitest';
import { AnthropicClient, DeepSeekClient, LLMGateway, LLMRouter } from '../../src/gateway/llm-gateway.ts';

describe('LLMRouter', () => {
  it('routes model families with wildcard rules', () => {
    const router = new LLMRouter();

    expect(router.resolveProvider('claude-sonnet-4-6')).toBe('anthropic');
    expect(router.resolveProvider('claude-haiku-4-5')).toBe('anthropic');
    expect(router.resolveProvider('claude-opus-4-8')).toBe('anthropic');
    expect(router.resolveProvider('deepseek-coder')).toBe('deepseek');
    expect(router.resolveProvider('custom-model')).toBe('deepseek');
    expect(router.resolveProvider('deepseek-prod/admin')).toBe('deepseek');
  });

  it('honors registered model and rule precedence', () => {
    const router = new LLMRouter();

    router.registerRule({
      pattern: 'cost-capped-*',
      provider: 'anthropic',
      priority: 0,
      conditions: { max_tokens: 128 },
    });
    router.registerModel('local-claude-alias', 'anthropic');

    expect(router.resolveProvider('cost-capped-model', { max_tokens: 128 })).toBe('anthropic');
    expect(router.resolveProvider('cost-capped-model', { max_tokens: 129 })).toBe('deepseek');
    expect(router.resolveProvider('local-claude-alias')).toBe('anthropic');
  });

  it('returns defensive copies of route rules', () => {
    const router = new LLMRouter();
    const rules = router.listRules();

    rules[0].provider = 'deepseek';

    expect(router.resolveProvider('claude-sonnet-4-6')).toBe('anthropic');
  });
});

describe('LLM clients', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it('sends DeepSeek chat requests with gateway-held API key', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      id: 'chat-1',
      model: 'deepseek-chat',
      choices: [{ message: { content: 'ok' } }],
      usage: { prompt_tokens: 2, completion_tokens: 3, total_tokens: 5 },
    }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    const result = await new DeepSeekClient('test-deepseek-key').chat({
      model: 'deepseek-chat',
      messages: [{ role: 'user', content: 'hello' }],
      max_tokens: 32,
      temperature: 0,
    });

    expect(result).toMatchObject({
      provider: 'deepseek',
      content: 'ok',
      usage: { total_tokens: 5 },
    });
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://api.deepseek.com/v1/chat/completions');
    expect(init.headers).toMatchObject({ Authorization: ['Bearer', 'test-deepseek-key'].join(' ') });
  });

  it('normalizes Anthropic usage into the shared LLM response shape', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      id: 'msg-1',
      model: 'claude-sonnet-4-6',
      content: [{ type: 'text', text: 'ok' }],
      usage: { input_tokens: 4, output_tokens: 6 },
    }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    const result = await new AnthropicClient('anthropic-key', 'https://anthropic.example/v1').messages({
      model: 'claude-sonnet-4-6',
      messages: [{ role: 'user', content: 'hello' }],
      max_tokens: 32,
    });

    expect(result).toMatchObject({
      provider: 'anthropic',
      content: 'ok',
      usage: { prompt_tokens: 4, completion_tokens: 6, total_tokens: 10 },
    });
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://anthropic.example/v1/messages');
    expect(init.headers).toMatchObject({ 'x-api-key': 'anthropic-key' });
  });
});

describe('LLMGateway', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it('uses explicit provider overrides for requests', async () => {
    vi.stubEnv('DEEPSEEK_API_KEY', 'test-deepseek-key');
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      id: 'chat-1',
      model: 'deepseek-chat',
      choices: [{ message: { content: 'ok' } }],
      usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
    }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    const result = await new LLMGateway().chat({
      provider: 'deepseek',
      model: 'custom-chat-model',
      messages: [{ role: 'user', content: 'hello' }],
    });

    expect(result.provider).toBe('deepseek');
    expect(fetchMock).toHaveBeenCalledOnce();
  });
});

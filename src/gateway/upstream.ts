import type { GatewayConfig } from '../shared/types.ts';
import { newId } from '../shared/crypto.ts';

export type ModelRequest = {
  model: string;
  body: Record<string, unknown>;
};

export type ModelResponse = {
  status: number;
  body: unknown;
  usage?: { input_tokens?: number; output_tokens?: number };
};

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
  const apiKey = process.env[cfg.upstream.apiKeyEnv];
  if (!apiKey) {
    return {
      status: 502,
      body: {
        type: 'error',
        error: {
          type: 'upstream_misconfigured',
          message: `passthrough mode requires the enterprise key in env ${cfg.upstream.apiKeyEnv}`,
        },
      },
    };
  }
  const url = `${cfg.upstream.anthropicBaseUrl.replace(/\/$/, '')}/v1/messages`;
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
  return { status: resp.status, body, usage };
}

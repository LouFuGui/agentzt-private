// Pluggable guardrail detectors. The gateway calls a provider to decide whether
// a prompt (input) or a model response (output) is safe. Two providers ship:
//
//   - OpenGuardrails: an LLM-based, context-aware detector (https://openguardrails.com).
//     Because it scores the WHOLE conversation, it catches *indirect* prompt
//     injection — malicious instructions hidden in tool outputs / retrieved web
//     pages that have been fed back into the messages — which pattern matching
//     misses. Also flags content-compliance and sensitive-data leakage.
//   - Local: a zero-dependency regex detector used as an offline fallback (and
//     the default when no OpenGuardrails key is configured) so the demo and
//     tests run without network access.
//
// Selecting "auto" uses OpenGuardrails when its API key env var is set, else local.

import type {
  GuardrailConfig,
  GuardrailVerdict,
  OpenGuardrailsConfig,
} from '../shared/types.ts';
import type { SimpleMessage } from './guardrails.ts';
import { scanInjection, redactSecretsDeep } from './guardrails.ts';

export interface GuardrailProvider {
  readonly name: string;
  checkInput(messages: SimpleMessage[]): Promise<GuardrailVerdict>;
  checkOutput(prompt: string, response: string): Promise<GuardrailVerdict>;
}

const PASS: Omit<GuardrailVerdict, 'provider'> = {
  flagged: false,
  action: 'pass',
  riskLevel: 'no_risk',
  categories: [],
};

// ---- Local regex provider --------------------------------------------------

export class LocalGuardrailProvider implements GuardrailProvider {
  readonly name = 'local';

  checkInput(messages: SimpleMessage[]): Promise<GuardrailVerdict> {
    // Scan every message so injected instructions in tool/assistant content
    // (a poor-man's indirect-injection check) are caught, not just the last user turn.
    const patterns = new Set<string>();
    for (const m of messages) {
      for (const p of scanInjection(m.content).patterns) patterns.add(p);
    }
    const flagged = patterns.size > 0;
    return Promise.resolve({
      provider: this.name,
      flagged,
      action: flagged ? 'reject' : 'pass',
      riskLevel: flagged ? 'high_risk' : 'no_risk',
      categories: flagged ? ['prompt_injection'] : [],
      patterns: [...patterns],
    });
  }

  checkOutput(_prompt: string, response: string): Promise<GuardrailVerdict> {
    // The local provider relies on secret redaction (applied separately) for
    // output safety and does not block; report pass.
    const r = redactSecretsDeep(response);
    return Promise.resolve({
      provider: this.name,
      ...PASS,
      categories: r.count > 0 ? r.types : [],
    });
  }
}

// ---- OpenGuardrails API provider ------------------------------------------

type OGResponse = {
  id?: string;
  overall_risk_level?: string;
  suggest_action?: 'pass' | 'reject' | 'replace';
  suggest_answer?: string;
  result?: {
    compliance?: { risk_level?: string; categories?: string[] };
    security?: { risk_level?: string; categories?: string[] };
    data?: { risk_level?: string; categories?: string[] };
  };
};

export class OpenGuardrailsProvider implements GuardrailProvider {
  readonly name = 'openguardrails';
  private cfg: OpenGuardrailsConfig;
  private apiKey: string;

  constructor(cfg: OpenGuardrailsConfig, apiKey: string) {
    this.cfg = cfg;
    this.apiKey = apiKey;
  }

  private failVerdict(err: string): GuardrailVerdict {
    // Honor fail-open / fail-closed policy on detector outage.
    if (this.cfg.failOpen) {
      return { provider: this.name, ...PASS, error: err };
    }
    return {
      provider: this.name,
      flagged: true,
      action: 'reject',
      riskLevel: 'unknown',
      categories: ['guardrail_unavailable'],
      error: err,
    };
  }

  private async call(messages: SimpleMessage[]): Promise<GuardrailVerdict> {
    const url = `${this.cfg.baseUrl.replace(/\/$/, '')}/guardrails`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.cfg.timeoutMs);
    try {
      const resp = await fetch(url, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${this.apiKey}`,
          'content-type': 'application/json',
          'user-agent': 'agentzt/0.1',
        },
        body: JSON.stringify({ model: this.cfg.model, messages }),
        signal: controller.signal,
      });
      if (!resp.ok) return this.failVerdict(`openguardrails http ${resp.status}`);
      const data = (await resp.json()) as OGResponse;
      const action = data.suggest_action ?? 'pass';
      const categories = [
        ...(data.result?.security?.categories ?? []),
        ...(data.result?.compliance?.categories ?? []),
        ...(data.result?.data?.categories ?? []),
      ];
      return {
        provider: this.name,
        flagged: action !== 'pass',
        action,
        riskLevel: data.overall_risk_level ?? 'no_risk',
        categories,
        suggestAnswer: data.suggest_answer,
      };
    } catch (err) {
      return this.failVerdict((err as Error).message);
    } finally {
      clearTimeout(timer);
    }
  }

  checkInput(messages: SimpleMessage[]): Promise<GuardrailVerdict> {
    if (messages.length === 0) return Promise.resolve({ provider: this.name, ...PASS });
    return this.call(messages);
  }

  checkOutput(prompt: string, response: string): Promise<GuardrailVerdict> {
    // Context-aware output review: score the user turn + assistant turn together.
    return this.call([
      { role: 'user', content: prompt },
      { role: 'assistant', content: response },
    ]);
  }
}

// ---- Factory ---------------------------------------------------------------

export function createGuardrailProvider(cfg: GuardrailConfig): GuardrailProvider {
  const apiKey = process.env[cfg.openguardrails.apiKeyEnv];
  const wantOG =
    cfg.provider === 'openguardrails' || (cfg.provider === 'auto' && !!apiKey);
  if (wantOG) {
    if (!apiKey) {
      // Explicitly requested but unconfigured — fail safe to local rather than crash.
      return new LocalGuardrailProvider();
    }
    return new OpenGuardrailsProvider(cfg.openguardrails, apiKey);
  }
  return new LocalGuardrailProvider();
}

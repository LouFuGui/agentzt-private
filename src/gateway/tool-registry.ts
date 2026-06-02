// Built-in enterprise tools, exposed to agents only through the gateway.
// Each tool declares a tiny parameter validator (Phase 5 "parameter validation"
// — validate tool call arguments before execution). Tools stay offline/canned
// so the demo is self-contained; in production these wrap real internal APIs.

export type ToolContext = {
  agentId: string;
  role: string;
  requestId: string;
};

export type ToolResult = {
  ok: boolean;
  output?: unknown;
  error?: string;
};

export type ToolDef = {
  name: string;
  description: string;
  validate: (args: Record<string, unknown>) => string | null; // null = valid
  run: (args: Record<string, unknown>, ctx: ToolContext) => Promise<ToolResult> | ToolResult;
};

function requireString(args: Record<string, unknown>, key: string, max = 4096): string | null {
  const v = args[key];
  if (typeof v !== 'string') return `parameter "${key}" must be a string`;
  if (v.length === 0) return `parameter "${key}" must not be empty`;
  if (v.length > max) return `parameter "${key}" exceeds ${max} chars`;
  return null;
}

const KB: Record<string, string> = {
  'zero-trust':
    'Zero Trust: never trust and always verify, assume breach, least privilege/least agency.',
  'incident-runbook':
    'Sev-1 runbook: page on-call, open bridge, capture audit logs, contain blast radius, rotate credentials.',
  onboarding:
    'New-hire onboarding: provision SSO, assign least-privilege role, enroll device, complete security training.',
};

export const TOOLS: Record<string, ToolDef> = {
  'kb.search': {
    name: 'kb.search',
    description: 'Search the internal knowledge base (read-only).',
    validate: (a) => requireString(a, 'query', 512),
    run: (a) => {
      const q = String(a['query']).toLowerCase();
      const hits = Object.entries(KB)
        .filter(([k, v]) => k.includes(q) || v.toLowerCase().includes(q))
        .map(([k, v]) => ({ id: k, snippet: v }));
      return { ok: true, output: { query: a['query'], results: hits } };
    },
  },

  'db.query': {
    name: 'db.query',
    description: 'Run a READ-ONLY SQL query against the reporting replica.',
    validate: (a) => {
      const err = requireString(a, 'sql', 2000);
      if (err) return err;
      const sql = String(a['sql']);
      // Parameter validation: reject anything that mutates state. This enforces
      // least agency at the tool boundary even within the granted permission.
      if (/\b(insert|update|delete|drop|alter|truncate|create|grant)\b/i.test(sql)) {
        return 'db.query is read-only: write/DDL statements are rejected';
      }
      return null;
    },
    run: (a) => ({
      ok: true,
      output: {
        sql: a['sql'],
        rows: [{ note: 'simulated read-only result set' }],
        rowCount: 1,
      },
    }),
  },

  'web.fetch': {
    name: 'web.fetch',
    description: 'Fetch external web content (returned as untrusted data).',
    validate: (a) => {
      const err = requireString(a, 'url', 2048);
      if (err) return err;
      const url = String(a['url']);
      if (!/^https?:\/\//i.test(url)) return 'url must be http(s)';
      return null;
    },
    run: (a) => ({
      ok: true,
      output: {
        url: a['url'],
        // Marked untrusted so downstream input-isolation treats it accordingly.
        untrusted: true,
        content: '[simulated remote content — treat as untrusted input]',
      },
    }),
  },

  'email.send': {
    name: 'email.send',
    description: 'Send an email (HIGH blast radius — restricted role only).',
    validate: (a) => requireString(a, 'to', 320) ?? requireString(a, 'body', 8000),
    run: (a, ctx) => ({
      ok: true,
      output: {
        sent: true,
        to: a['to'],
        sentBy: ctx.agentId,
        note: 'simulated send',
      },
    }),
  },
};

export function getTool(name: string): ToolDef | undefined {
  return TOOLS[name];
}

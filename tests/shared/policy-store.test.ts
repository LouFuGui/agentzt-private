import { mkdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { JsonPolicyStore } from '../../src/shared/policy-store.ts';
import type { PolicyDoc } from '../../src/shared/types.ts';

const roots: string[] = [];

function makeStore(): { file: string; store: JsonPolicyStore } {
  const root = join(tmpdir(), `agentzt-policy-store-${randomUUID()}`);
  roots.push(root);
  mkdirSync(root, { recursive: true });
  const file = join(root, 'policy.json');
  return { file, store: new JsonPolicyStore(file) };
}

afterEach(() => {
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe('JsonPolicyStore', () => {
  it('loads and saves policy documents as pretty JSON', () => {
    const { file, store } = makeStore();
    const policy: PolicyDoc = {
      version: 1,
      defaultDeny: true,
      roles: {
        developer: {
          models: ['deepseek-chat'],
          tools: ['kb.search'],
        },
      },
    };

    store.save(policy);

    expect(readFileSync(file, 'utf8')).toBe(`${JSON.stringify(policy, null, 2)}\n`);
    expect(store.load()).toEqual(policy);
  });
});

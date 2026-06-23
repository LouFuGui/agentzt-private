import { execFileSync } from 'node:child_process';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { FileSandbox } from '../../src/gateway/sandbox.ts';

const roots: string[] = [];

function makeRoot(): string {
  const root = join(tmpdir(), `agentzt-sandbox-${randomUUID()}`);
  roots.push(root);
  mkdirSync(root, { recursive: true });
  return root;
}

afterEach(() => {
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe('sandbox runtime compatibility', () => {
  it('imports with Node native TypeScript stripping', () => {
    execFileSync(process.execPath, ['-e', "import('./src/gateway/sandbox.ts')"], {
      cwd: process.cwd(),
    });
  });
});

describe('FileSandbox', () => {
  it('allows files under configured roots and denies prefix escapes', async () => {
    const root = makeRoot();
    const allowed = join(root, 'allowed');
    const escaped = join(root, 'allowed-other');
    mkdirSync(allowed);
    mkdirSync(escaped);
    writeFileSync(join(allowed, 'ok.txt'), 'allowed');
    writeFileSync(join(escaped, 'secret.txt'), 'denied');

    const sandbox = new FileSandbox({
      timeout: 1000,
      memoryLimit: 128,
      networkAccess: false,
      filesystemAccess: [allowed],
      env: {},
    });

    const ok = await sandbox.execute('read', { path: join(allowed, 'ok.txt') });
    expect(ok).toMatchObject({ success: true, output: 'allowed' });

    const denied = await sandbox.execute('read', { path: join(escaped, 'secret.txt') });
    expect(denied).toMatchObject({ success: false });
    expect(denied.error).toContain('Access denied');
  });
});

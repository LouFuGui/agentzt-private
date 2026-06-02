import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type { AuditEvent } from './types.ts';

/**
 * Append-only audit logger. Writes one JSON object per line (JSONL) so the log
 * is greppable and stream-friendly. At the Foundation tier this is a local
 * file; the Enterprise tier would replace the sink with append-only/immutable
 * storage and ship to a SIEM. The call sites do not change.
 */
export class AuditLogger {
  private file: string;

  constructor(file: string) {
    this.file = file;
    mkdirSync(dirname(file), { recursive: true });
  }

  write(ev: AuditEvent): void {
    appendFileSync(this.file, JSON.stringify(ev) + '\n');
  }

  record(partial: Omit<AuditEvent, 'ts'>): AuditEvent {
    const ev: AuditEvent = { ts: new Date().toISOString(), ...partial };
    this.write(ev);
    return ev;
  }
}

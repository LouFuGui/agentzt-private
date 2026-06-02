import { appendFileSync, mkdirSync, existsSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { createHash } from 'node:crypto';
import type { AuditEvent } from './types.ts';

const GENESIS = '0'.repeat(64);

function hashEvent(prevHash: string, payloadJson: string): string {
  return createHash('sha256').update(prevHash).update('\n').update(payloadJson).digest('hex');
}

/**
 * Append-only, tamper-evident audit logger (Enterprise tier: "immutable audit
 * trails with integrity verification"). Each event carries a monotonically
 * increasing `seq` and a `hash` chaining it to the previous event:
 *
 *     hash_i = sha256(hash_{i-1} || payload_i)
 *
 * Any insertion, deletion, or modification of a past event breaks the chain at
 * that point, which `verifyChain` detects. At the Foundation tier this is a
 * local JSONL file; the sink can be swapped for append-only/WORM storage and a
 * SIEM stream without changing call sites.
 */
export class AuditLogger {
  private file: string;
  private prevHash: string;
  private seq: number;

  constructor(file: string) {
    this.file = file;
    mkdirSync(dirname(file), { recursive: true });
    const tail = readLastEvent(file);
    this.prevHash = tail?.hash ?? GENESIS;
    this.seq = tail?.seq ?? 0;
  }

  record(partial: Omit<AuditEvent, 'ts' | 'seq' | 'hash'>): AuditEvent {
    const seq = this.seq + 1;
    // Build the event WITHOUT the hash, in stable key order, then chain it.
    const base: AuditEvent = { ts: new Date().toISOString(), seq, ...partial };
    const payloadJson = JSON.stringify(base);
    const hash = hashEvent(this.prevHash, payloadJson);
    const full: AuditEvent = { ...base, hash };
    appendFileSync(this.file, JSON.stringify(full) + '\n');
    this.prevHash = hash;
    this.seq = seq;
    return full;
  }
}

function readLastEvent(file: string): AuditEvent | null {
  if (!existsSync(file)) return null;
  const lines = readFileSync(file, 'utf8').trim().split('\n').filter(Boolean);
  const last = lines[lines.length - 1];
  if (!last) return null;
  return JSON.parse(last) as AuditEvent;
}

export type ChainVerification = {
  ok: boolean;
  count: number;
  brokenAtSeq?: number;
  reason?: string;
};

/** Recompute the hash chain and report the first break, if any. */
export function verifyChain(file: string): ChainVerification {
  if (!existsSync(file)) return { ok: true, count: 0 };
  const lines = readFileSync(file, 'utf8').trim().split('\n').filter(Boolean);
  let prev = GENESIS;
  let expectedSeq = 0;
  for (const line of lines) {
    expectedSeq++;
    let ev: AuditEvent;
    try {
      ev = JSON.parse(line) as AuditEvent;
    } catch {
      return { ok: false, count: expectedSeq - 1, brokenAtSeq: expectedSeq, reason: 'unparseable line' };
    }
    if (ev.seq !== expectedSeq) {
      return { ok: false, count: expectedSeq - 1, brokenAtSeq: expectedSeq, reason: `seq gap (expected ${expectedSeq}, got ${ev.seq})` };
    }
    const stored = ev.hash;
    // Recreate the pre-hash payload: the event minus its hash field, same order.
    const { hash: _omit, ...base } = ev;
    const payloadJson = JSON.stringify(base);
    const recomputed = hashEvent(prev, payloadJson);
    if (recomputed !== stored) {
      return { ok: false, count: expectedSeq - 1, brokenAtSeq: expectedSeq, reason: 'hash mismatch (event altered or reordered)' };
    }
    prev = stored ?? prev;
  }
  return { ok: true, count: lines.length };
}

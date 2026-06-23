import { readFileSync, writeFileSync } from 'node:fs';
import type { PolicyDoc } from './types.ts';

export type PolicyStore = {
  load(): PolicyDoc;
  save(policy: PolicyDoc): void;
};

export class JsonPolicyStore implements PolicyStore {
  private file: string;

  constructor(file: string) {
    this.file = file;
  }

  load(): PolicyDoc {
    return JSON.parse(readFileSync(this.file, 'utf8')) as PolicyDoc;
  }

  save(policy: PolicyDoc): void {
    writeFileSync(this.file, JSON.stringify(policy, null, 2) + '\n');
  }
}

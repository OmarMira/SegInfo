import type { RawFinding } from './leak-scan-engine.js';
import type { Finding } from '../../report/sarif.js';

/** Normalizes raw engine output to the shared SARIF Finding contract. */
export function toFindings(raw: RawFinding[]): Finding[] {
  return raw.map((f) => ({
    ruleId: `leakscan/${f.type}`,
    message: `Potential secret (${f.type}) found in ${f.source}`,
    file: f.file,
    line: f.line,
    column: 1,
    level: 'warning',
    properties: {
      entropy: f.entropy,
      type: f.type,
      source: f.source,
      ...(f.commit ? { commit: f.commit } : {}),
    },
  }));
}

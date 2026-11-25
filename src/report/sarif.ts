import * as fs from 'node:fs';
import * as path from 'node:path';

/** Severity levels aligned with SARIF 2.1.0. */
export type SarifLevel = 'error' | 'warning' | 'note' | 'none';

/** Every module normalizes its findings to this shape before reporting. */
export interface Finding {
  ruleId: string;
  message: string;
  file: string;
  line: number;
  column: number;
  level: SarifLevel;
  /** Optional module-specific data (e.g. entropy, package version). */
  properties?: Record<string, unknown>;
}

/** One module's contribution to a (possibly merged) SARIF report. */
export interface SarifRunEntry {
  toolName: string;
  findings: Finding[];
}

const DEFAULT_OUTPUT = 'seginfo-secure-scan-results.sarif';

function buildRun({ toolName, findings }: SarifRunEntry): Record<string, unknown> {
  const results = findings.map((f) => ({
    ruleId: f.ruleId,
    message: { text: f.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.file },
          region: { startLine: f.line, startColumn: f.column },
        },
      },
    ],
    level: f.level,
    ...(f.properties ? { properties: f.properties } : {}),
  }));

  // Derive unique rule metadata so consumers (GitHub code scanning, IDEs)
  // can render meaningful rule names instead of bare ids.
  const seen = new Set<string>();
  for (const f of findings) seen.add(f.ruleId);
  const rules = [...seen].map((id) => ({ id, shortDescription: { text: id } }));

  return {
    tool: {
      driver: {
        name: `secure-scan/${toolName}`,
        informationUri: 'https://example.com/secure-scan',
        rules,
      },
    },
    results,
  };
}

/** Builds a SARIF 2.1.0 document with one run per module entry. */
export function buildSarif(entries: SarifRunEntry[]): Record<string, unknown> {
  return {
    $schema:
      'https://docs.oasis-open.org/sarif/sarif-2.1.0/csprd01/schemas/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: entries.map(buildRun),
  };
}

function writeDoc(doc: Record<string, unknown>, outputPath: string): string {
  const resolved = path.resolve(outputPath);
  fs.writeFileSync(resolved, JSON.stringify(doc, null, 2), { mode: 0o600 });
  return resolved;
}

/**
 * Serialize one module's findings to a SARIF 2.1.0 report on disk.
 *
 * @param toolName   Logical module name (leakscan | sca | iac).
 * @param findings   Normalized findings from the module.
 * @param outputPath Override for the output file (used by the orchestrator
 *                   to give each run a distinct file before merging).
 * @returns the path the report was written to.
 */
export function writeSarif(
  toolName: string,
  findings: Finding[],
  outputPath: string = DEFAULT_OUTPUT,
): string {
  return writeDoc(buildSarif([{ toolName, findings }]), outputPath);
}

/**
 * Serialize several modules' findings into a single SARIF document
 * (one run per module) — the orchestrator's merged report.
 */
export function writeMergedSarif(entries: SarifRunEntry[], outputPath: string): string {
  return writeDoc(buildSarif(entries), outputPath);
}

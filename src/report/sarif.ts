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

const DEFAULT_OUTPUT = 'seginfo-secure-scan-results.sarif';

/**
 * Serialize findings to a SARIF 2.1.0 report and write it to disk.
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
  const seen = new Map<string, string>();
  for (const f of findings) {
    if (!seen.has(f.ruleId)) seen.set(f.ruleId, f.ruleId);
  }
  const rules = [...seen.keys()].map((id) => ({
    id,
    shortDescription: { text: id },
  }));

  const sarif = {
    $schema:
      'https://docs.oasis-open.org/sarif/sarif-2.1.0/csprd01/schemas/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: `secure-scan/${toolName}`,
            informationUri: 'https://example.com/secure-scan',
            rules,
          },
        },
        results,
      },
    ],
  };

  const resolved = path.resolve(outputPath);
  fs.writeFileSync(resolved, JSON.stringify(sarif, null, 2), { mode: 0o600 });
  return resolved;
}

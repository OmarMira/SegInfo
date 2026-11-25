import { describe, expect, it, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { writeSarif, writeMergedSarif, type Finding } from '../../src/report/sarif.js';

const outputs: string[] = [];

afterEach(() => {
  for (const f of outputs.splice(0)) fs.rmSync(f, { recursive: true, force: true });
});

function tmpFile(): string {
  const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'seginfo-sarif-')), 'out.sarif');
  outputs.push(p);
  outputs.push(path.dirname(p));
  return p;
}

const sample: Finding[] = [
  {
    ruleId: 'leakscan/aws-access-key',
    message: 'Potential secret (aws-access-key)',
    file: 'src/config.ts',
    line: 2,
    column: 1,
    level: 'warning',
    properties: { entropy: 4.2 },
  },
  {
    ruleId: 'leakscan/jwt-token',
    message: 'Potential secret (jwt-token)',
    file: 'auth.py',
    line: 1,
    column: 8,
    level: 'warning',
  },
];

describe('writeSarif', () => {
  it('writes a SARIF 2.1.0 document with the requested tool name', () => {
    const out = tmpFile();
    writeSarif('leakscan', sample, out);
    const doc = JSON.parse(fs.readFileSync(out, 'utf8'));
    expect(doc.version).toBe('2.1.0');
    expect(doc.$schema).toContain('sarif-2.1.0');
    expect(doc.runs[0].tool.driver.name).toBe('secure-scan/leakscan');
  });

  it('emits one result per finding with location and level', () => {
    const out = tmpFile();
    writeSarif('sca', sample, out);
    const doc = JSON.parse(fs.readFileSync(out, 'utf8'));
    const results = doc.runs[0].results;
    expect(results).toHaveLength(2);
    expect(results[0].ruleId).toBe('leakscan/aws-access-key');
    expect(results[0].level).toBe('warning');
    expect(results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('src/config.ts');
    expect(results[0].locations[0].physicalLocation.region.startLine).toBe(2);
    expect(results[0].locations[0].physicalLocation.region.startColumn).toBe(1);
  });

  it('derives unique rule metadata from findings', () => {
    const out = tmpFile();
    writeSarif('leakscan', sample, out);
    const doc = JSON.parse(fs.readFileSync(out, 'utf8'));
    const ruleIds = doc.runs[0].tool.driver.rules.map((r: { id: string }) => r.id);
    expect(ruleIds).toEqual(['leakscan/aws-access-key', 'leakscan/jwt-token']);
  });

  it('carries module properties through to the result', () => {
    const out = tmpFile();
    writeSarif('leakscan', sample, out);
    const doc = JSON.parse(fs.readFileSync(out, 'utf8'));
    expect(doc.runs[0].results[0].properties).toEqual({ entropy: 4.2 });
    expect(doc.runs[0].results[1].properties).toBeUndefined();
  });

  it('returns the resolved path it wrote to', () => {
    const out = tmpFile();
    const returned = writeSarif('leakscan', [], out);
    expect(returned).toBe(path.resolve(out));
    expect(fs.existsSync(returned)).toBe(true);
  });

  it('merges multiple module runs into a single SARIF document', () => {
    const out = tmpFile();
    writeMergedSarif(
      [
        { toolName: 'leakscan', findings: sample },
        { toolName: 'iac', findings: [sample[1]] },
      ],
      out,
    );
    const doc = JSON.parse(fs.readFileSync(out, 'utf8'));
    expect(doc.version).toBe('2.1.0');
    expect(doc.runs).toHaveLength(2);
    expect(doc.runs[0].tool.driver.name).toBe('secure-scan/leakscan');
    expect(doc.runs[1].tool.driver.name).toBe('secure-scan/iac');
    expect(doc.runs[0].results).toHaveLength(2);
    expect(doc.runs[1].results).toHaveLength(1);
    expect(doc.runs[1].tool.driver.rules.map((r: { id: string }) => r.id)).toEqual([
      'leakscan/jwt-token',
    ]);
  });
});

import { describe, expect, it } from 'vitest';
import { classifyFinding, formatTriageSummary, triageFindings } from '../../src/triage/triage.js';
import type { Finding } from '../../src/report/sarif.js';

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'sast/xss-innerhtml',
    message: 'Possible XSS: untrusted data is written to an HTML sink.',
    file: 'src/app.ts',
    line: 1,
    column: 1,
    level: 'warning',
    ...overrides,
  };
}

describe('triage classification', () => {
  it('confirms a CISA KEV finding', () => {
    const result = classifyFinding(finding({ ruleId: 'sca/CVE-2024-0001', properties: { kev: true } }));
    expect(result.bucket).toBe('confirmed');
    expect(result.reason).toContain('CISA KEV');
  });

  it('treats test, fixture, docs and vendor paths as likely examples', () => {
    for (const file of [
      'tests/app.test.ts',
      'src/fixtures/secret.ts',
      'docs/README.md',
      'vendor/lib/thing.py',
      'service/conftest.py',
    ]) {
      expect(classifyFinding(finding({ file })).bucket).toBe('likely-example');
    }
  });

  it('keeps a production source finding in review with a rule-specific reason', () => {
    const result = classifyFinding(finding());
    expect(result.bucket).toBe('review');
    expect(result.reason).toContain('flujo de datos');
  });

  it('and a secret finding asks whether the credential is live', () => {
    expect(classifyFinding(finding({ ruleId: 'leakscan/aws-access-key' })).reason).toContain('activa');
  });
});

describe('triage grouping', () => {
  it('collapses identical findings into one group with a count and lines', () => {
    const findings = [
      finding({ line: 3 }),
      finding({ line: 9 }),
      finding({ line: 12, level: 'error' }),
    ];
    const result = triageFindings(findings);
    expect(result.groups).toHaveLength(1);
    expect(result.groups[0].count).toBe(3);
    expect(result.groups[0].lines).toEqual([3, 9, 12]);
    expect(result.groups[0].level).toBe('error');
  });

  it('keeps different messages as separate problems', () => {
    const result = triageFindings([
      finding({ message: 'Possible SQL injection' }),
      finding({ message: 'Possible XSS' }),
    ]);
    expect(result.groups).toHaveLength(2);
  });

  it('never hides findings: group counts add up to the total', () => {
    const findings = [
      finding({ file: 'tests/a.test.ts', line: 1 }),
      finding({ file: 'src/a.ts', line: 2 }),
      finding({ file: 'src/a.ts', line: 5 }),
    ];
    const result = triageFindings(findings);
    expect(result.groups.reduce((n, g) => n + g.count, 0)).toBe(findings.length);
    expect(result.summary.total).toBe(3);
    expect(result.summary.likelyExample).toBe(1);
    expect(result.summary.review).toBe(2);
  });

  it('orders confirmed first, then review, then likely examples', () => {
    const result = triageFindings([
      finding({ file: 'tests/a.test.ts' }),
      finding({ file: 'src/a.ts' }),
      finding({ file: 'src/b.ts', properties: { kev: true }, ruleId: 'sca/CVE-2024-0001' }),
    ]);
    expect(result.groups.map((g) => g.bucket)).toEqual(['confirmed', 'review', 'likely-example']);
  });

  it('annotates every finding with its triage bucket and reason', () => {
    const findings = [finding()];
    triageFindings(findings);
    expect(findings[0].properties?.triage).toEqual({
      bucket: 'review',
      reason: expect.stringContaining('flujo de datos'),
    });
  });

  it('gives every group a rule-specific why and a next step', () => {
    const findings = [finding({ properties: { sink: 'innerHTML', language: 'js' } })];
    const result = triageFindings(findings);
    expect(result.groups[0].why).toContain('sink HTML');
    expect(result.groups[0].evidence).toContain('Sink: innerHTML');
    expect(result.groups[0].nextStep).toContain('Revisa');
    expect(result.findings[0].why).toBe(result.groups[0].why);
  });

  it('formats a one-line summary', () => {
    expect(formatTriageSummary({ total: 6, confirmed: 1, review: 2, likelyExample: 3 })).toBe(
      '1 confirmados, 2 por revisar, 3 probables ejemplos o duplicados',
    );
  });
});

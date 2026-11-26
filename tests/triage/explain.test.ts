import { describe, expect, it } from 'vitest';
import { explainFinding } from '../../src/triage/explain.js';
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

describe('finding explanations', () => {
  it('explains a hardcoded credential with its pattern, entropy and origin', () => {
    const result = explainFinding(
      finding({
        ruleId: 'leakscan/hardcoded-credential',
        properties: { type: 'hardcoded-credential', entropy: 3.4213, source: 'working-tree' },
      }),
    );
    expect(result.why).toContain('credencial');
    expect(result.evidence).toContain('Patrón: hardcoded-credential');
    expect(result.evidence).toContain('Entropía: 3.42');
    expect(result.evidence).toContain('Origen: árbol de trabajo (archivo actual)');
  });

  it('warns when a secret only appears in git history, with the commit', () => {
    const result = explainFinding(
      finding({
        ruleId: 'leakscan/aws-access-key',
        properties: {
          type: 'aws-access-key',
          entropy: 4.1,
          source: 'git-history',
          commit: 'abcdef1234567890',
        },
      }),
    );
    expect(result.why).toContain('historial');
    expect(result.evidence).toContain('Commit: abcdef123456');
  });

  it('explains a vulnerable dependency with package, advisory and fixed version', () => {
    const result = explainFinding(
      finding({
        ruleId: 'sca/CVE-2020-8203',
        properties: {
          package: 'lodash',
          version: '4.17.15',
          vulnerabilityId: 'CVE-2020-8203',
          aliases: ['CVE-2020-8203', 'GHSA-p6mc-m468-83gw'],
          severity: 'HIGH',
          fixedIn: ['4.17.19'],
          kev: true,
        },
      }),
    );
    expect(result.why).toContain('lodash@4.17.15');
    expect(result.why).toContain('CVE-2020-8203');
    expect(result.evidence).toContain('Severidad OSV: Alta');
    expect(result.evidence).toContain('Corregido en: 4.17.19');
    expect(result.evidence).toContain(
      'Explotada conocida (CISA KEV): Sí (explotada en el mundo real)',
    );
    expect(result.evidence).toContain('Alias: CVE-2020-8203, GHSA-p6mc-m468-83gw');
  });

  it('names the HTML sink and language for a SAST finding', () => {
    const result = explainFinding(
      finding({ properties: { sink: 'innerHTML', language: 'js' } }),
    );
    expect(result.why).toContain('sink HTML');
    expect(result.evidence).toContain('Sink: innerHTML');
    expect(result.evidence).toContain('Lenguaje: JavaScript');
  });

  it('explains an open security group with its resource and ports', () => {
    const result = explainFinding(
      finding({
        ruleId: 'iac/sg-sensitive-port-open',
        properties: { resource: 'aws_security_group.bastion', fromPort: 22, toPort: 22 },
      }),
    );
    expect(result.why).toContain('puerto sensible');
    expect(result.evidence).toContain('Recurso: aws_security_group.bastion');
    expect(result.evidence).toContain('Puerto desde: 22');
  });

  it('explains a missing HSTS header', () => {
    const result = explainFinding(
      finding({
        ruleId: 'web/missing-hsts',
        file: 'https://example.com',
        message: 'Site does not serve Strict-Transport-Security (HSTS).',
      }),
    );
    expect(result.why).toContain('HSTS');
    expect(result.evidence).toEqual([]);
  });

  it('falls back to a family explanation and never leaks unknown property keys', () => {
    const result = explainFinding(
      finding({
        ruleId: 'sast/unknown-rule',
        properties: { triage: { bucket: 'review' }, internalDebugKey: 'x' },
      }),
    );
    expect(result.why).toContain('análisis estático');
    expect(result.evidence).toEqual([]);
  });
});

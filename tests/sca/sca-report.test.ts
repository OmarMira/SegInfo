import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { scanDependencies, type FetchLike } from '../../src/modules/sca/sca-engine.js';
import { scanRepoDetailed } from '../../src/modules/leakscan/leak-scan-engine.js';
import { toFindings } from '../../src/modules/leakscan/normalize.js';
import { triageFindings } from '../../src/triage/triage.js';
import { buildScaView, pickFixTarget } from '../../src/triage/sca-packages.js';

/**
 * End-to-end verification fixture for the grouped SCA report.
 *
 * The fixture has two advisories for one direct package, one transitive
 * package introduced by two different parents, one dev-only package and one
 * non-SCA secret finding. Grouping must not change any total or drop any
 * advisory.
 */

const FIXTURE = path.join(process.cwd(), 'tests', 'sca', 'fixtures', 'report');

const ADVISORIES: Record<string, unknown> = {
  'GHSA-alpha-0001': {
    id: 'GHSA-alpha-0001',
    summary: 'Alpha remote code execution',
    aliases: ['CVE-2026-1001'],
    modified: '2026-02-01T10:00:00Z',
    published: '2026-01-15T10:00:00Z',
    database_specific: { severity: 'HIGH' },
    affected: [
      {
        package: { name: 'alpha', ecosystem: 'npm' },
        ranges: [{ events: [{ introduced: '0', fixed: '2.0.1' }] }],
      },
    ],
  },
  'GHSA-alpha-0002': {
    id: 'GHSA-alpha-0002',
    summary: 'Alpha prototype pollution',
    aliases: ['CVE-2026-1002'],
    modified: '2026-03-01T10:00:00Z',
    database_specific: { severity: 'MODERATE' },
    affected: [
      {
        package: { name: 'alpha', ecosystem: 'npm' },
        ranges: [{ events: [{ introduced: '0', fixed: '2.1.0' }] }],
      },
    ],
  },
  'GHSA-shared-0001': {
    id: 'GHSA-shared-0001',
    summary: 'Shared package denial of service',
    aliases: ['CVE-2026-2001'],
    modified: '2026-01-20T10:00:00Z',
    database_specific: { severity: 'CRITICAL' },
    affected: [
      {
        package: { name: 'compartido', ecosystem: 'npm' },
        ranges: [{ events: [{ introduced: '0', fixed: '1.0.1' }] }],
      },
    ],
  },
  'GHSA-gamma-0001': {
    id: 'GHSA-gamma-0001',
    summary: 'Gamma information disclosure',
    database_specific: { severity: 'LOW' },
    affected: [
      {
        package: { name: 'gamma', ecosystem: 'npm' },
        ranges: [{ events: [{ introduced: '0', fixed: '1.0.1' }] }],
      },
    ],
  },
};

const VULNS_BY_PACKAGE: Record<string, string[]> = {
  alpha: ['GHSA-alpha-0001', 'GHSA-alpha-0002'],
  compartido: ['GHSA-shared-0001'],
  gamma: ['GHSA-gamma-0001'],
};

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

const fakeFetch: FetchLike = async (url, init) => {
  if (url.endsWith('/v1/querybatch')) {
    const payload = JSON.parse(String(init?.body)) as {
      queries: { package: { name: string } }[];
    };
    return json({
      results: payload.queries.map((query) => ({
        vulns: (VULNS_BY_PACKAGE[query.package.name] ?? []).map((id) => ({ id })),
      })),
    });
  }
  if (url.includes('/v1/vulns/')) {
    const id = decodeURIComponent(url.split('/v1/vulns/')[1]);
    const detail = ADVISORIES[id];
    return detail ? json(detail) : new Response('not found', { status: 404 });
  }
  // CISA KEV / EPSS enrichment is optional: an unavailable feed must not fail.
  return new Response('unavailable', { status: 503 });
};

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seginfo-sca-report-'));
  fs.cpSync(FIXTURE, dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'secrets.txt'), 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n');
});

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

describe('grouped SCA report', () => {
  it('groups by package identity without losing advisories, occurrences or locations', async () => {
    const scaFindings = await scanDependencies(undefined, { cwd: dir, fetchImpl: fakeFetch });
    const secretFindings = toFindings((await scanRepoDetailed(undefined, { cwd: dir })).findings);
    expect(secretFindings.some((finding) => finding.ruleId.startsWith('leakscan/'))).toBe(true);

    const all = [...scaFindings, ...secretFindings];
    const triaged = triageFindings(all);
    const view = buildScaView(all);

    // 2 advisories on alpha + 1 on compartido + 1 on gamma.
    expect(scaFindings).toHaveLength(4);
    expect(view.summary).toEqual({
      packages: 3,
      advisories: 4,
      occurrences: 4,
      directPackages: 2,
      transitivePackages: 1,
      unknownDirectness: 0,
      devPackages: 1,
      unclassified: 0,
    });
    // The flat triage view still holds every finding: grouping hides nothing.
    expect(triaged.summary.total).toBe(all.length);
    expect(view.packages.some((pkg) => pkg.key.startsWith('leakscan'))).toBe(false);

    const alpha = view.packages.find((pkg) => pkg.name === 'alpha');
    expect(alpha).toBeDefined();
    expect(alpha?.direct).toBe(true);
    expect(alpha?.dev).toBe(false);
    expect(alpha?.advisoryCount).toBe(2);
    expect(alpha?.occurrenceCount).toBe(2);
    // Same-major fix wins over the smaller jump to 2.1.0.
    expect(alpha?.fixTarget).toBe('2.0.1');
    expect(alpha?.fix).toContain('npm install alpha@2.0.1');
    expect(alpha?.why).toContain('directa');

    const alphaAdvisories = new Map(alpha?.advisories.map((item) => [item.vulnerabilityId, item]));
    expect([...alphaAdvisories.keys()].sort()).toEqual(['GHSA-alpha-0001', 'GHSA-alpha-0002']);
    expect(alphaAdvisories.get('GHSA-alpha-0001')).toMatchObject({
      severity: 'HIGH',
      level: 'error',
      kev: false,
      advisoryModified: '2026-02-01T10:00:00Z',
    });
    expect(alphaAdvisories.get('GHSA-alpha-0001')?.aliases).toContain('CVE-2026-1001');
    expect(alphaAdvisories.get('GHSA-alpha-0001')?.locations[0]?.file).toBe('package-lock.json');
    expect(alphaAdvisories.get('GHSA-alpha-0002')?.severity).toBe('MODERATE');

    const shared = view.packages.find((pkg) => pkg.name === 'compartido');
    expect(shared).toBeDefined();
    expect(shared?.direct).toBe(false);
    expect(shared?.dev).toBe(false);
    expect(shared?.introducedBy).toEqual(['alpha@2.0.0', 'beta@1.0.0']);
    expect(shared?.paths).toHaveLength(2);
    expect(shared?.paths).toContain('alpha > compartido');
    expect(shared?.paths).toContain('beta > compartido');
    // A transitive dependency is never presented as a direct install, and a
    // parent upgrade is never promised to fix it.
    expect(shared?.fix).toContain('no la instales directamente');
    expect(shared?.fix).toContain('alpha@2.0.0');
    expect(shared?.fix).toContain('beta@1.0.0');
    expect(shared?.fix).not.toContain('npm install compartido');

    const gamma = view.packages.find((pkg) => pkg.name === 'gamma');
    expect(gamma).toMatchObject({ direct: true, dev: true });
    expect(gamma?.fix).toContain('npm install gamma@1.0.1');
  });

  it('reports SCA findings without package data instead of dropping them', () => {
    const view = buildScaView([
      {
        ruleId: 'sca/GHSA-broken',
        message: 'A dependency is affected by GHSA-broken.',
        file: 'package-lock.json',
        line: 3,
        column: 1,
        level: 'warning',
      },
    ]);
    expect(view.summary).toMatchObject({ packages: 0, advisories: 0, occurrences: 0, unclassified: 1 });
  });
});

describe('pickFixTarget', () => {
  it('prefers the smallest same-major fixed version', () => {
    expect(pickFixTarget('2.0.0', ['2.1.0', '2.0.1', '3.0.0'])).toBe('2.0.1');
  });

  it('falls back to the smallest fixed version above the installed one', () => {
    expect(pickFixTarget('1.5.0', ['2.0.0', '1.4.9'])).toBe('2.0.0');
  });

  it('never returns a version at or below the installed one', () => {
    expect(pickFixTarget('2.0.0', ['2.0.0', '1.9.9'])).toBeNull();
    expect(pickFixTarget('2.0.0', [])).toBeNull();
    expect(pickFixTarget('2.0.0', ['not-a-version'])).toBeNull();
  });

  it('orders prereleases below the matching release', () => {
    expect(pickFixTarget('1.0.0', ['1.0.1-beta.1', '1.0.1'])).toBe('1.0.1');
  });
});

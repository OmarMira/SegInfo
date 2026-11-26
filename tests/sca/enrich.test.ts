import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { scanDependencies, type FetchLike } from '../../src/modules/sca/sca-engine.js';

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seginfo-sca-enrich-'));
});

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

function write(rel: string, content: string): void {
  const p = path.join(dir, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
}

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

const LOCK_V3 = JSON.stringify({
  lockfileVersion: 3,
  packages: {
    '': { name: 'fixture', version: '1.0.0' },
    'node_modules/lodash': { version: '4.17.15' },
  },
});

const LodashVuln = {
  id: 'GHSA-29mw-wpgm-hmr9',
  summary: 'Regular Expression Denial of Service (ReDoS) in lodash',
  aliases: ['CVE-2020-28500'],
  database_specific: { severity: 'MODERATE' },
  affected: [
    {
      package: { name: 'lodash', ecosystem: 'npm' },
      ranges: [{ events: [{ introduced: '4.0.0', fixed: '4.17.21' }] }],
    },
  ],
};

const KEV_URL_PART = 'known_exploited_vulnerabilities.json';
const EPSS_URL_PART = 'api.first.org/data/v1/epss';

/** A route value is a response body, or 'throw' to simulate a network failure. */
type IntelRoute = unknown | 'throw';

interface FetchRoutes {
  /** OSV vulnerability detail body (defaults to LodashVuln). */
  detail?: unknown;
  kev?: IntelRoute;
  epss?: IntelRoute;
}

/**
 * Fake fetch in the same style as sca-engine.test.ts: routes OSV first, then
 * the two threat-intel feeds. Unspecified intel routes throw, mimicking a
 * strict fake that knows nothing about KEV/EPSS (the pre-existing tests).
 */
function makeFetch(routes: FetchRoutes = {}): { fetchImpl: FetchLike; calls: string[] } {
  const calls: string[] = [];
  const fetchImpl: FetchLike = async (url) => {
    calls.push(url);
    if (url.endsWith('/v1/querybatch')) {
      return json({ results: [{ vulns: [{ id: LodashVuln.id }] }] });
    }
    if (url.includes('/v1/vulns/')) return json(routes.detail ?? LodashVuln);
    if (url.includes(KEV_URL_PART)) {
      if (routes.kev === 'throw') throw new TypeError('fetch failed');
      if (routes.kev !== undefined) return json(routes.kev);
      throw new Error(`unexpected url: ${url}`);
    }
    if (url.includes(EPSS_URL_PART)) {
      if (routes.epss === 'throw') throw new TypeError('fetch failed');
      if (routes.epss !== undefined) return json(routes.epss);
      throw new Error(`unexpected url: ${url}`);
    }
    throw new Error(`unexpected url: ${url}`);
  };
  return { fetchImpl, calls };
}

/** Realistic CISA KEV catalog body containing the given CVE ids. */
function kevCatalog(cves: string[]): unknown {
  return {
    title: 'CISA Catalog of Known Exploited Vulnerabilities',
    count: cves.length,
    vulnerabilities: cves.map((cveID) => ({
      cveID,
      vendorProject: 'Example',
      product: 'Example',
      vulnerabilityName: 'Example vulnerability',
      dateAdded: '2021-03-10',
      shortDescription: 'Example description',
      requiredAction: 'Apply updates',
      dueDate: '2021-04-01',
      knownRansomwareCampaignUse: 'Known',
      notes: 'https://example.test',
    })),
  };
}

/** Realistic FIRST EPSS response body (scores are strings in the real API). */
function epssBody(rows: Array<{ cve: string; epss: string }>): unknown {
  return { status: 'OK', total: rows.length, data: rows };
}

describe('threat-intel enrichment (KEV + EPSS)', () => {
  it('marks KEV-known vulnerabilities, bumps level to error and attaches EPSS', async () => {
    write('package-lock.json', LOCK_V3);
    const { fetchImpl, calls } = makeFetch({
      kev: kevCatalog(['CVE-2020-28500']),
      epss: epssBody([{ cve: 'CVE-2020-28500', epss: '0.00421' }]),
    });

    const findings = await scanDependencies(undefined, { cwd: dir, fetchImpl });

    expect(findings).toHaveLength(1);
    const f = findings[0];
    const props = f.properties ?? {};
    expect(f.level).toBe('error'); // MODERATE -> warning, KEV bump -> error
    expect(props.kev).toBe(true);
    expect(props.kevDate).toBe('2021-03-10');
    expect(props.ransomwareUse).toBe('Known');
    expect(typeof props.epss).toBe('number');
    expect(props.epss).toBeCloseTo(0.00421, 5);
    expect(props).not.toHaveProperty('enrichment');
    // KEV is fetched once per scan.
    expect(calls.filter((u) => u.includes(KEV_URL_PART))).toHaveLength(1);
    expect(calls.filter((u) => u.includes(EPSS_URL_PART))).toHaveLength(1);
  });

  it('adds kev:false only when the catalog was fetched, parsed, and missed', async () => {
    write('package-lock.json', LOCK_V3);
    const { fetchImpl } = makeFetch({
      kev: kevCatalog(['CVE-1999-0001']), // valid catalog without our CVE
      epss: epssBody([{ cve: 'CVE-2020-28500', epss: '0.5' }]),
    });

    const findings = await scanDependencies(undefined, { cwd: dir, fetchImpl });

    const f = findings[0];
    const props = f.properties ?? {};
    expect(f.level).toBe('warning'); // no bump on a KEV miss
    expect(props.kev).toBe(false);
    expect(props).not.toHaveProperty('kevDate');
    expect(props).not.toHaveProperty('ransomwareUse');
    expect(typeof props.epss).toBe('number');
    expect(props.epss).toBeCloseTo(0.5, 5);
    expect(props).not.toHaveProperty('enrichment');
  });

  it('keeps scanning when KEV and EPSS cannot be fetched', async () => {
    write('package-lock.json', LOCK_V3);
    const { fetchImpl } = makeFetch({ kev: 'throw', epss: 'throw' });

    const findings = await scanDependencies(undefined, { cwd: dir, fetchImpl });

    expect(findings).toHaveLength(1); // network failure must not fail the scan
    const props = findings[0].properties ?? {};
    expect(findings[0].level).toBe('warning');
    expect(props).not.toHaveProperty('kev'); // no "not exploited" claim
    expect(props).not.toHaveProperty('kevDate');
    expect(props).not.toHaveProperty('ransomwareUse');
    expect(props).not.toHaveProperty('epss');
    expect(props.enrichment).toBe('unavailable');
  });

  it('degrades to enrichment unavailable on unparseable feed bodies', async () => {
    write('package-lock.json', LOCK_V3);
    const { fetchImpl } = makeFetch({ kev: { unexpected: true }, epss: { unexpected: true } });

    const findings = await scanDependencies(undefined, { cwd: dir, fetchImpl });

    expect(findings).toHaveLength(1);
    const props = findings[0].properties ?? {};
    expect(props).not.toHaveProperty('kev');
    expect(props).not.toHaveProperty('epss');
    expect(props.enrichment).toBe('unavailable');
  });

  it('keeps KEV enrichment when only EPSS fails', async () => {
    write('package-lock.json', LOCK_V3);
    const { fetchImpl } = makeFetch({
      kev: kevCatalog(['CVE-2020-28500']),
      epss: 'throw',
    });

    const findings = await scanDependencies(undefined, { cwd: dir, fetchImpl });

    const f = findings[0];
    const props = f.properties ?? {};
    expect(f.level).toBe('error');
    expect(props.kev).toBe(true);
    expect(props.kevDate).toBe('2021-03-10');
    expect(props).not.toHaveProperty('epss'); // omitted, not guessed
    expect(props.enrichment).toBe('unavailable');
  });

  it('skips enrichment entirely when findings carry no CVE id', async () => {
    write('package-lock.json', LOCK_V3);
    const { fetchImpl, calls } = makeFetch({
      detail: { ...LodashVuln, aliases: ['GHSA-29mw-wpgm-hmr9'] }, // no CVE alias
    });

    const findings = await scanDependencies(undefined, { cwd: dir, fetchImpl });

    expect(findings).toHaveLength(1);
    const props = findings[0].properties ?? {};
    expect(calls.some((u) => u.includes(KEV_URL_PART))).toBe(false);
    expect(calls.some((u) => u.includes(EPSS_URL_PART))).toBe(false);
    expect(props).not.toHaveProperty('kev');
    expect(props).not.toHaveProperty('epss');
    expect(props).not.toHaveProperty('enrichment');
  });

  it('batches EPSS requests at 100 CVEs per request', async () => {
    write('package-lock.json', LOCK_V3);
    const many = Array.from({ length: 105 }, (_, i) => ({
      id: `GHSA-batch-${i}`,
      aliases: [`CVE-2021-${10000 + i}`],
      database_specific: { severity: 'LOW' },
      affected: [
        {
          package: { name: 'lodash', ecosystem: 'npm' },
          ranges: [{ events: [{ introduced: '0' }] }],
        },
      ],
    }));
    const epssCalls: string[] = [];
    const fetchImpl: FetchLike = async (url) => {
      if (url.endsWith('/v1/querybatch')) {
        return json({ results: [{ vulns: many.map((v) => ({ id: v.id })) }] });
      }
      if (url.includes('/v1/vulns/')) {
        const id = decodeURIComponent(url.split('/').pop() ?? '');
        const detail = many.find((v) => v.id === id);
        if (!detail) throw new Error(`unexpected id: ${id}`);
        return json(detail);
      }
      if (url.includes(KEV_URL_PART)) return json(kevCatalog([]));
      if (url.includes(EPSS_URL_PART)) {
        epssCalls.push(url);
        const cves = (url.split('cve=')[1] ?? '').split(',').filter(Boolean);
        return json(epssBody(cves.map((cve) => ({ cve, epss: '0.01' }))));
      }
      throw new Error(`unexpected url: ${url}`);
    };

    const findings = await scanDependencies(undefined, { cwd: dir, fetchImpl });

    expect(findings).toHaveLength(105);
    expect(epssCalls).toHaveLength(2);
    const firstCves = (epssCalls[0].split('cve=')[1] ?? '').split(',');
    const secondCves = (epssCalls[1].split('cve=')[1] ?? '').split(',');
    expect(firstCves).toHaveLength(100);
    expect(secondCves).toHaveLength(5);
    expect(findings[0].properties?.epss).toBeCloseTo(0.01, 5);
  });
});

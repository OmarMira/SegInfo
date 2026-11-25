import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { scanDependencies, severityToLevel, type FetchLike } from '../../src/modules/sca/sca-engine.js';

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seginfo-sca-'));
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

function fakeFetch(detail: unknown = LodashVuln): { fetchImpl: FetchLike; calls: string[] } {
  const calls: string[] = [];
  const fetchImpl: FetchLike = async (url, init) => {
    calls.push(url);
    if (url.endsWith('/v1/querybatch')) {
      const payload = JSON.parse(String(init?.body));
      expect(payload.queries[0]).toEqual({
        package: { name: 'lodash', ecosystem: 'npm' },
        version: '4.17.15',
      });
      return json({ results: [{ vulns: [{ id: LodashVuln.id }] }] });
    }
    if (url.includes('/v1/vulns/')) return json(detail);
    throw new Error(`unexpected url: ${url}`);
  };
  return { fetchImpl, calls };
}

describe('scanDependencies', () => {
  it('reports a vulnerable dependency with severity, remediation and manifest location', async () => {
    write('package-lock.json', LOCK_V3);
    const { fetchImpl } = fakeFetch();
    const findings = await scanDependencies(undefined, { cwd: dir, fetchImpl });

    expect(findings).toHaveLength(1);
    const f = findings[0];
    expect(f.ruleId).toBe('sca/GHSA-29mw-wpgm-hmr9');
    expect(f.file).toBe('package-lock.json');
    expect(f.line).toBeGreaterThan(0);
    expect(f.level).toBe('warning'); // MODERATE -> warning
    expect(f.message).toContain('lodash@4.17.15');
    expect(f.message).toContain('4.17.21');
    expect(f.properties).toMatchObject({
      package: 'lodash',
      version: '4.17.15',
      ecosystem: 'npm',
      vulnerabilityId: 'GHSA-29mw-wpgm-hmr9',
      fixedIn: ['4.17.21'],
      severity: 'MODERATE',
    });
  });

  it('escalates CRITICAL findings to error level', async () => {
    write('package-lock.json', LOCK_V3);
    const { fetchImpl } = fakeFetch({
      ...LodashVuln,
      database_specific: { severity: 'CRITICAL' },
    });
    const findings = await scanDependencies(undefined, { cwd: dir, fetchImpl });
    expect(findings[0].level).toBe('error');
  });

  it('scans requirements.txt against PyPI', async () => {
    write('requirements.txt', 'requests==2.19.0\n');
    const fetchImpl: FetchLike = async (url, init) => {
      if (url.endsWith('/v1/querybatch')) {
        const payload = JSON.parse(String(init?.body));
        expect(payload.queries[0]).toEqual({
          package: { name: 'requests', ecosystem: 'PyPI' },
          version: '2.19.0',
        });
        return json({ results: [{ vulns: [{ id: 'GHSA-3pcd-x44j-gq47' }] }] });
      }
      return json({
        id: 'GHSA-3pcd-x44j-gq47',
        summary: 'Leak proxy-authorization header on redirect',
        aliases: ['CVE-2018-18074'],
        database_specific: { severity: 'HIGH' },
        affected: [
          {
            package: { name: 'requests', ecosystem: 'PyPI' },
            ranges: [{ events: [{ introduced: '0', fixed: '2.20.0' }] }],
          },
        ],
      });
    };
    const findings = await scanDependencies(undefined, { cwd: dir, fetchImpl });
    expect(findings).toHaveLength(1);
    expect(findings[0].level).toBe('error'); // HIGH -> error
    expect(findings[0].file).toBe('requirements.txt');
    expect(findings[0].message).toContain('2.20.0');
  });

  it('returns an empty list when no manifest is found', async () => {
    await expect(scanDependencies(undefined, { cwd: dir })).rejects.toThrow(/manifest/i);
  });

  it('propagates network failures instead of reporting a clean scan', async () => {
    write('package-lock.json', LOCK_V3);
    const fetchImpl: FetchLike = async () => {
      throw new TypeError('fetch failed');
    };
    await expect(scanDependencies(undefined, { cwd: dir, fetchImpl })).rejects.toThrow(/OSV/);
  });

  it('rejects malformed OSV responses', async () => {
    write('package-lock.json', LOCK_V3);
    const fetchImpl: FetchLike = async (url) => {
      if (url.endsWith('/v1/querybatch')) return json({ unexpected: true });
      return json({});
    };
    await expect(scanDependencies(undefined, { cwd: dir, fetchImpl })).rejects.toThrow(/OSV/);
  });

  it('returns [] when OSV reports no vulnerabilities', async () => {
    write('package-lock.json', LOCK_V3);
    const fetchImpl: FetchLike = async (url) => {
      if (url.endsWith('/v1/querybatch')) return json({ results: [{}] });
      throw new Error('should not fetch details without vuln ids');
    };
    const findings = await scanDependencies(undefined, { cwd: dir, fetchImpl });
    expect(findings).toEqual([]);
  });
});

describe('severityToLevel', () => {
  it('maps GHSA/OSV severities to SARIF levels', () => {
    expect(severityToLevel('CRITICAL')).toBe('error');
    expect(severityToLevel('HIGH')).toBe('error');
    expect(severityToLevel('MODERATE')).toBe('warning');
    expect(severityToLevel('MEDIUM')).toBe('warning');
    expect(severityToLevel('LOW')).toBe('note');
    expect(severityToLevel(undefined)).toBe('warning');
    expect(severityToLevel('SOMETHING_NEW')).toBe('warning');
  });
});

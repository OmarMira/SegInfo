import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  buildProvenance,
  latestAdvisoryUpdate,
  readGitState,
} from '../../src/server/provenance.js';
import type { Finding } from '../../src/report/sarif.js';

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seginfo-prov-'));
});

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

function git(args: string[]): string {
  return execFileSync('git', args, {
    cwd: dir,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  }).trim();
}

function finding(ruleId: string, properties?: Record<string, unknown>): Finding {
  return { ruleId, message: ruleId, file: 'package-lock.json', line: 1, column: 1, level: 'warning', properties };
}

describe('readGitState', () => {
  it('reports no repository facts outside a git work tree', async () => {
    expect(await readGitState(dir)).toEqual({
      gitRepository: false,
      ref: null,
      commit: null,
      dirty: null,
      shallow: null,
    });
  });

  it('captures the branch, commit and dirty state of a real repository', async () => {
    git(['init', '-q']);
    git(['-c', 'user.email=test@example.com', '-c', 'user.name=Test', 'commit', '--allow-empty', '-m', 'init']);
    const branch = git(['symbolic-ref', '--short', 'HEAD']);

    const clean = await readGitState(dir);
    expect(clean.gitRepository).toBe(true);
    expect(clean.ref).toBe(branch);
    expect(clean.commit).toMatch(/^[0-9a-f]{40}$/);
    expect(clean.dirty).toBe(false);
    expect(clean.shallow).toBe(false);

    fs.writeFileSync(path.join(dir, 'new-file.txt'), 'x');
    expect((await readGitState(dir)).dirty).toBe(true);
  });
});

describe('latestAdvisoryUpdate', () => {
  it('returns the newest advisory timestamp and ignores other findings', () => {
    expect(
      latestAdvisoryUpdate([
        finding('sca/GHSA-1', { advisoryModified: '2026-01-01T00:00:00Z' }),
        finding('sca/GHSA-2', {
          advisoryModified: '2026-05-01T00:00:00Z',
          advisoryPublished: '2025-01-01T00:00:00Z',
        }),
        finding('sca/GHSA-3', { advisoryPublished: '2024-01-01T00:00:00Z' }),
        finding('leakscan/aws-access-key', { advisoryModified: '2030-01-01T00:00:00Z' }),
      ]),
    ).toBe('2026-05-01T00:00:00Z');
  });

  it('returns null when no advisory publishes a timestamp', () => {
    expect(latestAdvisoryUpdate([finding('sca/GHSA-1', { advisoryModified: null })])).toBeNull();
    expect(latestAdvisoryUpdate([])).toBeNull();
  });
});

describe('buildProvenance', () => {
  it('describes a shallow clone without presenting it as a complete history scan', () => {
    const prov = buildProvenance({
      origin: 'repository-clone',
      source: 'https://github.com/owner/repo',
      git: {
        gitRepository: true,
        ref: 'main',
        commit: 'a'.repeat(40),
        dirty: false,
        shallow: true,
      },
      scannedAt: '2026-11-26T00:00:00.000Z',
      workingTree: true,
      history: {
        attempted: true,
        gitRepository: true,
        shallow: true,
        commitsScanned: 1,
        truncated: false,
      },
      manifests: ['package-lock.json'],
      findings: [
        finding('sca/GHSA-1', { advisoryModified: '2026-01-01T00:00:00Z' }),
        finding('sca/GHSA-2', { advisoryModified: '2026-05-01T00:00:00Z' }),
      ],
      scaRan: true,
    });

    expect(prov).toMatchObject({
      origin: 'repository-clone',
      source: 'https://github.com/owner/repo',
      ref: 'main',
      commit: 'a'.repeat(40),
      dirty: false,
      scannedAt: '2026-11-26T00:00:00.000Z',
      scope: {
        workingTree: true,
        gitHistory: true,
        manifests: ['package-lock.json'],
      },
      vulnerabilityData: { source: 'OSV', latestAdvisoryUpdate: '2026-05-01T00:00:00Z' },
    });
    expect(prov.scope.history?.shallow).toBe(true);
  });

  it('omits vulnerability data when SCA did not run and history when it was not attempted', () => {
    const prov = buildProvenance({
      origin: 'local-path',
      source: 'C:/work/project',
      scannedAt: '2026-11-26T00:00:00.000Z',
      workingTree: true,
      findings: [],
      scaRan: false,
    });
    expect(prov.vulnerabilityData).toBeNull();
    expect(prov.scope.history).toBeNull();
    expect(prov.scope.gitHistory).toBe(false);
    expect(prov.commit).toBeNull();
  });
});

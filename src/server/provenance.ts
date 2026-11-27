import { execFile } from 'node:child_process';
import type { HistoryCoverage } from '../modules/leakscan/leak-scan-engine.js';
import type { Finding } from '../report/sarif.js';

/**
 * Scan provenance: where the scanned code came from and what was actually
 * covered. The report must never present a shallow clone or a capped history
 * walk as a complete scan, and it must not call a temporary clone a "local
 * working tree".
 */

export type ProvenanceOrigin = 'repository-clone' | 'local-path' | 'remote-url';

export interface GitState {
  gitRepository: boolean;
  /** Checked-out branch, or `null` for a detached HEAD. */
  ref: string | null;
  /** Full commit sha of HEAD, when the tree is a git repository. */
  commit: string | null;
  /** True when the checkout has uncommitted or untracked changes. */
  dirty: boolean | null;
  /** True for a shallow clone, whose history is incomplete; `null` when unknown. */
  shallow: boolean | null;
}

export interface ProvenanceScope {
  /** True when the current file tree was walked. */
  workingTree: boolean;
  /** True when a git history pass ran on a real repository. */
  gitHistory: boolean;
  /** Observed history coverage, `null` when the pass did not run. */
  history: HistoryCoverage | null;
  /** Manifests the SCA module actually read, relative to the scan root. */
  manifests: string[];
}

export interface Provenance {
  origin: ProvenanceOrigin;
  /** Repository URL, local absolute path or live URL that was scanned. */
  source: string;
  /** Ref explicitly requested by the caller, when the UI/API supports one. */
  requestedRef: string | null;
  ref: string | null;
  commit: string | null;
  dirty: boolean | null;
  /** ISO timestamp of the scan start (the moment the request was accepted). */
  scannedAt: string;
  scope: ProvenanceScope;
  /** Vulnerability data source; `null` when the SCA module did not run. */
  vulnerabilityData: { source: 'OSV'; latestAdvisoryUpdate: string | null } | null;
}

const GIT_TIMEOUT_MS = 10_000;
const FULL_SHA = /^[0-9a-f]{40}$/i;

function runGit(dir: string, args: string[]): Promise<string | null> {
  return new Promise((resolve) => {
    execFile(
      'git',
      ['-C', dir, ...args],
      { timeout: GIT_TIMEOUT_MS, windowsHide: true, maxBuffer: 1024 * 1024 },
      (error, stdout) => resolve(error ? null : String(stdout).trim()),
    );
  });
}

/**
 * Reads the git state of `dir` without ever throwing: a missing git binary,
 * a non-repository or a permission error degrade to `null` facts instead of
 * inventing metadata.
 */
export async function readGitState(dir: string): Promise<GitState> {
  const inside = await runGit(dir, ['rev-parse', '--is-inside-work-tree']);
  if (inside !== 'true') {
    return { gitRepository: false, ref: null, commit: null, dirty: null, shallow: null };
  }

  const [commit, ref, status, shallow] = await Promise.all([
    runGit(dir, ['rev-parse', 'HEAD']),
    runGit(dir, ['rev-parse', '--abbrev-ref', 'HEAD']),
    runGit(dir, ['status', '--porcelain']),
    runGit(dir, ['rev-parse', '--is-shallow-repository']),
  ]);

  return {
    gitRepository: true,
    commit: commit && FULL_SHA.test(commit) ? commit : null,
    ref: ref && ref !== 'HEAD' ? ref : null,
    dirty: status === null ? null : status.length > 0,
    shallow: shallow === 'true' ? true : shallow === 'false' ? false : null,
  };
}

/**
 * Latest advisory `modified` (or `published`) timestamp seen in this scan.
 * OSV does not publish a feed-wide "updated" date, so only the advisories'
 * own timestamps are reported.
 */
export function latestAdvisoryUpdate(findings: Finding[]): string | null {
  let latest: string | null = null;
  let latestTime = Number.NEGATIVE_INFINITY;
  for (const finding of findings) {
    if (!finding.ruleId.startsWith('sca/')) continue;
    const value = finding.properties?.advisoryModified ?? finding.properties?.advisoryPublished;
    if (typeof value !== 'string' || value.trim() === '') continue;
    const time = Date.parse(value);
    if (Number.isNaN(time) || time <= latestTime) continue;
    latest = value;
    latestTime = time;
  }
  return latest;
}

export interface ProvenanceInput {
  origin: ProvenanceOrigin;
  source: string;
  requestedRef?: string | null;
  git?: GitState | null;
  scannedAt: string;
  workingTree: boolean;
  history?: HistoryCoverage | null;
  manifests?: string[];
  findings: Finding[];
  scaRan: boolean;
}

export function buildProvenance(input: ProvenanceInput): Provenance {
  const git = input.git ?? null;
  const history = input.history ?? null;
  return {
    origin: input.origin,
    source: input.source,
    requestedRef: input.requestedRef ?? null,
    ref: git?.ref ?? null,
    commit: git?.commit ?? null,
    dirty: git?.dirty ?? null,
    scannedAt: input.scannedAt,
    scope: {
      workingTree: input.workingTree,
      gitHistory: history?.attempted === true && history.gitRepository === true,
      history,
      manifests: input.manifests ?? [],
    },
    vulnerabilityData: input.scaRan
      ? { source: 'OSV', latestAdvisoryUpdate: latestAdvisoryUpdate(input.findings) }
      : null,
  };
}

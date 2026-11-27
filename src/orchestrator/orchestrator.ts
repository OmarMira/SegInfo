import * as fs from 'node:fs';
import * as path from 'node:path';
import { minimatch } from 'minimatch';
import {
  scanRepoDetailed,
  type HistoryCoverage,
} from '../modules/leakscan/leak-scan-engine.js';
import { toFindings } from '../modules/leakscan/normalize.js';
import { findManifests, scanDependencies } from '../modules/sca/sca-engine.js';
import { scanIac } from '../modules/iac/iac-engine.js';
import { NothingToScanError } from '../util/errors.js';
import { writeMergedSarif, type Finding } from '../report/sarif.js';
import { triageFindings, type TriageResult } from '../triage/triage.js';
import { loadConfig, type ModuleId, type ScanConfig } from './config.js';

export type ModuleRunner = (
  target: string | undefined,
  options: { cwd: string },
) => Promise<Finding[]>;

/** What the modules actually observed, for the provenance block. */
export interface ObservedCoverage {
  /** History coverage reported by leakscan, when that module ran. */
  history?: HistoryCoverage;
  /** Manifests the SCA module read, relative to the scan root. */
  manifests?: string[];
}

/** Real engines, used for any module without an injected runner. */
function realRunners(observed: ObservedCoverage): Record<ModuleId, ModuleRunner> {
  return {
    leakscan: async (target, options) => {
      const result = await scanRepoDetailed(target, { cwd: options.cwd });
      observed.history = result.coverage.history;
      return toFindings(result.findings);
    },
    sca: async (target, options) => {
      const manifests = findManifests(target, options.cwd);
      observed.manifests = manifests
        .map((manifest) => path.relative(options.cwd, manifest).split(path.sep).join('/'))
        .sort();
      return scanDependencies(target, { cwd: options.cwd });
    },
    iac: (target, options) => scanIac(target, { cwd: options.cwd }),
  };
}

const LEVEL_RANK: Record<Finding['level'], number> = {
  none: 0,
  note: 1,
  warning: 2,
  error: 3,
};

export interface OrchestratorOptions {
  cwd?: string;
  /** Pre-loaded config; otherwise loaded from cwd / configPath. */
  config?: ScanConfig;
  configPath?: string;
  /** Injected module runners (tests); defaults to the real engines. */
  runners?: Partial<Record<ModuleId, ModuleRunner>>;
  /**
   * Write the merged SARIF file. The local server sets this to false so a
   * browser scan never mutates the directory being scanned.
   */
  writeReport?: boolean;
}

export interface ModuleSkip {
  module: ModuleId;
  reason: string;
}

export interface ModuleFailure {
  module: ModuleId;
  message: string;
}

export interface OrchestratorResult {
  exitCode: 0 | 1;
  /** Findings after the ignore filter, across all modules. */
  totalFindings: number;
  findings: Finding[];
  skipped: ModuleSkip[];
  failures: ModuleFailure[];
  outputPath: string;
  /** Deduplicated, bucketed view of `findings` (findings are annotated too). */
  triage: TriageResult;
  /** What the modules actually observed (history depth, SCA manifests). */
  coverage?: ObservedCoverage;
}

function isDirectory(p: string): boolean {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
}

/**
 * Runs every enabled module in parallel, merges their findings into a single
 * SARIF document and computes an honest exit code:
 *
 * - a module that throws NothingToScanError is reported as skipped;
 * - any other module failure forces exit 1 (an outage is never a clean scan);
 * - otherwise exit 1 when a kept finding reaches the `failOn` threshold.
 *
 * @param target scan root directory (or undefined for cwd). Files and globs
 *               belong to the single-module modes.
 * @throws on a non-directory target or an invalid/missing explicit config.
 */
export async function runOrchestrator(
  target?: string,
  options: OrchestratorOptions = {},
): Promise<OrchestratorResult> {
  const cwd = options.cwd ?? process.cwd();
  // Scan root: everything (config discovery, module cwd, relative finding
  // paths, output resolution) anchors to the directory being scanned.
  const absTarget = target ? path.resolve(cwd, target) : cwd;

  if (target && !isDirectory(absTarget)) {
    throw new Error(
      `Orchestrator target must be a directory: ${target} ` +
        '(use --mode leakscan|sca|iac for files or glob patterns)',
    );
  }

  const config =
    options.config ?? loadConfig({ cwd, searchDir: absTarget, configPath: options.configPath });

  const enabled = config.modules;
  const observed: ObservedCoverage = {};
  const runners = realRunners(observed);
  const settled = await Promise.allSettled(
    enabled.map(async (id) => {
      const runner = options.runners?.[id] ?? runners[id];
      return { id, findings: await runner(absTarget, { cwd: absTarget }) };
    }),
  );

  const skipped: ModuleSkip[] = [];
  const failures: ModuleFailure[] = [];
  const ran: Array<{ id: ModuleId; findings: Finding[] }> = [];

  settled.forEach((result, i) => {
    const id = enabled[i];
    if (result.status === 'fulfilled') {
      ran.push(result.value);
      return;
    }
    const err = result.reason;
    const message = err instanceof Error ? err.message : String(err);
    if (err instanceof NothingToScanError) skipped.push({ module: id, reason: message });
    else failures.push({ module: id, message });
  });

  const notIgnored = (f: Finding): boolean =>
    !config.ignore.some((pattern) => minimatch(f.file, pattern, { dot: true }));

  const runs = ran.map((entry) => ({
    toolName: entry.id,
    findings: entry.findings.filter(notIgnored),
  }));
  const findings = runs.flatMap((run) => run.findings);
  const triage = triageFindings(findings);

  const outputPath =
    options.writeReport === false
      ? ''
      : writeMergedSarif(runs, path.resolve(absTarget, config.output));

  const threshold = LEVEL_RANK[config.failOn];
  const failsOnSeverity = findings.some((f) => LEVEL_RANK[f.level] >= threshold);
  const exitCode: 0 | 1 = failures.length > 0 || failsOnSeverity ? 1 : 0;

  return {
    exitCode,
    totalFindings: findings.length,
    findings,
    skipped,
    failures,
    outputPath,
    triage,
    coverage: observed,
  };
}

import * as fs from 'node:fs';
import * as path from 'node:path';
import { parsePackageLock, parseRequirementsTxt, type Dependency } from './manifest.js';
import { queryVulnerabilities, type VulnDetail } from './osv.js';
import type { Finding, SarifLevel } from '../../report/sarif.js';

export type { FetchLike, HttpResponse } from './osv.js';

export interface ScaOptions {
  cwd?: string;
  /** Injected OSV client (tests); defaults to global fetch. */
  fetchImpl?: import('./osv.js').FetchLike;
  timeoutMs?: number;
}

const MANIFESTS = ['package-lock.json', 'requirements.txt'] as const;
const MAX_SUMMARY_LENGTH = 200;

export function severityToLevel(severity: string | undefined): SarifLevel {
  switch ((severity ?? '').toUpperCase()) {
    case 'CRITICAL':
    case 'HIGH':
      return 'error';
    case 'MODERATE':
    case 'MEDIUM':
      return 'warning';
    case 'LOW':
      return 'note';
    default:
      return 'warning';
  }
}

function extractSeverity(detail: VulnDetail): string | undefined {
  const db = detail.database_specific;
  if (db && typeof db === 'object' && 'severity' in db) {
    const severity = (db as Record<string, unknown>).severity;
    if (typeof severity === 'string') return severity.toUpperCase();
  }
  return undefined;
}

/** Collects `fixed` events from affected entries matching this exact package. */
function extractFixedIn(detail: VulnDetail, dep: Dependency): string[] {
  const affected = detail.affected;
  if (!Array.isArray(affected)) return [];
  const fixed = new Set<string>();
  for (const entry of affected) {
    if (!entry || typeof entry !== 'object') continue;
    const record = entry as Record<string, unknown>;
    const pkg = record.package as Record<string, unknown> | undefined;
    if (!pkg || pkg.name !== dep.name || pkg.ecosystem !== dep.ecosystem) continue;
    const ranges = record.ranges;
    if (!Array.isArray(ranges)) continue;
    for (const range of ranges) {
      if (!range || typeof range !== 'object') continue;
      const events = (range as Record<string, unknown>).events;
      if (!Array.isArray(events)) continue;
      for (const event of events) {
        if (event && typeof event === 'object') {
          const fixedVersion = (event as Record<string, unknown>).fixed;
          if (typeof fixedVersion === 'string') fixed.add(fixedVersion);
        }
      }
    }
  }
  return [...fixed];
}

function safeIsDirectory(p: string): boolean {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
}

function loadManifest(absPath: string, relPath: string): Dependency[] {
  let content: string;
  try {
    content = fs.readFileSync(absPath, 'utf8');
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new Error(`Cannot read ${relPath}: ${reason}`, { cause: err });
  }
  const base = path.basename(absPath);
  const deps =
    base === 'package-lock.json'
      ? parsePackageLock(content, relPath)
      : parseRequirementsTxt(content, relPath);
  return deps;
}

/**
 * SCA scan: find manifests, resolve pinned versions against OSV and
 * normalize results to SARIF findings.
 *
 * @param target directory, or an explicit manifest file. Defaults to cwd.
 * @throws when no manifest exists or OSV is unreachable — never reports a
 *         clean scan it did not actually perform.
 */
export async function scanDependencies(
  target?: string,
  options: ScaOptions = {},
): Promise<Finding[]> {
  const cwd = options.cwd ?? process.cwd();
  const resolved = target ? path.resolve(cwd, target) : cwd;
  const isDir = safeIsDirectory(resolved);

  const manifests: string[] = [];
  if (target && !isDir) {
    const base = path.basename(resolved);
    if (!(MANIFESTS as readonly string[]).includes(base)) {
      throw new Error(`Unsupported manifest: ${base} (expected one of ${MANIFESTS.join(', ')})`);
    }
    manifests.push(resolved);
  } else {
    for (const name of MANIFESTS) {
      const candidate = path.join(resolved, name);
      if (safeIsDirectory(candidate)) continue;
      if (fs.existsSync(candidate)) manifests.push(candidate);
    }
  }
  if (manifests.length === 0) {
    throw new Error(
      `No manifests found: SCA scanning needs ${MANIFESTS.join(' or ')} in ${resolved}`,
    );
  }

  const deps: Dependency[] = [];
  const relOf = (abs: string): string =>
    path.relative(cwd, abs).split(path.sep).join('/') || path.basename(abs);
  for (const manifest of manifests) {
    const rel = relOf(manifest);
    for (const dep of loadManifest(manifest, rel)) {
      deps.push({ ...dep, file: rel });
    }
  }
  if (deps.length === 0) return []; // manifests exist but pin nothing

  const byDep = await queryVulnerabilities(deps, {
    fetchImpl: options.fetchImpl,
    timeoutMs: options.timeoutMs,
  });

  const findings: Finding[] = [];
  for (const [depIndex, vulns] of byDep) {
    const dep = deps[depIndex];
    if (!dep) continue;
    for (const vuln of vulns) {
      const severity = extractSeverity(vuln);
      const fixedIn = extractFixedIn(vuln, dep);
      const cve = vuln.aliases?.find((alias) => alias.startsWith('CVE-'));
      const summary = vuln.summary ? vuln.summary.slice(0, MAX_SUMMARY_LENGTH) : '';
      findings.push({
        ruleId: `sca/${vuln.id}`,
        message:
          `${dep.name}@${dep.version} is affected by ${vuln.id}${cve ? ` (${cve})` : ''}` +
          `${summary ? `: ${summary}` : ''}. ` +
          (fixedIn.length > 0 ? `Fixed in ${fixedIn.join(', ')}` : 'No fixed version published'),
        file: dep.file,
        line: dep.line,
        column: 1,
        level: severityToLevel(severity),
        properties: {
          package: dep.name,
          version: dep.version,
          ecosystem: dep.ecosystem,
          vulnerabilityId: vuln.id,
          aliases: vuln.aliases ?? [],
          severity: severity ?? 'UNKNOWN',
          fixedIn,
        },
      });
    }
  }
  return findings;
}

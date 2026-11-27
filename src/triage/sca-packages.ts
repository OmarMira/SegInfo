import type { Finding, SarifLevel } from '../report/sarif.js';
import type { TriageBucket } from './triage.js';

/**
 * Grouped SCA view: one row per resolved package identity
 * (`ecosystem:name@version`) instead of one row per advisory occurrence.
 *
 * Grouping is presentation only. Every advisory keeps its id, aliases,
 * severity, evidence and manifest location, and the view reports three
 * separate counts (packages, distinct advisories, occurrences) so the real
 * total is never reduced. Non-SCA findings are ignored here and stay in the
 * regular triage groups.
 */

export interface ScaLocation {
  file: string;
  line: number;
}

export interface ScaAdvisory {
  ruleId: string;
  vulnerabilityId: string;
  aliases: string[];
  severity: string;
  level: SarifLevel;
  bucket: TriageBucket;
  message: string;
  fixedIn: string[];
  kev: boolean;
  advisoryModified: string | null;
  advisoryPublished: string | null;
  /** Every manifest location this advisory was reported at. */
  locations: ScaLocation[];
  /** Number of findings collapsed into this advisory entry. */
  occurrences: number;
}

export interface ScaPackage {
  /** Stable identity: `ecosystem:name@version`. */
  key: string;
  name: string;
  version: string;
  ecosystem: string;
  /** `true` only when every resolved instance is a direct dependency. */
  direct: boolean | null;
  /** `true` only when every path reaches it through dev dependencies. */
  dev: boolean | null;
  /** Immediate packages that require it, as `name@version`. */
  introducedBy: string[];
  /** Introduction chains from the root (display-capped). */
  paths: string[];
  pathsTotal: number | null;
  pathsTruncated: boolean;
  locations: ScaLocation[];
  level: SarifLevel;
  severity: string;
  bucket: TriageBucket;
  advisories: ScaAdvisory[];
  /** Distinct advisories affecting this package. */
  advisoryCount: number;
  /** Findings collapsed into this package (advisory occurrences). */
  occurrenceCount: number;
  /** Smallest published fixed version above the installed one, when known. */
  fixTarget: string | null;
  /** Package-specific explanation (Spanish). */
  why: string;
  /** Package-specific remediation (Spanish, never a direct install for transitives). */
  fix: string;
}

export interface ScaSummary {
  packages: number;
  /** Distinct advisory ids across the whole view. */
  advisories: number;
  /** SCA finding rows collapsed into packages. */
  occurrences: number;
  directPackages: number;
  transitivePackages: number;
  unknownDirectness: number;
  devPackages: number;
  /** SCA findings without package data; kept out of the view, never dropped. */
  unclassified: number;
}

export interface ScaView {
  summary: ScaSummary;
  packages: ScaPackage[];
}

const LEVEL_RANK: Record<SarifLevel, number> = {
  none: 0,
  note: 1,
  warning: 2,
  error: 3,
};

const BUCKET_RANK: Record<TriageBucket, number> = {
  confirmed: 0,
  review: 1,
  'likely-example': 2,
};

const SEVERITY_RANK: Record<string, number> = {
  UNKNOWN: 0,
  LOW: 1,
  MODERATE: 2,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

const MAX_DISPLAY_PATHS = 10;

interface ParsedVersion {
  nums: number[];
  pre: string[];
}

/** Parses a dotted version (with optional prerelease) without extra deps. */
function parseVersion(value: string): ParsedVersion | null {
  const match = /^v?(\d+(?:\.\d+)*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(
    value.trim(),
  );
  if (!match) return null;
  return {
    nums: match[1].split('.').map((part) => Number(part)),
    pre: match[2] ? match[2].split('.') : [],
  };
}

function compareVersions(a: ParsedVersion, b: ParsedVersion): number {
  const length = Math.max(a.nums.length, b.nums.length);
  for (let i = 0; i < length; i++) {
    const left = a.nums[i] ?? 0;
    const right = b.nums[i] ?? 0;
    if (left !== right) return left - right;
  }
  if (a.pre.length === 0 && b.pre.length > 0) return 1;
  if (b.pre.length === 0 && a.pre.length > 0) return -1;
  const preLength = Math.max(a.pre.length, b.pre.length);
  for (let i = 0; i < preLength; i++) {
    const left = a.pre[i];
    const right = b.pre[i];
    if (left === undefined) return -1;
    if (right === undefined) return 1;
    const leftNumeric = /^\d+$/.test(left);
    const rightNumeric = /^\d+$/.test(right);
    if (leftNumeric && rightNumeric) {
      const delta = Number(left) - Number(right);
      if (delta !== 0) return delta;
    } else if (leftNumeric) {
      return -1;
    } else if (rightNumeric) {
      return 1;
    } else {
      const delta = left.localeCompare(right);
      if (delta !== 0) return delta;
    }
  }
  return 0;
}

/**
 * Smallest fixed version strictly above the installed one, preferring the
 * same major (the least disruptive upgrade). Returns `null` when no advisory
 * publishes a usable fixed version — never invents one.
 */
export function pickFixTarget(installed: string, candidates: string[]): string | null {
  const installedParsed = parseVersion(installed);
  const parsed: { raw: string; version: ParsedVersion }[] = [];
  for (const candidate of new Set(candidates)) {
    if (typeof candidate !== 'string' || candidate.trim() === '') continue;
    const version = parseVersion(candidate);
    if (!version) continue;
    if (installedParsed && compareVersions(version, installedParsed) <= 0) continue;
    parsed.push({ raw: candidate.trim(), version });
  }
  parsed.sort((a, b) => compareVersions(a.version, b.version));
  if (parsed.length === 0) return null;
  // Prefer a stable release over a prerelease when both are published: a
  // prerelease is a valid fixed version but a risky default upgrade.
  const stable = parsed.filter((entry) => entry.version.pre.length === 0);
  const pool = stable.length > 0 ? stable : parsed;
  if (installedParsed) {
    const sameMajor = pool.find(
      (entry) => (entry.version.nums[0] ?? 0) === (installedParsed.nums[0] ?? 0),
    );
    if (sameMajor) return sameMajor.raw;
  }
  return pool[0].raw;
}

function stringProperty(
  properties: Record<string, unknown> | undefined,
  key: string,
): string | null {
  const value = properties?.[key];
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : null;
}

function stringArrayProperty(
  properties: Record<string, unknown> | undefined,
  key: string,
): string[] {
  const value = properties?.[key];
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === 'string' && item.trim() !== '');
}

function booleanProperty(
  properties: Record<string, unknown> | undefined,
  key: string,
): boolean | null {
  const value = properties?.[key];
  return typeof value === 'boolean' ? value : null;
}

function locationsProperty(
  properties: Record<string, unknown> | undefined,
  fallback: ScaLocation,
): ScaLocation[] {
  const value = properties?.locations;
  if (!Array.isArray(value)) return [fallback];
  const locations: ScaLocation[] = [];
  for (const item of value) {
    if (typeof item !== 'object' || item === null) continue;
    const record = item as Record<string, unknown>;
    if (typeof record.file !== 'string' || record.file === '') continue;
    const line = typeof record.line === 'number' && Number.isFinite(record.line) ? record.line : 1;
    if (locations.some((entry) => entry.file === record.file && entry.line === line)) continue;
    locations.push({ file: record.file, line });
  }
  return locations.length > 0 ? locations : [fallback];
}

function bucketOf(properties: Record<string, unknown> | undefined): TriageBucket {
  const triage = properties?.triage;
  if (typeof triage === 'object' && triage !== null) {
    const bucket = (triage as Record<string, unknown>).bucket;
    if (bucket === 'confirmed' || bucket === 'review' || bucket === 'likely-example') {
      return bucket;
    }
  }
  return 'review';
}

function highestLevel(levels: SarifLevel[]): SarifLevel {
  let best: SarifLevel = 'none';
  for (const level of levels) {
    if (LEVEL_RANK[level] > LEVEL_RANK[best]) best = level;
  }
  return best;
}

function highestSeverity(severities: string[]): string {
  let best = 'UNKNOWN';
  for (const severity of severities) {
    const normalized = severity.toUpperCase();
    if ((SEVERITY_RANK[normalized] ?? 0) > (SEVERITY_RANK[best] ?? 0)) best = normalized;
  }
  return best;
}

function highestRiskBucket(buckets: TriageBucket[]): TriageBucket {
  let best: TriageBucket = 'likely-example';
  for (const bucket of buckets) {
    if (BUCKET_RANK[bucket] < BUCKET_RANK[best]) best = bucket;
  }
  return best;
}

function ecosystemCommand(ecosystem: string, name: string, version: string): string | null {
  if (ecosystem === 'npm') return `npm install ${name}@${version}`;
  if (ecosystem === 'PyPI') return `pip install -U "${name}>=${version}"`;
  return null;
}

/** Package-level explanation: what is affected, how it arrives, how bad it is. */
function buildWhy(pkg: Omit<ScaPackage, 'why' | 'fix'>): string {
  const ids = pkg.advisories.map((advisory) => advisory.vulnerabilityId).filter(Boolean);
  const shown = ids.slice(0, 3).join(', ');
  const more = ids.length > 3 ? ` y ${ids.length - 3} más` : '';
  const scope =
    pkg.direct === false
      ? 'transitiva'
      : pkg.direct === true
        ? 'directa'
        : 'de directness desconocida';
  const dev = pkg.dev === true ? ', solo de desarrollo' : pkg.dev === false ? ', de producción' : '';
  const count = pkg.advisoryCount === 1 ? '1 aviso' : `${pkg.advisoryCount} avisos`;

  let text =
    `La dependencia ${scope} ${pkg.name}@${pkg.version} acumula ${count} de OSV` +
    `${ids.length > 0 ? ` (${shown}${more})` : ''}${dev}.`;
  if (pkg.direct === false && pkg.introducedBy.length > 0) {
    text += ` Llega a través de ${pkg.introducedBy.join(', ')}.`;
  }
  if (pkg.pathsTruncated && pkg.pathsTotal !== null) {
    text += ` Se enumeraron ${pkg.pathsTotal} rutas de introducción (se muestran ${pkg.paths.length}).`;
  } else if (pkg.paths.length > 0) {
    const shownPaths = pkg.paths.slice(0, 3).join('; ');
    text += ` Rutas: ${shownPaths}${pkg.paths.length > 3 ? '; …' : ''}.`;
  }
  return text;
}

/**
 * Package-level remediation. A transitive package is never presented as a
 * direct install, and a parent upgrade is never promised to fix it.
 */
function buildFix(pkg: Omit<ScaPackage, 'why' | 'fix'>): string {
  const urgency = pkg.advisories.some((advisory) => advisory.kev)
    ? ' Al menos un aviso está catalogado como explotado en el mundo real (CISA KEV): priorizalo.'
    : '';
  const target = pkg.fixTarget;
  const published = target
    ? `La corrección publicada más cercana es ${target}.`
    : 'No hay versión corregida publicada en los avisos consultados.';

  if (pkg.direct === false) {
    const parents = pkg.introducedBy.length > 0 ? pkg.introducedBy.join(', ') : 'el paquete que la requiere';
    return (
      `Es una dependencia transitiva: no la instales directamente en el proyecto. ` +
      `Actualizá el paquete que la introduce (${parents}) y volvé a escanear; si el padre sigue fijando esta versión, ` +
      `evaluá un override o resolución y verificá el árbol resultante. ${published}${urgency}`
    );
  }

  if (pkg.direct === true) {
    const command = target ? ecosystemCommand(pkg.ecosystem, pkg.name, target) : null;
    const hint = command ? ` (${command})` : '';
    return target
      ? `Actualizá la dependencia directa ${pkg.name} a ${target} o superior${hint}. ` +
          `Si todavía no podés, aplicá el mitigante del aviso y registrá la excepción con fecha de revisión.${urgency}`
      : `No hay versión corregida publicada para ${pkg.name}: aplicá el mitigante del aviso o reemplazala por una alternativa mantenida.${urgency}`;
  }

  return (
    `No se pudo determinar si ${pkg.name} es directa o transitiva con los manifiestos disponibles: ` +
    `revisá package.json y el lockfile antes de cambiar nada. ${published}${urgency}`
  );
}

interface GroupedEntry {
  key: string;
  name: string;
  version: string;
  ecosystem: string;
  findings: Finding[];
}

/**
 * Builds the package-grouped SCA view from triaged findings.
 *
 * The returned summary is always internally consistent with the input:
 * `occurrences` equals the number of SCA findings that carry package data and
 * `unclassified` counts the rest, so no finding disappears silently.
 */
export function buildScaView(findings: Finding[]): ScaView {
  const groups = new Map<string, GroupedEntry>();
  let unclassified = 0;
  let scaOccurrences = 0;

  for (const finding of findings) {
    if (!finding.ruleId.startsWith('sca/')) continue;
    scaOccurrences++;
    const properties = finding.properties;
    const name = stringProperty(properties, 'package');
    const version = stringProperty(properties, 'version');
    if (!name || !version) {
      unclassified++;
      continue;
    }
    const ecosystem = stringProperty(properties, 'ecosystem') ?? 'unknown';
    const key = `${ecosystem}:${name}@${version}`;
    const existing = groups.get(key);
    if (existing) {
      existing.findings.push(finding);
    } else {
      groups.set(key, { key, name, version, ecosystem, findings: [finding] });
    }
  }

  const packages: ScaPackage[] = [];
  for (const entry of groups.values()) {
    const advisories = new Map<string, ScaAdvisory>();
    const introducedBy = new Set<string>();
    const paths = new Set<string>();
    const locations = new Map<string, ScaLocation>();
    const fixedVersions: string[] = [];
    let direct: boolean | null = null;
    let dev: boolean | null = null;
    let pathsTotal: number | null = null;
    let pathsTruncated = false;

    for (const finding of entry.findings) {
      const properties = finding.properties;
      const fallbackLocation: ScaLocation = { file: finding.file, line: finding.line };
      for (const location of locationsProperty(properties, fallbackLocation)) {
        locations.set(`${location.file}:${location.line}`, location);
      }

      const findingDirect = booleanProperty(properties, 'direct');
      if (findingDirect === false) direct = false;
      else if (findingDirect === true && direct === null) direct = true;

      const findingDev = booleanProperty(properties, 'dev');
      if (findingDev === false) dev = false;
      else if (findingDev === true && dev === null) dev = true;

      for (const parent of stringArrayProperty(properties, 'introducedBy')) introducedBy.add(parent);
      for (const path of stringArrayProperty(properties, 'paths')) paths.add(path);
      if (booleanProperty(properties, 'pathsTruncated') === true) pathsTruncated = true;
      // The graph facts are per package and repeated on every advisory, so the
      // total is the maximum reported, never a sum across advisories.
      const total = properties?.pathsTotal;
      if (typeof total === 'number' && Number.isFinite(total)) {
        pathsTotal = pathsTotal === null ? total : Math.max(pathsTotal, total);
      }

      const fixedIn = stringArrayProperty(properties, 'fixedIn');
      fixedVersions.push(...fixedIn);

      const vulnerabilityId =
        stringProperty(properties, 'vulnerabilityId') ?? finding.ruleId.replace(/^sca\//, '');
      const existing = advisories.get(vulnerabilityId);
      if (existing) {
        existing.occurrences++;
        for (const location of locationsProperty(properties, fallbackLocation)) {
          if (
            !existing.locations.some(
              (item) => item.file === location.file && item.line === location.line,
            )
          ) {
            existing.locations.push(location);
          }
        }
        continue;
      }

      const severity = (stringProperty(properties, 'severity') ?? 'UNKNOWN').toUpperCase();
      advisories.set(vulnerabilityId, {
        ruleId: finding.ruleId,
        vulnerabilityId,
        aliases: stringArrayProperty(properties, 'aliases'),
        severity,
        level: finding.level,
        bucket: bucketOf(properties),
        message: finding.message,
        fixedIn,
        kev: properties?.kev === true,
        advisoryModified: stringProperty(properties, 'advisoryModified'),
        advisoryPublished: stringProperty(properties, 'advisoryPublished'),
        locations: locationsProperty(properties, fallbackLocation),
        occurrences: 1,
      });
    }

    const advisoryList = [...advisories.values()].sort(
      (a, b) =>
        LEVEL_RANK[b.level] - LEVEL_RANK[a.level] ||
        a.vulnerabilityId.localeCompare(b.vulnerabilityId),
    );
    const locationList = [...locations.values()].sort(
      (a, b) => a.file.localeCompare(b.file) || a.line - b.line,
    );
    const pathList = [...paths].sort();
    const displayPaths = pathList.slice(0, MAX_DISPLAY_PATHS);
    const fixTarget = pickFixTarget(entry.version, fixedVersions);

    const base: Omit<ScaPackage, 'why' | 'fix'> = {
      key: entry.key,
      name: entry.name,
      version: entry.version,
      ecosystem: entry.ecosystem,
      direct,
      dev,
      introducedBy: [...introducedBy].sort(),
      paths: displayPaths,
      pathsTotal: pathsTotal ?? (pathList.length > 0 ? pathList.length : null),
      pathsTruncated: pathsTruncated || pathList.length > displayPaths.length,
      locations: locationList,
      level: highestLevel(advisoryList.map((advisory) => advisory.level)),
      severity: highestSeverity(advisoryList.map((advisory) => advisory.severity)),
      bucket: highestRiskBucket(advisoryList.map((advisory) => advisory.bucket)),
      advisories: advisoryList,
      advisoryCount: advisoryList.length,
      occurrenceCount: entry.findings.length,
      fixTarget,
    };

    packages.push({ ...base, why: buildWhy(base), fix: buildFix(base) });
  }

  packages.sort(
    (a, b) =>
      BUCKET_RANK[a.bucket] - BUCKET_RANK[b.bucket] ||
      LEVEL_RANK[b.level] - LEVEL_RANK[a.level] ||
      a.name.localeCompare(b.name) ||
      a.version.localeCompare(b.version),
  );

  const advisoryIds = new Set<string>();
  for (const pkg of packages) {
    for (const advisory of pkg.advisories) advisoryIds.add(advisory.vulnerabilityId);
  }

  return {
    summary: {
      packages: packages.length,
      advisories: advisoryIds.size,
      occurrences: scaOccurrences - unclassified,
      directPackages: packages.filter((pkg) => pkg.direct === true).length,
      transitivePackages: packages.filter((pkg) => pkg.direct === false).length,
      unknownDirectness: packages.filter((pkg) => pkg.direct === null).length,
      devPackages: packages.filter((pkg) => pkg.dev === true).length,
      unclassified,
    },
    packages,
  };
}

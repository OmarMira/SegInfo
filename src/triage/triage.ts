import type { Finding } from '../report/sarif.js';
import { explainFinding } from './explain.js';

/**
 * Triage layer: turns a flat finding list into decision-ready buckets without
 * ever hiding a finding.
 *
 * - `confirmed`: objective external evidence (CISA KEV membership).
 * - `likely-example`: the path looks like tests, fixtures, docs or vendor code.
 * - `review`: everything else, with a rule-family specific reason.
 *
 * Findings are annotated in place (`properties.triage`) so SARIF consumers and
 * the UI can explain the classification. Grouping only collapses identical
 * (ruleId, file, message) occurrences into one row with a count.
 */

export type TriageBucket = 'confirmed' | 'review' | 'likely-example';

export interface TriagedFinding {
  finding: Finding;
  bucket: TriageBucket;
  reason: string;
  /** Rule-specific reason the finding was reported (Spanish). */
  why: string;
  /** Concrete evidence captured by the module (Spanish, labeled). */
  evidence: string[];
  /** Technical remediation for this rule (Spanish, specific). */
  fix: string;
  /** What the reader should do with this bucket. */
  nextStep: string;
}

export interface TriageGroup {
  key: string;
  ruleId: string;
  file: string;
  message: string;
  level: Finding['level'];
  bucket: TriageBucket;
  reason: string;
  why: string;
  evidence: string[];
  fix: string;
  nextStep: string;
  count: number;
  lines: number[];
  findings: TriagedFinding[];
}

export interface TriageSummary {
  total: number;
  confirmed: number;
  review: number;
  likelyExample: number;
}

export interface TriageResult {
  summary: TriageSummary;
  groups: TriageGroup[];
  findings: TriagedFinding[];
}

const EXAMPLE_DIRS = new Set([
  'test',
  'tests',
  '__tests__',
  'testing',
  'fixtures',
  'fixture',
  'testdata',
  'examples',
  'example',
  'samples',
  'sample',
  'docs',
  'doc',
  'demo',
  'demos',
  'vendor',
  'vendors',
  'third_party',
  'third-party',
  'site-packages',
  'node_modules',
]);

const EXAMPLE_FILE_PATTERNS = [
  /\.test\.[cm]?[jt]sx?$/i,
  /\.spec\.[cm]?[jt]sx?$/i,
  /(^|\/)test_[^/]+\.py$/i,
  /_test\.py$/i,
  /(^|\/)conftest\.py$/i,
  /(^|\/)readme(\.[a-z]+)?$/i,
];

const LEVEL_RANK: Record<Finding['level'], number> = {
  none: 0,
  note: 1,
  warning: 2,
  error: 3,
};

function looksLikeExample(file: string): boolean {
  const posix = file.replace(/\\/g, '/').toLowerCase();
  const segments = posix.split('/');
  if (segments.some((segment) => EXAMPLE_DIRS.has(segment))) return true;
  return EXAMPLE_FILE_PATTERNS.some((pattern) => pattern.test(posix));
}

function reviewReason(ruleId: string): string {
  if (ruleId.startsWith('leakscan/')) {
    return 'Coincide con un patrón de secreto; confirma si la credencial sigue activa';
  }
  if (ruleId.startsWith('sca/')) {
    return 'Aviso de dependencia; confirma si el paquete se usa y es alcanzable';
  }
  if (ruleId.startsWith('iac/')) {
    return 'Riesgo de configuración; confirma si aplica al entorno desplegado';
  }
  if (ruleId.startsWith('sast/')) {
    return 'Coincidencia de patrón en el código; requiere revisión manual (sin confirmación de flujo de datos)';
  }
  if (ruleId.startsWith('web/')) {
    return 'Hallazgo en cabeceras en vivo; verifícalo contra la configuración de producción';
  }
  return 'Requiere revisión manual';
}

/** What to do next, depending on how much the scanner could prove. */
export const BUCKET_ADVICE: Record<TriageBucket, string> = {
  confirmed:
    'Está catalogada como explotada en el mundo real: actualiza o aplica el mitigante cuanto antes.',
  review: 'Revisa el punto señalado y decide si el riesgo es real en tu contexto.',
  'likely-example':
    'Está en tests, fixtures o ejemplos: probablemente no llega a producción, pero verifícalo antes de descartarlo.',
};

interface Classification {
  bucket: TriageBucket;
  reason: string;
}

export function classifyFinding(finding: Finding): Classification {
  if (finding.properties?.kev === true) {
    return {
      bucket: 'confirmed',
      reason: 'Vulnerabilidad de explotación conocida (CISA KEV)',
    };
  }
  if (looksLikeExample(finding.file)) {
    return {
      bucket: 'likely-example',
      reason: 'La ruta parece de tests, fixtures, ejemplos o código de terceros',
    };
  }
  return { bucket: 'review', reason: reviewReason(finding.ruleId) };
}

function compareGroups(a: TriageGroup, b: TriageGroup): number {
  const bucketOrder: Record<TriageBucket, number> = {
    confirmed: 0,
    review: 1,
    'likely-example': 2,
  };
  return (
    bucketOrder[a.bucket] - bucketOrder[b.bucket] ||
    LEVEL_RANK[b.level] - LEVEL_RANK[a.level] ||
    a.file.localeCompare(b.file) ||
    a.ruleId.localeCompare(b.ruleId)
  );
}

/** Classifies, groups and annotates findings (mutates `properties.triage`). */
export function triageFindings(findings: Finding[]): TriageResult {
  const triaged: TriagedFinding[] = findings.map((finding) => {
    const { bucket, reason } = classifyFinding(finding);
    const { why, evidence, fix } = explainFinding(finding);
    finding.properties = { ...finding.properties, triage: { bucket, reason } };
    return { finding, bucket, reason, why, evidence, fix, nextStep: BUCKET_ADVICE[bucket] };
  });

  const groups = new Map<string, TriageGroup>();
  for (const entry of triaged) {
    const { finding, bucket, reason } = entry;
    const key = `${finding.ruleId}|${finding.file}|${finding.message}`;
    const existing = groups.get(key);
    if (existing) {
      existing.count += 1;
      existing.lines.push(finding.line);
      existing.findings.push(entry);
      if (LEVEL_RANK[finding.level] > LEVEL_RANK[existing.level]) existing.level = finding.level;
      continue;
    }
    groups.set(key, {
      key,
      ruleId: finding.ruleId,
      file: finding.file,
      message: finding.message,
      level: finding.level,
      bucket,
      reason,
      why: entry.why,
      evidence: entry.evidence,
      fix: entry.fix,
      nextStep: entry.nextStep,
      count: 1,
      lines: [finding.line],
      findings: [entry],
    });
  }

  const ordered = [...groups.values()].sort(compareGroups);
  const summary: TriageSummary = {
    total: triaged.length,
    confirmed: triaged.filter((entry) => entry.bucket === 'confirmed').length,
    review: triaged.filter((entry) => entry.bucket === 'review').length,
    likelyExample: triaged.filter((entry) => entry.bucket === 'likely-example').length,
  };

  return { summary, groups: ordered, findings: triaged };
}

/** One-line human summary, e.g. "3 confirmados, 12 por revisar, 629 probables ejemplos". */
export function formatTriageSummary(summary: TriageSummary): string {
  return (
    `${summary.confirmed} confirmados, ${summary.review} por revisar, ` +
    `${summary.likelyExample} probables ejemplos o duplicados`
  );
}

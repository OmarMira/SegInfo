import { z } from 'zod';
import type { FetchLike } from '../../util/http.js';
import type { Finding } from '../../report/sarif.js';

/**
 * Threat-intel enrichment for SCA findings: CISA KEV (known-exploited) and
 * FIRST EPSS (exploit probability), both public feeds without API keys.
 *
 * Honesty contract: enrichment is OPTIONAL. A network failure, an HTTP error
 * or an unparseable body never fails the scan and never masquerades as
 * "not exploited" — the corresponding properties are omitted and the finding
 * is flagged `enrichment: 'unavailable'`. The OSV query itself keeps its
 * fail-loud behavior in osv.ts.
 */

const KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_URL = 'https://api.first.org/data/v1/epss';
const DEFAULT_TIMEOUT_MS = 10_000;
/** Cap per EPSS request so the `?cve=` URL stays a reasonable length. */
const EPSS_BATCH_SIZE = 100;
const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/;

export interface EnrichmentOptions {
  /** Injected client (tests); defaults to global fetch. Same fetch as OSV. */
  fetchImpl?: FetchLike;
  timeoutMs?: number;
}

/** CISA KEV catalog (validated core, tolerant of extra fields). */
const kevCatalogSchema = z.object({
  vulnerabilities: z.array(
    z.object({
      cveID: z.string(),
      dateAdded: z.string(),
      knownRansomwareCampaignUse: z.string().optional(),
    }),
  ),
});

/** FIRST EPSS response: scores arrive as strings. */
const epssResponseSchema = z.object({
  data: z.array(
    z.object({
      cve: z.string(),
      epss: z.union([z.string(), z.number()]),
    }),
  ),
});

/** Returns the first CVE id carried in a finding's properties, if any. */
function cveOf(finding: Finding): string | undefined {
  const props = finding.properties;
  if (!props) return undefined;
  const candidates: unknown[] = [
    props.vulnerabilityId,
    ...(Array.isArray(props.aliases) ? props.aliases : []),
  ];
  for (const candidate of candidates) {
    if (typeof candidate === 'string' && CVE_PATTERN.test(candidate)) {
      return candidate.toUpperCase();
    }
  }
  return undefined;
}

/**
 * Enriches findings that carry a CVE id with KEV and EPSS data.
 *
 * - KEV hit → `kev: true`, `kevDate`, `ransomwareUse`, level bumped to `error`.
 * - KEV fetched-and-parsed miss → `kev: false` (never on failure).
 * - EPSS hit → `epss: <number>` (only when successfully obtained).
 * - Any failed feed → its properties are omitted entirely and the affected
 *   findings get `enrichment: 'unavailable'`; the scan still succeeds.
 *
 * Fetches the KEV catalog once per call and batches EPSS requests at 100
 * CVEs. Does nothing (no network) when no finding carries a CVE id.
 */
export async function enrichFindings(
  findings: Finding[],
  options: EnrichmentOptions = {},
): Promise<void> {
  const targets = findings
    .map((finding) => ({ finding, cve: cveOf(finding) }))
    .filter((t): t is { finding: Finding; cve: string } => t.cve !== undefined);
  if (targets.length === 0) return; // enrichment disabled without CVE ids

  const fetchImpl: FetchLike =
    options.fetchImpl ?? ((url: string, init?: RequestInit) => fetch(url, init));
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const uniqueCves = [...new Set(targets.map((t) => t.cve))];

  let degraded = false;

  // CISA KEV: one catalog fetch per scan, matched by CVE id.
  try {
    const res = await fetchImpl(KEV_URL, { signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const parsed = kevCatalogSchema.safeParse(await res.json());
    if (!parsed.success) throw new Error('unexpected KEV response shape');
    const byCve = new Map(
      parsed.data.vulnerabilities.map((entry) => [entry.cveID.toUpperCase(), entry]),
    );
    for (const { finding, cve } of targets) {
      const hit = byCve.get(cve);
      if (hit) {
        finding.properties = {
          ...finding.properties,
          kev: true,
          kevDate: hit.dateAdded,
          ransomwareUse: hit.knownRansomwareCampaignUse ?? 'Unknown',
        };
        finding.level = 'error'; // known-exploited is urgent
      } else {
        finding.properties = { ...finding.properties, kev: false };
      }
    }
  } catch {
    degraded = true; // omit every kev* claim rather than guess
  }

  // FIRST EPSS: batched score lookup by CVE id.
  try {
    const scores = new Map<string, number>();
    for (let start = 0; start < uniqueCves.length; start += EPSS_BATCH_SIZE) {
      const chunk = uniqueCves.slice(start, start + EPSS_BATCH_SIZE);
      const res = await fetchImpl(`${EPSS_URL}?cve=${chunk.join(',')}`, {
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const parsed = epssResponseSchema.safeParse(await res.json());
      if (!parsed.success) throw new Error('unexpected EPSS response shape');
      const rows = parsed.data.data; // the EPSS `data` array
      for (const row of rows) {
        const score = typeof row.epss === 'number' ? row.epss : Number(row.epss);
        if (Number.isFinite(score)) scores.set(row.cve.toUpperCase(), score);
      }
    }
    for (const { finding, cve } of targets) {
      const score = scores.get(cve);
      if (score !== undefined) {
        finding.properties = { ...finding.properties, epss: score };
      }
    }
  } catch {
    degraded = true; // omit epss rather than guess
  }

  if (degraded) {
    for (const { finding } of targets) {
      finding.properties = { ...finding.properties, enrichment: 'unavailable' };
    }
  }
}

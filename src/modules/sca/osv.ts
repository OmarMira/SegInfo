import { z } from 'zod';
import type { HttpResponse, FetchLike } from '../../util/http.js';
import type { Dependency } from './manifest.js';

export type { HttpResponse, FetchLike };

export interface OsvClientOptions {
  fetchImpl?: FetchLike;
  timeoutMs?: number;
  /** Cap on unique vulnerability detail fetches (keeps huge repos bounded). */
  maxDetails?: number;
}

/** An OSV vulnerability record (validated core, tolerant of extra fields). */
export type VulnDetail = z.infer<typeof vulnDetailSchema>;

const OSV_ENDPOINT = 'https://api.osv.dev';
const BATCH_SIZE = 500;
const DETAIL_CONCURRENCY = 8;
const DEFAULT_MAX_DETAILS = 200;
const DEFAULT_TIMEOUT_MS = 15_000;

const batchResponseSchema = z.object({
  results: z.array(
    z.object({
      vulns: z.array(z.object({ id: z.string() })).optional(),
    }),
  ),
});

const vulnDetailSchema = z.object({
  id: z.string(),
  summary: z.string().optional(),
  aliases: z.array(z.string()).optional(),
  /** ISO timestamps published by OSV (present on real records). */
  modified: z.string().optional(),
  published: z.string().optional(),
  database_specific: z.unknown().optional(),
  affected: z.unknown().optional(),
});

function describeError(err: unknown): string {
  if (err instanceof Error) {
    return err.name === 'TimeoutError' ? 'timed out' : err.message;
  }
  return String(err);
}

/**
 * Resolves pinned dependencies against the OSV database (which aggregates
 * GitHub Advisories, CVE/NVD and ecosystem-specific sources).
 *
 * Two phases: one `querybatch` per 500 dependencies to learn vulnerability
 * ids, then `GET /v1/vulns/{id}` per unique id for severity and fixed
 * versions. Network failures throw — a scanner must never turn an outage
 * into a clean report.
 *
 * @returns map of dependency index → vulnerabilities affecting it.
 */
export async function queryVulnerabilities(
  deps: Dependency[],
  options: OsvClientOptions = {},
): Promise<Map<number, VulnDetail[]>> {
  const fetchImpl: FetchLike =
    options.fetchImpl ?? ((url: string, init?: RequestInit) => fetch(url, init));
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxDetails = options.maxDetails ?? DEFAULT_MAX_DETAILS;

  const idToDepIndexes = new Map<string, number[]>();

  try {
    for (let start = 0; start < deps.length; start += BATCH_SIZE) {
      const chunk = deps.slice(start, start + BATCH_SIZE);
      const res = await fetchImpl(`${OSV_ENDPOINT}/v1/querybatch`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          queries: chunk.map((d) => ({
            package: { name: d.name, ecosystem: d.ecosystem },
            version: d.version,
          })),
        }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) throw new Error(`OSV querybatch failed with HTTP ${res.status}`);
      const parsed = batchResponseSchema.safeParse(await res.json());
      if (!parsed.success) throw new Error('OSV querybatch returned an unexpected response shape');
      parsed.data.results.forEach((result, i) => {
        for (const vuln of result.vulns ?? []) {
          const indexes = idToDepIndexes.get(vuln.id) ?? [];
          indexes.push(start + i);
          idToDepIndexes.set(vuln.id, indexes);
        }
      });
    }
  } catch (err) {
    throw new Error(`OSV query failed: ${describeError(err)}`, { cause: err });
  }

  const ids = [...idToDepIndexes.keys()];
  const details = new Map<string, VulnDetail>();
  for (let i = 0; i < ids.length && i < maxDetails; i += DETAIL_CONCURRENCY) {
    const group = ids.slice(i, i + DETAIL_CONCURRENCY);
    await Promise.all(
      group.map(async (id) => {
        try {
          const res = await fetchImpl(`${OSV_ENDPOINT}/v1/vulns/${encodeURIComponent(id)}`, {
            signal: AbortSignal.timeout(timeoutMs),
          });
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          const parsed = vulnDetailSchema.safeParse(await res.json());
          if (!parsed.success) throw new Error('unexpected response shape');
          details.set(id, parsed.data);
        } catch {
          // Keep the id-only record: an unstyled finding beats a silent gap.
          details.set(id, { id });
        }
      }),
    );
  }

  const byDep = new Map<number, VulnDetail[]>();
  for (const [id, depIndexes] of idToDepIndexes) {
    const detail = details.get(id) ?? { id };
    for (const depIndex of depIndexes) {
      const list = byDep.get(depIndex) ?? [];
      list.push(detail);
      byDep.set(depIndex, list);
    }
  }
  return byDep;
}

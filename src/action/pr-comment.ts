import type { FetchLike } from '../util/http.js';
import type { OrchestratorResult } from '../orchestrator/orchestrator.js';

const API_BASE = 'https://api.github.com';
const USER_AGENT = 'seginfo-secure-scan';

/** Marker that identifies our comment so re-runs update it instead of spamming. */
export const PR_MARKER = '<!-- seginfo-secure-scan -->';

const MAX_LISTED_FINDINGS = 20;
const MAX_MESSAGE_LENGTH = 200;

/** Strips characters that could break out of markdown code spans. */
function sanitize(text: string): string {
  return text.replace(/`/g, "'").replace(/\r?\n/g, ' ');
}

function truncate(text: string): string {
  const clean = sanitize(text);
  return clean.length > MAX_MESSAGE_LENGTH ? `${clean.slice(0, MAX_MESSAGE_LENGTH)}…` : clean;
}

/**
 * Builds the PR comment body: marker, per-module status table, up to 20
 * findings (sanitized + truncated — comment content comes from the scanned
 * repository and must not be able to inject markdown).
 */
export function buildPrComment(result: OrchestratorResult): string {
  const lines: string[] = [PR_MARKER, '### 🔐 secure-scan report', ''];
  lines.push('| Module | Status |', '|--------|--------|');

  const byModule = new Map<string, number>();
  for (const f of result.findings) {
    const module = f.ruleId.split('/')[0] ?? 'unknown';
    byModule.set(module, (byModule.get(module) ?? 0) + 1);
  }
  for (const [module, count] of byModule) {
    lines.push(`| ${module} | ⚠️ ${count} finding(s) |`);
  }
  for (const skip of result.skipped) {
    lines.push(`| ${skip.module} | ⊘ skipped — ${truncate(skip.reason)} |`);
  }
  for (const failure of result.failures) {
    lines.push(`| ${failure.module} | ✖ failed — ${truncate(failure.message)} |`);
  }

  lines.push(
    '',
    `**${result.totalFindings} finding(s)** — exit ${result.exitCode}.`,
    '',
  );

  if (result.findings.length > 0) {
    lines.push('<details><summary>Findings</summary>', '');
    for (const f of result.findings.slice(0, MAX_LISTED_FINDINGS)) {
      lines.push(`- \`${sanitize(f.file)}:${f.line}\` — \`${sanitize(f.ruleId)}\`: ${truncate(f.message)}`);
    }
    const remaining = result.findings.length - MAX_LISTED_FINDINGS;
    if (remaining > 0) lines.push(`- …and ${remaining} more (see the SARIF artifact)`);
    lines.push('', '</details>');
  }

  return lines.join('\n');
}

export interface CommentListing {
  id: number;
  body?: string | null;
  user?: { login?: string };
}

/** Returns the id of the existing bot comment carrying our marker, if any. */
export function findBotComment(comments: CommentListing[]): number | null {
  for (const comment of comments) {
    if (typeof comment.body === 'string' && comment.body.includes(PR_MARKER)) return comment.id;
  }
  return null;
}

export interface UpsertInput {
  repo: string;
  prNumber: number;
  token: string;
  body: string;
}

/**
 * Creates the PR comment, or updates the one a previous run left behind.
 * Throws on API failures — the caller reports them as visible warnings.
 */
export async function upsertPrComment(
  input: UpsertInput,
  fetchImpl?: FetchLike,
): Promise<'created' | 'updated'> {
  const doFetch: FetchLike = fetchImpl ?? ((url, init) => fetch(url, init));
  const headers = {
    authorization: `Bearer ${input.token}`,
    'content-type': 'application/json',
    accept: 'application/vnd.github+json',
    'user-agent': USER_AGENT,
  };
  const base = `${API_BASE}/repos/${input.repo}`;

  const listRes = await doFetch(
    `${base}/issues/${input.prNumber}/comments?per_page=100`,
    { method: 'GET', headers },
  );
  if (!listRes.ok) {
    throw new Error(`PR comment list failed with HTTP ${listRes.status}`);
  }
  const list = (await listRes.json()) as unknown;
  if (!Array.isArray(list)) {
    throw new Error('PR comment list returned an unexpected response shape');
  }

  const existingId = findBotComment(list as CommentListing[]);
  const method = existingId ? 'PATCH' : 'POST';
  const url = existingId
    ? `${base}/issues/comments/${existingId}`
    : `${base}/issues/${input.prNumber}/comments`;

  const res = await doFetch(url, {
    method,
    headers,
    body: JSON.stringify({ body: input.body }),
  });
  if (!res.ok) {
    throw new Error(`PR comment ${existingId ? 'update' : 'create'} failed with HTTP ${res.status}`);
  }
  return existingId ? 'updated' : 'created';
}

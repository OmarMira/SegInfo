import { gzipSync } from 'node:zlib';
import type { FetchLike } from '../util/http.js';

const API_BASE = 'https://api.github.com';
const USER_AGENT = 'seginfo-secure-scan';

export interface UploadInput {
  /** Repository full name, e.g. `owner/name`. */
  repo: string;
  commitSha: string;
  /** Git ref (e.g. refs/heads/main); omitted from the payload when empty. */
  ref: string;
  /** Raw SARIF document text. */
  sarif: string;
  toolName?: string;
}

export interface UploadBody {
  tool_name: string;
  commit_sha: string;
  ref?: string;
  sarif: string;
}

/** gzip + base64 — the encoding required by the code-scanning API. */
export function encodeSarif(sarif: string): string {
  return gzipSync(Buffer.from(sarif, 'utf8')).toString('base64');
}

export function buildUploadBody(input: UploadInput): UploadBody {
  return {
    tool_name: input.toolName ?? 'secure-scan',
    commit_sha: input.commitSha,
    ...(input.ref ? { ref: input.ref } : {}),
    sarif: encodeSarif(input.sarif),
  };
}

/**
 * Uploads a SARIF report to the repository's Security tab (code scanning).
 * The token travels in headers only; failures throw with the API status so
 * the caller can surface them instead of pretending the upload happened.
 */
export async function uploadSarif(
  input: UploadInput,
  token: string,
  fetchImpl?: FetchLike,
): Promise<void> {
  const doFetch: FetchLike = fetchImpl ?? ((url, init) => fetch(url, init));
  const res = await doFetch(`${API_BASE}/repos/${input.repo}/code-scanning/sarifs`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      accept: 'application/vnd.github+json',
      'user-agent': USER_AGENT,
    },
    body: JSON.stringify(buildUploadBody(input)),
  });
  if (!res.ok) {
    let detail = '';
    try {
      const data = (await res.json()) as { message?: unknown };
      if (typeof data.message === 'string') detail = `: ${data.message}`;
    } catch {
      // no parseable body: status alone is still an honest error
    }
    throw new Error(`SARIF upload failed with HTTP ${res.status}${detail}`);
  }
}

import * as fs from 'node:fs';
import { runOrchestrator, type OrchestratorResult } from '../orchestrator/orchestrator.js';
import type { FetchLike } from '../util/http.js';
import { uploadSarif } from './upload.js';
import { buildPrComment, upsertPrComment } from './pr-comment.js';

export interface ActionEnvironment {
  token?: string;
  /** Full repository name `owner/name` (GITHUB_REPOSITORY). */
  repository?: string;
  sha?: string;
  ref?: string;
  files?: string;
  configPath?: string;
  /** Parsed webhook payload (GITHUB_EVENT_PATH) — used for the PR number. */
  eventPayload?: unknown;
}

export interface ActionDependencies {
  fetchImpl?: FetchLike;
  /** SARIF reader (tests inject a fake; defaults to reading the file). */
  readSarif?: (path: string) => string;
  orchestrator?: (
    target?: string,
    options?: { configPath?: string },
  ) => Promise<OrchestratorResult>;
}

export interface ActionResult {
  /** Exit code from the scan itself — reporting failures never change it. */
  exitCode: 0 | 1;
  scan: OrchestratorResult;
  uploaded: boolean;
  commentAction: 'created' | 'updated' | 'skipped';
  /** Reporting problems surfaced to the log (never swallowed). */
  warnings: string[];
}

/** Extracts the PR number from a webhook payload, when present. */
function prNumberFromEvent(payload: unknown): number | null {
  if (!payload || typeof payload !== 'object') return null;
  const pr = (payload as { pull_request?: unknown }).pull_request;
  if (!pr || typeof pr !== 'object') return null;
  const number = (pr as { number?: unknown }).number;
  return typeof number === 'number' ? number : null;
}

/** Reads the action environment (CI variables) into a typed object. */
export function readActionEnv(env: Record<string, string | undefined>): ActionEnvironment {
  let eventPayload: unknown;
  const eventPath = env.GITHUB_EVENT_PATH;
  if (eventPath) {
    let raw: string;
    try {
      raw = fs.readFileSync(eventPath, 'utf8');
    } catch (err) {
      throw new Error(`Cannot read event payload ${eventPath}: ${err instanceof Error ? err.message : String(err)}`, {
        cause: err,
      });
    }
    try {
      eventPayload = JSON.parse(raw);
    } catch (err) {
      throw new Error(`Invalid JSON in event payload ${eventPath}`, { cause: err });
    }
  }
  return {
    token: env.GITHUB_TOKEN,
    repository: env.GITHUB_REPOSITORY,
    sha: env.GITHUB_SHA,
    ref: env.GITHUB_REF,
    files: env.SECURE_SCAN_FILES,
    configPath: env.SECURE_SCAN_CONFIG,
    eventPayload,
  };
}

/**
 * Runs the scan, then the reporting steps: SARIF upload to the Security tab
 * and the PR comment (upsert). Reporting failures become visible warnings —
 * they never alter the scan's exit code, and a failed step is never faked
 * as a success.
 */
export async function runAction(
  env: ActionEnvironment,
  deps: ActionDependencies = {},
): Promise<ActionResult> {
  const orchestrator = deps.orchestrator ?? runOrchestrator;
  const scan = await orchestrator(env.files || undefined, {
    configPath: env.configPath || undefined,
  });

  const warnings: string[] = [];
  const [owner, repoName] = (env.repository ?? '').split('/');
  const repo = owner && repoName ? `${owner}/${repoName}` : null;

  let uploaded = false;
  if (env.token && repo && env.sha) {
    try {
      const readSarif = deps.readSarif ?? ((p: string) => fs.readFileSync(p, 'utf8'));
      const sarif = readSarif(scan.outputPath);
      await uploadSarif(
        { repo, commitSha: env.sha, ref: env.ref ?? '', sarif },
        env.token,
        deps.fetchImpl,
      );
      uploaded = true;
    } catch (err) {
      warnings.push(err instanceof Error ? err.message : String(err));
    }
  }

  let commentAction: ActionResult['commentAction'] = 'skipped';
  const prNumber = prNumberFromEvent(env.eventPayload);
  if (env.token && repo && prNumber !== null) {
    try {
      commentAction = await upsertPrComment(
        { repo, prNumber, token: env.token, body: buildPrComment(scan) },
        deps.fetchImpl,
      );
    } catch (err) {
      warnings.push(err instanceof Error ? err.message : String(err));
    }
  }

  return { exitCode: scan.exitCode, scan, uploaded, commentAction, warnings };
}

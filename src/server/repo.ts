import { execFile } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

/**
 * Shallow clone of a public Git repository for scanning.
 *
 * Only https URLs on well-known hosts are accepted (no ssh/scp syntax, no
 * credentials, no query strings) and `git clone` always runs with an argument
 * array and `--`, so a crafted URL cannot inject options or shell syntax.
 */

const ALLOWED_HOSTS = new Set([
  'github.com',
  'www.github.com',
  'gitlab.com',
  'www.gitlab.com',
  'bitbucket.org',
  'www.bitbucket.org',
]);

const DEFAULT_TIMEOUT_MS = 120_000;
const OWNER_REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\.git)?$/;

export interface CloneHandle {
  dir: string;
  cleanup: () => void;
}

export type CloneImpl = (url: string) => Promise<CloneHandle>;

/** Validates and canonicalizes a repository URL (or `owner/repo` shorthand). */
export function normalizeRepoUrl(input: string): string {
  const raw = input.trim();
  if (!raw) throw new Error('Repository URL is required');

  const candidate = OWNER_REPO_RE.test(raw) ? `https://github.com/${raw}` : raw;
  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new Error(`Invalid repository URL: ${input}`);
  }

  if (parsed.protocol !== 'https:') {
    throw new Error('Only https:// repository URLs are supported');
  }
  if (!ALLOWED_HOSTS.has(parsed.hostname.toLowerCase())) {
    throw new Error(`Unsupported repository host: ${parsed.hostname}`);
  }
  if (parsed.username || parsed.password) {
    throw new Error('Credentials in repository URLs are not supported');
  }
  if (parsed.search || parsed.hash) {
    throw new Error('Query strings and fragments are not supported in repository URLs');
  }
  const segments = parsed.pathname.split('/').filter(Boolean);
  if (segments.length < 2) {
    throw new Error('Repository URL must include an owner and a repository name');
  }

  return `https://${parsed.hostname.toLowerCase()}/${segments.join('/')}`;
}

function runGit(args: string[], timeoutMs: number): Promise<void> {
  return new Promise((resolve, reject) => {
    execFile(
      'git',
      args,
      { timeout: timeoutMs, windowsHide: true, maxBuffer: 1024 * 1024 },
      (error) => (error ? reject(error) : resolve()),
    );
  });
}

function cloneError(error: unknown, url: string, timeoutMs: number): Error {
  const err = error as NodeJS.ErrnoException & { killed?: boolean; stderr?: string; stdout?: string };
  if (err.code === 'ENOENT') return new Error('git is not installed or not in PATH');
  if (err.killed) return new Error(`git clone timed out after ${Math.round(timeoutMs / 1000)}s`);
  const detail = (err.stderr ?? err.stdout ?? err.message ?? '').trim().split('\n').slice(-1)[0];
  return new Error(`git clone failed for ${url}${detail ? `: ${detail}` : ''}`);
}

/**
 * Clones `url` into a fresh temp directory (depth 1, single branch).
 * The caller owns `cleanup()`; it is safe to call more than once.
 */
export async function cloneRepository(
  url: string,
  options: { timeoutMs?: number } = {},
): Promise<CloneHandle> {
  const normalized = normalizeRepoUrl(url);
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'seginfo-repo-'));
  const dir = path.join(parent, 'repo');

  try {
    await runGit(
      ['clone', '--depth', '1', '--single-branch', '--no-tags', '--quiet', '--', normalized, dir],
      timeoutMs,
    );
  } catch (error) {
    fs.rmSync(parent, { recursive: true, force: true });
    throw cloneError(error, normalized, timeoutMs);
  }

  let cleaned = false;
  return {
    dir,
    cleanup: () => {
      if (cleaned) return;
      cleaned = true;
      fs.rmSync(parent, { recursive: true, force: true });
    },
  };
}

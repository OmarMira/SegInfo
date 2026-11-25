import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * Shared directory walker — single source of truth for the safety rules
 * every scanner must follow: never follow symlinks (a malicious repository
 * could point one outside the scan root or into a cycle), skip known noise
 * directories, bound depth and file count.
 */
export const DEFAULT_SKIP_DIRS = new Set([
  '.git',
  'node_modules',
  'dist',
  'build',
  'coverage',
  '.venv',
  'venv',
  '.next',
  '.cache',
  '.gradle',
  'target',
  '__pycache__',
  '.terraform',
  'bower_components',
]);

export interface FileFilters {
  /** Lowercase extensions to include (e.g. `.tf`). */
  extensions?: Set<string>;
  /** Exact basenames to include (e.g. `id_rsa`). */
  filenames?: Set<string>;
  /** Basename prefixes to include (e.g. `.env`). */
  basenamePrefixes?: string[];
}

export interface WalkOptions extends FileFilters {
  skipDirs?: Set<string>;
  maxDepth?: number;
  maxFiles?: number;
}

const DEFAULT_MAX_DEPTH = 32;
const DEFAULT_MAX_FILES = 50_000;

/** True when the path satisfies at least one defined filter (or none given). */
export function matchesFilters(filePath: string, filters: FileFilters): boolean {
  const base = path.basename(filePath);
  const hasFilter = Boolean(
    filters.extensions || filters.filenames || filters.basenamePrefixes,
  );
  if (!hasFilter) return true;
  if (filters.basenamePrefixes?.some((prefix) => base.startsWith(prefix))) return true;
  if (filters.filenames?.has(base)) return true;
  if (filters.extensions) return filters.extensions.has(path.extname(base).toLowerCase());
  return false;
}

/**
 * Breadth-first collection of scannable files under `root`. Unreadable
 * directories are skipped rather than aborting the scan.
 */
export async function collectFiles(root: string, options: WalkOptions = {}): Promise<string[]> {
  const skipDirs = options.skipDirs ?? DEFAULT_SKIP_DIRS;
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
  const maxFiles = options.maxFiles ?? DEFAULT_MAX_FILES;
  const out: string[] = [];
  const queue: Array<{ dir: string; depth: number }> = [{ dir: root, depth: 0 }];
  while (queue.length > 0) {
    const { dir, depth } = queue.shift()!;
    if (depth > maxDepth) continue;
    let entries: fs.Dirent[];
    try {
      entries = await fs.promises.readdir(dir, { withFileTypes: true });
    } catch {
      continue; // unreadable directory: skip, never crash the scan
    }
    for (const entry of entries) {
      if (out.length >= maxFiles) return out;
      if (entry.isSymbolicLink()) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!skipDirs.has(entry.name)) queue.push({ dir: full, depth: depth + 1 });
      } else if (entry.isFile() && matchesFilters(full, options)) {
        out.push(full);
      }
    }
  }
  return out;
}

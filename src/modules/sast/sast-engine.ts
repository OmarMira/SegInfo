import * as fs from 'node:fs';
import * as path from 'node:path';
import { glob } from 'glob';
import { collectFiles, DEFAULT_SKIP_DIRS } from '../../util/walk.js';
import { NothingToScanError } from '../../util/errors.js';
import { scanSastContent, type SastLanguage } from './sast-rules.js';
import type { Finding } from '../../report/sarif.js';

const SAST_EXTENSIONS = new Map<string, SastLanguage>([
  ['.js', 'js'],
  ['.jsx', 'js'],
  ['.mjs', 'js'],
  ['.cjs', 'js'],
  ['.ts', 'js'],
  ['.tsx', 'js'],
  ['.py', 'py'],
]);

const GLOB_IGNORE = ['**/.git/**', '**/node_modules/**', '**/dist/**', '**/coverage/**'];
const MAX_FILE_BYTES = 1024 * 1024;

export interface SastOptions {
  cwd?: string;
}

function relPath(root: string, abs: string): string {
  return path.relative(root, abs).split(path.sep).join('/') || path.basename(abs);
}

async function scanOne(abs: string, root: string): Promise<Finding[] | null> {
  const language = SAST_EXTENSIONS.get(path.extname(abs).toLowerCase());
  if (!language) {
    throw new Error(`Unsupported file for SAST scan: ${abs} (expected .js, .ts, .jsx, .tsx or .py)`);
  }
  try {
    const stat = await fs.promises.lstat(abs);
    if (stat.isSymbolicLink() || !stat.isFile() || stat.size > MAX_FILE_BYTES) return null;
    const content = await fs.promises.readFile(abs, 'utf8');
    if (content.includes('\u0000')) return null; // binary
    return scanSastContent(content, relPath(root, abs), language);
  } catch (error) {
    throw new Error(`Cannot read ${relPath(root, abs)}: ${error instanceof Error ? error.message : String(error)}`, {
      cause: error,
    });
  }
}

/**
 * SAST scan over JavaScript/TypeScript and Python sources.
 *
 * @param target directory, explicit file, or glob. Defaults to cwd.
 * @throws when nothing scannable exists — never claims a clean scan it did
 *         not perform.
 */
export async function scanSast(target?: string, options: SastOptions = {}): Promise<Finding[]> {
  const cwd = options.cwd ?? process.cwd();
  const resolved = target ? path.resolve(cwd, target) : cwd;

  let stat: fs.Stats | null;
  try {
    stat = fs.statSync(resolved);
  } catch {
    stat = null;
  }

  const extensions = new Set(SAST_EXTENSIONS.keys());
  const findings: Finding[] = [];
  let candidates: number;
  let scanned = 0;
  const run = (result: Finding[] | null): void => {
    if (result) {
      scanned++;
      findings.push(...result);
    }
  };
  const rootLabel = stat?.isDirectory() ? resolved : cwd;
  const noFilesError = (): Error =>
    new NothingToScanError(`No JavaScript/TypeScript or Python sources found under ${rootLabel}`);

  if (stat?.isFile()) {
    candidates = 1;
    run(await scanOne(resolved, cwd));
  } else if (stat?.isDirectory()) {
    const files = await collectFiles(resolved, {
      extensions,
      skipDirs: DEFAULT_SKIP_DIRS,
    });
    candidates = files.length;
    for (const file of files) run(await scanOne(file, resolved));
  } else if (target) {
    const matches = await glob(target, {
      cwd,
      dot: true,
      nodir: true,
      follow: false,
      ignore: GLOB_IGNORE,
    });
    if (matches.length === 0) throw noFilesError();
    candidates = matches.length;
    for (const rel of matches) run(await scanOne(path.resolve(cwd, rel), cwd));
  } else {
    throw noFilesError();
  }

  if (scanned === 0) {
    if (candidates > 0) {
      throw new NothingToScanError(
        `All ${candidates} source file(s) under ${rootLabel} were skipped (unreadable, binary or oversized)`,
      );
    }
    throw noFilesError();
  }
  return findings;
}

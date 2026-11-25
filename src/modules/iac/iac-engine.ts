import * as fs from 'node:fs';
import * as path from 'node:path';
import { glob } from 'glob';
import { collectFiles, DEFAULT_SKIP_DIRS } from '../../util/walk.js';
import { NothingToScanError } from '../../util/errors.js';
import { scanTerraform } from './tf-checks.js';
import { scanK8s } from './k8s-checks.js';
import type { Finding } from '../../report/sarif.js';

const IAC_EXTENSIONS = new Set(['.tf', '.yaml', '.yml']);
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const HELM_MARKER = '{{';
const GLOB_IGNORE = ['**/.git/**', '**/node_modules/**', '**/dist/**', '**/coverage/**'];

export interface IacOptions {
  cwd?: string;
}

function relPath(cwd: string, abs: string): string {
  return path.relative(cwd, abs).split(path.sep).join('/') || path.basename(abs);
}

/**
 * Reads one file and runs the matching checks.
 * @returns findings, or null when the file was skipped (helm template,
 *          binary, oversized).
 */
async function scanOne(abs: string, cwd: string): Promise<Finding[] | null> {
  const rel = relPath(cwd, abs);
  const ext = path.extname(abs).toLowerCase();
  if (!IAC_EXTENSIONS.has(ext)) {
    throw new Error(`Unsupported file for IaC scan: ${rel} (expected .tf, .yaml or .yml)`);
  }
  let content: string;
  try {
    const st = await fs.promises.lstat(abs);
    if (st.isSymbolicLink() || !st.isFile() || st.size > MAX_FILE_BYTES) return null;
    content = await fs.promises.readFile(abs, 'utf8');
  } catch (err) {
    throw new Error(`Cannot read ${rel}: ${err instanceof Error ? err.message : String(err)}`, {
      cause: err,
    });
  }
  if (content.includes('\u0000')) return null; // binary
  if (ext !== '.tf' && content.includes(HELM_MARKER)) return null; // Helm template
  return ext === '.tf' ? scanTerraform(content, rel) : scanK8s(content, rel);
}

/**
 * IaC scan over Terraform files and Kubernetes manifests.
 *
 * @param target directory, explicit file, or glob. Defaults to cwd.
 * @throws when nothing scannable exists — never claims a clean scan it
 *         did not perform.
 */
export async function scanIac(target?: string, options: IacOptions = {}): Promise<Finding[]> {
  const cwd = options.cwd ?? process.cwd();
  const resolved = target ? path.resolve(cwd, target) : cwd;

  let stat: fs.Stats | null = null;
  try {
    stat = fs.statSync(resolved);
  } catch {
    stat = null;
  }

  const findings: Finding[] = [];
  let scanned = 0;
  const run = (result: Finding[] | null): void => {
    if (result) {
      scanned++;
      findings.push(...result);
    }
  };

  const noFilesError = (): Error =>
    new NothingToScanError(
      `No Terraform or Kubernetes files found under ${stat?.isDirectory() ? resolved : cwd}`,
    );

  if (stat?.isFile()) {
    run(await scanOne(resolved, cwd));
  } else if (stat?.isDirectory()) {
    const files = await collectFiles(resolved, {
      extensions: IAC_EXTENSIONS,
      skipDirs: DEFAULT_SKIP_DIRS,
    });
    // Paths relative to the scanned root so out-of-cwd targets stay readable.
    for (const file of files) run(await scanOne(file, resolved));
  } else if (target) {
    // Not an existing path: treat the target as a glob pattern.
    const matches = await glob(target, {
      cwd,
      dot: true,
      nodir: true,
      follow: false,
      ignore: GLOB_IGNORE,
    });
    if (matches.length === 0) throw noFilesError();
    for (const rel of matches) run(await scanOne(path.resolve(cwd, rel), cwd));
  } else {
    throw noFilesError();
  }

  if (scanned === 0) throw noFilesError();
  return findings;
}

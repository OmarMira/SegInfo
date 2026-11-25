import * as fs from 'node:fs';
import * as path from 'node:path';
import { z } from 'zod';

export type ModuleId = 'leakscan' | 'sca' | 'iac';
export type FailOn = 'error' | 'warning' | 'note';

export interface ScanConfig {
  /** Modules to run, in report order. */
  modules: ModuleId[];
  /** SARIF output path, relative to the scan directory unless absolute. */
  output: string;
  /** Lowest finding level that makes the run fail (exit code 1). */
  failOn: FailOn;
  /** Glob patterns (posix paths) whose findings are excluded from the report. */
  ignore: string[];
}

export const DEFAULT_CONFIG: ScanConfig = {
  modules: ['leakscan', 'sca', 'iac'],
  output: 'seginfo-secure-scan-results.sarif',
  failOn: 'warning',
  ignore: [],
};

export const CONFIG_FILENAME = 'secure-scan.config.json';

const configSchema = z.object({
  modules: z
    .array(z.enum(['leakscan', 'sca', 'iac']))
    .min(1)
    .default(DEFAULT_CONFIG.modules),
  output: z.string().min(1).default(DEFAULT_CONFIG.output),
  failOn: z.enum(['error', 'warning', 'note']).default(DEFAULT_CONFIG.failOn),
  ignore: z.array(z.string().min(1)).default(DEFAULT_CONFIG.ignore),
});

/** Validates raw config data against the schema with a readable error. */
export function parseConfig(data: unknown): ScanConfig {
  const result = configSchema.safeParse(data);
  if (!result.success) {
    const issues = result.error.issues
      .map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`)
      .join('; ');
    throw new Error(`Invalid scan config: ${issues}`);
  }
  return result.data;
}

/**
 * Loads the scan config: an explicit path (must exist) or
 * `secure-scan.config.json` in `searchDir` (the scanned directory; defaults
 * to cwd) — defaults when absent.
 */
export function loadConfig(options: {
  cwd: string;
  searchDir?: string;
  configPath?: string;
}): ScanConfig {
  const candidate = options.configPath
    ? path.resolve(options.cwd, options.configPath)
    : path.join(options.searchDir ?? options.cwd, CONFIG_FILENAME);

  if (!fs.existsSync(candidate)) {
    if (options.configPath) throw new Error(`Config file not found: ${candidate}`);
    return {
      ...DEFAULT_CONFIG,
      modules: [...DEFAULT_CONFIG.modules],
      ignore: [...DEFAULT_CONFIG.ignore],
    };
  }

  let raw: string;
  try {
    raw = fs.readFileSync(candidate, 'utf8');
  } catch (err) {
    throw new Error(`Cannot read config ${candidate}: ${err instanceof Error ? err.message : String(err)}`, {
      cause: err,
    });
  }

  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new Error(`Invalid JSON in ${path.basename(candidate)}: ${reason}`, { cause: err });
  }
  return parseConfig(data);
}

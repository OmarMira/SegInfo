import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { glob } from 'glob';
import { collectFiles, matchesFilters, type FileFilters } from '../../util/walk.js';

const execFileAsync = promisify(execFile);

export type FindingSource = 'working-tree' | 'git-history';

/** A raw secret finding produced by the engine (module-agnostic shape). */
export interface RawFinding {
  /** Path relative to the scan root (or cwd for globs), always posix separators. */
  file: string;
  line: number;
  type: string;
  entropy: number;
  source: FindingSource;
  /** Commit sha when source is 'git-history'. */
  commit?: string;
}

export interface ScanOptions {
  /** Base directory for relative targets/globs. Defaults to process.cwd(). */
  cwd?: string;
  /** Scan committed history for deleted secrets. Defaults to true. */
  gitHistory?: boolean;
  /** Skip files larger than this. Defaults to 2 MiB. */
  maxFileBytes?: number;
  /** Maximum number of commits to inspect. Defaults to 500. */
  maxCommits?: number;
}

interface SecretPattern {
  /**
   * Regex source shared verbatim by the JS engine and `git grep -E`.
   * Must stay POSIX-ERE-safe: no lookarounds, no `\b`/`\s`/`\d`, no `(?:`.
   */
  src: string;
  type: string;
  /** 1-based capture group holding the candidate value for entropy checks. */
  valueGroup?: number;
  /** Skip the blob-boundary check for structurally unique patterns. */
  noBoundary?: boolean;
}

/**
 * Pattern order matters: specific token shapes win over the generic
 * keyword+entropy rule, which runs last.
 */
const SECRET_PATTERNS: SecretPattern[] = [
  { src: 'AKIA[0-9A-Z]{16}', type: 'aws-access-key' },
  { src: 'ASIA[0-9A-Z]{16}', type: 'aws-sts-access-key' },
  { src: 'gh[pousr]_?[A-Za-z0-9]{36,}', type: 'github-token' },
  { src: 'github_pat_[A-Za-z0-9_]{22,}', type: 'github-fine-grained-pat' },
  { src: 'xox[baprs]-[A-Za-z0-9-]{10,}', type: 'slack-token' },
  { src: 'sk_(live|test)_[0-9a-zA-Z]{24,}', type: 'stripe-key' },
  { src: 'AIza[0-9A-Za-z_-]{35}', type: 'google-api-key' },
  { src: 'npm_[A-Za-z0-9]{36}', type: 'npm-token' },
  {
    src: 'eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}',
    type: 'jwt-token',
  },
  {
    src: '-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----',
    type: 'private-key',
  },
  {
    // The scheme + embedded user:password@host structure cannot occur inside
    // base64/hex blobs — `:` and `@` are not base64 characters — so the URL
    // path's trailing `/` must not disqualify a match.
    src: '[a-z][a-z0-9+.\\-]*://[^ \\t/:@]+:[^ \\t/:@]+@[^ \\t/]+',
    type: 'db-url-credentials',
    noBoundary: true,
  },
  {
    src: '[A-Za-z0-9_.\\-]*(api[_-]?key|apikey|secret|token|password|passwd|pwd|credential)[A-Za-z0-9_\\-]*["\']?[ \t]*[:=][ \t]*["\']?([A-Za-z0-9/+=_\\-]{16,})',
    type: 'hardcoded-credential',
    valueGroup: 2,
  },
];

const COMPILED = SECRET_PATTERNS.map((p) => ({
  ...p,
  re: new RegExp(p.src, 'i'),
}));

/**
 * Characters that indicate a match is embedded inside a larger base64 or
 * hex blob rather than a standalone token. A real token is delimited by
 * quotes, spaces, parens or line edges — never by `+/` or surrounding
 * alphanumerics. This kills lookalikes such as `gho...` inside sha512
 * integrity hashes without needing lookarounds (which git grep cannot
 * compile anyway).
 */
const BLOB_CHAR = /[A-Za-z0-9+/]/;

function hasCleanBoundary(line: string, index: number, length: number): boolean {
  const before = index > 0 ? line[index - 1] : '';
  const after = index + length < line.length ? line[index + length] : '';
  return (
    (before === '' || !BLOB_CHAR.test(before)) &&
    (after === '' || !BLOB_CHAR.test(after))
  );
}

const DEFAULT_EXTS = new Set([
  '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts',
  '.py', '.rb', '.go', '.java', '.php', '.cs', '.pl', '.rs',
  '.sh', '.bash', '.zsh', '.ps1',
  '.json', '.yml', '.yaml', '.toml', '.ini', '.cfg', '.conf',
  '.properties', '.tf', '.tfvars', '.xml', '.txt', '.md', '.sql',
  '.env', '.pem', '.key', '.p12', '.pfx', '.crt', '.cer', '.jks',
]);

/** Extensionless files that are known secret carriers. */
const SECRET_FILENAMES = new Set([
  'id_rsa',
  'id_dsa',
  'id_ecdsa',
  'id_ed25519',
  'credentials',
  'credentials.json',
  'shadow',
]);

const DEFAULTS = {
  gitHistory: true,
  maxFileBytes: 2 * 1024 * 1024,
  maxCommits: 500,
};

const MAX_LINE_LENGTH = 10_000;
const GIT_GREP_BATCH = 50;
const MIN_SECRET_LENGTH = 16;
const MIN_ENTROPY = 3.0;

function calcEntropy(text: string): number {
  const freq = new Map<string, number>();
  for (const ch of text) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / text.length;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 100) / 100;
}

/**
 * Filters generic keyword matches down to values that actually look like
 * generated credentials: long enough, mixed letters+digits, and not a
 * repetitive string. This is what keeps `password = "hunter2"`-style noise
 * and `tokenize = someFunctionCall()` out of reports.
 */
function plausibleSecret(value: string): boolean {
  if (value.length < MIN_SECRET_LENGTH) return false;
  if (!/[0-9]/.test(value) || !/[A-Za-z]/.test(value)) return false;
  return calcEntropy(value) >= MIN_ENTROPY;
}

/** First pattern that validates wins; returns null when nothing matches. */
function matchLine(line: string): { type: string; entropy: number } | null {
  for (const p of COMPILED) {
    const m = p.re.exec(line);
    if (!m) continue;
    if (!p.noBoundary && !hasCleanBoundary(line, m.index, m[0].length)) continue;
    if (p.valueGroup !== undefined) {
      const value = m[p.valueGroup];
      if (!value || !plausibleSecret(value)) continue;
      return { type: p.type, entropy: calcEntropy(value) };
    }
    return { type: p.type, entropy: calcEntropy(m[0]) };
  }
  return null;
}

/** What counts as a secret carrier, in one place for walk + glob modes. */
const LEAKSCAN_FILTERS: FileFilters = {
  extensions: DEFAULT_EXTS,
  filenames: SECRET_FILENAMES,
  basenamePrefixes: ['.env'],
};

const GLOB_IGNORE = [
  '**/.git/**',
  '**/node_modules/**',
  '**/dist/**',
  '**/coverage/**',
  '**/.venv/**',
  '**/vendor/**',
];

async function scanFile(
  abs: string,
  relBase: string,
  maxBytes: number,
): Promise<RawFinding[]> {
  try {
    const st = await fs.promises.lstat(abs);
    if (!st.isFile() || st.size > maxBytes) return [];
    const content = await fs.promises.readFile(abs, 'utf8');
    if (content.includes('\u0000')) return []; // binary file
    const rel = path.relative(relBase, abs).split(path.sep).join('/');
    const findings: RawFinding[] = [];
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line =
        lines[i].length > MAX_LINE_LENGTH ? lines[i].slice(0, MAX_LINE_LENGTH) : lines[i];
      const hit = matchLine(line);
      if (hit) {
        findings.push({
          file: rel,
          line: i + 1,
          type: hit.type,
          entropy: hit.entropy,
          source: 'working-tree',
        });
      }
    }
    return findings;
  } catch {
    return []; // unreadable file: skip
  }
}

function isExitCode(err: unknown, code: number): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'code' in err &&
    (err as { code: unknown }).code === code
  );
}

function parseGitGrepLine(
  raw: string,
): { commit?: string; file: string; line: number; content: string } | null {
  const withSha = /^([0-9a-f]{7,64}):(.+?):(\d+):([\s\S]*)$/.exec(raw);
  if (withSha) {
    return { commit: withSha[1], file: withSha[2], line: Number(withSha[3]), content: withSha[4] };
  }
  const noSha = /^(.+?):(\d+):([\s\S]*)$/.exec(raw);
  if (noSha) {
    return { file: noSha[1], line: Number(noSha[2]), content: noSha[3] };
  }
  return null;
}

/** What the git-history pass actually covered (never what it intended to). */
export interface HistoryCoverage {
  /** True when the history pass was requested and ran. */
  attempted: boolean;
  /** True when the target is inside a Git work tree. */
  gitRepository: boolean;
  /** True for a shallow clone, whose history is incomplete; `null` when unknown. */
  shallow: boolean | null;
  /** Commits actually inspected. */
  commitsScanned: number;
  /** True when more commits exist than the configured limit allowed. */
  truncated: boolean;
  /** Populated when the pass could not complete. */
  error?: string;
}

export interface ScanCoverage {
  /** True when the working tree was walked to completion. */
  workingTree: boolean;
  history: HistoryCoverage;
}

export interface ScanResult {
  findings: RawFinding[];
  coverage: ScanCoverage;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Scans committed history with a single broad `git grep -E` prefilter per
 * batch of commits, then re-validates every candidate line with the strict
 * in-process patterns. Never uses a shell (no injection surface).
 *
 * Returns the observed coverage next to the findings so callers can report
 * what was really analysed: a shallow clone, a commit cap or a git error must
 * never be presented as a complete history scan.
 */
async function scanHistory(
  root: string,
  maxCommits: number,
): Promise<{ findings: RawFinding[]; coverage: HistoryCoverage }> {
  const coverage: HistoryCoverage = {
    attempted: true,
    gitRepository: false,
    shallow: null,
    commitsScanned: 0,
    truncated: false,
  };

  try {
    await execFileAsync('git', ['-C', root, 'rev-parse', '--is-inside-work-tree'], {
      timeout: 10_000,
    });
    coverage.gitRepository = true;
  } catch (err) {
    coverage.error = errorMessage(err);
    return { findings: [], coverage };
  }

  try {
    const { stdout } = await execFileAsync(
      'git',
      ['-C', root, 'rev-parse', '--is-shallow-repository'],
      { timeout: 10_000 },
    );
    coverage.shallow = stdout.trim() === 'true';
  } catch {
    coverage.shallow = null; // older git: cannot tell
  }

  let shas: string[];
  try {
    const { stdout } = await execFileAsync(
      'git',
      ['-C', root, 'rev-list', `--max-count=${maxCommits + 1}`, '--all'],
      { timeout: 30_000 },
    );
    const all = stdout
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);
    coverage.truncated = all.length > maxCommits;
    shas = all.slice(0, maxCommits);
  } catch (err) {
    coverage.error = errorMessage(err);
    return { findings: [], coverage };
  }
  if (shas.length === 0) return { findings: [], coverage };

  const combined = SECRET_PATTERNS.map((p) => p.src).join('|');
  const findings: RawFinding[] = [];
  let inspected = 0;

  for (let i = 0; i < shas.length; i += GIT_GREP_BATCH) {
    const batch = shas.slice(i, i + GIT_GREP_BATCH);
    let stdout: string;
    try {
      ({ stdout } = await execFileAsync(
        'git',
        ['-C', root, 'grep', '-n', '-i', '-I', '-E', '-e', combined, ...batch],
        { timeout: 60_000, maxBuffer: 64 * 1024 * 1024 },
      ));
    } catch (err) {
      if (isExitCode(err, 1)) {
        inspected += batch.length; // no matches in this batch
        continue;
      }
      coverage.error = errorMessage(err);
      break; // git error: keep findings gathered so far
    }
    inspected += batch.length;
    for (const raw of stdout.split('\n')) {
      if (!raw) continue;
      const parsed = parseGitGrepLine(raw);
      if (!parsed) continue;
      const hit = matchLine(parsed.content);
      if (hit) {
        findings.push({
          file: parsed.file,
          line: parsed.line,
          type: hit.type,
          entropy: hit.entropy,
          source: 'git-history',
          ...(parsed.commit ? { commit: parsed.commit } : {}),
        });
      }
    }
  }
  coverage.commitsScanned = inspected;
  return { findings, coverage };
}

/** Working-tree findings always win over their historical duplicates. */
function dedupe(findings: RawFinding[]): RawFinding[] {
  const map = new Map<string, RawFinding>();
  for (const f of findings) {
    const key = `${f.file}:${f.line}:${f.type}`;
    const prev = map.get(key);
    if (!prev || (prev.source === 'git-history' && f.source === 'working-tree')) {
      map.set(key, f);
    }
  }
  return [...map.values()];
}

/**
 * Scan a directory or glob pattern for secrets and report what was actually
 * covered. Use this when the caller needs reproducible provenance.
 *
 * @param target Directory, file or glob pattern. Defaults to options.cwd.
 * @returns findings (deduplicated per file:line:type) plus observed coverage.
 */
export async function scanRepoDetailed(
  target?: string,
  options: ScanOptions = {},
): Promise<ScanResult> {
  const gitHistory = options.gitHistory ?? DEFAULTS.gitHistory;
  const maxFileBytes = options.maxFileBytes ?? DEFAULTS.maxFileBytes;
  const maxCommits = options.maxCommits ?? DEFAULTS.maxCommits;
  const cwd = options.cwd ?? process.cwd();

  const coverage: ScanCoverage = {
    workingTree: true,
    history: {
      attempted: gitHistory,
      gitRepository: false,
      shallow: null,
      commitsScanned: 0,
      truncated: false,
    },
  };

  const collectHistory = async (root: string): Promise<RawFinding[]> => {
    if (!gitHistory) return [];
    const result = await scanHistory(root, maxCommits);
    coverage.history = result.coverage;
    return result.findings;
  };

  const findings: RawFinding[] = [];
  const resolved = target ? path.resolve(cwd, target) : cwd;
  const isDir = fs.existsSync(resolved) && safeIsDirectory(resolved);

  if (target && !isDir) {
    // Glob mode: match relative to cwd, then filter to scannable files.
    const matches = await glob(target, {
      cwd,
      dot: true,
      nodir: true,
      follow: false,
      ignore: GLOB_IGNORE,
    });
    for (const rel of matches) {
      const abs = path.resolve(cwd, rel);
      if (!matchesFilters(abs, LEAKSCAN_FILTERS)) continue;
      findings.push(...(await scanFile(abs, cwd, maxFileBytes)));
    }
    findings.push(...(await collectHistory(cwd)));
    return { findings: dedupe(findings), coverage };
  }

  const root = resolved;
  const files = await collectFiles(root, LEAKSCAN_FILTERS);
  for (const file of files) {
    findings.push(...(await scanFile(file, root, maxFileBytes)));
  }
  findings.push(...(await collectHistory(root)));
  return { findings: dedupe(findings), coverage };
}

/**
 * Scan a directory or glob pattern for secrets.
 *
 * @param target Directory, file or glob pattern. Defaults to options.cwd.
 * @returns findings sorted by discovery order, deduplicated per file:line:type.
 */
export async function scanRepo(
  target?: string,
  options: ScanOptions = {},
): Promise<RawFinding[]> {
  return (await scanRepoDetailed(target, options)).findings;
}

function safeIsDirectory(p: string): boolean {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
}
